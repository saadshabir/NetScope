use std::path::{Component, Path, PathBuf};

// Resolve existing ancestors as well as existing files, so future outputs and
// paths through symlinked directories have a comparable identity.
pub fn resolved(path: &Path) -> Result<PathBuf, String> {
    resolved_inner(path, 0)
}

fn resolved_inner(path: &Path, depth: usize) -> Result<PathBuf, String> {
    if depth >= 40 {
        return Err(format!("too many symlinks in {}", path.display()));
    }
    match std::fs::canonicalize(path) {
        Ok(path) => return Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("cannot resolve {}: {err}", path.display())),
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|err| err.to_string())?
            .join(path)
    };
    let mut result = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => {
                result.push(other.as_os_str());
                if let Ok(target) = std::fs::read_link(&result) {
                    let target = if target.is_absolute() {
                        target
                    } else {
                        result.parent().unwrap_or(Path::new("/")).join(target)
                    };
                    result = resolved_inner(&target, depth + 1)?;
                }
                if let Ok(canonical) = std::fs::canonicalize(&result) {
                    result = canonical;
                }
            }
        }
    }
    Ok(result)
}

fn same_file(a: &Path, b: &Path) -> Result<bool, String> {
    let resolved_a = resolved(a)?;
    let resolved_b = resolved(b)?;
    if resolved_a == resolved_b {
        return Ok(true);
    }
    #[cfg(any(target_os = "macos", windows))]
    if (!a.exists() || !b.exists())
        && resolved_a
            .to_string_lossy()
            .eq_ignore_ascii_case(&resolved_b.to_string_lossy())
    {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(same_file::is_same_file(a, b).unwrap_or(false))
    }
}

pub fn same_parent(a: &Path, b: &Path) -> Result<bool, String> {
    let parent = |p: &Path| {
        resolved(
            p.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
    };
    Ok(parent(a)? == parent(b)?)
}

pub fn validate(reads: &[(&str, &Path)], writes: &[(&str, &Path)]) -> Result<(), String> {
    for (idx, (name, path)) in writes.iter().enumerate() {
        for (other_name, other) in reads.iter().chain(writes[..idx].iter()) {
            if same_file(path, other)? {
                return Err(format!(
                    "{name} and {other_name} refer to the same file: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_existing_aliases_and_future_output_collisions() {
        let root = std::env::temp_dir().join(format!("netscope-paths-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("input.pcap");
        let link = root.join("hardlink.pcap");
        std::fs::write(&input, b"capture data").unwrap();
        std::fs::hard_link(&input, &link).unwrap();
        assert!(validate(&[("input", &input)], &[("output", &input)]).is_err());
        assert!(validate(&[("input", &input)], &[("output", &link)]).is_err());
        let future = root.join("future.json");
        let alias = root.join("./future.json");
        assert!(validate(&[], &[("json", &future), ("csv", &alias)]).is_err());
        #[cfg(unix)]
        {
            let symlink = root.join("symlink.pcap");
            std::os::unix::fs::symlink(&input, &symlink).unwrap();
            assert!(validate(&[("input", &input)], &[("output", &symlink)]).is_err());
            let dangling = root.join("dangling.json");
            std::os::unix::fs::symlink(&future, &dangling).unwrap();
            assert!(validate(&[], &[("json", &future), ("csv", &dangling)]).is_err());
            let dirlink = root.join("dirlink");
            std::os::unix::fs::symlink(&root, &dirlink).unwrap();
            assert!(
                validate(
                    &[],
                    &[("json", &future), ("csv", &dirlink.join("future.json"))]
                )
                .is_err()
            );
        }
        assert_eq!(std::fs::read(&input).unwrap(), b"capture data");
        std::fs::remove_dir_all(root).unwrap();
    }
}
