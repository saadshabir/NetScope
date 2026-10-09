//! Open sensitive outputs before modifying them. On Unix, files are private,
//! and links, special files, and files owned by another user are rejected.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[derive(Clone, Copy)]
enum Mode {
    Overwrite,
    Append,
    New,
}

pub fn create(path: &Path) -> io::Result<File> {
    open(path, Mode::Overwrite)
}

pub fn append(path: &Path) -> io::Result<File> {
    open(path, Mode::Append)
}

pub fn create_new(path: &Path) -> io::Result<File> {
    open(path, Mode::New)
}

fn open(path: &Path, mode: Mode) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    match mode {
        Mode::New => {
            options.create_new(true);
        }
        Mode::Overwrite | Mode::Append => {
            options.create(true);
        }
    }
    if matches!(mode, Mode::Append) {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not truncate until descriptor metadata has been checked. Nonblocking
        // open prevents a planted FIFO from hanging a privileged capture run.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Inspect a reparse point itself instead of opening its target.
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and does not take pointers.
        if metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "output must have one link and belong to the effective user",
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    if matches!(mode, Mode::Overwrite) {
        file.set_len(0)?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn outputs_are_private_and_reject_links_without_changing_the_target() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("netscope-output-{unique}"));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("output");
        create(&path).unwrap().write_all(b"sensitive").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        append(&path).unwrap().write_all(b" data").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"sensitive data");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("symlink");
        symlink(&path, &link).unwrap();
        assert!(create(&link).is_err());
        assert!(append(&link).is_err());
        let hardlink = dir.join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(create(&hardlink).is_err());
        assert!(append(&hardlink).is_err());
        assert!(create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"sensitive data");
        assert!(create_new(&path).is_err());
        std::fs::remove_file(hardlink).unwrap();
        create(&path).unwrap().write_all(b"replacement").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(create(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
