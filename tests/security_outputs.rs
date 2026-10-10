#![cfg(unix)]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "netscope-security-{}-{unique}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const OUTPUT_FLAGS: [&str; 7] = [
    "--write-pcap",
    "--export-json",
    "--export-csv",
    "--summary-json",
    "--expired-flows-jsonl",
    "--expired-flows-csv",
    "--alerts-jsonl",
];

fn command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_netscope"));
    cmd.args([
        "--read-pcap",
        "examples/pcaps/normal.pcap",
        "--quiet",
        "--anomalies",
    ]);
    cmd
}

#[test]
fn every_capture_output_is_private_even_when_overwriting_public_files() {
    let dir = TempDir::new();
    for existing in [false, true] {
        let mut cmd = command();
        for (idx, flag) in OUTPUT_FLAGS.iter().enumerate() {
            let path = dir.0.join(format!("output-{idx}"));
            if existing {
                std::fs::write(&path, b"old output\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            cmd.arg(flag).arg(path);
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for idx in 0..OUTPUT_FLAGS.len() {
            let path = dir.0.join(format!("output-{idx}"));
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn every_capture_output_rejects_symlinks_and_hardlinks_without_clobbering_targets() {
    let dir = TempDir::new();
    let target = dir.0.join("important-file");
    std::fs::write(&target, b"keep this data").unwrap();
    for flag in OUTPUT_FLAGS {
        for hardlink in [false, true] {
            let output = dir.0.join("output");
            if hardlink {
                std::fs::hard_link(&target, &output).unwrap();
            } else {
                symlink(&target, &output).unwrap();
            }
            let result = command().arg(flag).arg(&output).output().unwrap();
            assert!(!result.status.success(), "{flag} accepted an unsafe output");
            assert_eq!(std::fs::read(&target).unwrap(), b"keep this data", "{flag}");
            std::fs::remove_file(output).unwrap();
        }
    }
}
