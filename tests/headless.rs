#![cfg(not(feature = "dashboard"))]

use std::{fs, process::Command};

#[test]
fn dashboard_request_fails_before_capture_or_output_files_are_opened() {
    let dir = std::env::temp_dir().join(format!("netscope-headless-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    fs::write(&config, "[web]\nenabled = true\n").unwrap();
    let capture = dir.join("capture.pcap");
    let export = dir.join("flows.json");
    let summary = dir.join("summary.json");
    fs::write(&export, "existing investigation").unwrap();

    for config_request in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_netscope"));
        command
            .arg("--read-pcap")
            .arg(dir.join("missing.pcap"))
            .arg("--write-pcap")
            .arg(&capture)
            .arg("--export-json")
            .arg(&export)
            .arg("--summary-json")
            .arg(&summary);
        if config_request {
            command.arg("--config").arg(&config);
        } else {
            command.arg("--web");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("dashboard support is unavailable")
        );
        assert_eq!(
            fs::read_to_string(&export).unwrap(),
            "existing investigation"
        );
        assert!(!capture.exists());
        assert!(!summary.exists());
    }
    fs::remove_dir_all(dir).unwrap();
}
