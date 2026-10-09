#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct CaptureProcess(Child);

impl Drop for CaptureProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires an isolated Linux veth interface and CAP_NET_RAW"]
fn idle_live_capture_interrupt_flushes_outputs_in_both_modes() {
    let interface = std::env::var("NETSCOPE_LIVE_TEST_INTERFACE")
        .expect("set NETSCOPE_LIVE_TEST_INTERFACE to the isolated receiver veth");
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let root = std::env::temp_dir().join(format!(
        "netscope-live-shutdown-{}-{}",
        std::process::id(),
        stamp.as_nanos()
    ));
    for pipeline in [false, true] {
        for immediate in [false, true] {
            for timeout in [0, 20] {
                let case = root.join(format!(
                    "pipeline-{pipeline}-immediate-{immediate}-{timeout}"
                ));
                fs::create_dir_all(&case).unwrap();
                let config = case.join("config.toml");
                let summary = case.join("summary.json");
                let pcap = case.join("empty.pcap");
                fs::write(
                    &config,
                    format!(
                        "[capture]\nimmediate_mode = {immediate}\ntimeout_ms = {timeout}\n\
                         [stats]\nenabled = false\n\
                         [pipeline]\nenabled = {pipeline}\nworkers = 2\n"
                    ),
                )
                .unwrap();
                let mut process = CaptureProcess(
                    Command::new(env!("CARGO_BIN_EXE_netscope"))
                        .args(["--config"])
                        .arg(&config)
                        .args(["--interface", &interface, "--filter", "ip", "--quiet"])
                        .arg("--summary-json")
                        .arg(&summary)
                        .arg("--write-pcap")
                        .arg(&pcap)
                        .stdout(Stdio::piped())
                        .spawn()
                        .unwrap(),
                );
                let stdout = process.0.stdout.take().unwrap();
                let (ready_tx, ready_rx) = mpsc::channel();
                let mut log = fs::File::create(case.join("stdout.log")).unwrap();
                let reader = thread::spawn(move || {
                    for line in BufReader::new(stdout).lines() {
                        let line = line.unwrap();
                        writeln!(log, "{line}").unwrap();
                        if line.starts_with("NETSCOPE_READY ") {
                            ready_tx.send(()).unwrap();
                        }
                    }
                });
                ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                thread::sleep(Duration::from_millis(200));
                // SAFETY: the child is alive and its positive PID identifies
                // only the capture process started for this case.
                assert_eq!(
                    unsafe { libc::kill(process.0.id() as i32, libc::SIGINT) },
                    0
                );
                let deadline = Instant::now() + Duration::from_secs(3);
                let status = loop {
                    if let Some(status) = process.0.try_wait().unwrap() {
                        break status;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "idle capture hung; logs: {case:?}"
                    );
                    thread::sleep(Duration::from_millis(10));
                };
                assert!(status.success(), "capture failed; logs: {case:?}");
                reader.join().unwrap();
                let summary: serde_json::Value =
                    serde_json::from_slice(&fs::read(summary).unwrap()).unwrap();
                assert_eq!(summary["status"], "interrupted");
                assert_eq!(summary["frames_read"], 0);
                assert_eq!(summary["output_errors"], serde_json::json!([]));
                if pipeline {
                    assert_eq!(summary["worker_processed_frames"], 0);
                    assert_eq!(summary["worker_failures"], 0);
                }
                assert_eq!(fs::metadata(pcap).unwrap().len(), 24);
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
