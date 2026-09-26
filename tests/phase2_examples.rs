use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");
const MANIFEST: &str = include_str!("../examples/pcaps/manifest.json");

struct TempRunDir(PathBuf);

impl TempRunDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "netscope-phase2-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("temporary run directory should be created");
        TempRunDir(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempRunDir {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0) {
            eprintln!("warning: failed to remove {}: {err}", self.0.display());
        }
    }
}

struct RunOutput {
    _temp_dir: TempRunDir,
    stdout: String,
    summary: Value,
    flows: Vec<Value>,
    alerts: Vec<Value>,
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(REPO_ROOT).join("examples/pcaps").join(name)
}

fn manifest_fixture(name: &str) -> Value {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("fixture manifest should parse");
    manifest["fixtures"]
        .as_array()
        .expect("manifest fixture list should be an array")
        .iter()
        .find(|fixture| fixture["file"] == name)
        .unwrap_or_else(|| panic!("fixture {name} should be listed in the manifest"))
        .clone()
}

fn run_fixture(name: &str, pipeline: bool, show_packets: bool) -> RunOutput {
    let mode = if pipeline { "pipeline" } else { "inline" };
    let temp_dir = TempRunDir::new(&format!("{name}-{mode}"));
    let summary_path = temp_dir.file("summary.json");
    let flow_path = temp_dir.file("flows.json");
    let alert_path = temp_dir.file("alerts.jsonl");
    let config_path = Path::new(REPO_ROOT).join("examples/anomaly-demo.toml");

    let mut command = Command::new(env!("CARGO_BIN_EXE_netscope"));
    command
        .arg("--read-pcap")
        .arg(fixture_path(name))
        .arg("--config")
        .arg(config_path)
        .arg("--summary-json")
        .arg(&summary_path)
        .arg("--export-json")
        .arg(&flow_path)
        .arg("--alerts-jsonl")
        .arg(&alert_path);
    if show_packets {
        command.arg("--no-quiet");
    } else {
        command.arg("--quiet");
    }
    if pipeline {
        command.arg("--pipeline").arg("--workers").arg("2");
    }

    let output: Output = command.output().expect("netscope should run");
    assert!(
        output.status.success(),
        "{name} {mode} run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(
        &std::fs::read(&summary_path).expect("summary JSON should be written"),
    )
    .expect("summary JSON should parse");
    let flows: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&flow_path).expect("flow export should be written"))
            .expect("flow export should parse");
    let alerts = std::fs::read_to_string(&alert_path)
        .expect("alert JSONL output should be written")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("alert JSONL record should parse"))
        .collect();

    RunOutput {
        _temp_dir: temp_dir,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        summary,
        flows,
        alerts,
    }
}

fn assert_accounting(name: &str, run: &RunOutput, pipeline: bool) {
    let fixture = manifest_fixture(name);
    assert_eq!(
        run.summary["frames_read"].as_u64(),
        fixture["packet_count"].as_u64(),
        "frame count should match the checked-in manifest for {name}"
    );
    assert_eq!(
        run.summary["input_wire_bytes"].as_u64(),
        fixture["wire_bytes"].as_u64(),
        "input byte count should match the checked-in manifest for {name}"
    );
    assert_eq!(
        run.summary["packets_parsed"].as_u64(),
        fixture["packet_count"].as_u64(),
        "parsed packet count should match the checked-in manifest for {name}"
    );
    for field in [
        "packets_with_transport_header",
        "malformed_or_unsupported_packets",
    ] {
        assert_eq!(
            run.summary[field].as_u64(),
            fixture["expected_packet_accounting"][field].as_u64(),
            "{field} should match the checked-in manifest for {name}"
        );
    }
    assert_eq!(run.summary["status"], "success");
    assert_eq!(
        run.summary["alerts_emitted"].as_u64(),
        Some(run.alerts.len() as u64)
    );

    if pipeline {
        let frames_read = run.summary["frames_read"].as_u64().unwrap();
        let dispatched = run.summary["dispatched_frames"].as_u64().unwrap();
        let drops = run.summary["dispatch_drops"].as_u64().unwrap();
        let processed = run.summary["worker_processed_frames"].as_u64().unwrap();
        let failures = run.summary["worker_failures"].as_u64().unwrap();
        assert_eq!(
            frames_read,
            dispatched + drops,
            "pipeline dispatch should reconcile"
        );
        assert_eq!(
            dispatched,
            processed + failures,
            "worker completion should reconcile"
        );
        assert_eq!(drops, 0, "offline fixture dispatch must not drop frames");
        assert_eq!(failures, 0, "offline fixture workers must not fail");
        assert_eq!(run.summary["worker_count"].as_u64(), Some(2));
    } else {
        assert!(run.summary["dispatched_frames"].is_null());
        assert!(run.summary["dispatch_drops"].is_null());
    }
}

fn flow_facts(flows: &[Value]) -> Vec<String> {
    let mut facts: Vec<String> = flows
        .iter()
        .map(|flow| {
            serde_json::json!({
                "protocol": flow["protocol"],
                "endpoint_a": flow["endpoint_a"],
                "endpoint_b": flow["endpoint_b"],
                "packets_a_to_b": flow["packets_a_to_b"],
                "packets_b_to_a": flow["packets_b_to_a"],
                "bytes_a_to_b": flow["bytes_a_to_b"],
                "bytes_b_to_a": flow["bytes_b_to_a"],
                "packets_total": flow["packets_total"],
                "bytes_total": flow["bytes_total"],
            })
            .to_string()
        })
        .collect();
    facts.sort();
    facts
}

fn assert_alert_count(run: &RunOutput, kind: &str, count: usize) {
    assert_eq!(run.alerts.len(), count);
    assert!(run.alerts.iter().all(|alert| alert["kind"] == kind));
}

#[test]
fn normal_and_protocol_edge_fixtures_reconcile_and_match_across_modes() {
    let normal_inline = run_fixture("normal.pcap", false, true);
    let normal_pipeline = run_fixture("normal.pcap", true, true);
    assert_accounting("normal.pcap", &normal_inline, false);
    assert_accounting("normal.pcap", &normal_pipeline, true);
    assert_alert_count(&normal_inline, "port_scan", 0);
    assert_alert_count(&normal_pipeline, "port_scan", 0);
    assert_eq!(normal_inline.flows.len(), 2);
    assert_eq!(
        flow_facts(&normal_inline.flows),
        flow_facts(&normal_pipeline.flows)
    );
    let tcp = normal_inline
        .flows
        .iter()
        .find(|flow| flow["protocol"] == "tcp")
        .expect("normal fixture should produce a TCP flow");
    let udp = normal_inline
        .flows
        .iter()
        .find(|flow| flow["protocol"] == "udp")
        .expect("normal fixture should produce a UDP flow");
    assert_eq!(tcp["packets_total"], 6);
    assert_eq!(tcp["packets_a_to_b"], 4);
    assert_eq!(tcp["packets_b_to_a"], 2);
    assert_eq!(udp["packets_total"], 2);
    assert_eq!(udp["packets_a_to_b"], 1);
    assert_eq!(udp["packets_b_to_a"], 1);
    assert!(
        normal_inline
            .stdout
            .contains("TLS ClientHello sni=api.example.test")
    );
    assert!(
        normal_inline
            .stdout
            .contains("DNS id=0x4242 Q A www.example.test")
    );

    let edges_inline = run_fixture("protocol-edges.pcap", false, true);
    let edges_pipeline = run_fixture("protocol-edges.pcap", true, false);
    assert_accounting("protocol-edges.pcap", &edges_inline, false);
    assert_accounting("protocol-edges.pcap", &edges_pipeline, true);
    assert_eq!(
        flow_facts(&edges_inline.flows),
        flow_facts(&edges_pipeline.flows)
    );
    assert!(edges_inline.stdout.contains("IPv6:"));
    assert!(edges_inline.stdout.contains("VLAN:100/200"));
    assert!(edges_inline.stdout.contains("ICMP "));
    assert!(edges_inline.stdout.contains("ICMPv6 "));
    assert!(edges_inline.stdout.contains("malformed transport:"));
    assert!(edges_inline.stdout.contains("unsupported protocol payload"));
}

#[test]
fn anomaly_fixtures_emit_documented_inline_and_pipeline_alerts() {
    let scan_inline = run_fixture("port-scan.pcap", false, false);
    let scan_pipeline = run_fixture("port-scan.pcap", true, false);
    assert_accounting("port-scan.pcap", &scan_inline, false);
    assert_accounting("port-scan.pcap", &scan_pipeline, true);
    assert_alert_count(&scan_inline, "port_scan", 1);
    assert_alert_count(&scan_pipeline, "port_scan", 2);
    assert!(
        scan_inline.alerts[0]["description"]
            .as_str()
            .unwrap()
            .contains("4 ports")
    );

    let flood_inline = run_fixture("syn-flood.pcap", false, false);
    let flood_pipeline = run_fixture("syn-flood.pcap", true, false);
    assert_accounting("syn-flood.pcap", &flood_inline, false);
    assert_accounting("syn-flood.pcap", &flood_pipeline, true);
    assert_alert_count(&flood_inline, "syn_flood", 1);
    assert_alert_count(&flood_pipeline, "syn_flood", 2);
    assert!(
        flood_inline.alerts[0]["description"]
            .as_str()
            .unwrap()
            .contains("8 syns, 8 sources")
    );
}
