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
            "netscope-investigation-{label}-{}-{unique}",
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
    run_fixture_with_options(name, pipeline, show_packets, false)
}

fn run_fixture_with_options(
    name: &str,
    pipeline: bool,
    show_packets: bool,
    disable_anomalies: bool,
) -> RunOutput {
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
    if disable_anomalies {
        command.arg("--no-anomalies");
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

fn assert_pipeline_anomalies_rejected(name: &str) {
    let config_path = Path::new(REPO_ROOT).join("examples/anomaly-demo.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_netscope"))
        .arg("--read-pcap")
        .arg(fixture_path(name))
        .arg("--config")
        .arg(config_path)
        .arg("--pipeline")
        .arg("--workers")
        .arg("2")
        .arg("--quiet")
        .output()
        .expect("netscope should reject unsupported pipeline/anomaly configuration");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("pipeline mode does not support anomaly detection"));
    assert!(
        output.stdout.is_empty(),
        "capture must not start before rejection"
    );
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
        "packets_with_network_header",
        "packets_with_transport_header",
        "packet_parse_errors",
        "transport_parse_errors",
        "unsupported_packets",
        "malformed_or_unsupported_packets",
    ] {
        assert_eq!(
            run.summary[field].as_u64(),
            fixture["expected_packet_accounting"][field].as_u64(),
            "{field} should match the checked-in manifest for {name}"
        );
    }
    assert_eq!(
        run.summary["malformed_or_unsupported_packets"].as_u64(),
        Some(
            run.summary["packet_parse_errors"].as_u64().unwrap()
                + run.summary["transport_parse_errors"].as_u64().unwrap()
                + run.summary["unsupported_packets"].as_u64().unwrap()
        ),
        "the compatibility aggregate should reconcile with the detailed counters"
    );
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
    let normal_pipeline = run_fixture_with_options("normal.pcap", true, true, true);
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
    let edges_pipeline = run_fixture_with_options("protocol-edges.pcap", true, false, true);
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
    assert!(edges_inline.stdout.contains("Malformed transport: 1"));
    assert!(edges_inline.stdout.contains("Unsupported packets:  1"));
    assert!(edges_inline.stdout.contains("Packet parse errors: 0"));
    assert!(!edges_inline.stdout.contains("Success rate:"));
    assert!(edges_inline.stdout.contains("malformed transport:"));
    assert!(edges_inline.stdout.contains("unsupported protocol payload"));
}

#[test]
fn anomaly_fixtures_emit_versioned_inline_alerts_and_reject_pipeline_mode() {
    let scan_inline = run_fixture("port-scan.pcap", false, false);
    assert_accounting("port-scan.pcap", &scan_inline, false);
    assert_alert_count(&scan_inline, "port_scan", 1);
    assert_pipeline_anomalies_rejected("port-scan.pcap");
    assert!(
        scan_inline.alerts[0]["description"]
            .as_str()
            .unwrap()
            .contains("4 ports")
    );
    assert_eq!(scan_inline.alerts[0]["schema_version"], 1);
    assert!(scan_inline.alerts[0]["ts"].as_f64().is_some());
    assert_eq!(scan_inline.alerts[0]["kind"], "port_scan");
    assert_eq!(scan_inline.alerts[0]["source_ip"], "192.0.2.50");
    assert!(scan_inline.alerts[0]["target_ip"].is_null());
    assert_eq!(scan_inline.alerts[0]["window_secs"], 10.0);
    assert_eq!(scan_inline.alerts[0]["thresholds"]["unique_ports"], 4);
    assert_eq!(scan_inline.alerts[0]["observed"]["unique_ports"], 4);

    let flood_inline = run_fixture("syn-flood.pcap", false, false);
    assert_accounting("syn-flood.pcap", &flood_inline, false);
    assert_alert_count(&flood_inline, "syn_flood", 1);
    assert_pipeline_anomalies_rejected("syn-flood.pcap");
    assert!(
        flood_inline.alerts[0]["description"]
            .as_str()
            .unwrap()
            .contains("8 syns, 8 sources")
    );
    assert_eq!(flood_inline.alerts[0]["schema_version"], 1);
    assert_eq!(flood_inline.alerts[0]["kind"], "syn_flood");
    assert!(flood_inline.alerts[0]["source_ip"].is_null());
    assert_eq!(flood_inline.alerts[0]["target_ip"], "203.0.113.200");
    assert_eq!(flood_inline.alerts[0]["target_port"], 443);
    assert_eq!(flood_inline.alerts[0]["window_secs"], 5.0);
    assert_eq!(flood_inline.alerts[0]["thresholds"]["syn_count"], 8);
    assert_eq!(flood_inline.alerts[0]["observed"]["unique_sources"], 8);
}

#[test]
fn non_transport_frames_advance_the_anomaly_window() {
    let fixture = std::fs::read(fixture_path("port-scan.pcap")).expect("fixture should exist");
    let mut records = Vec::new();
    let mut offset = 24; // classic PCAP global header
    for _ in 0..4 {
        let captured_len =
            u32::from_le_bytes(fixture[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let end = offset + 16 + captured_len;
        records.push(&fixture[offset..end]);
        offset = end;
    }
    let first_second = u32::from_le_bytes(records[0][..4].try_into().unwrap());
    let temp_dir = TempRunDir::new("anomaly-watermark");

    for (label, malformed) in [("unsupported", false), ("malformed", true)] {
        let mut future_record = records[0].to_vec();
        future_record[..4].copy_from_slice(&(first_second + 100).to_le_bytes());
        if malformed {
            future_record[8..12].copy_from_slice(&10u32.to_le_bytes());
            future_record.truncate(16 + 10); // incomplete Ethernet header
        } else {
            future_record[28..30].copy_from_slice(&0x9999u16.to_be_bytes());
        }

        let mut pcap = fixture[..24].to_vec();
        for record in records.iter().take(3) {
            pcap.extend_from_slice(record);
        }
        pcap.extend_from_slice(&future_record);
        pcap.extend_from_slice(records[3]); // older fourth SYN would cross the threshold

        let pcap_path = temp_dir.file(&format!("{label}.pcap"));
        let alert_path = temp_dir.file(&format!("{label}-alerts.jsonl"));
        let summary_path = temp_dir.file(&format!("{label}-summary.json"));
        std::fs::write(&pcap_path, pcap).expect("test PCAP should be written");
        let output = Command::new(env!("CARGO_BIN_EXE_netscope"))
            .arg("--read-pcap")
            .arg(&pcap_path)
            .arg("--config")
            .arg(Path::new(REPO_ROOT).join("examples/anomaly-demo.toml"))
            .arg("--quiet")
            .arg("--alerts-jsonl")
            .arg(&alert_path)
            .arg("--summary-json")
            .arg(&summary_path)
            .output()
            .expect("netscope should run the timestamp regression fixture");
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&alert_path).unwrap(),
            "",
            "{label} frame should expire older scan observations"
        );

        let summary: Value =
            serde_json::from_slice(&std::fs::read(&summary_path).unwrap()).unwrap();
        assert_eq!(summary["frames_read"], 5);
        assert_eq!(summary["alerts_emitted"], 0);
        assert_eq!(summary["packet_parse_errors"], u64::from(malformed));
        assert_eq!(summary["unsupported_packets"], u64::from(!malformed));
    }
}
