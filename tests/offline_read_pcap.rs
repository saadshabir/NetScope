use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("netscope-{}-{}.pcap", name, unique))
}

fn write_test_pcap(path: &Path, linktype: u32, packet: &[u8]) {
    let mut file = File::create(path).expect("failed to create temp pcap");

    // pcap global header (little-endian, microsecond resolution)
    let mut header = Vec::with_capacity(24);
    header.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes()); // major
    header.extend_from_slice(&4u16.to_le_bytes()); // minor
    header.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    header.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    header.extend_from_slice(&linktype.to_le_bytes());
    file.write_all(&header)
        .expect("failed to write pcap header");

    // pcap packet record header
    file.write_all(&1u32.to_le_bytes()) // ts_sec
        .expect("failed to write ts_sec");
    file.write_all(&123u32.to_le_bytes()) // ts_usec
        .expect("failed to write ts_usec");
    file.write_all(&(packet.len() as u32).to_le_bytes()) // incl_len
        .expect("failed to write incl_len");
    file.write_all(&(packet.len() as u32).to_le_bytes()) // orig_len
        .expect("failed to write orig_len");
    file.write_all(packet).expect("failed to write packet");
    file.flush().expect("failed to flush pcap file");
}

fn write_empty_test_pcap(path: &Path, linktype: u32) {
    let mut file = File::create(path).expect("failed to create empty temp pcap");
    file.write_all(&0xa1b2c3d4u32.to_le_bytes())
        .expect("failed to write magic");
    file.write_all(&2u16.to_le_bytes())
        .expect("failed to write version major");
    file.write_all(&4u16.to_le_bytes())
        .expect("failed to write version minor");
    file.write_all(&0i32.to_le_bytes())
        .expect("failed to write thiszone");
    file.write_all(&0u32.to_le_bytes())
        .expect("failed to write sigfigs");
    file.write_all(&65535u32.to_le_bytes())
        .expect("failed to write snaplen");
    file.write_all(&linktype.to_le_bytes())
        .expect("failed to write linktype");
}

fn make_ipv4_packet() -> Vec<u8> {
    let mut packet = vec![
        0x45, // version + ihl
        0x00, // dscp/ecn
        0x00, 0x28, // total length = 40
        0x00, 0x01, // identification
        0x00, 0x00, // flags + fragment offset
        64,   // ttl
        6,    // protocol TCP
        0x00, 0x00, // checksum (not validated by parser)
        192, 168, 1, 10, // src ip
        192, 168, 1, 20, // dst ip
    ];
    packet.extend_from_slice(&[
        0x30, 0x39, // src port 12345
        0x00, 0x50, // dst port 80
        0, 0, 0, 1, // sequence
        0, 0, 0, 0, // acknowledgment
        0x50, 0x10, // data offset, ACK
        0x20, 0x00, // window
        0, 0, // checksum
        0, 0, // urgent pointer
    ]);
    packet
}

fn make_ethernet_packet() -> Vec<u8> {
    let mut packet = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x08, 0x00, // ethertype IPv4
    ];
    packet.extend_from_slice(&make_ipv4_packet());
    packet
}

fn make_linux_sll_packet() -> Vec<u8> {
    let mut packet = vec![
        0x00, 0x00, // packet type = host
        0x00, 0x01, // ARPHRD = ethernet
        0x00, 0x06, // address length
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // address (8 bytes)
        0x08, 0x00, // protocol = IPv4
    ];
    packet.extend_from_slice(&make_ipv4_packet());
    packet
}

fn make_loopback_null_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&2u32.to_ne_bytes()); // AF_INET in native endian
    packet.extend_from_slice(&make_ipv4_packet());
    packet
}

fn make_raw_ip_packet() -> Vec<u8> {
    make_ipv4_packet()
}

fn run_netscope(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_netscope");
    Command::new(bin)
        .args(args)
        .output()
        .expect("failed to run netscope binary")
}

fn run_read_pcap_test(
    name: &str,
    linktype: u32,
    packet: &[u8],
    extra_args: &[&str],
    expect_parse_errors_zero: bool,
) {
    let pcap_path = temp_path(name);
    write_test_pcap(&pcap_path, linktype, packet);

    let pcap_path_str = pcap_path
        .to_str()
        .expect("temp pcap path must be valid utf-8 for cli");
    let mut args = vec!["--read-pcap", pcap_path_str, "--count", "1", "--quiet"];
    args.extend_from_slice(extra_args);
    let output = run_netscope(&args);

    if let Err(err) = std::fs::remove_file(&pcap_path) {
        eprintln!(
            "warning: failed to delete temp pcap {}: {}",
            pcap_path.display(),
            err
        );
    }

    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Packets captured:  1"),
        "stdout was: {}",
        stdout
    );

    if expect_parse_errors_zero {
        assert!(
            stdout.contains("Parse errors:      0"),
            "stdout was: {}",
            stdout
        );
    }
}

#[test]
fn read_pcap_inline_mode() {
    let packet = make_ethernet_packet();
    run_read_pcap_test("inline", 1, &packet, &[], true);
}

#[test]
fn read_pcap_pipeline_mode() {
    let packet = make_ethernet_packet();
    run_read_pcap_test("pipeline", 1, &packet, &["--pipeline"], false);
}

#[test]
fn read_pcap_inline_linux_sll_mode() {
    let packet = make_linux_sll_packet();
    run_read_pcap_test("inline-sll", 113, &packet, &[], true);
}

#[test]
fn read_pcap_inline_loopback_null_mode() {
    let packet = make_loopback_null_packet();
    run_read_pcap_test("inline-null", 0, &packet, &[], true);
}

#[test]
fn read_pcap_inline_raw_ip_mode() {
    let packet = make_raw_ip_packet();
    run_read_pcap_test("inline-raw", 101, &packet, &[], true);
}

#[test]
fn read_pcap_pipeline_linux_sll_mode() {
    let packet = make_linux_sll_packet();
    run_read_pcap_test("pipeline-sll", 113, &packet, &["--pipeline"], false);
}

#[test]
fn read_pcap_pipeline_loopback_null_mode() {
    let packet = make_loopback_null_packet();
    run_read_pcap_test("pipeline-null", 0, &packet, &["--pipeline"], false);
}

#[test]
fn read_pcap_pipeline_raw_ip_mode() {
    let packet = make_raw_ip_packet();
    run_read_pcap_test("pipeline-raw", 101, &packet, &["--pipeline"], false);
}

#[test]
fn summary_json_accounts_for_zero_packet_offline_run() {
    let pcap_path = temp_path("empty-summary");
    let summary_path = pcap_path.with_extension("json");
    write_empty_test_pcap(&pcap_path, 1);

    let output = run_netscope(&[
        "--read-pcap",
        pcap_path.to_str().unwrap(),
        "--quiet",
        "--summary-json",
        summary_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("summary JSON should exist"))
            .expect("summary JSON should parse");
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["status"], "success");
    assert_eq!(summary["frames_read"], 0);
    assert_eq!(summary["input_wire_bytes"], 0);
    assert_eq!(summary["packets_parsed"], 0);
    assert!(summary["elapsed_wall_seconds"].as_f64().unwrap() >= 0.0);
    assert!(summary["kernel_drops"].is_null());
    assert!(summary["interface_drops"].is_null());
    assert!(summary["dispatch_drops"].is_null());

    let _ = std::fs::remove_file(pcap_path);
    let _ = std::fs::remove_file(summary_path);
}

#[test]
fn summary_json_marks_truncated_transport_as_partial_and_malformed() {
    let pcap_path = temp_path("malformed-summary");
    let summary_path = pcap_path.with_extension("json");
    let mut packet = make_ipv4_packet();
    packet.truncate(24); // 20-byte IPv4 header plus an incomplete TCP header
    packet[2..4].copy_from_slice(&24u16.to_be_bytes());
    write_test_pcap(&pcap_path, 101, &packet);

    let output = run_netscope(&[
        "--read-pcap",
        pcap_path.to_str().unwrap(),
        "--quiet",
        "--summary-json",
        summary_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "expected a partial parse to be reported, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("summary JSON should exist"))
            .expect("summary JSON should parse");
    assert_eq!(summary["frames_read"], 1);
    assert_eq!(summary["packets_parsed"], 1);
    assert_eq!(summary["packets_with_transport_header"], 0);
    assert_eq!(summary["malformed_or_unsupported_packets"], 1);

    let _ = std::fs::remove_file(pcap_path);
    let _ = std::fs::remove_file(summary_path);
}

#[test]
fn output_open_error_is_recorded_and_returns_failure() {
    let pcap_path = temp_path("output-error");
    let summary_path = pcap_path.with_extension("json");
    let alerts_path = pcap_path.with_extension("missing").join("alerts.jsonl");
    write_test_pcap(&pcap_path, 1, &make_ethernet_packet());

    let output = run_netscope(&[
        "--read-pcap",
        pcap_path.to_str().unwrap(),
        "--quiet",
        "--alerts-jsonl",
        alerts_path.to_str().unwrap(),
        "--summary-json",
        summary_path.to_str().unwrap(),
    ]);
    assert!(!output.status.success(), "output failure must fail the run");
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).expect("summary JSON should exist"))
            .expect("summary JSON should parse");
    assert_eq!(summary["status"], "failed");
    assert!(!summary["output_errors"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_file(pcap_path);
    let _ = std::fs::remove_file(summary_path);
}
