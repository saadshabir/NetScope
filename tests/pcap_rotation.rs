use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("netscope-{}-{}", name, unique));
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    dir
}

fn write_test_pcap(path: &Path, linktype: u32, packet: &[u8], packet_count: u32) {
    let mut file = File::create(path).expect("failed to create input pcap");

    // pcap global header (little-endian, microsecond resolution)
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

    for i in 0..packet_count {
        let ts_sec = 1u32.saturating_add(i);
        let incl_len = packet.len() as u32;

        file.write_all(&ts_sec.to_le_bytes())
            .expect("failed to write ts_sec");
        file.write_all(&0u32.to_le_bytes())
            .expect("failed to write ts_usec");
        file.write_all(&incl_len.to_le_bytes())
            .expect("failed to write incl_len");
        file.write_all(&incl_len.to_le_bytes())
            .expect("failed to write orig_len");
        file.write_all(packet)
            .expect("failed to write packet payload");
    }

    file.flush().expect("failed to flush input pcap");
}

fn make_large_ethernet_packet(payload_len: usize) -> Vec<u8> {
    let total_len = 20usize.saturating_add(payload_len);
    let total_len_u16 = u16::try_from(total_len).expect("payload too large for IPv4 header");

    let mut packet = vec![
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // dst
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src
        0x08,
        0x00, // ethertype IPv4
        0x45, // version + ihl
        0x00, // dscp/ecn
        (total_len_u16 >> 8) as u8,
        (total_len_u16 & 0xff) as u8,
        0x00,
        0x01, // id
        0x00,
        0x00, // flags + fragment offset
        64,   // ttl
        6,    // protocol TCP
        0x00,
        0x00, // checksum (not validated by parser)
        10,
        0,
        0,
        1, // src ip
        10,
        0,
        0,
        2, // dst ip
    ];
    packet.extend(std::iter::repeat_n(0x42, payload_len));
    packet
}

fn make_tcp_ethernet_packet(payload_len: usize) -> Vec<u8> {
    let ip_total_len = 20 + 20 + payload_len;
    let ip_total_len = u16::try_from(ip_total_len).expect("payload too large for IPv4 packet");
    let mut packet = vec![
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // dst MAC
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src MAC
        0x08,
        0x00, // IPv4
        0x45,
        0x00, // version/IHL, DSCP/ECN
        (ip_total_len >> 8) as u8,
        (ip_total_len & 0xff) as u8,
        0x00,
        0x01, // identification
        0x00,
        0x00, // flags/fragment offset
        64,
        6, // TTL, TCP
        0x00,
        0x00, // checksum
        10,
        0,
        0,
        1, // src IP
        10,
        0,
        0,
        2, // dst IP
        0x30,
        0x39, // src port 12345
        0x00,
        0x50, // dst port 80
        0x00,
        0x00,
        0x00,
        0x01, // sequence number
        0x00,
        0x00,
        0x00,
        0x00, // acknowledgement number
        0x50,
        0x10, // data offset, ACK
        0x20,
        0x00, // window
        0x00,
        0x00, // checksum
        0x00,
        0x00, // urgent pointer
    ];
    packet.extend(std::iter::repeat_n(0x42, payload_len));
    packet
}

fn run_netscope(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_netscope");
    Command::new(bin)
        .args(args)
        .output()
        .expect("failed to run netscope binary")
}

fn parse_rotation_index(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_string_lossy();
    if !name.starts_with("capture.") || !name.ends_with(".pcap") {
        return None;
    }
    let middle = name.strip_prefix("capture.")?.strip_suffix(".pcap")?;
    middle.parse::<u64>().ok()
}

fn rotation_segment_path(base: &Path, index: u64) -> PathBuf {
    let parent = base.parent().unwrap_or_else(|| Path::new(""));
    let stem = base
        .file_stem()
        .or_else(|| base.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("capture");

    parent.join(format!("{}.{:06}.pcap", stem, index))
}

fn run_rotation_retention_test(pipeline: bool) {
    let dir = unique_temp_dir(if pipeline {
        "pcap-rotation-pipeline"
    } else {
        "pcap-rotation-inline"
    });
    let input = dir.join("input.pcap");
    let output_base = dir.join("capture.pcap");

    let packet = make_large_ethernet_packet(4096);
    write_test_pcap(&input, 1, &packet, 800);

    let input_str = input
        .to_str()
        .expect("input path must be valid utf-8 for cli");
    let output_str = output_base
        .to_str()
        .expect("output path must be valid utf-8 for cli");

    let mut args = vec![
        "--read-pcap",
        input_str,
        "--write-pcap",
        output_str,
        "--write-pcap-rotate-mb",
        "1",
        "--write-pcap-max-files",
        "2",
        "--quiet",
    ];
    if pipeline {
        args.push("--pipeline");
    }

    let output = run_netscope(&args);
    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut indices: Vec<u64> = std::fs::read_dir(&dir)
        .expect("failed to read temp dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter_map(|path| parse_rotation_index(&path))
        .collect();
    indices.sort_unstable();

    assert_eq!(
        indices.len(),
        2,
        "expected retention to keep exactly 2 rotated files, got {:?}",
        indices
    );
    assert!(
        !output_base.exists(),
        "rotation output should use numbered segments only"
    );
    assert!(
        indices[0] > 1,
        "oldest retained segment should be newer than the initial segment"
    );
    assert_eq!(
        indices[1],
        indices[0] + 1,
        "retained segments should be consecutive"
    );

    if let Err(err) = std::fs::remove_dir_all(&dir) {
        eprintln!(
            "warning: failed to delete temp test directory {}: {}",
            dir.display(),
            err
        );
    }
}

#[test]
fn offline_pipeline_backpressures_and_processes_every_frame() {
    let dir = unique_temp_dir("offline-pipeline-backpressure");
    let input = dir.join("input.pcap");
    let config = dir.join("pipeline.toml");
    let output = dir.join("rewritten.pcap");
    let flows = dir.join("flows.json");
    let summary = dir.join("summary.json");
    let inline_output = dir.join("inline-rewritten.pcap");
    let inline_flows = dir.join("inline-flows.json");
    let inline_summary = dir.join("inline-summary.json");
    let packet_count = 10_000;
    let packet = make_tcp_ethernet_packet(128);

    write_test_pcap(&input, 1, &packet, packet_count);
    std::fs::write(
        &config,
        "[pipeline]\nchannel_capacity = 1\n\n[flow]\ntimeout_secs = 0.0\n",
    )
    .expect("pipeline config should be written");

    let input_str = input.to_str().expect("input path must be valid UTF-8");
    let config_str = config.to_str().expect("config path must be valid UTF-8");
    let output_str = output.to_str().expect("output path must be valid UTF-8");
    let flows_str = flows.to_str().expect("flow path must be valid UTF-8");
    let inline_output_str = inline_output
        .to_str()
        .expect("inline output path must be valid UTF-8");
    let inline_flows_str = inline_flows
        .to_str()
        .expect("inline flow path must be valid UTF-8");
    let inline_summary_str = inline_summary
        .to_str()
        .expect("inline summary path must be valid UTF-8");
    let run = run_netscope(&[
        "--read-pcap",
        input_str,
        "--config",
        config_str,
        "--pipeline",
        "--workers",
        "1",
        "--write-pcap",
        output_str,
        "--export-json",
        flows_str,
        "--summary-json",
        summary.to_str().expect("summary path must be valid UTF-8"),
        "--quiet",
    ]);

    assert!(
        run.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.contains(&format!("Packets captured:  {}", packet_count)),
        "stdout was: {}",
        stdout
    );
    assert!(
        stdout.contains("Dispatch drops:    0"),
        "stdout was: {}",
        stdout
    );

    let summary_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&summary).expect("summary JSON should exist after pipeline shutdown"),
    )
    .expect("summary JSON should parse");
    assert_eq!(summary_json["frames_read"], packet_count);
    assert_eq!(summary_json["dispatched_frames"], packet_count);
    assert_eq!(summary_json["dispatch_drops"], 0);
    assert_eq!(summary_json["worker_processed_frames"], packet_count);
    assert_eq!(summary_json["worker_failures"], 0);
    assert_eq!(summary_json["flows_created"], 1);

    let expected_pcap_bytes = 24 + packet_count as u64 * (16 + packet.len() as u64);
    assert_eq!(
        std::fs::metadata(&output)
            .expect("rewritten pcap should exist")
            .len(),
        expected_pcap_bytes,
        "rewritten pcap should preserve every input frame"
    );
    let flows_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&flows).expect("flow export should exist after pipeline shutdown"),
    )
    .expect("flow export should be valid JSON");
    assert_eq!(flows_json.as_array().expect("flow export array").len(), 1);
    assert_eq!(flows_json[0]["packets_total"], packet_count);

    let inline_run = run_netscope(&[
        "--read-pcap",
        input_str,
        "--config",
        config_str,
        "--write-pcap",
        inline_output_str,
        "--export-json",
        inline_flows_str,
        "--summary-json",
        inline_summary_str,
        "--quiet",
    ]);
    assert!(
        inline_run.status.success(),
        "inline run should succeed, got stderr: {}",
        String::from_utf8_lossy(&inline_run.stderr)
    );
    let inline_summary_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&inline_summary).expect("inline summary should exist"),
    )
    .expect("inline summary should be valid JSON");
    for field in [
        "frames_read",
        "input_wire_bytes",
        "packets_parsed",
        "packets_with_transport_header",
        "malformed_or_unsupported_packets",
        "flows_created",
        "flows_expired",
        "flows_evicted",
        "alerts_emitted",
    ] {
        assert_eq!(
            inline_summary_json[field], summary_json[field],
            "inline and pipeline summaries should agree for {field}"
        );
    }
    let inline_flows_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&inline_flows).expect("inline flow export should exist"),
    )
    .expect("inline flow export should be valid JSON");
    assert_eq!(inline_flows_json, flows_json);
    assert_eq!(
        std::fs::read(&inline_output).expect("inline pcap should exist"),
        std::fs::read(&output).expect("pipeline pcap should exist"),
        "inline and pipeline capture outputs should preserve identical input frames"
    );

    std::fs::remove_dir_all(&dir).expect("temporary test directory should be removed");
}

fn run_rotation_retention_restart_test(pipeline: bool) {
    let dir = unique_temp_dir(if pipeline {
        "pcap-rotation-restart-pipeline"
    } else {
        "pcap-rotation-restart-inline"
    });
    let input = dir.join("input.pcap");
    let output_base = dir.join("capture.pcap");

    File::create(rotation_segment_path(&output_base, 90)).expect("failed to create old segment");
    File::create(rotation_segment_path(&output_base, 91)).expect("failed to create old segment");

    let packet = make_large_ethernet_packet(4096);
    write_test_pcap(&input, 1, &packet, 800);

    let input_str = input
        .to_str()
        .expect("input path must be valid utf-8 for cli");
    let output_str = output_base
        .to_str()
        .expect("output path must be valid utf-8 for cli");

    let mut args = vec![
        "--read-pcap",
        input_str,
        "--write-pcap",
        output_str,
        "--write-pcap-rotate-mb",
        "1",
        "--write-pcap-max-files",
        "2",
        "--quiet",
    ];
    if pipeline {
        args.push("--pipeline");
    }

    let output = run_netscope(&args);
    assert!(
        output.status.success(),
        "expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut indices: Vec<u64> = std::fs::read_dir(&dir)
        .expect("failed to read temp dir")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter_map(|path| parse_rotation_index(&path))
        .collect();
    indices.sort_unstable();

    assert_eq!(
        indices.len(),
        2,
        "expected retention to keep exactly 2 rotated files, got {:?}",
        indices
    );
    assert!(
        indices[0] > 91,
        "expected old segments from previous runs to be pruned, got {:?}",
        indices
    );
    assert_eq!(
        indices[1],
        indices[0] + 1,
        "retained segments should be consecutive"
    );

    if let Err(err) = std::fs::remove_dir_all(&dir) {
        eprintln!(
            "warning: failed to delete temp test directory {}: {}",
            dir.display(),
            err
        );
    }
}

#[test]
fn write_pcap_rotation_retains_latest_segments_inline() {
    run_rotation_retention_test(false);
}

#[test]
fn write_pcap_rotation_retains_latest_segments_pipeline() {
    run_rotation_retention_test(true);
}

#[test]
fn write_pcap_rotation_prunes_previous_run_segments_inline() {
    run_rotation_retention_restart_test(false);
}

#[test]
fn write_pcap_rotation_prunes_previous_run_segments_pipeline() {
    run_rotation_retention_restart_test(true);
}
