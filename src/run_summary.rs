//! Versioned per-run accounting written after capture processing and exports.

use serde::Serialize;
use std::path::Path;

use crate::protocol::LinkType;

pub const SUMMARY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Default, Clone)]
pub struct RunAccounting {
    pub worker_count: Option<usize>,
    pub frames_read: u64,
    pub input_wire_bytes: u64,
    pub packets_parsed: u64,
    pub packets_with_transport_header: u64,
    pub malformed_or_unsupported_packets: u64,
    pub dispatched_frames: Option<u64>,
    pub dispatch_drops: Option<u64>,
    pub worker_processed_frames: Option<u64>,
    pub worker_failures: Option<u64>,
    pub flows_created: u64,
    pub flows_expired: u64,
    pub flows_evicted: u64,
    pub alerts_emitted: u64,
    pub kernel_drops: Option<u64>,
    pub interface_drops: Option<u64>,
    pub output_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub schema_version: u32,
    pub application_version: &'static str,
    pub status: &'static str,
    pub run_error: Option<String>,
    pub mode: &'static str,
    pub source: String,
    pub worker_count: Option<usize>,
    pub elapsed_wall_seconds: f64,
    pub effective_config: EffectiveConfig,
    pub frames_read: u64,
    pub input_wire_bytes: u64,
    /// Frames with a recognized link header; a malformed transport header can
    /// still be partially parsed and is counted separately below.
    pub packets_parsed: u64,
    pub packets_with_transport_header: u64,
    pub malformed_or_unsupported_packets: u64,
    /// Pipeline-only counters are null in inline mode.
    pub dispatched_frames: Option<u64>,
    pub dispatch_drops: Option<u64>,
    pub worker_processed_frames: Option<u64>,
    pub worker_failures: Option<u64>,
    pub flows_created: u64,
    pub flows_expired: u64,
    pub flows_evicted: u64,
    pub alerts_emitted: u64,
    /// Live capture counters are null for offline input or when libpcap did not
    /// make the counters available.
    pub kernel_drops: Option<u64>,
    pub interface_drops: Option<u64>,
    pub output_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EffectiveConfig {
    pub capture: EffectiveCaptureConfig,
    pub packet_limit: u64,
    pub flow_timeout_secs: f64,
    pub max_flows: usize,
    pub rtt_tracking: bool,
    pub retransmission_tracking: bool,
    pub out_of_order_tracking: bool,
    pub anomaly_detection: bool,
    pub anomaly_settings: crate::config::AnomalyConfig,
    pub stats: EffectiveStatsConfig,
    pub output: EffectiveOutputConfig,
    pub web: EffectiveWebConfig,
    pub pipeline_enabled: bool,
    pub requested_workers: usize,
    pub pipeline_channel_capacity: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EffectiveCaptureConfig {
    pub link_type: String,
    pub filter: Option<String>,
    pub snaplen: i32,
    pub timeout_ms: i32,
    pub promiscuous: Option<bool>,
    pub buffer_size_mb: Option<u32>,
    pub immediate_mode: bool,
}

#[derive(Debug, Serialize)]
pub struct EffectiveStatsConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub top_flows: u32,
}

#[derive(Debug, Serialize)]
pub struct EffectiveOutputConfig {
    pub write_pcap: Option<String>,
    pub write_pcap_rotate_mb: u64,
    pub write_pcap_max_files: usize,
    pub export_json: Option<String>,
    pub export_csv: Option<String>,
    pub summary_json: Option<String>,
    pub alerts_jsonl: Option<String>,
    pub expired_flows_jsonl: Option<String>,
    pub expired_flows_csv: Option<String>,
    pub hex_dump: bool,
    pub quiet: bool,
}

#[derive(Debug, Serialize)]
pub struct EffectiveWebConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    pub tick_ms: u64,
    pub top_n: usize,
    pub packet_buffer: usize,
    pub sample_rate: u64,
    pub payload_bytes: usize,
    pub tls_enabled: bool,
    pub auth_enabled: bool,
}

pub struct EffectiveConfigInput<'a> {
    pub capture: &'a crate::config::CaptureConfig,
    pub flow: &'a crate::config::FlowConfig,
    pub packet_limit: u64,
    pub analysis: &'a crate::config::AnalysisConfig,
    pub output: &'a crate::config::OutputConfig,
    pub stats: &'a crate::config::StatsConfig,
    pub web: &'a crate::config::WebConfig,
    pub pipeline_enabled: bool,
    pub requested_workers: usize,
    pub pipeline_channel_capacity: usize,
    pub link_type: LinkType,
}

impl RunSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: &'static str,
        source: String,
        elapsed_wall_seconds: f64,
        status: &'static str,
        run_error: Option<String>,
        effective_config: EffectiveConfig,
        accounting: RunAccounting,
    ) -> Self {
        RunSummary {
            schema_version: SUMMARY_SCHEMA_VERSION,
            application_version: env!("CARGO_PKG_VERSION"),
            status,
            run_error,
            mode,
            source,
            worker_count: accounting.worker_count,
            elapsed_wall_seconds,
            effective_config,
            frames_read: accounting.frames_read,
            input_wire_bytes: accounting.input_wire_bytes,
            packets_parsed: accounting.packets_parsed,
            packets_with_transport_header: accounting.packets_with_transport_header,
            malformed_or_unsupported_packets: accounting.malformed_or_unsupported_packets,
            dispatched_frames: accounting.dispatched_frames,
            dispatch_drops: accounting.dispatch_drops,
            worker_processed_frames: accounting.worker_processed_frames,
            worker_failures: accounting.worker_failures,
            flows_created: accounting.flows_created,
            flows_expired: accounting.flows_expired,
            flows_evicted: accounting.flows_evicted,
            alerts_emitted: accounting.alerts_emitted,
            kernel_drops: accounting.kernel_drops,
            interface_drops: accounting.interface_drops,
            output_errors: accounting.output_errors,
        }
    }
}

pub fn write_json(path: &Path, summary: &RunSummary) -> Result<(), std::io::Error> {
    let encoded = serde_json::to_vec_pretty(summary).map_err(std::io::Error::other)?;
    std::fs::write(path, encoded)
}

pub fn source_description(read_pcap: Option<&Path>, interface: Option<&str>) -> String {
    if let Some(path) = read_pcap {
        format!("pcap:{}", path.display())
    } else {
        format!("interface:{}", interface.unwrap_or("default"))
    }
}

pub fn effective_config(input: EffectiveConfigInput<'_>) -> EffectiveConfig {
    let EffectiveConfigInput {
        capture,
        flow,
        packet_limit,
        analysis,
        output,
        stats,
        web,
        pipeline_enabled,
        requested_workers,
        pipeline_channel_capacity,
        link_type,
    } = input;
    EffectiveConfig {
        capture: EffectiveCaptureConfig {
            link_type: link_type.to_string(),
            filter: capture.filter.clone(),
            snaplen: capture.snaplen,
            timeout_ms: capture.timeout_ms,
            promiscuous: capture.read_pcap.is_none().then_some(capture.promiscuous),
            buffer_size_mb: capture.buffer_size_mb,
            immediate_mode: capture.immediate_mode,
        },
        packet_limit,
        flow_timeout_secs: flow.timeout_secs,
        max_flows: flow.max_flows,
        rtt_tracking: analysis.rtt,
        retransmission_tracking: analysis.retrans,
        out_of_order_tracking: analysis.out_of_order,
        anomaly_detection: analysis.anomalies.enabled,
        anomaly_settings: analysis.anomalies.clone(),
        stats: EffectiveStatsConfig {
            enabled: stats.enabled,
            interval_ms: stats.interval_ms,
            top_flows: stats.top_flows,
        },
        output: EffectiveOutputConfig {
            write_pcap: output
                .write_pcap
                .as_ref()
                .map(|path| path.display().to_string()),
            write_pcap_rotate_mb: output.write_pcap_rotate_mb,
            write_pcap_max_files: output.write_pcap_max_files,
            export_json: output
                .export_json
                .as_ref()
                .map(|path| path.display().to_string()),
            export_csv: output
                .export_csv
                .as_ref()
                .map(|path| path.display().to_string()),
            summary_json: output
                .summary_json
                .as_ref()
                .map(|path| path.display().to_string()),
            alerts_jsonl: analysis
                .alerts_jsonl
                .as_ref()
                .map(|path| path.display().to_string()),
            expired_flows_jsonl: output
                .expired_flows_jsonl
                .as_ref()
                .map(|path| path.display().to_string()),
            expired_flows_csv: output
                .expired_flows_csv
                .as_ref()
                .map(|path| path.display().to_string()),
            hex_dump: output.hex_dump,
            quiet: output.quiet,
        },
        web: EffectiveWebConfig {
            enabled: web.enabled,
            bind: web.bind.clone(),
            port: web.port,
            tick_ms: web.tick_ms,
            top_n: web.top_n,
            packet_buffer: web.packet_buffer,
            sample_rate: web.sample_rate,
            payload_bytes: web.payload_bytes,
            tls_enabled: web.tls.enabled,
            auth_enabled: web.auth.enabled,
        },
        pipeline_enabled,
        requested_workers,
        pipeline_channel_capacity: pipeline_enabled.then_some(pipeline_channel_capacity),
    }
}
