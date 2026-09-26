//! WebSocket message types for the dashboard.
//!
//! All messages are JSON-serialised with a `"type"` tag so the frontend
//! can dispatch on `msg.type`.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Server → Client messages
// ---------------------------------------------------------------------------

/// Envelope sent to each connected WebSocket client.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMsg {
    /// Sent immediately after the WebSocket upgrade succeeds.
    Hello { version: String, tick_ms: u64 },

    /// A merged per-tick frame containing stats and batched live events.
    Frame(Frame),

    /// Periodic aggregate statistics (one per tick).
    StatsTick(StatsTick),

    /// A sampled packet summary (not every packet — just enough for the UI).
    PacketSample(PacketSample),

    /// Full packet detail (requested by client).
    PacketDetail(PacketDetail),

    /// Anomaly alert forwarded in real time.
    Alert(AlertMsg),

    /// Response to a client-side performance ping.
    PerfPong { client_ts: u64, server_ts: u64 },

    /// Error response for invalid client messages.
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Frame {
    pub frame_seq: u64,
    pub tick: StatsTick,
    pub packets: Vec<PacketSample>,
    pub alerts: Vec<AlertMsg>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsTick {
    pub ts: f64,
    /// Monotonic frame sequence number.
    pub frame_seq: u64,
    /// Server emit timestamp in unix milliseconds.
    pub server_ts: u64,
    pub interval_ms: u64,
    pub bytes: u64,
    pub packets: u64,
    pub mbps: f64,
    pub pps: f64,
    pub active_flows: usize,
    pub dispatch_drops: u64,
    pub dispatch_drops_total: u64,
    pub kernel_drops: u64,
    pub kernel_drops_total: u64,
    pub kernel_if_drops: u64,
    pub kernel_if_drops_total: u64,
    pub top_flows: Vec<FlowInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowInfo {
    pub protocol: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_total: u64,
    pub packets_total: u64,
    pub delta_bytes: u64,
    pub delta_mbps: f64,
    pub duration_secs: f64,
    pub tcp_state: Option<String>,
    pub rtt_ewma_ms: Option<f64>,
    pub retransmissions: u64,
    pub out_of_order: u64,
}

impl FlowInfo {
    pub fn from_snapshot_delta(
        snap: &crate::flow::FlowSnapshot,
        delta_bytes: u64,
        elapsed_secs: f64,
    ) -> Self {
        let elapsed_secs = elapsed_secs.max(0.001);
        let delta_mbps = delta_bytes as f64 * 8.0 / elapsed_secs / 1_000_000.0;
        Self {
            protocol: format!("{}", snap.protocol),
            src_ip: snap.endpoint_a.ip,
            src_port: snap.endpoint_a.port,
            dst_ip: snap.endpoint_b.ip,
            dst_port: snap.endpoint_b.port,
            bytes_a_to_b: snap.bytes_a_to_b,
            bytes_b_to_a: snap.bytes_b_to_a,
            packets_a_to_b: snap.packets_a_to_b,
            packets_b_to_a: snap.packets_b_to_a,
            bytes_total: snap.bytes_total,
            packets_total: snap.packets_total,
            delta_bytes,
            delta_mbps,
            duration_secs: snap.duration_secs,
            tcp_state: snap.tcp_state.map(|s| format!("{}", s)),
            rtt_ewma_ms: snap.rtt_ewma_ms,
            retransmissions: snap.retransmissions,
            out_of_order: snap.out_of_order,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketSample {
    /// Monotonic packet id (capture-wide index).
    pub id: u64,
    pub ts: f64,
    pub len: usize,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketDetail {
    pub id: u64,
    pub ts: f64,
    pub layers: Vec<LayerDetail>,
    pub hex_dump: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerDetail {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertMsg {
    pub schema_version: u32,
    pub ts: f64,
    pub kind: String,
    pub source_ip: Option<IpAddr>,
    pub target_ip: Option<IpAddr>,
    pub target_port: Option<u16>,
    pub window_secs: f64,
    pub thresholds: crate::analysis::anomaly::AlertThresholds,
    pub observed: crate::analysis::anomaly::AlertObservations,
    pub description: String,
}

impl From<&crate::analysis::anomaly::Alert> for AlertMsg {
    fn from(alert: &crate::analysis::anomaly::Alert) -> Self {
        AlertMsg {
            schema_version: alert.schema_version,
            ts: alert.ts,
            kind: alert.kind.as_str().to_string(),
            source_ip: alert.source_ip,
            target_ip: alert.target_ip,
            target_port: alert.target_port,
            window_secs: alert.window_secs,
            thresholds: alert.thresholds.clone(),
            observed: alert.observed.clone(),
            description: alert.description.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Client → Server messages
// ---------------------------------------------------------------------------

/// Messages the browser may send to the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMsg {
    /// Request full detail for a specific packet.
    GetPacketDetail { id: u64 },
    /// Ping carrying the client-side unix-ms timestamp.
    PerfPing { client_ts: u64 },
}

// ---------------------------------------------------------------------------
// Internal channel message (capture thread → web server ingest task)
// ---------------------------------------------------------------------------

/// Events pushed from the capture loop into the web server.
#[derive(Debug, Clone)]
pub enum CaptureEvent {
    /// Periodic stats tick.
    Tick(StatsTick),
    /// A sampled packet summary.
    Packet(PacketSample),
    /// A stored packet for the detail ring buffer.
    PacketStored(StoredPacket),
    /// An anomaly alert.
    Alert(AlertMsg),
}

/// Full owned representation of a packet kept in the ring buffer for
/// on-demand detail retrieval.
#[derive(Debug, Clone)]
pub struct StoredPacket {
    pub id: u64,
    pub ts: f64,
    pub layers: Vec<LayerDetail>,
    pub hex_dump: String,
}
