use serde::Serialize;
use std::fmt;

use super::scale::ScaleFlowEntry;
use super::{Endpoint, FlowDirection, FlowKey, FlowProtocol, SeqStatus, TcpFlags, TcpSeqTracker};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    SynSent,
    SynAck,
    Established,
    FinWait,
    Closed,
    Reset,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowEntry {
    pub first_seen: f64,
    pub last_seen: f64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub tcp_state: Option<TcpState>,
    pub client: Option<FlowDirection>,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub rtt_last_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_ewma_ms: Option<f64>,
    pub rtt_samples: u64,
    #[serde(skip)]
    pub(crate) last_report_bytes_stats: u64,
    #[serde(skip)]
    pub(crate) last_report_bytes_web: u64,
    #[serde(skip)]
    fin_seen: u8,
    #[serde(skip)]
    a_to_b_seq: TcpSeqTracker,
    #[serde(skip)]
    b_to_a_seq: TcpSeqTracker,
}

impl FlowEntry {
    pub(crate) fn new(ts: f64, protocol: FlowProtocol) -> Self {
        FlowEntry {
            first_seen: ts,
            last_seen: ts,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            tcp_state: match protocol {
                FlowProtocol::Tcp => Some(TcpState::Unknown),
                FlowProtocol::Udp => None,
            },
            client: None,
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
            last_report_bytes_stats: 0,
            last_report_bytes_web: 0,
            fin_seen: 0,
            a_to_b_seq: TcpSeqTracker::new(),
            b_to_a_seq: TcpSeqTracker::new(),
        }
    }

    #[inline]
    pub(crate) fn observe(
        &mut self,
        ts: f64,
        direction: FlowDirection,
        bytes: u64,
        flags: Option<TcpFlags>,
    ) {
        self.first_seen = self.first_seen.min(ts);
        self.last_seen = self.last_seen.max(ts);
        match direction {
            FlowDirection::AtoB => {
                self.packets_a_to_b += 1;
                self.bytes_a_to_b += bytes;
            }
            FlowDirection::BtoA => {
                self.packets_b_to_a += 1;
                self.bytes_b_to_a += bytes;
            }
        }
        if let Some(flags) = flags {
            self.update_tcp_state(flags, direction);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_tcp(
        &mut self,
        ts: f64,
        direction: FlowDirection,
        seq: u32,
        ack: Option<u32>,
        seq_len: u32,
        track_rtt: bool,
        track_retrans: bool,
        track_out_of_order: bool,
    ) {
        // Accumulate RTT updates and seq-tracker deltas into plain scalars so
        // no heap allocation is needed on the hot path.
        let mut rtt_last: Option<f64> = None;
        let mut rtt_min: Option<f64> = None;
        let mut rtt_ewma: Option<f64> = self.rtt_ewma_ms;
        let mut rtt_count: u64 = 0;
        let mut retrans_delta: u64 = 0;
        let mut ooo_delta: u64 = 0;

        {
            let (sender, receiver) = match direction {
                FlowDirection::AtoB => (&mut self.a_to_b_seq, &mut self.b_to_a_seq),
                FlowDirection::BtoA => (&mut self.b_to_a_seq, &mut self.a_to_b_seq),
            };

            if let Some(ack_no) = ack {
                if track_rtt {
                    // Stream RTT samples via callback -- no Vec allocation.
                    let rtt_min_prev = self.rtt_min_ms;
                    receiver.on_ack(ts, ack_no, |rtt_ms| {
                        rtt_last = Some(rtt_ms);
                        rtt_min = Some(match rtt_min_prev.or(rtt_min) {
                            Some(prev_min) => prev_min.min(rtt_ms),
                            None => rtt_ms,
                        });
                        rtt_ewma = Some(match rtt_ewma {
                            Some(prev) => 0.875 * prev + 0.125 * rtt_ms,
                            None => rtt_ms,
                        });
                        rtt_count += 1;
                    });
                }
                if track_retrans || track_out_of_order {
                    receiver.last_ack = Some(ack_no);
                }
            }

            if seq_len > 0 {
                let seq_end = seq.wrapping_add(seq_len);
                let peer_ack = sender.last_ack;
                let status = sender.on_segment(seq_end, peer_ack);
                match status {
                    SeqStatus::Advanced => {
                        if track_rtt {
                            sender.push_sample(seq_end, ts);
                        }
                    }
                    SeqStatus::Retransmission => {
                        if track_retrans {
                            retrans_delta = 1;
                        }
                    }
                    SeqStatus::OutOfOrder => {
                        if track_out_of_order {
                            ooo_delta = 1;
                        }
                    }
                }
            }
        }

        // Write RTT results back to self -- no intermediate Vec needed.
        if rtt_count > 0 {
            self.rtt_last_ms = rtt_last;
            if let Some(m) = rtt_min {
                self.rtt_min_ms = Some(self.rtt_min_ms.map_or(m, |prev| prev.min(m)));
            }
            self.rtt_ewma_ms = rtt_ewma;
            self.rtt_samples += rtt_count;
        }
        self.retransmissions += retrans_delta;
        self.out_of_order += ooo_delta;
    }

    pub(crate) fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    pub(crate) fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    pub(crate) fn update_tcp_state(&mut self, flags: TcpFlags, direction: FlowDirection) {
        update_tcp_state_fields(
            &mut self.tcp_state,
            &mut self.client,
            &mut self.fin_seen,
            flags,
            direction,
        );
    }
}

pub(crate) fn update_tcp_state_fields(
    tcp_state: &mut Option<TcpState>,
    client: &mut Option<FlowDirection>,
    fin_seen: &mut u8,
    flags: TcpFlags,
    direction: FlowDirection,
) {
    if flags.rst {
        *tcp_state = Some(TcpState::Reset);
        return;
    }
    if flags.syn && !flags.ack {
        if client.is_none() {
            *client = Some(direction);
        }
        *fin_seen = 0;
        *tcp_state = Some(TcpState::SynSent);
        return;
    }
    if flags.syn && flags.ack {
        *tcp_state = Some(TcpState::SynAck);
        return;
    }
    if flags.fin {
        if matches!(tcp_state, Some(TcpState::Reset | TcpState::Closed)) {
            return;
        }
        *fin_seen |= match direction {
            FlowDirection::AtoB => 1,
            FlowDirection::BtoA => 2,
        };
        *tcp_state = Some(if *fin_seen == 3 {
            TcpState::Closed
        } else {
            TcpState::FinWait
        });
        return;
    }
    if flags.ack {
        if !matches!(
            tcp_state,
            Some(TcpState::Reset | TcpState::Closed | TcpState::FinWait)
        ) {
            *tcp_state = Some(TcpState::Established);
        }
        return;
    }
    if tcp_state.is_none() {
        *tcp_state = Some(TcpState::Unknown);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSnapshot {
    pub protocol: FlowProtocol,
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_secs: f64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub avg_bps: f64,
    pub tcp_state: Option<TcpState>,
    pub client: Option<FlowDirection>,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub rtt_last_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_ewma_ms: Option<f64>,
    pub rtt_samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiredFlowReason {
    Timeout,
    Eviction,
}

impl ExpiredFlowReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExpiredFlowReason::Timeout => "timeout",
            ExpiredFlowReason::Eviction => "eviction",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpiredFlowEvent {
    pub ts: f64,
    pub reason: ExpiredFlowReason,
    #[serde(flatten)]
    pub flow: FlowSnapshot,
}

#[derive(Debug, Clone)]
pub struct FlowDelta {
    pub key: FlowKey,
    pub delta_bytes: u64,
}

impl FlowSnapshot {
    pub(crate) fn from_entry(key: &FlowKey, entry: &FlowEntry) -> Self {
        let duration = (entry.last_seen - entry.first_seen).max(0.0);
        let bytes_total = entry.total_bytes();
        let packets_total = entry.total_packets();
        let avg_bps = if duration > 0.0 {
            bytes_total as f64 * 8.0 / duration
        } else {
            0.0
        };

        FlowSnapshot {
            protocol: key.protocol,
            endpoint_a: key.a,
            endpoint_b: key.b,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            duration_secs: duration,
            packets_a_to_b: entry.packets_a_to_b,
            packets_b_to_a: entry.packets_b_to_a,
            bytes_a_to_b: entry.bytes_a_to_b,
            bytes_b_to_a: entry.bytes_b_to_a,
            packets_total,
            bytes_total,
            avg_bps,
            tcp_state: entry.tcp_state,
            client: entry.client,
            retransmissions: entry.retransmissions,
            out_of_order: entry.out_of_order,
            rtt_last_ms: entry.rtt_last_ms,
            rtt_min_ms: entry.rtt_min_ms,
            rtt_ewma_ms: entry.rtt_ewma_ms,
            rtt_samples: entry.rtt_samples,
        }
    }

    pub(crate) fn from_scale_entry(key: &FlowKey, entry: &ScaleFlowEntry) -> Self {
        let first_seen = entry.first_seen();
        let last_seen = entry.last_seen();
        let duration = (last_seen - first_seen).max(0.0);
        let bytes_total = entry.total_bytes();
        let packets_total = entry.total_packets();
        let avg_bps = if duration > 0.0 {
            bytes_total as f64 * 8.0 / duration
        } else {
            0.0
        };

        FlowSnapshot {
            protocol: key.protocol,
            endpoint_a: key.a,
            endpoint_b: key.b,
            first_seen,
            last_seen,
            duration_secs: duration,
            packets_a_to_b: entry.packets_a_to_b as u64,
            packets_b_to_a: entry.packets_b_to_a as u64,
            bytes_a_to_b: entry.bytes_a_to_b,
            bytes_b_to_a: entry.bytes_b_to_a,
            packets_total,
            bytes_total,
            avg_bps,
            tcp_state: entry.tcp_state(),
            client: entry.client(),
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::SynSent => write!(f, "syn_sent"),
            TcpState::SynAck => write!(f, "syn_ack"),
            TcpState::Established => write!(f, "established"),
            TcpState::FinWait => write!(f, "fin_wait"),
            TcpState::Closed => write!(f, "closed"),
            TcpState::Reset => write!(f, "reset"),
            TcpState::Unknown => write!(f, "unknown"),
        }
    }
}
