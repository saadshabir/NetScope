//! Per-shard worker: owns a `FlowTracker`, processes packets from a bounded
//! channel, and emits events to the aggregator.

use crossbeam_channel::{Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::{AnalysisConfig, FlowConfig, WebConfig};
use crate::flow::{ExpiredFlowEvent, FlowDelta, FlowSnapshot, FlowTracker, FlowTrackerStats};
use crate::protocol;
#[cfg(feature = "dashboard")]
use crate::web::messages::{PacketSample, StoredPacket};

use super::top_flows::SpaceSavingTopFlows;
use super::{OwnedPacket, PacketBufReturner};

/// Events a worker sends to the aggregator.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Per-tick partial statistics from this shard.
    ShardTick(ShardTick),
    /// A sampled packet summary (for the live packet feed).
    #[cfg(feature = "dashboard")]
    Packet(PacketSample),
    /// A stored packet for the detail ring buffer.
    #[cfg(feature = "dashboard")]
    PacketStored(StoredPacket),
    /// Flows expired due to timeout or max-flow eviction.
    ExpiredFlows(Vec<ExpiredFlowEvent>),
    /// Worker is shutting down; final flow snapshot from this shard.
    Shutdown(ShardShutdown),
}

/// Partial tick data from one shard.
#[derive(Debug, Clone)]
pub struct ShardTick {
    pub shard_id: usize,
    pub bytes: u64,
    pub packets: u64,
    pub active_flows: usize,
    pub top_flows: Vec<(FlowDelta, FlowSnapshot)>,
}

/// Final state from a shutting-down worker.
#[derive(Debug)]
pub struct ShardShutdown {
    pub shard_id: usize,
    pub flows: Vec<FlowSnapshot>,
    pub stats: WorkerRunStats,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerRunStats {
    pub processed_frames: u64,
    pub parsed_packets: u64,
    pub packets_with_network_header: u64,
    pub packets_with_transport_header: u64,
    pub packet_parse_errors: u64,
    pub transport_parse_errors: u64,
    pub unsupported_packets: u64,
    pub malformed_or_unsupported_packets: u64,
    pub flows: FlowTrackerStats,
}

pub struct Worker {
    shard_id: usize,
    link_type: protocol::LinkType,
    flow_tracker: FlowTracker,
    web_cfg: WebConfig,
    heavy_hitter_top_n: usize,
    collect_final_flows: bool,
    buffer_returner: PacketBufReturner,
    top_flows_hh: SpaceSavingTopFlows,
    emit_expired_flows: bool,
    expired_flows_buf: Vec<ExpiredFlowEvent>,
    last_expire_check_ts: f64,
    offline: bool,
    capture_watermark: Option<f64>,
    agg_send_failed: bool,
    // Per-tick accumulators
    tick_bytes: u64,
    tick_packets: u64,
    tick_next: Instant,
    run_stats: WorkerRunStats,
}

pub struct WorkerConfigBundle {
    pub offline: bool,
    pub flow_cfg: FlowConfig,
    pub analysis_cfg: AnalysisConfig,
    pub web_cfg: WebConfig,
    pub heavy_hitter_top_n: usize,
    pub collect_final_flows: bool,
    pub emit_expired_flows: bool,
}

impl Worker {
    pub fn new(
        shard_id: usize,
        link_type: protocol::LinkType,
        cfg: WorkerConfigBundle,
        buffer_returner: PacketBufReturner,
    ) -> Self {
        let WorkerConfigBundle {
            offline,
            flow_cfg,
            analysis_cfg,
            web_cfg,
            heavy_hitter_top_n,
            collect_final_flows,
            emit_expired_flows,
        } = cfg;
        let tick_interval = tick_interval_for(&web_cfg);
        let flow_tracker = FlowTracker::new(
            flow_cfg.timeout_secs,
            flow_cfg.max_flows,
            analysis_cfg.rtt,
            analysis_cfg.retrans,
            analysis_cfg.out_of_order,
        );
        Worker {
            shard_id,
            link_type,
            flow_tracker,
            web_cfg,
            heavy_hitter_top_n,
            collect_final_flows,
            buffer_returner,
            top_flows_hh: SpaceSavingTopFlows::new(heavy_hitter_top_n),
            emit_expired_flows,
            expired_flows_buf: Vec::new(),
            last_expire_check_ts: 0.0,
            offline,
            capture_watermark: None,
            agg_send_failed: false,
            tick_bytes: 0,
            tick_packets: 0,
            tick_next: Instant::now() + tick_interval,
            run_stats: WorkerRunStats::default(),
        }
    }

    pub fn run(
        &mut self,
        rx: Receiver<OwnedPacket>,
        agg_tx: Sender<WorkerEvent>,
        running: &AtomicBool,
    ) {
        loop {
            // Check for pipeline shutdown
            if !running.load(Ordering::Relaxed) {
                // Drain remaining packets in the channel before shutting down.
                while let Ok(mut pkt) = rx.try_recv() {
                    self.process_packet(&pkt, &agg_tx);
                    let owned = std::mem::take(&mut pkt.data);
                    self.buffer_returner.release(owned);
                }
                break;
            }

            if self.agg_send_failed {
                break;
            }

            let now = Instant::now();
            if now >= self.tick_next {
                self.expire_idle_flows(&agg_tx);
                self.emit_tick_at(&agg_tx, now);
                continue;
            }

            match rx.recv_timeout(timeout_until_tick(now, self.tick_next)) {
                Ok(mut pkt) => {
                    self.process_packet(&pkt, &agg_tx);
                    let owned = std::mem::take(&mut pkt.data);
                    self.buffer_returner.release(owned);
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    self.expire_idle_flows(&agg_tx);
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }

            // Emit shard tick if interval elapsed.
            self.maybe_emit_tick(&agg_tx);
        }

        // Final tick flush.
        self.emit_tick(&agg_tx);
        self.flush_expired_flows(&agg_tx);

        // Always send accounting; only materialize retained flows when a
        // final export will consume them.
        let flows = if self.collect_final_flows {
            self.flow_tracker.snapshot()
        } else {
            Vec::new()
        };
        let _ = agg_tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: self.shard_id,
            flows,
            stats: WorkerRunStats {
                flows: self.flow_tracker.stats(),
                ..self.run_stats
            },
        }));

        tracing::debug!(shard = self.shard_id, "worker shut down");
    }

    fn process_packet(&mut self, pkt: &OwnedPacket, agg_tx: &Sender<WorkerEvent>) {
        self.capture_watermark = Some(self.capture_watermark.map_or(pkt.ts, |ts| ts.max(pkt.ts)));
        self.run_stats.processed_frames = self.run_stats.processed_frames.saturating_add(1);
        self.tick_bytes += pkt.wire_len;
        self.tick_packets += 1;

        match protocol::parse_packet_with_linktype(&pkt.data, self.link_type) {
            Ok(parsed) => {
                self.run_stats.parsed_packets = self.run_stats.parsed_packets.saturating_add(1);
                if parsed.network.is_some() {
                    self.run_stats.packets_with_network_header =
                        self.run_stats.packets_with_network_header.saturating_add(1);
                }
                if parsed.transport.is_some() {
                    self.run_stats.packets_with_transport_header = self
                        .run_stats
                        .packets_with_transport_header
                        .saturating_add(1);
                }
                if parsed.transport_parse_error.is_some() {
                    self.run_stats.transport_parse_errors =
                        self.run_stats.transport_parse_errors.saturating_add(1);
                }
                if parsed.unsupported {
                    self.run_stats.unsupported_packets =
                        self.run_stats.unsupported_packets.saturating_add(1);
                }
                if parsed.transport_parse_error.is_some() || parsed.unsupported {
                    self.run_stats.malformed_or_unsupported_packets = self
                        .run_stats
                        .malformed_or_unsupported_packets
                        .saturating_add(1);
                }

                // Flow tracking
                if self.emit_expired_flows {
                    self.flow_tracker.observe_collect(
                        pkt.ts,
                        pkt.wire_len,
                        &parsed,
                        &mut self.expired_flows_buf,
                    );
                    self.flush_expired_flows(agg_tx);
                } else {
                    self.flow_tracker.observe(pkt.ts, pkt.wire_len, &parsed);
                }

                if self.heavy_hitter_top_n > 0
                    && let Some(key) = crate::flow::flow_compact_key_from_packet(&parsed)
                {
                    self.top_flows_hh.observe(&key, pkt.wire_len);
                }

                // Packet sampling for web dashboard.
                // Use the global packet id (assigned by the capture thread) so
                // that sample_rate controls the global rate across all shards,
                // not a per-shard rate that would produce N*sample_rate samples.
                #[cfg(feature = "dashboard")]
                if self.web_cfg.enabled
                    && self.web_cfg.sample_rate > 0
                    && pkt.id.is_multiple_of(self.web_cfg.sample_rate)
                {
                    let (sample, stored) = crate::build_packet_data(
                        pkt.id,
                        pkt.ts,
                        &pkt.data,
                        &parsed,
                        self.web_cfg.payload_bytes,
                    );
                    if self
                        .send_event(agg_tx, WorkerEvent::Packet(sample))
                        .is_err()
                    {
                        return;
                    }
                    if self
                        .send_event(agg_tx, WorkerEvent::PacketStored(stored))
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(e) => {
                self.run_stats.packet_parse_errors =
                    self.run_stats.packet_parse_errors.saturating_add(1);
                self.run_stats.malformed_or_unsupported_packets = self
                    .run_stats
                    .malformed_or_unsupported_packets
                    .saturating_add(1);
                tracing::trace!(shard = self.shard_id, error = %e, "parse error");
            }
        }
        // Advance expiry even for malformed frames, using monotonic capture time.
        let now = self.capture_watermark.unwrap_or(pkt.ts);
        if now - self.last_expire_check_ts >= 1.0 {
            self.last_expire_check_ts = now;
            self.expire_at(now, agg_tx);
        }
    }

    fn maybe_emit_tick(&mut self, agg_tx: &Sender<WorkerEvent>) {
        let now = Instant::now();
        if now >= self.tick_next {
            self.emit_tick_at(agg_tx, now);
        }
    }

    fn emit_tick(&mut self, agg_tx: &Sender<WorkerEvent>) {
        self.emit_tick_at(agg_tx, Instant::now());
    }

    fn emit_tick_at(&mut self, agg_tx: &Sender<WorkerEvent>, now: Instant) {
        let candidates = self.top_flows_hh.take_top(self.heavy_hitter_top_n);
        let candidate_keys: Vec<crate::flow::CompactFlowKey> =
            candidates.iter().map(|(key, _)| *key).collect();
        let top_flows = self
            .flow_tracker
            .top_flows_with_snapshot_for_compact_keys(&candidate_keys, self.heavy_hitter_top_n);

        let tick = ShardTick {
            shard_id: self.shard_id,
            bytes: self.tick_bytes,
            packets: self.tick_packets,
            active_flows: self.flow_tracker.len(),
            top_flows,
        };

        if self
            .send_event(agg_tx, WorkerEvent::ShardTick(tick))
            .is_err()
        {
            return;
        }

        self.tick_bytes = 0;
        self.tick_packets = 0;
        self.tick_next =
            advance_tick_deadline(self.tick_next, now, tick_interval_for(&self.web_cfg));
    }

    fn expire_idle_flows(&mut self, agg_tx: &Sender<WorkerEvent>) {
        let now = if self.offline {
            let Some(ts) = self.capture_watermark else {
                return;
            };
            ts
        } else {
            unix_secs_now()
        };
        self.expire_at(now, agg_tx);
    }

    fn expire_at(&mut self, now: f64, agg_tx: &Sender<WorkerEvent>) {
        if self.emit_expired_flows {
            self.flow_tracker
                .maybe_expire_collect(now, &mut self.expired_flows_buf);
            self.flush_expired_flows(agg_tx);
        } else {
            self.flow_tracker.maybe_expire(now);
        }
    }

    fn flush_expired_flows(&mut self, agg_tx: &Sender<WorkerEvent>) {
        if self.expired_flows_buf.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.expired_flows_buf);
        let _ = self.send_event(agg_tx, WorkerEvent::ExpiredFlows(batch));
    }

    fn send_event(&mut self, agg_tx: &Sender<WorkerEvent>, event: WorkerEvent) -> Result<(), ()> {
        if self.agg_send_failed {
            return Err(());
        }

        if agg_tx.send(event).is_err() {
            tracing::warn!(shard = self.shard_id, "aggregator channel closed");
            self.agg_send_failed = true;
            return Err(());
        }

        Ok(())
    }
}

#[inline]
fn tick_interval_for(web_cfg: &WebConfig) -> Duration {
    Duration::from_millis(web_cfg.tick_ms.max(1))
}

#[inline]
fn timeout_until_tick(now: Instant, tick_next: Instant) -> Duration {
    if now >= tick_next {
        Duration::ZERO
    } else {
        tick_next.duration_since(now)
    }
}

#[inline]
fn advance_tick_deadline(mut tick_next: Instant, now: Instant, tick_interval: Duration) -> Instant {
    if now < tick_next {
        return now + tick_interval;
    }

    loop {
        tick_next += tick_interval;
        if tick_next > now {
            return tick_next;
        }
    }
}

#[inline]
fn unix_secs_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_exports_are_optional_but_shutdown_accounting_is_always_present() {
        for collect_final_flows in [false, true] {
            let pool = crate::pipeline::PacketBufPool::new(1, 65535);
            let mut worker = Worker::new(
                0,
                protocol::LinkType::Ethernet,
                WorkerConfigBundle {
                    offline: true,
                    flow_cfg: FlowConfig {
                        timeout_secs: 0.0,
                        max_flows: 10,
                    },
                    analysis_cfg: AnalysisConfig::default(),
                    web_cfg: WebConfig::default(),
                    heavy_hitter_top_n: 0,
                    collect_final_flows,
                    emit_expired_flows: false,
                },
                pool.returner(),
            );
            let trace = include_bytes!("../../examples/pcaps/normal.pcap");
            let length = u32::from_le_bytes(trace[32..36].try_into().unwrap()) as usize;
            let (pkt_tx, pkt_rx) = crossbeam_channel::unbounded();
            let (agg_tx, agg_rx) = crossbeam_channel::unbounded();
            pkt_tx
                .send(OwnedPacket {
                    id: 1,
                    ts: 1.0,
                    wire_len: length as u64,
                    data: trace[40..40 + length].to_vec(),
                })
                .unwrap();
            drop(pkt_tx);
            worker.run(pkt_rx, agg_tx, &AtomicBool::new(true));
            let shutdown = agg_rx
                .try_iter()
                .find_map(|event| match event {
                    WorkerEvent::Shutdown(shutdown) => Some(shutdown),
                    _ => None,
                })
                .unwrap();
            assert_eq!(shutdown.stats.processed_frames, 1);
            assert_eq!(shutdown.stats.parsed_packets, 1);
            assert_eq!(shutdown.stats.flows.created, 1);
            assert_eq!(shutdown.flows.len(), usize::from(collect_final_flows));
            if collect_final_flows {
                assert_eq!(shutdown.flows[0].packets_total, 1);
            }
        }
    }

    #[test]
    fn offline_idle_expiry_uses_capture_watermark_including_malformed_frames() {
        for offline in [true, false] {
            let pool = crate::pipeline::PacketBufPool::new(1, 64);
            let mut worker = Worker::new(
                0,
                protocol::LinkType::Ethernet,
                WorkerConfigBundle {
                    offline,
                    flow_cfg: FlowConfig {
                        timeout_secs: 120.0,
                        max_flows: 10,
                    },
                    analysis_cfg: AnalysisConfig::default(),
                    web_cfg: WebConfig::default(),
                    heavy_hitter_top_n: 0,
                    collect_final_flows: false,
                    emit_expired_flows: true,
                },
                pool.returner(),
            );
            let trace = include_bytes!("../../examples/pcaps/normal.pcap");
            let length = u32::from_le_bytes(trace[32..36].try_into().unwrap()) as usize;
            let (tx, rx) = crossbeam_channel::unbounded();
            let mut packet = OwnedPacket {
                id: 1,
                ts: 100.0,
                wire_len: length as u64,
                data: trace[40..40 + length].to_vec(),
            };
            worker.process_packet(&packet, &tx);
            packet.ts = 90.0;
            worker.process_packet(&packet, &tx);
            assert_eq!(worker.capture_watermark, Some(100.0));
            worker.expire_idle_flows(&tx);
            assert_eq!(worker.flow_tracker.len(), usize::from(offline));
            if offline {
                packet.ts = 221.0;
                packet.data.clear();
                worker.process_packet(&packet, &tx);
                assert!(worker.flow_tracker.is_empty());
            }
            let expired: Vec<_> = rx
                .try_iter()
                .filter_map(|event| match event {
                    WorkerEvent::ExpiredFlows(events) => Some(events),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].reason, crate::flow::ExpiredFlowReason::Timeout);
            if offline {
                assert_eq!(expired[0].ts, 221.0);
            }
        }
    }

    #[test]
    fn timeout_until_tick_returns_remaining_duration() {
        let now = Instant::now();
        let tick_next = now + Duration::from_millis(33);

        assert_eq!(
            timeout_until_tick(now, tick_next),
            Duration::from_millis(33)
        );
    }

    #[test]
    fn advance_tick_deadline_skips_missed_intervals() {
        let start = Instant::now();
        let interval = Duration::from_millis(33);
        let tick_next = start + interval;
        let now = start + Duration::from_millis(80);

        assert_eq!(
            advance_tick_deadline(tick_next, now, interval),
            start + Duration::from_millis(99)
        );
    }

    #[test]
    fn advance_tick_deadline_resets_from_now_for_early_flush() {
        let start = Instant::now();
        let interval = Duration::from_millis(33);
        let tick_next = start + interval;
        let now = start + Duration::from_millis(10);

        assert_eq!(
            advance_tick_deadline(tick_next, now, interval),
            now + interval
        );
    }
}
