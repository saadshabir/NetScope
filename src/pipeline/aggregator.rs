//! Aggregator: collects events from all worker shards, merges per-tick
//! statistics, and forwards results to the CLI and web dashboard.

use crossbeam_channel::Receiver;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::flow::{FlowDelta, FlowSnapshot};
use crate::metrics;
use crate::sinks::OutputSinks;
use crate::web::messages::{CaptureEvent, FlowInfo, StatsTick};

use super::worker::{ShardShutdown, ShardTick, WorkerEvent, WorkerRunStats};
use super::{KernelPcapStats, PipelineStats};

#[derive(Debug, Clone, Copy, Default)]
struct KernelTickStats {
    drops: u64,
    drops_total: u64,
    if_drops: u64,
    if_drops_total: u64,
}

fn kernel_tick_stats(
    kernel_stats: &KernelPcapStats,
    prev_totals: &mut Option<(u64, u64)>,
) -> KernelTickStats {
    if !kernel_stats.initialized() {
        return KernelTickStats::default();
    }

    let dropped_total = kernel_stats.dropped_total();
    let if_dropped_total = kernel_stats.if_dropped_total();

    let (drops, if_drops) = match prev_totals.replace((dropped_total, if_dropped_total)) {
        None => (0, 0),
        Some((prev_dropped, prev_if_dropped)) => (
            dropped_total.saturating_sub(prev_dropped),
            if_dropped_total.saturating_sub(prev_if_dropped),
        ),
    };

    KernelTickStats {
        drops,
        drops_total: dropped_total,
        if_drops,
        if_drops_total: if_dropped_total,
    }
}

/// Aggregated tick data merged from all shards.
#[derive(Debug, Clone)]
pub struct AggregatedTick {
    pub ts: f64,
    pub interval_ms: u64,
    pub bytes: u64,
    pub packets: u64,
    pub mbps: f64,
    pub pps: f64,
    pub active_flows: usize,
    pub top_flows: Vec<(FlowDelta, FlowSnapshot)>,
    pub dispatch_drops: u64,
    pub dispatch_drops_total: u64,
    pub kernel_drops: u64,
    pub kernel_drops_total: u64,
    pub kernel_if_drops: u64,
    pub kernel_if_drops_total: u64,
}

/// Shared state the main thread can read for CLI stats / final snapshot.
#[derive(Clone)]
pub struct AggregatorHandle {
    inner: Arc<Mutex<AggregatorState>>,
}

struct AggregatorState {
    num_workers: usize,
    /// Latest merged tick (main thread reads this for CLI stats).
    latest_tick: Option<AggregatedTick>,
    /// Accumulated alert count.
    alert_count: u64,
    /// Per-shard final snapshots collected on shutdown.
    shard_snapshots: Vec<Option<Vec<FlowSnapshot>>>,
    /// Cumulative packet and flow accounting collected from workers.
    worker_stats: WorkerRunStats,
    /// Output errors recorded by the capture sinks.
    output_errors: Vec<String>,
    /// Fatal error that should terminate capture.
    fatal_error: Option<String>,
}

impl AggregatorHandle {
    pub fn new(num_workers: usize) -> Self {
        AggregatorHandle {
            inner: Arc::new(Mutex::new(AggregatorState {
                num_workers,
                latest_tick: None,
                alert_count: 0,
                shard_snapshots: vec![None; num_workers],
                worker_stats: WorkerRunStats::default(),
                output_errors: Vec::new(),
                fatal_error: None,
            })),
        }
    }

    /// Take the latest aggregated tick (returns `None` if no new tick since last call).
    pub fn take_tick(&self) -> Option<AggregatedTick> {
        self.inner.lock().ok()?.latest_tick.take()
    }

    /// Current alert count.
    pub fn alert_count(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .alert_count
    }

    pub fn worker_stats(&self) -> WorkerRunStats {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .worker_stats
    }

    pub fn output_errors(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .output_errors
            .clone()
    }

    fn append_output_errors(&self, errors: Vec<String>) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .output_errors
            .extend(errors);
    }

    /// Collect all final flow snapshots (call after pipeline shutdown).
    pub fn take_final_snapshots(&self) -> Vec<FlowSnapshot> {
        let mut state = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut all: Vec<FlowSnapshot> = state
            .shard_snapshots
            .drain(..)
            .flatten()
            .flat_map(|flows| flows.into_iter())
            .collect();
        all.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        all
    }

    /// Take the fatal error, if any.
    pub fn take_fatal_error(&self) -> Option<String> {
        self.inner.lock().ok()?.fatal_error.take()
    }
}

/// Run the aggregator loop. This blocks until all worker senders disconnect.
pub fn run(rx: Receiver<WorkerEvent>, handle: AggregatorHandle, config: AggregatorRunConfig) {
    let AggregatorRunConfig {
        web_event_tx,
        max_top_n,
        web_top_n,
        stats,
        kernel_stats,
        tick_deadline_ms,
        mut output_sinks,
        running,
    } = config;

    let num_workers = handle
        .inner
        .lock()
        .map(|g| g.num_workers)
        .unwrap_or_else(|e| e.into_inner().num_workers);
    let frame_seq = AtomicU64::new(0);

    // Accumulate partial shard ticks, then merge once all shards have reported.
    let mut pending_ticks: Vec<Option<ShardTick>> = vec![None; num_workers];
    let mut tick_start = Instant::now();
    let mut prev_kernel_totals: Option<(u64, u64)> = None;

    loop {
        let elapsed_ms = tick_start.elapsed().as_millis() as u64;
        let remaining_ms = tick_deadline_ms.saturating_sub(elapsed_ms).max(1);
        let timeout_ms = remaining_ms.min(100);
        match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
            Ok(event) => match event {
                WorkerEvent::ShardTick(shard_tick) => {
                    let idx = shard_tick.shard_id;
                    if idx < pending_ticks.len() {
                        pending_ticks[idx] = Some(shard_tick);
                    }

                    // Check if all shards have reported.
                    let all_present = pending_ticks.iter().all(|t| t.is_some());
                    if all_present {
                        let elapsed = tick_start.elapsed().as_secs_f64().max(0.001);
                        let kstats = kernel_tick_stats(&kernel_stats, &mut prev_kernel_totals);
                        let merged =
                            merge_ticks(&mut pending_ticks, elapsed, max_top_n, &stats, kstats);

                        metrics::observe_tick(
                            merged.bytes,
                            merged.packets,
                            merged.active_flows,
                            merged.dispatch_drops,
                            merged.kernel_drops,
                            merged.kernel_if_drops,
                        );

                        // Forward to web dashboard.
                        if let Some(tx) = &web_event_tx {
                            let stats_tick = aggregated_to_stats_tick(
                                &merged,
                                web_top_n,
                                frame_seq.fetch_add(1, Ordering::Relaxed),
                            );
                            let _ = tx.try_send(CaptureEvent::Tick(stats_tick));
                        }

                        // Store for CLI consumption.
                        {
                            let mut state = handle.inner.lock().unwrap_or_else(|e| e.into_inner());
                            state.latest_tick = Some(merged);
                        }

                        tick_start = Instant::now();
                    }
                }
                _ => {
                    if let Err(err) = handle_event(
                        event,
                        &handle,
                        &web_event_tx,
                        &mut output_sinks,
                        DrainMode::Full,
                    ) {
                        handle_fatal_error(&handle, &running, err, "event handling failed");
                        let _ = drain_channel(
                            &rx,
                            &handle,
                            &web_event_tx,
                            &mut output_sinks,
                            DrainMode::ShutdownOnly,
                        );
                        break;
                    }
                }
            },
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let elapsed_ms = tick_start.elapsed().as_millis() as u64;
                if elapsed_ms >= tick_deadline_ms && pending_ticks.iter().any(|t| t.is_some()) {
                    let elapsed = tick_start.elapsed().as_secs_f64().max(0.001);
                    let kstats = kernel_tick_stats(&kernel_stats, &mut prev_kernel_totals);
                    let merged =
                        merge_ticks(&mut pending_ticks, elapsed, max_top_n, &stats, kstats);

                    metrics::observe_tick(
                        merged.bytes,
                        merged.packets,
                        merged.active_flows,
                        merged.dispatch_drops,
                        merged.kernel_drops,
                        merged.kernel_if_drops,
                    );

                    if let Some(tx) = &web_event_tx {
                        let stats_tick = aggregated_to_stats_tick(
                            &merged,
                            web_top_n,
                            frame_seq.fetch_add(1, Ordering::Relaxed),
                        );
                        let _ = tx.try_send(CaptureEvent::Tick(stats_tick));
                    }

                    {
                        let mut state = handle.inner.lock().unwrap_or_else(|e| e.into_inner());
                        state.latest_tick = Some(merged);
                    }

                    tick_start = Instant::now();
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                // All workers have dropped their senders — drain whatever
                // remains in the channel before exiting so that Shutdown
                // events (and their flow snapshots) are not lost.
                if let Err(err) = drain_channel(
                    &rx,
                    &handle,
                    &web_event_tx,
                    &mut output_sinks,
                    DrainMode::Full,
                ) {
                    handle_fatal_error(&handle, &running, err, "failed while draining events");
                }
                break;
            }
        }
    }

    handle.append_output_errors(output_sinks.take_errors());
    tracing::debug!("aggregator shut down");
}

pub struct AggregatorRunConfig {
    pub web_event_tx: Option<mpsc::Sender<CaptureEvent>>,
    pub max_top_n: usize,
    pub web_top_n: usize,
    pub stats: Arc<PipelineStats>,
    pub kernel_stats: Arc<KernelPcapStats>,
    pub tick_deadline_ms: u64,
    pub output_sinks: OutputSinks,
    pub running: Arc<AtomicBool>,
}

enum DrainMode {
    Full,
    ShutdownOnly,
}

impl Clone for DrainMode {
    fn clone(&self) -> Self {
        match self {
            DrainMode::Full => DrainMode::Full,
            DrainMode::ShutdownOnly => DrainMode::ShutdownOnly,
        }
    }
}

fn handle_event(
    event: WorkerEvent,
    handle: &AggregatorHandle,
    web_event_tx: &Option<mpsc::Sender<CaptureEvent>>,
    output_sinks: &mut OutputSinks,
    mode: DrainMode,
) -> Result<(), std::io::Error> {
    if let DrainMode::ShutdownOnly = mode
        && !matches!(event, WorkerEvent::Shutdown(_))
    {
        return Ok(());
    }

    match event {
        WorkerEvent::Shutdown(shutdown) => {
            let mut state = handle.inner.lock().unwrap_or_else(|e| e.into_inner());
            record_shutdown_snapshot(&mut state, shutdown);
        }
        WorkerEvent::Alert(alert) => {
            {
                let mut state = handle.inner.lock().unwrap_or_else(|e| e.into_inner());
                state.alert_count += 1;
            }
            output_sinks.write_alert(alert.ts, &alert.kind, &alert.description)?;
            println!("[alert] {}", alert.description);
            if let Some(tx) = web_event_tx {
                let _ = tx.try_send(CaptureEvent::Alert(alert));
            }
        }
        WorkerEvent::ExpiredFlows(events) => {
            output_sinks.write_expired_flows(&events)?;
        }
        WorkerEvent::Packet(sample) => {
            if let Some(tx) = web_event_tx {
                let _ = tx.try_send(CaptureEvent::Packet(sample));
            }
        }
        WorkerEvent::PacketStored(stored) => {
            if let Some(tx) = web_event_tx {
                let _ = tx.try_send(CaptureEvent::PacketStored(stored));
            }
        }
        WorkerEvent::ShardTick(_) => {}
    }

    Ok(())
}

/// Drain all remaining events from the channel.
/// Used during normal shutdown and fatal-error paths to collect final
/// snapshots (and optionally flush sinks).
fn drain_channel(
    rx: &Receiver<WorkerEvent>,
    handle: &AggregatorHandle,
    web_event_tx: &Option<mpsc::Sender<CaptureEvent>>,
    output_sinks: &mut OutputSinks,
    mode: DrainMode,
) -> Result<(), std::io::Error> {
    while let Ok(event) = rx.try_recv() {
        handle_event(event, handle, web_event_tx, output_sinks, mode.clone())?;
    }

    Ok(())
}

fn record_shutdown_snapshot(state: &mut AggregatorState, shutdown: ShardShutdown) {
    if shutdown.shard_id >= state.shard_snapshots.len() {
        state
            .shard_snapshots
            .resize_with(shutdown.shard_id + 1, || None);
    }

    if state.shard_snapshots[shutdown.shard_id].is_some() {
        tracing::debug!(
            shard = shutdown.shard_id,
            "duplicate shutdown snapshot received; replacing previous value"
        );
    }

    state.worker_stats.processed_frames = state
        .worker_stats
        .processed_frames
        .saturating_add(shutdown.stats.processed_frames);
    state.worker_stats.parsed_packets = state
        .worker_stats
        .parsed_packets
        .saturating_add(shutdown.stats.parsed_packets);
    state.worker_stats.packets_with_transport_header = state
        .worker_stats
        .packets_with_transport_header
        .saturating_add(shutdown.stats.packets_with_transport_header);
    state.worker_stats.malformed_or_unsupported_packets = state
        .worker_stats
        .malformed_or_unsupported_packets
        .saturating_add(shutdown.stats.malformed_or_unsupported_packets);
    state.worker_stats.flows.created = state
        .worker_stats
        .flows
        .created
        .saturating_add(shutdown.stats.flows.created);
    state.worker_stats.flows.expired = state
        .worker_stats
        .flows
        .expired
        .saturating_add(shutdown.stats.flows.expired);
    state.worker_stats.flows.evicted = state
        .worker_stats
        .flows
        .evicted
        .saturating_add(shutdown.stats.flows.evicted);
    state.shard_snapshots[shutdown.shard_id] = Some(shutdown.flows);
}

fn handle_fatal_error(
    handle: &AggregatorHandle,
    running: &AtomicBool,
    err: std::io::Error,
    context: &str,
) {
    tracing::error!(error = %err, context, "fatal pipeline error");
    let mut state = handle.inner.lock().unwrap_or_else(|e| e.into_inner());
    if state.fatal_error.is_none() {
        state.fatal_error = Some(format!("{}: {}", context, err));
    }
    running.store(false, Ordering::SeqCst);
}

fn merge_ticks(
    pending: &mut [Option<ShardTick>],
    elapsed_secs: f64,
    max_top_n: usize,
    stats: &PipelineStats,
    kernel: KernelTickStats,
) -> AggregatedTick {
    let mut total_bytes: u64 = 0;
    let mut total_packets: u64 = 0;
    let mut total_active_flows: usize = 0;
    let mut all_top_flows: Vec<(FlowDelta, FlowSnapshot)> =
        Vec::with_capacity(pending.len().saturating_mul(max_top_n.max(1)));

    for slot in pending.iter_mut() {
        if let Some(tick) = slot.take() {
            total_bytes += tick.bytes;
            total_packets += tick.packets;
            total_active_flows += tick.active_flows;
            all_top_flows.extend(tick.top_flows);
        }
    }

    // Merge top flows: sort all shard top-flows by delta, take global top-N.
    all_top_flows.sort_unstable_by(|a, b| b.0.delta_bytes.cmp(&a.0.delta_bytes));
    if max_top_n > 0 {
        all_top_flows.truncate(max_top_n);
    }

    let mbps = total_bytes as f64 * 8.0 / elapsed_secs / 1_000_000.0;
    let pps = total_packets as f64 / elapsed_secs;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    AggregatedTick {
        ts,
        interval_ms: (elapsed_secs * 1000.0) as u64,
        bytes: total_bytes,
        packets: total_packets,
        mbps,
        pps,
        active_flows: total_active_flows,
        top_flows: all_top_flows,
        dispatch_drops: stats.take_dispatch_drops_interval(),
        dispatch_drops_total: stats.dispatch_drops_total(),
        kernel_drops: kernel.drops,
        kernel_drops_total: kernel.drops_total,
        kernel_if_drops: kernel.if_drops,
        kernel_if_drops_total: kernel.if_drops_total,
    }
}

fn aggregated_to_stats_tick(agg: &AggregatedTick, web_top_n: usize, frame_seq: u64) -> StatsTick {
    let elapsed_secs = (agg.interval_ms as f64 / 1000.0).max(0.001);

    let top_flows: Vec<FlowInfo> = agg
        .top_flows
        .iter()
        .take(web_top_n)
        .map(|(delta, snap)| FlowInfo::from_snapshot_delta(snap, delta.delta_bytes, elapsed_secs))
        .collect();

    StatsTick {
        ts: agg.ts,
        frame_seq,
        server_ts: unix_ms_now(),
        interval_ms: agg.interval_ms,
        bytes: agg.bytes,
        packets: agg.packets,
        mbps: agg.mbps,
        pps: agg.pps,
        active_flows: agg.active_flows,
        dispatch_drops: agg.dispatch_drops,
        dispatch_drops_total: agg.dispatch_drops_total,
        kernel_drops: agg.kernel_drops,
        kernel_drops_total: agg.kernel_drops_total,
        kernel_if_drops: agg.kernel_if_drops,
        kernel_if_drops_total: agg.kernel_if_drops_total,
        top_flows,
    }
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Endpoint, FlowProtocol};
    use crate::pipeline::KernelPcapStats;
    use crate::pipeline::worker::{ShardShutdown, WorkerRunStats};
    use std::sync::atomic::AtomicBool;

    fn test_snapshot(seed: u16) -> FlowSnapshot {
        FlowSnapshot {
            protocol: FlowProtocol::Tcp,
            endpoint_a: Endpoint {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                port: seed,
            },
            endpoint_b: Endpoint {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                port: 80,
            },
            first_seen: 1.0,
            last_seen: 2.0,
            duration_secs: 1.0,
            packets_a_to_b: 1,
            packets_b_to_a: 0,
            bytes_a_to_b: 100,
            bytes_b_to_a: 0,
            packets_total: 1,
            bytes_total: 100,
            avg_bps: 800.0,
            tcp_state: None,
            client: None,
            retransmissions: 0,
            out_of_order: 0,
            rtt_last_ms: None,
            rtt_min_ms: None,
            rtt_ewma_ms: None,
            rtt_samples: 0,
        }
    }

    #[test]
    fn collects_all_shutdown_snapshots_before_exit() {
        let (tx, rx) = crossbeam_channel::unbounded::<WorkerEvent>();
        let handle = AggregatorHandle::new(2);
        let stats = Arc::new(PipelineStats::new());
        let kernel_stats = Arc::new(KernelPcapStats::new());
        let running = Arc::new(AtomicBool::new(true));
        let thread_handle = handle.clone();

        let join = std::thread::spawn(move || {
            let config = AggregatorRunConfig {
                web_event_tx: None,
                max_top_n: 0,
                web_top_n: 0,
                stats,
                kernel_stats,
                tick_deadline_ms: 10,
                output_sinks: OutputSinks::open(None, None, None),
                running,
            };
            run(rx, thread_handle, config);
        });

        tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: 0,
            flows: vec![test_snapshot(1001)],
            stats: WorkerRunStats::default(),
        }))
        .unwrap();
        tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: 1,
            flows: vec![test_snapshot(1002)],
            stats: WorkerRunStats::default(),
        }))
        .unwrap();
        drop(tx);

        join.join().unwrap();

        let snapshots = handle.take_final_snapshots();
        assert_eq!(snapshots.len(), 2);
        let mut ports: Vec<u16> = snapshots.iter().map(|f| f.endpoint_a.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![1001, 1002]);
    }

    #[test]
    fn duplicate_shutdown_snapshot_replaces_same_shard() {
        let (tx, rx) = crossbeam_channel::unbounded::<WorkerEvent>();
        let handle = AggregatorHandle::new(2);
        let stats = Arc::new(PipelineStats::new());
        let kernel_stats = Arc::new(KernelPcapStats::new());
        let running = Arc::new(AtomicBool::new(true));
        let thread_handle = handle.clone();

        let join = std::thread::spawn(move || {
            let config = AggregatorRunConfig {
                web_event_tx: None,
                max_top_n: 0,
                web_top_n: 0,
                stats,
                kernel_stats,
                tick_deadline_ms: 10,
                output_sinks: OutputSinks::open(None, None, None),
                running,
            };
            run(rx, thread_handle, config);
        });

        tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: 0,
            flows: vec![test_snapshot(2001)],
            stats: WorkerRunStats::default(),
        }))
        .unwrap();
        tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: 0,
            flows: vec![test_snapshot(2002)],
            stats: WorkerRunStats::default(),
        }))
        .unwrap();
        tx.send(WorkerEvent::Shutdown(ShardShutdown {
            shard_id: 1,
            flows: vec![test_snapshot(2003)],
            stats: WorkerRunStats::default(),
        }))
        .unwrap();
        drop(tx);

        join.join().unwrap();

        let snapshots = handle.take_final_snapshots();
        assert_eq!(snapshots.len(), 2);
        let mut ports: Vec<u16> = snapshots.iter().map(|f| f.endpoint_a.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![2002, 2003]);
    }
}
