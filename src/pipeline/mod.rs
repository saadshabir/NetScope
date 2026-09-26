//! Sharded capture pipeline.
//!
//! The pipeline splits packet processing across N worker threads ("shards").
//! Each worker owns its own `FlowTracker` and `AnomalyDetector`, so the
//! hot path is completely lock-free.
//!
//! Architecture:
//!
//! ```text
//! pcap capture (main thread)
//!   |
//!   |-- extract 5-tuple hash → shard = hash % N
//!   |
//!   +--[crossbeam channel]--→ Worker 0  (parse, flow, anomaly)
//!   +--[crossbeam channel]--→ Worker 1
//!   ...
//!   +--[crossbeam channel]--→ Worker N-1
//!
//! Workers --[mpsc]--→ Aggregator thread
//!   |                     |
//!   |                     +--→ CLI stats
//!   |                     +--→ Web dashboard events
//! ```

pub mod aggregator;
pub mod pool;
pub mod router;
pub mod top_flows;
pub mod worker;

use crate::config::{AnalysisConfig, FlowConfig, StatsConfig, WebConfig};
use crate::protocol::LinkType;
use crate::sinks;
use crate::web;
use crossbeam_channel::{Sender, bounded};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

pub use aggregator::AggregatorHandle;
pub use pool::{PacketBufPool, PacketBufReturner};
pub use worker::WorkerEvent;

#[derive(Debug)]
pub struct PipelineStats {
    dispatch_drops_total: AtomicU64,
    dispatch_drops_interval: AtomicU64,
}

#[derive(Debug)]
pub struct KernelPcapStats {
    initialized: AtomicBool,
    dropped_total: AtomicU64,
    if_dropped_total: AtomicU64,
}

impl Default for KernelPcapStats {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelPcapStats {
    pub fn new() -> Self {
        KernelPcapStats {
            initialized: AtomicBool::new(false),
            dropped_total: AtomicU64::new(0),
            if_dropped_total: AtomicU64::new(0),
        }
    }

    pub fn update_totals(&self, dropped_total: u64, if_dropped_total: u64) {
        // Store the monotonic totals from pcap. The aggregator computes per-tick
        // deltas from these totals to avoid interval races.
        self.dropped_total.store(dropped_total, Ordering::SeqCst);
        self.if_dropped_total
            .store(if_dropped_total, Ordering::SeqCst);
        self.initialized.store(true, Ordering::SeqCst);
    }

    pub fn initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::SeqCst)
    }

    pub fn if_dropped_total(&self) -> u64 {
        self.if_dropped_total.load(Ordering::SeqCst)
    }
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineStats {
    pub fn new() -> Self {
        PipelineStats {
            dispatch_drops_total: AtomicU64::new(0),
            dispatch_drops_interval: AtomicU64::new(0),
        }
    }

    pub fn record_dispatch_drop(&self) {
        self.dispatch_drops_total.fetch_add(1, Ordering::Relaxed);
        self.dispatch_drops_interval.fetch_add(1, Ordering::Relaxed);
    }

    pub fn take_dispatch_drops_interval(&self) -> u64 {
        self.dispatch_drops_interval.swap(0, Ordering::Relaxed)
    }

    pub fn dispatch_drops_total(&self) -> u64 {
        self.dispatch_drops_total.load(Ordering::Relaxed)
    }
}

/// An owned packet buffer sent from the capture thread to a worker.
#[derive(Debug)]
pub struct OwnedPacket {
    /// Monotonic capture-wide packet index.
    pub id: u64,
    /// pcap timestamp as seconds since epoch.
    pub ts: f64,
    /// Wire length (from pcap header).
    pub wire_len: u64,
    /// Owned copy of packet bytes.
    pub data: Vec<u8>,
}

/// Configuration for the pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Number of worker shards (0 = auto-detect from CPU count).
    pub num_workers: usize,
    /// Capacity of each capture → worker channel.
    pub channel_capacity: usize,
    /// Capacity for the packet buffer pool.
    pub buffer_pool_capacity: usize,
    /// Buffer size for packet byte storage.
    pub packet_buf_size: usize,
    /// Flow tracker settings.
    pub flow: FlowConfig,
    /// Analysis settings.
    pub analysis: AnalysisConfig,
    /// CLI stats settings (for top-N truncation).
    pub stats: StatsConfig,
    /// Web dashboard settings (for sampling decisions).
    pub web: WebConfig,
    /// Number of heavy-hitter candidates to track per worker tick.
    pub heavy_hitter_top_n: usize,
    /// Pipeline alert JSONL file sink path.
    pub alerts_jsonl: Option<PathBuf>,
    /// Pipeline expired-flow JSONL file sink path.
    pub expired_flows_jsonl: Option<PathBuf>,
    /// Pipeline expired-flow CSV file sink path.
    pub expired_flows_csv: Option<PathBuf>,
    /// Shared kernel/libpcap drop counters.
    pub kernel_stats: Arc<KernelPcapStats>,
    /// Capture datalink type (applies to all packets in this run).
    pub link_type: LinkType,
}

/// Handle returned by [`spawn`] — the capture thread uses this to dispatch
/// packets and retrieve the aggregator.
pub struct PipelineHandle {
    /// Per-shard senders. The capture thread picks `senders[shard]`.
    pub senders: Vec<Sender<OwnedPacket>>,
    /// The aggregator collects merged results from all workers.
    pub aggregator: AggregatorHandle,
    /// Shared pool for packet byte buffers.
    pub buffer_pool: PacketBufPool,
    /// Shared counters for pipeline drop statistics.
    pub stats: Arc<PipelineStats>,
    /// Shared kernel/libpcap drop statistics.
    pub kernel_stats: Arc<KernelPcapStats>,
    /// Worker join handles (for clean shutdown).
    worker_handles: Vec<thread::JoinHandle<()>>,
    /// Aggregator join handle.
    aggregator_handle: Option<thread::JoinHandle<()>>,
}

impl PipelineHandle {
    /// Number of worker shards.
    pub fn num_workers(&self) -> usize {
        self.senders.len()
    }

    /// Signal all workers to stop (by dropping senders) and join threads.
    /// The `aggregator` handle remains valid after this call for reading
    /// final snapshots.
    pub fn shutdown(&mut self) {
        // Drop senders so workers see channel disconnect.
        self.senders.clear();
        for h in self.worker_handles.drain(..) {
            let _ = h.join();
        }
        // Aggregator shuts down once all worker event senders are dropped.
        if let Some(h) = self.aggregator_handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn the sharded pipeline.
///
/// Returns a `PipelineHandle` the caller uses to dispatch packets (via
/// `senders`) and to read aggregated results (via `aggregator`).
pub fn spawn(
    config: PipelineConfig,
    running: Arc<AtomicBool>,
    web_handle: Option<&web::server::WebHandle>,
) -> Result<PipelineHandle, std::io::Error> {
    let num_workers =
        resolve_num_workers_for_flow_budget(config.num_workers, config.flow.max_flows);

    tracing::info!(num_workers, "starting sharded pipeline");

    let output_sinks = sinks::OutputSinks::open(
        config.alerts_jsonl.as_deref(),
        config.expired_flows_jsonl.as_deref(),
        config.expired_flows_csv.as_deref(),
    );

    // Aggregator channel: all workers send events here.
    let (agg_tx, agg_rx) = crossbeam_channel::unbounded::<WorkerEvent>();

    // Spawn workers.
    let mut senders = Vec::with_capacity(num_workers);
    let mut worker_handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(num_workers);
    let buffer_pool = PacketBufPool::new(config.buffer_pool_capacity, config.packet_buf_size);
    let buffer_returner = buffer_pool.returner();
    let stats = Arc::new(PipelineStats::new());
    let kernel_stats = config.kernel_stats.clone();
    let emit_expired_flows = output_sinks.emit_expired_flows();

    for shard_id in 0..num_workers {
        let (pkt_tx, pkt_rx) = bounded::<OwnedPacket>(config.channel_capacity);
        senders.push(pkt_tx);

        let agg_tx = agg_tx.clone();
        let running = running.clone();
        let mut flow_cfg = config.flow.clone();
        flow_cfg.max_flows = flow_limit_for_shard(config.flow.max_flows, num_workers, shard_id);
        let analysis_cfg = config.analysis.clone();
        let web_cfg = config.web.clone();
        let heavy_hitter_top_n = config.heavy_hitter_top_n;
        let buffer_returner = buffer_returner.clone();
        let link_type = config.link_type;
        let running_for_worker = running.clone();

        let handle = match thread::Builder::new()
            .name(format!("ns-worker-{}", shard_id))
            .spawn(move || {
                let mut w = worker::Worker::new(
                    shard_id,
                    link_type,
                    worker::WorkerConfigBundle {
                        flow_cfg,
                        analysis_cfg,
                        web_cfg,
                        heavy_hitter_top_n,
                        emit_expired_flows,
                    },
                    buffer_returner,
                );
                w.run(pkt_rx, agg_tx, &running_for_worker);
            }) {
            Ok(handle) => handle,
            Err(err) => {
                running.store(false, Ordering::SeqCst);
                senders.clear();
                for h in worker_handles.drain(..) {
                    let _ = h.join();
                }
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("failed to spawn worker thread {}: {}", shard_id, err),
                ));
            }
        };

        worker_handles.push(handle);
    }

    // Drop the aggregator sender held by this thread so the aggregator can
    // detect when all workers are done.
    drop(agg_tx);

    // Spawn aggregator.
    let web_event_tx = web_handle.map(|h| h.event_tx.clone());
    let agg_handle = aggregator::AggregatorHandle::new(num_workers);
    let agg_handle_clone = agg_handle.clone();
    let max_top_n = (config.stats.top_flows as usize).max(config.web.top_n);
    let web_top_n = config.web.top_n;
    // Use a small deadline slightly above the configured tick to avoid
    // gating merged frames on idle shards. Previously this was a 2x multiplier
    // which caused merged frame cadence to be artificially low (e.g. ~26fps
    // for a 33ms tick). Use tick_ms + 5ms as a pragmatic deadline.
    let tick_deadline_ms = config.web.tick_ms.saturating_add(5).max(1);
    let stats_clone = stats.clone();
    let kernel_stats_clone = kernel_stats.clone();
    let running_for_aggregator = running.clone();

    let aggregator_thread =
        match thread::Builder::new()
            .name("ns-aggregator".into())
            .spawn(move || {
                let run_cfg = aggregator::AggregatorRunConfig {
                    web_event_tx,
                    max_top_n,
                    web_top_n,
                    stats: stats_clone,
                    kernel_stats: kernel_stats_clone,
                    tick_deadline_ms,
                    output_sinks,
                    running: running_for_aggregator,
                };
                aggregator::run(agg_rx, agg_handle_clone, run_cfg);
            }) {
            Ok(handle) => handle,
            Err(err) => {
                running.store(false, Ordering::SeqCst);
                senders.clear();
                for h in worker_handles.drain(..) {
                    let _ = h.join();
                }
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("failed to spawn aggregator thread: {}", err),
                ));
            }
        };

    Ok(PipelineHandle {
        senders,
        aggregator: agg_handle,
        buffer_pool,
        stats,
        kernel_stats,
        worker_handles,
        aggregator_handle: Some(aggregator_thread),
    })
}

/// Divide the configured total flow budget across shards. A skewed workload can
/// evict flows on a busy shard while another shard has unused quota; the sum
/// of shard quotas never exceeds the configured limit.
fn flow_limit_for_shard(total: usize, workers: usize, shard: usize) -> usize {
    if total == 0 || workers == 0 {
        return 0;
    }
    let base = total / workers;
    let remainder = total % workers;
    base + if shard < remainder { 1 } else { 0 }
}

fn resolve_num_workers_for_flow_budget(configured: usize, max_flows: usize) -> usize {
    let workers = resolve_num_workers(configured);
    if max_flows == 0 {
        workers
    } else {
        workers.min(max_flows).max(1)
    }
}

pub fn resolve_num_workers(configured: usize) -> usize {
    if configured == 0 {
        (num_cpus::get() / 2).clamp(1, 8)
    } else {
        configured.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::{KernelPcapStats, flow_limit_for_shard, resolve_num_workers_for_flow_budget};

    #[test]
    fn flow_budget_is_partitioned_without_exceeding_the_global_limit() {
        let limits: Vec<_> = (0..3)
            .map(|shard| flow_limit_for_shard(8, 3, shard))
            .collect();
        assert_eq!(limits, [3, 3, 2]);
        assert_eq!(limits.iter().sum::<usize>(), 8);
        assert_eq!(flow_limit_for_shard(0, 4, 0), 0);
    }

    #[test]
    fn worker_count_is_reduced_when_the_flow_budget_cannot_give_each_worker_a_slot() {
        assert_eq!(resolve_num_workers_for_flow_budget(4, 2), 2);
        assert_eq!(resolve_num_workers_for_flow_budget(4, 1), 1);
        assert_eq!(resolve_num_workers_for_flow_budget(4, 0), 4);
    }

    #[test]
    fn kernel_stats_tracks_initialized_and_totals() {
        let stats = KernelPcapStats::new();
        assert!(!stats.initialized());
        assert_eq!(stats.dropped_total(), 0);
        assert_eq!(stats.if_dropped_total(), 0);

        stats.update_totals(10, 3);
        assert!(stats.initialized());
        assert_eq!(stats.dropped_total(), 10);
        assert_eq!(stats.if_dropped_total(), 3);

        stats.update_totals(15, 5);
        assert!(stats.initialized());
        assert_eq!(stats.dropped_total(), 15);
        assert_eq!(stats.if_dropped_total(), 5);
    }
}
