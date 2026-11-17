//! Prometheus-compatible metrics exposed by the web server.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::analysis::anomaly::{AlertKind, AnomalySaturation};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

struct MetricsState {
    started_at: Instant,
    capture_bytes_total: AtomicU64,
    capture_packets_total: AtomicU64,
    active_flows: AtomicU64,
    dispatch_drops_total: AtomicU64,
    kernel_drops_total: AtomicU64,
    kernel_if_drops_total: AtomicU64,
    anomaly_saturation: Mutex<AnomalySaturation>,
}

impl MetricsState {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            capture_bytes_total: AtomicU64::new(0),
            capture_packets_total: AtomicU64::new(0),
            active_flows: AtomicU64::new(0),
            dispatch_drops_total: AtomicU64::new(0),
            kernel_drops_total: AtomicU64::new(0),
            kernel_if_drops_total: AtomicU64::new(0),
            anomaly_saturation: Mutex::default(),
        }
    }
}

static METRICS: OnceLock<MetricsState> = OnceLock::new();

fn metrics() -> &'static MetricsState {
    METRICS.get_or_init(MetricsState::new)
}

/// Initialize metrics state eagerly so uptime reflects process lifetime.
pub fn initialize() {
    let _ = metrics();
}

/// Observe one periodic capture tick.
pub fn observe_tick(
    bytes: u64,
    packets: u64,
    active_flows: usize,
    dispatch_drops: u64,
    kernel_drops: u64,
    kernel_if_drops: u64,
) {
    let state = metrics();

    state
        .capture_bytes_total
        .fetch_add(bytes, Ordering::Relaxed);
    state
        .capture_packets_total
        .fetch_add(packets, Ordering::Relaxed);
    state
        .dispatch_drops_total
        .fetch_add(dispatch_drops, Ordering::Relaxed);
    state
        .kernel_drops_total
        .fetch_add(kernel_drops, Ordering::Relaxed);
    state
        .kernel_if_drops_total
        .fetch_add(kernel_if_drops, Ordering::Relaxed);

    let active_flows = active_flows.min(u64::MAX as usize) as u64;
    state.active_flows.store(active_flows, Ordering::Relaxed);
}

/// Publish the inline detector's cumulative counters.
pub fn set_anomaly_saturation(saturation: AnomalySaturation) {
    *metrics()
        .anomaly_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = saturation;
}

/// Content type for Prometheus text exposition format.
pub fn prometheus_content_type() -> &'static str {
    PROMETHEUS_CONTENT_TYPE
}

/// Render all metrics in Prometheus text exposition format.
pub fn render_prometheus_text() -> String {
    let state = metrics();

    let capture_bytes_total = state.capture_bytes_total.load(Ordering::Relaxed);
    let capture_packets_total = state.capture_packets_total.load(Ordering::Relaxed);
    let active_flows = state.active_flows.load(Ordering::Relaxed);
    let dispatch_drops_total = state.dispatch_drops_total.load(Ordering::Relaxed);
    let kernel_drops_total = state.kernel_drops_total.load(Ordering::Relaxed);
    let kernel_if_drops_total = state.kernel_if_drops_total.load(Ordering::Relaxed);
    let anomaly_saturation = *state
        .anomaly_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();

    let mut out = String::with_capacity(1024);
    let version = escape_label_value(env!("CARGO_PKG_VERSION"));

    let _ = writeln!(
        out,
        "# HELP netscope_build_info Build information for the running NetScope binary."
    );
    let _ = writeln!(out, "# TYPE netscope_build_info gauge");
    let _ = writeln!(out, "netscope_build_info{{version=\"{}\"}} 1", version);

    let _ = writeln!(
        out,
        "# HELP netscope_uptime_seconds Process uptime in seconds."
    );
    let _ = writeln!(out, "# TYPE netscope_uptime_seconds gauge");
    let _ = writeln!(out, "netscope_uptime_seconds {}", uptime_seconds);

    let _ = writeln!(
        out,
        "# HELP netscope_capture_bytes_total Total captured bytes across ticks."
    );
    let _ = writeln!(out, "# TYPE netscope_capture_bytes_total counter");
    let _ = writeln!(out, "netscope_capture_bytes_total {}", capture_bytes_total);

    let _ = writeln!(
        out,
        "# HELP netscope_capture_packets_total Total captured packets across ticks."
    );
    let _ = writeln!(out, "# TYPE netscope_capture_packets_total counter");
    let _ = writeln!(
        out,
        "netscope_capture_packets_total {}",
        capture_packets_total
    );

    let _ = writeln!(
        out,
        "# HELP netscope_active_flows Active flow count from the latest tick."
    );
    let _ = writeln!(out, "# TYPE netscope_active_flows gauge");
    let _ = writeln!(out, "netscope_active_flows {}", active_flows);

    let _ = writeln!(
        out,
        "# HELP netscope_dispatch_drops_total Total capture-to-worker dispatch drops."
    );
    let _ = writeln!(out, "# TYPE netscope_dispatch_drops_total counter");
    let _ = writeln!(
        out,
        "netscope_dispatch_drops_total {}",
        dispatch_drops_total
    );

    let _ = writeln!(
        out,
        "# HELP netscope_kernel_drops_total Total kernel/libpcap dropped packets."
    );
    let _ = writeln!(out, "# TYPE netscope_kernel_drops_total counter");
    let _ = writeln!(out, "netscope_kernel_drops_total {}", kernel_drops_total);

    let _ = writeln!(
        out,
        "# HELP netscope_kernel_if_drops_total Total interface-level dropped packets."
    );
    let _ = writeln!(out, "# TYPE netscope_kernel_if_drops_total counter");
    let _ = writeln!(
        out,
        "netscope_kernel_if_drops_total {}",
        kernel_if_drops_total
    );

    let _ = writeln!(
        out,
        "# HELP netscope_anomaly_evidence_discards_total Evidence rejections and record evictions caused by detector limits."
    );
    let _ = writeln!(
        out,
        "# TYPE netscope_anomaly_evidence_discards_total counter"
    );
    for (detector, saturation) in [
        (AlertKind::SynFlood, anomaly_saturation.syn_flood),
        (AlertKind::PortScan, anomaly_saturation.port_scan),
    ] {
        for (reason, count) in saturation.counts() {
            let _ = writeln!(
                out,
                "netscope_anomaly_evidence_discards_total{{detector=\"{}\",reason=\"{reason}\"}} {count}",
                detector.as_str()
            );
        }
    }

    out
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::{observe_tick, render_prometheus_text, set_anomaly_saturation};
    use crate::analysis::anomaly::{AnomalySaturation, DetectorSaturation};

    #[test]
    fn render_contains_expected_metric_families() {
        observe_tick(10, 5, 3, 1, 2, 4);
        let saturation = AnomalySaturation {
            syn_flood: DetectorSaturation {
                key_limit_rejections: 17,
                ..DetectorSaturation::default()
            },
            ..AnomalySaturation::default()
        };
        set_anomaly_saturation(saturation);
        set_anomaly_saturation(saturation);

        let body = render_prometheus_text();

        assert!(body.contains("netscope_build_info"));
        assert!(body.contains("netscope_uptime_seconds"));
        assert!(body.contains("netscope_capture_bytes_total"));
        assert!(body.contains("netscope_capture_packets_total"));
        assert!(body.contains("netscope_active_flows"));
        assert!(body.contains("netscope_dispatch_drops_total"));
        assert!(body.contains("netscope_kernel_drops_total"));
        assert!(body.contains("netscope_kernel_if_drops_total"));
        assert!(body.lines().any(|line| line ==
            "netscope_anomaly_evidence_discards_total{detector=\"syn_flood\",reason=\"key_limit_rejections\"} 17"));
        assert!(body.lines().any(|line| line ==
            "netscope_anomaly_evidence_discards_total{detector=\"port_scan\",reason=\"per_key_record_evictions\"} 0"));
    }
}
