use crate::config::{AnomalyConfig, PortScanConfig, SynFloodConfig};
use crate::flow::{Endpoint, FlowProtocol};
use crate::sinks::AlertJsonlSink;
use ahash::AHashMap;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;
use std::net::IpAddr;

pub const ALERT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    SynFlood,
    PortScan,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub schema_version: u32,
    pub ts: f64,
    pub kind: AlertKind,
    pub source_ip: Option<IpAddr>,
    pub target_ip: Option<IpAddr>,
    pub target_port: Option<u16>,
    pub window_secs: f64,
    pub thresholds: AlertThresholds,
    pub observed: AlertObservations,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertThresholds {
    pub syn_count: Option<u32>,
    pub unique_sources: Option<u32>,
    pub unique_ports: Option<u32>,
    pub unique_hosts: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertObservations {
    pub syn_count: Option<u64>,
    pub unique_sources: Option<u64>,
    pub unique_ports: Option<u64>,
    pub unique_hosts: Option<u64>,
}

#[derive(Debug)]
pub struct AnomalyDetector {
    config: AnomalyConfig,
    syn_flood: SynFloodState,
    port_scan: PortScanState,
    alert_sink: Option<AlertJsonlSink>,
    latest_event_ts: Option<f64>,
    last_cleanup_ts: Option<f64>,
}

/// How often (in seconds) to sweep stale entries from anomaly detector state.
const CLEANUP_INTERVAL_SECS: f64 = 30.0;

fn configured_window(window_secs: f64) -> f64 {
    if window_secs.is_finite() && window_secs > 0.0 {
        window_secs
    } else {
        0.1
    }
}

impl AnomalyDetector {
    pub fn new(config: AnomalyConfig) -> Self {
        AnomalyDetector {
            syn_flood: SynFloodState::new(config.syn_flood.clone()),
            port_scan: PortScanState::new(config.port_scan.clone()),
            config,
            alert_sink: None,
            latest_event_ts: None,
            last_cleanup_ts: None,
        }
    }

    pub fn new_with_alerts_jsonl(
        config: AnomalyConfig,
        path: &std::path::Path,
    ) -> Result<Self, std::io::Error> {
        let alert_sink = AlertJsonlSink::open(path)?;
        Ok(AnomalyDetector {
            syn_flood: SynFloodState::new(config.syn_flood.clone()),
            port_scan: PortScanState::new(config.port_scan.clone()),
            config,
            alert_sink: Some(alert_sink),
            latest_event_ts: None,
            last_cleanup_ts: None,
        })
    }

    pub fn observe(
        &mut self,
        ts: f64,
        protocol: FlowProtocol,
        src: Endpoint,
        dst: Endpoint,
        tcp_syn: bool,
        tcp_ack: bool,
    ) -> Result<Vec<Alert>, std::io::Error> {
        if !self.config.enabled || !ts.is_finite() {
            return Ok(Vec::new());
        }

        self.advance_time(ts);
        let watermark = self.latest_event_ts.unwrap_or(ts);

        let mut alerts = Vec::new();

        let syn_is_new = tcp_syn && !tcp_ack;

        if self.config.syn_flood.enabled
            && protocol == FlowProtocol::Tcp
            && syn_is_new
            && let Some(alert) = self
                .syn_flood
                .observe(ts, watermark, src.ip, dst.ip, dst.port)
        {
            alerts.push(alert);
        }

        if self.config.port_scan.enabled
            && let Some(alert) = self.port_scan.observe(
                ts, watermark, protocol, src.ip, dst.ip, dst.port, syn_is_new,
            )
        {
            alerts.push(alert);
        }

        if let Some(sink) = &mut self.alert_sink {
            for alert in &alerts {
                sink.write_alert(alert)?;
            }
        }

        Ok(alerts)
    }

    /// Advance event time for every captured frame, including frames that
    /// cannot contribute to an anomaly or fail protocol parsing.
    pub fn advance_time(&mut self, ts: f64) {
        if !self.config.enabled || !ts.is_finite() {
            return;
        }

        // PCAP timestamps can move backwards. Keep cleanup and cooldown time
        // monotonic so an out-of-order packet cannot revive expired state.
        let watermark = self.latest_event_ts.map_or(ts, |latest| latest.max(ts));
        self.latest_event_ts = Some(watermark);

        if self
            .last_cleanup_ts
            .is_none_or(|last| watermark - last >= CLEANUP_INTERVAL_SECS)
        {
            self.syn_flood.cleanup(watermark);
            self.port_scan.cleanup(watermark);
            self.last_cleanup_ts = Some(watermark);
        }
    }
}

impl AlertKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::SynFlood => "syn_flood",
            AlertKind::PortScan => "port_scan",
        }
    }
}

// Admission limits apply independently to each detector. Saturated windows
// retain bounded evidence and can miss alerts; they never invent observations.
const MAX_KEYS: usize = 4096;
const MAX_RECORDS: usize = 65_536;
const MAX_RECORDS_PER_KEY: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct EventTime(f64);
impl PartialEq for EventTime {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}
impl Eq for EventTime {}
impl PartialOrd for EventTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for EventTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

#[derive(Debug, Clone)]
struct CountWindow<T> {
    records: BTreeMap<(EventTime, T), u64>,
    counts: AHashMap<T, u64>,
    total: u64,
}
impl<T: Copy + Ord + Hash> Default for CountWindow<T> {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            counts: AHashMap::new(),
            total: 0,
        }
    }
}
impl<T: Copy + Ord + Hash> CountWindow<T> {
    fn pop_oldest(&mut self) {
        if let Some(((_, value), count)) = self.records.pop_first() {
            self.total -= count;
            let remaining = self.counts.get_mut(&value).expect("counted record");
            *remaining -= count;
            if *remaining == 0 {
                self.counts.remove(&value);
            }
        }
    }
    fn expire(&mut self, cutoff: f64) {
        while self
            .records
            .first_key_value()
            .is_some_and(|((ts, _), _)| ts.0 < cutoff)
        {
            self.pop_oldest();
        }
    }
    fn observe(&mut self, ts: f64, value: T, room: bool) {
        let key = (EventTime(ts), value);
        if !self.records.contains_key(&key) {
            if self.records.len() >= MAX_RECORDS_PER_KEY {
                self.pop_oldest();
            } else if !room {
                return;
            }
        }
        let count = self.records.entry(key).or_default();
        *count = count.saturating_add(1);
        let count = self.counts.entry(value).or_default();
        *count = count.saturating_add(1);
        self.total = self.total.saturating_add(1);
    }
}

#[derive(Debug, Clone)]
struct DistinctWindow<T> {
    records: BTreeSet<(EventTime, T)>,
    latest: AHashMap<T, EventTime>,
}
impl<T: Copy + Ord + Hash> Default for DistinctWindow<T> {
    fn default() -> Self {
        Self {
            records: BTreeSet::new(),
            latest: AHashMap::new(),
        }
    }
}
impl<T: Copy + Ord + Hash> DistinctWindow<T> {
    fn pop_oldest(&mut self) {
        if let Some((_, value)) = self.records.pop_first() {
            self.latest.remove(&value);
        }
    }
    fn expire(&mut self, cutoff: f64) {
        while self.records.first().is_some_and(|(ts, _)| ts.0 < cutoff) {
            self.pop_oldest();
        }
    }
    fn observe(&mut self, ts: f64, value: T, room: bool) {
        let ts = EventTime(ts);
        if let Some(previous) = self.latest.get(&value) {
            if *previous >= ts {
                return;
            }
            self.records.remove(&(*previous, value));
        } else if self.records.len() >= MAX_RECORDS_PER_KEY {
            self.pop_oldest();
        } else if !room {
            return;
        }
        self.records.insert((ts, value));
        self.latest.insert(value, ts);
    }
}

#[derive(Debug, Clone, Default)]
struct ScanWindow {
    ports: DistinctWindow<u16>,
    hosts: DistinctWindow<IpAddr>,
}
impl ScanWindow {
    fn len(&self) -> usize {
        self.ports.records.len() + self.hosts.records.len()
    }
    fn expire(&mut self, cutoff: f64) {
        self.ports.expire(cutoff);
        self.hosts.expire(cutoff);
    }
}

#[derive(Debug, Clone)]
struct SynFloodState {
    config: SynFloodConfig,
    events: AHashMap<SynFloodKey, CountWindow<IpAddr>>,
    records: usize,
    cooldowns: AHashMap<SynFloodKey, f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SynFloodKey {
    dst_ip: IpAddr,
    dst_port: u16,
}

impl SynFloodState {
    fn new(config: SynFloodConfig) -> Self {
        SynFloodState {
            config,
            events: AHashMap::new(),
            records: 0,
            cooldowns: AHashMap::new(),
        }
    }

    fn observe(
        &mut self,
        ts: f64,
        watermark: f64,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<Alert> {
        let key = SynFloodKey { dst_ip, dst_port };
        if let Some(until) = self.cooldowns.get(&key)
            && *until > watermark
        {
            return None;
        }

        let window = configured_window(self.config.window_secs);
        if let Some(events) = self.events.get_mut(&key) {
            let previous = events.records.len();
            events.expire(watermark - window);
            self.records -= previous - events.records.len();
            if events.records.is_empty() {
                self.events.remove(&key);
            }
        }
        if watermark - ts > window {
            return None;
        }
        if !self.events.contains_key(&key)
            && (self.events.len() >= MAX_KEYS
                || self.records >= MAX_RECORDS
                || self.cooldowns.len() >= MAX_KEYS)
        {
            return None;
        }
        let events = self.events.entry(key).or_default();
        let previous = events.records.len();
        events.observe(ts, src_ip, self.records < MAX_RECORDS);
        self.records = self.records - previous + events.records.len();
        let syn_count = events.total;
        let unique_sources = events.counts.len();
        if syn_count >= self.config.syn_threshold as u64
            && unique_sources >= self.config.unique_src_threshold as usize
        {
            let desc = format!(
                "SYN flood suspected: {} syns, {} sources to {}:{}",
                syn_count, unique_sources, dst_ip, dst_port
            );
            self.cooldowns
                .insert(key, watermark + self.config.cooldown_secs.max(0.0));
            return Some(Alert {
                schema_version: ALERT_SCHEMA_VERSION,
                ts,
                kind: AlertKind::SynFlood,
                source_ip: None,
                target_ip: Some(dst_ip),
                target_port: Some(dst_port),
                window_secs: window,
                thresholds: AlertThresholds {
                    syn_count: Some(self.config.syn_threshold),
                    unique_sources: Some(self.config.unique_src_threshold),
                    unique_ports: None,
                    unique_hosts: None,
                },
                observed: AlertObservations {
                    syn_count: Some(syn_count),
                    unique_sources: Some(unique_sources as u64),
                    unique_ports: None,
                    unique_hosts: None,
                },
                description: desc,
            });
        }

        None
    }

    /// Remove events outside their configured window and expired cooldowns.
    fn cleanup(&mut self, now: f64) {
        let cutoff = now - configured_window(self.config.window_secs);
        self.events.retain(|_, events| {
            events.expire(cutoff);
            !events.records.is_empty()
        });
        self.records = self
            .events
            .values()
            .map(|events| events.records.len())
            .sum();
        self.cooldowns.retain(|_, until| *until > now);
        self.events.shrink_to_fit();
        self.cooldowns.shrink_to_fit();
    }
}

#[derive(Debug, Clone)]
struct PortScanState {
    config: PortScanConfig,
    events: AHashMap<IpAddr, ScanWindow>,
    records: usize,
    cooldowns: AHashMap<IpAddr, f64>,
}

impl PortScanState {
    fn new(config: PortScanConfig) -> Self {
        PortScanState {
            config,
            events: AHashMap::new(),
            records: 0,
            cooldowns: AHashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe(
        &mut self,
        ts: f64,
        watermark: f64,
        protocol: FlowProtocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        syn_only: bool,
    ) -> Option<Alert> {
        if let Some(until) = self.cooldowns.get(&src_ip)
            && *until > watermark
        {
            return None;
        }

        if protocol == FlowProtocol::Tcp && !syn_only {
            return None;
        }

        let window = configured_window(self.config.window_secs);
        if let Some(events) = self.events.get_mut(&src_ip) {
            let previous = events.len();
            events.expire(watermark - window);
            self.records -= previous - events.len();
            if events.len() == 0 {
                self.events.remove(&src_ip);
            }
        }
        if watermark - ts > window {
            return None;
        }
        if !self.events.contains_key(&src_ip)
            && (self.events.len() >= MAX_KEYS
                || self.records >= MAX_RECORDS
                || self.cooldowns.len() >= MAX_KEYS)
        {
            return None;
        }
        let events = self.events.entry(src_ip).or_default();
        let previous = events.len();
        events
            .ports
            .observe(ts, dst_port, self.records < MAX_RECORDS);
        self.records = self.records - previous + events.len();
        let previous = events.len();
        events.hosts.observe(ts, dst_ip, self.records < MAX_RECORDS);
        self.records = self.records - previous + events.len();
        let unique_ports = events.ports.latest.len();
        let unique_hosts = events.hosts.latest.len();
        if (self.config.unique_ports_threshold > 0
            && unique_ports >= self.config.unique_ports_threshold as usize)
            || (self.config.unique_hosts_threshold > 0
                && unique_hosts >= self.config.unique_hosts_threshold as usize)
        {
            let desc = format!(
                "Port scan suspected: {} ports, {} hosts from {}",
                unique_ports, unique_hosts, src_ip
            );
            self.cooldowns
                .insert(src_ip, watermark + self.config.cooldown_secs.max(0.0));
            return Some(Alert {
                schema_version: ALERT_SCHEMA_VERSION,
                ts,
                kind: AlertKind::PortScan,
                source_ip: Some(src_ip),
                target_ip: None,
                target_port: None,
                window_secs: window,
                thresholds: AlertThresholds {
                    syn_count: None,
                    unique_sources: None,
                    unique_ports: Some(self.config.unique_ports_threshold),
                    unique_hosts: Some(self.config.unique_hosts_threshold),
                },
                observed: AlertObservations {
                    syn_count: None,
                    unique_sources: None,
                    unique_ports: Some(unique_ports as u64),
                    unique_hosts: Some(unique_hosts as u64),
                },
                description: desc,
            });
        }

        None
    }

    /// Remove events outside their configured window and expired cooldowns.
    fn cleanup(&mut self, now: f64) {
        let cutoff = now - configured_window(self.config.window_secs);
        self.events.retain(|_, events| {
            events.expire(cutoff);
            events.len() > 0
        });
        self.records = self.events.values().map(ScanWindow::len).sum();
        self.cooldowns.retain(|_, until| *until > now);
        self.events.shrink_to_fit();
        self.cooldowns.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortScanConfig, SynFloodConfig};
    use std::net::Ipv4Addr;

    fn endpoint(addr: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::from(addr)),
            port,
        }
    }

    fn config() -> AnomalyConfig {
        AnomalyConfig {
            enabled: true,
            syn_flood: SynFloodConfig {
                enabled: true,
                window_secs: 5.0,
                syn_threshold: 2,
                unique_src_threshold: 2,
                cooldown_secs: 3.0,
            },
            port_scan: PortScanConfig {
                enabled: true,
                window_secs: 5.0,
                unique_ports_threshold: 2,
                unique_hosts_threshold: 100,
                cooldown_secs: 3.0,
            },
        }
    }

    fn observe_syn(
        detector: &mut AnomalyDetector,
        ts: f64,
        src: [u8; 4],
        dst: [u8; 4],
        dst_port: u16,
    ) -> Vec<Alert> {
        detector
            .observe(
                ts,
                FlowProtocol::Tcp,
                endpoint(src, 40000),
                endpoint(dst, dst_port),
                true,
                false,
            )
            .expect("anomaly observation should not fail without an output sink")
    }

    #[test]
    fn zero_scan_threshold_disables_only_that_criterion() {
        for ports_enabled in [true, false] {
            let mut cfg = config();
            cfg.syn_flood.enabled = false;
            cfg.port_scan.unique_ports_threshold = if ports_enabled { 2 } else { 0 };
            cfg.port_scan.unique_hosts_threshold = if ports_enabled { 0 } else { 2 };
            let mut detector = AnomalyDetector::new(cfg);
            assert!(observe_syn(&mut detector, 10.0, [10, 0, 0, 1], [192, 0, 2, 1], 80).is_empty());
            let host = if ports_enabled { 1 } else { 2 };
            let port = if ports_enabled { 81 } else { 80 };
            let alerts = observe_syn(&mut detector, 10.1, [10, 0, 0, 1], [192, 0, 2, host], port);
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].kind.as_str(), "port_scan");
        }
    }

    fn high_threshold_config() -> AnomalyConfig {
        let mut cfg = config();
        cfg.syn_flood.unique_src_threshold = u32::MAX;
        cfg.port_scan.unique_ports_threshold = u32::MAX;
        cfg.port_scan.unique_hosts_threshold = u32::MAX;
        cfg
    }

    #[test]
    fn repetitive_observations_have_bounded_incremental_state() {
        let mut detector = AnomalyDetector::new(high_threshold_config());
        for index in 0..20_000 {
            assert!(
                observe_syn(
                    &mut detector,
                    100.0 + index as f64 / 1_000_000.0,
                    [10, 0, 0, 1],
                    [192, 0, 2, 1],
                    80
                )
                .is_empty()
            );
        }
        assert_eq!(detector.syn_flood.records, MAX_RECORDS_PER_KEY);
        assert_eq!(detector.port_scan.records, 2);
        assert_eq!(
            detector
                .syn_flood
                .events
                .values()
                .next()
                .unwrap()
                .counts
                .len(),
            1
        );
        detector.advance_time(200.0);
        assert_eq!(detector.syn_flood.records, 0);
        assert_eq!(detector.port_scan.records, 0);
    }

    #[test]
    fn detectors_bound_total_records_and_key_admission() {
        let mut detector = AnomalyDetector::new(high_threshold_config());
        for source in 0..256u32 {
            for port in 0..300u16 {
                let source = Ipv4Addr::from(0x0a00_0001 + source).octets();
                let _ = observe_syn(&mut detector, 100.0, source, [192, 0, 2, 1], port);
            }
        }
        assert_eq!(detector.syn_flood.records, MAX_RECORDS);
        assert!(detector.port_scan.records <= MAX_RECORDS);
        assert_eq!(
            detector.syn_flood.records,
            detector
                .syn_flood
                .events
                .values()
                .map(|window| window.records.len())
                .sum::<usize>()
        );
        assert_eq!(
            detector.port_scan.records,
            detector
                .port_scan
                .events
                .values()
                .map(ScanWindow::len)
                .sum::<usize>()
        );
        detector.advance_time(200.0);
        for index in 0..MAX_KEYS + 100 {
            let source = Ipv4Addr::from(0x0a00_0001 + index as u32).octets();
            let _ = observe_syn(&mut detector, 200.0, source, [192, 0, 2, 1], index as u16);
        }
        assert_eq!(detector.syn_flood.events.len(), MAX_KEYS);
        assert_eq!(detector.port_scan.events.len(), MAX_KEYS);
    }

    #[test]
    fn duplicate_scan_targets_keep_latest_time_when_events_arrive_out_of_order() {
        let mut detector = AnomalyDetector::new(high_threshold_config());
        let _ = observe_syn(&mut detector, 10.0, [10, 0, 0, 1], [192, 0, 2, 1], 80);
        let _ = observe_syn(&mut detector, 14.0, [10, 0, 0, 1], [192, 0, 2, 1], 80);
        let _ = observe_syn(&mut detector, 12.0, [10, 0, 0, 1], [192, 0, 2, 1], 80);
        let window = detector.port_scan.events.values().next().unwrap();
        assert_eq!(window.ports.records.first().unwrap().0.0, 14.0);
        assert_eq!(window.len(), 2);
        let _ = observe_syn(&mut detector, 19.0, [10, 0, 0, 1], [192, 0, 2, 1], 81);
        let window = detector.port_scan.events.values().next().unwrap();
        assert_eq!(window.ports.latest.len(), 2);
        let _ = observe_syn(&mut detector, 19.1, [10, 0, 0, 1], [192, 0, 2, 1], 81);
        assert_eq!(
            detector
                .port_scan
                .events
                .values()
                .next()
                .unwrap()
                .ports
                .latest
                .len(),
            1
        );
    }

    #[test]
    fn expired_one_time_keys_are_removed_after_a_timestamp_sweep() {
        let mut cfg = config();
        cfg.syn_flood.syn_threshold = 1;
        cfg.syn_flood.unique_src_threshold = 1;
        cfg.port_scan.unique_ports_threshold = 1;
        cfg.port_scan.unique_hosts_threshold = 1;
        let mut detector = AnomalyDetector::new(cfg);

        for index in 0..1024u32 {
            let source = Ipv4Addr::from(0x0a00_0001 + index).octets();
            let port = (index + 1) as u16;
            // Each fresh key crosses its threshold and creates a cooldown.
            let _ = observe_syn(&mut detector, 100.0, source, [203, 0, 113, 1], port);
        }
        assert_eq!(detector.syn_flood.events.len(), 1024);
        assert_eq!(detector.port_scan.events.len(), 1024);
        assert_eq!(detector.syn_flood.cooldowns.len(), 1024);
        assert_eq!(detector.port_scan.cooldowns.len(), 1024);

        let alerts = observe_syn(&mut detector, 131.0, [10, 9, 0, 1], [203, 0, 113, 1], 65000);
        assert_eq!(alerts.len(), 2);

        assert_eq!(detector.syn_flood.events.len(), 1);
        assert_eq!(detector.port_scan.events.len(), 1);
        assert_eq!(detector.syn_flood.cooldowns.len(), 1);
        assert_eq!(detector.port_scan.cooldowns.len(), 1);
        assert!(detector.syn_flood.events.capacity() <= 8);
        assert!(detector.port_scan.events.capacity() <= 8);
        assert!(detector.syn_flood.cooldowns.capacity() <= 8);
        assert!(detector.port_scan.cooldowns.capacity() <= 8);
    }

    #[test]
    fn out_of_order_records_older_than_the_window_do_not_restore_detector_state() {
        let mut detector = AnomalyDetector::new(config());
        assert!(observe_syn(&mut detector, 10.0, [10, 0, 0, 1], [203, 0, 113, 1], 443).is_empty());
        assert!(observe_syn(&mut detector, 20.0, [10, 0, 0, 2], [203, 0, 113, 2], 444).is_empty());

        let stale = observe_syn(&mut detector, 10.0, [10, 0, 0, 2], [203, 0, 113, 1], 443);
        assert!(stale.is_empty());
        assert!(!detector.syn_flood.events.contains_key(&SynFloodKey {
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            dst_port: 443,
        }));
        let active_scan_events = detector
            .port_scan
            .events
            .get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .expect("the source's newer in-window event should remain");
        assert_eq!(active_scan_events.ports.latest.len(), 1);
        assert_eq!(active_scan_events.ports.records.first().unwrap().0.0, 20.0);
    }

    #[test]
    fn thresholds_include_the_window_boundary_and_cooldowns_rearm() {
        let mut cfg = config();
        cfg.syn_flood.window_secs = 2.0;
        cfg.port_scan.window_secs = 2.0;
        let mut detector = AnomalyDetector::new(cfg);

        assert!(observe_syn(&mut detector, 10.0, [10, 0, 0, 1], [203, 0, 113, 1], 443).is_empty());
        let boundary_alerts =
            observe_syn(&mut detector, 12.0, [10, 0, 0, 2], [203, 0, 113, 1], 443);
        assert_eq!(boundary_alerts.len(), 1);
        assert_eq!(boundary_alerts[0].kind.as_str(), "syn_flood");
        assert_eq!(boundary_alerts[0].window_secs, 2.0);
        assert_eq!(boundary_alerts[0].thresholds.syn_count, Some(2));
        assert_eq!(boundary_alerts[0].observed.unique_sources, Some(2));

        assert!(observe_syn(&mut detector, 14.0, [10, 0, 0, 3], [203, 0, 113, 1], 443).is_empty());
        assert!(observe_syn(&mut detector, 15.0, [10, 0, 0, 4], [203, 0, 113, 1], 443).is_empty());
        let rearmed = observe_syn(&mut detector, 15.1, [10, 0, 0, 5], [203, 0, 113, 1], 443);
        assert_eq!(rearmed.len(), 1);
        assert_eq!(rearmed[0].kind.as_str(), "syn_flood");

        let serialized = serde_json::to_value(&rearmed[0]).expect("alert schema serializes");
        assert_eq!(serialized["schema_version"], ALERT_SCHEMA_VERSION);
        assert_eq!(serialized["kind"], "syn_flood");
        assert_eq!(serialized["source_ip"], serde_json::Value::Null);
        assert_eq!(serialized["target_ip"], "203.0.113.1");
        assert_eq!(serialized["target_port"], 443);
        assert_eq!(serialized["thresholds"]["syn_count"], 2);
        assert_eq!(serialized["observed"]["unique_sources"], 2);
        assert!(serialized["description"].is_string());

        let mut scan_cfg = config();
        scan_cfg.syn_flood.enabled = false;
        scan_cfg.port_scan.window_secs = 2.0;
        let mut scan_detector = AnomalyDetector::new(scan_cfg);
        assert!(
            observe_syn(&mut scan_detector, 10.0, [10, 1, 0, 1], [192, 0, 2, 1], 80).is_empty()
        );
        let scan_boundary =
            observe_syn(&mut scan_detector, 12.0, [10, 1, 0, 1], [192, 0, 2, 1], 81);
        assert_eq!(scan_boundary.len(), 1);
        assert_eq!(scan_boundary[0].kind.as_str(), "port_scan");
        assert_eq!(scan_boundary[0].thresholds.unique_ports, Some(2));
        assert_eq!(scan_boundary[0].observed.unique_ports, Some(2));
        assert!(
            observe_syn(&mut scan_detector, 14.0, [10, 1, 0, 1], [192, 0, 2, 1], 82).is_empty()
        );
        assert!(
            observe_syn(&mut scan_detector, 15.0, [10, 1, 0, 1], [192, 0, 2, 1], 83).is_empty()
        );
        let scan_rearmed = observe_syn(&mut scan_detector, 15.1, [10, 1, 0, 1], [192, 0, 2, 1], 84);
        assert_eq!(scan_rearmed.len(), 1);
        assert_eq!(scan_rearmed[0].kind.as_str(), "port_scan");
    }
}
