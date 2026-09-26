use crate::config::{AnomalyConfig, PortScanConfig, SynFloodConfig};
use crate::flow::{Endpoint, FlowProtocol};
use crate::sinks::AlertJsonlSink;
use ahash::{AHashMap, AHashSet};
use serde::Serialize;
use std::collections::VecDeque;
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
        if !self.config.enabled {
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
        if !self.config.enabled {
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

#[derive(Debug, Clone)]
struct SynFloodState {
    config: SynFloodConfig,
    events: AHashMap<SynFloodKey, VecDeque<(f64, IpAddr)>>,
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
        if watermark - ts > window {
            let remove_key = if let Some(events) = self.events.get_mut(&key) {
                events.retain(|(event_ts, _)| watermark - *event_ts <= window);
                if events.len() < events.capacity() / 2 {
                    events.shrink_to_fit();
                }
                events.is_empty()
            } else {
                false
            };
            if remove_key {
                self.events.remove(&key);
            }
            return None;
        }

        let events = self.events.entry(key).or_default();
        events.retain(|(event_ts, _)| watermark - *event_ts <= window);
        if events.len() < events.capacity() / 2 {
            events.shrink_to_fit();
        }
        events.push_back((ts, src_ip));

        let mut unique = AHashSet::new();
        for (_, ip) in events.iter() {
            unique.insert(*ip);
        }

        if events.len() as u32 >= self.config.syn_threshold
            && unique.len() as u32 >= self.config.unique_src_threshold
        {
            let desc = format!(
                "SYN flood suspected: {} syns, {} sources to {}:{}",
                events.len(),
                unique.len(),
                dst_ip,
                dst_port
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
                    syn_count: Some(events.len() as u64),
                    unique_sources: Some(unique.len() as u64),
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
        let window = configured_window(self.config.window_secs);
        self.events.retain(|_, events| {
            events.retain(|(event_ts, _)| now - *event_ts <= window);
            if events.len() < events.capacity() / 2 {
                events.shrink_to_fit();
            }
            !events.is_empty()
        });
        self.cooldowns.retain(|_, until| *until > now);
        if self.events.len() < self.events.capacity() / 2 {
            self.events.shrink_to_fit();
        }
        if self.cooldowns.len() < self.cooldowns.capacity() / 2 {
            self.cooldowns.shrink_to_fit();
        }
    }
}

#[derive(Debug, Clone)]
struct PortScanState {
    config: PortScanConfig,
    events: AHashMap<IpAddr, VecDeque<PortScanEvent>>,
    cooldowns: AHashMap<IpAddr, f64>,
}

#[derive(Debug, Clone, Copy)]
struct PortScanEvent {
    ts: f64,
    dst_ip: IpAddr,
    dst_port: u16,
}

impl PortScanState {
    fn new(config: PortScanConfig) -> Self {
        PortScanState {
            config,
            events: AHashMap::new(),
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
        if watermark - ts > window {
            let remove_key = if let Some(events) = self.events.get_mut(&src_ip) {
                events.retain(|event| watermark - event.ts <= window);
                if events.len() < events.capacity() / 2 {
                    events.shrink_to_fit();
                }
                events.is_empty()
            } else {
                false
            };
            if remove_key {
                self.events.remove(&src_ip);
            }
            return None;
        }

        let events = self.events.entry(src_ip).or_default();
        events.retain(|event| watermark - event.ts <= window);
        if events.len() < events.capacity() / 2 {
            events.shrink_to_fit();
        }
        events.push_back(PortScanEvent {
            ts,
            dst_ip,
            dst_port,
        });

        let mut unique_ports = AHashSet::new();
        let mut unique_hosts = AHashSet::new();
        for evt in events.iter() {
            unique_ports.insert(evt.dst_port);
            unique_hosts.insert(evt.dst_ip);
        }

        if unique_ports.len() as u32 >= self.config.unique_ports_threshold
            || unique_hosts.len() as u32 >= self.config.unique_hosts_threshold
        {
            let desc = format!(
                "Port scan suspected: {} ports, {} hosts from {}",
                unique_ports.len(),
                unique_hosts.len(),
                src_ip
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
                    unique_ports: Some(unique_ports.len() as u64),
                    unique_hosts: Some(unique_hosts.len() as u64),
                },
                description: desc,
            });
        }

        None
    }

    /// Remove events outside their configured window and expired cooldowns.
    fn cleanup(&mut self, now: f64) {
        let window = configured_window(self.config.window_secs);
        self.events.retain(|_, events| {
            events.retain(|event| now - event.ts <= window);
            if events.len() < events.capacity() / 2 {
                events.shrink_to_fit();
            }
            !events.is_empty()
        });
        self.cooldowns.retain(|_, until| *until > now);
        if self.events.len() < self.events.capacity() / 2 {
            self.events.shrink_to_fit();
        }
        if self.cooldowns.len() < self.cooldowns.capacity() / 2 {
            self.cooldowns.shrink_to_fit();
        }
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
        assert_eq!(active_scan_events.len(), 1);
        assert_eq!(active_scan_events[0].ts, 20.0);
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
