use ahash::{AHashMap, AHashSet};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::net::IpAddr;

use crate::protocol::{NetworkHeader, ParsedPacket, TransportHeader};

use super::{
    CompactFlowKey, Endpoint, ExpiredFlowEvent, ExpiredFlowReason, FlowDelta, FlowEntry, FlowKey,
    FlowKeyV4, FlowKeyV6, FlowProtocol, FlowSnapshot, ScaleFlowEntry, TcpFlags, tcp_sequence_len,
};

#[derive(Debug)]
enum FlowStore {
    Full(AHashMap<FlowKey, FlowEntry>),
    Scale {
        flows_v4: AHashMap<FlowKeyV4, ScaleFlowEntry>,
        flows_v6: AHashMap<FlowKeyV6, ScaleFlowEntry>,
    },
}

#[derive(Debug, Clone, Copy)]
enum ParsedFlowIps {
    V4(std::net::Ipv4Addr, std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr, std::net::Ipv6Addr),
}

#[derive(Debug)]
pub struct FlowTracker {
    store: FlowStore,
    timeout_secs: f64,
    max_flows: usize,
    last_prune: f64,
    eviction_clock: VecDeque<CompactFlowKey>,
    referenced: AHashSet<CompactFlowKey>,
    track_rtt: bool,
    track_retrans: bool,
    track_out_of_order: bool,
    stats: FlowTrackerStats,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowTrackerStats {
    pub created: u64,
    pub expired: u64,
    pub evicted: u64,
}

impl FlowTracker {
    pub fn new(
        timeout_secs: f64,
        max_flows: usize,
        track_rtt: bool,
        track_retrans: bool,
        track_out_of_order: bool,
    ) -> Self {
        // Pre-size the map to avoid rehash churn on the hot path.
        // Add 25% headroom so inserts near `max_flows` don't trigger a resize.
        let initial_capacity = if max_flows > 0 {
            max_flows + max_flows / 4
        } else {
            0
        };
        let scale_mode = !track_rtt && !track_retrans && !track_out_of_order;
        let store = if scale_mode {
            FlowStore::Scale {
                flows_v4: AHashMap::with_capacity(initial_capacity),
                flows_v6: AHashMap::with_capacity(initial_capacity / 8),
            }
        } else {
            FlowStore::Full(AHashMap::with_capacity(initial_capacity))
        };

        FlowTracker {
            store,
            timeout_secs,
            max_flows,
            last_prune: 0.0,
            eviction_clock: VecDeque::new(),
            referenced: AHashSet::new(),
            track_rtt,
            track_retrans,
            track_out_of_order,
            stats: FlowTrackerStats::default(),
        }
    }

    pub fn stats(&self) -> FlowTrackerStats {
        self.stats
    }

    pub fn len(&self) -> usize {
        match &self.store {
            FlowStore::Full(flows) => flows.len(),
            FlowStore::Scale {
                flows_v4, flows_v6, ..
            } => flows_v4.len() + flows_v6.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_scale_mode(&self) -> bool {
        matches!(self.store, FlowStore::Scale { .. })
    }

    /// Insert synthetic IPv4 flows directly into the table for focused tests.
    #[cfg(test)]
    pub fn insert_synthetic_ipv4_flows(&mut self, count: usize) {
        #[inline]
        fn ip_from_index(prefix_a: u8, prefix_b: u8, idx: u32) -> std::net::Ipv4Addr {
            std::net::Ipv4Addr::new(
                prefix_a,
                prefix_b,
                ((idx >> 8) & 0xFF) as u8,
                (idx & 0xFF) as u8,
            )
        }

        let previous_len = self.len();
        match &mut self.store {
            FlowStore::Scale { flows_v4, .. } => {
                for i in 0..count as u32 {
                    let src_ip = ip_from_index(10, ((i >> 16) & 0xFF) as u8, i);
                    let dst_ip = ip_from_index(172, 16, i);
                    let src_port = 1024 + (i % 48_000) as u16;
                    let dst_port = 80;
                    let (key, _dir) =
                        FlowKeyV4::new(FlowProtocol::Tcp, src_ip, src_port, dst_ip, dst_port);

                    flows_v4
                        .entry(key)
                        .or_insert_with(|| ScaleFlowEntry::new(0.0, FlowProtocol::Tcp));
                }
            }
            FlowStore::Full(flows) => {
                for i in 0..count as u32 {
                    let src = Endpoint {
                        ip: IpAddr::V4(ip_from_index(10, ((i >> 16) & 0xFF) as u8, i)),
                        port: 1024 + (i % 48_000) as u16,
                    };
                    let dst = Endpoint {
                        ip: IpAddr::V4(ip_from_index(172, 16, i)),
                        port: 80,
                    };
                    let (key, _dir) = FlowKey::new(FlowProtocol::Tcp, src, dst);
                    flows
                        .entry(key)
                        .or_insert_with(|| FlowEntry::new(0.0, FlowProtocol::Tcp));
                }
            }
        }

        self.stats.created = self
            .stats
            .created
            .saturating_add(self.len().saturating_sub(previous_len) as u64);
    }

    #[inline]
    pub fn observe(&mut self, ts: f64, wire_len: u64, packet: &ParsedPacket<'_>) {
        self.observe_inner(ts, wire_len, packet, None);
    }

    /// Observe a packet and collect capacity evictions immediately.
    pub fn observe_collect(
        &mut self,
        ts: f64,
        wire_len: u64,
        packet: &ParsedPacket<'_>,
        out: &mut Vec<ExpiredFlowEvent>,
    ) {
        self.observe_inner(ts, wire_len, packet, Some(out));
    }

    fn observe_inner(
        &mut self,
        ts: f64,
        wire_len: u64,
        packet: &ParsedPacket<'_>,
        mut out: Option<&mut Vec<ExpiredFlowEvent>>,
    ) {
        let (ips, skip_flow) = match &packet.network {
            Some(NetworkHeader::Ipv4(hdr)) => {
                let skip = hdr.fragment_offset() != 0;
                (ParsedFlowIps::V4(hdr.src_addr(), hdr.dst_addr()), skip)
            }
            Some(NetworkHeader::Ipv6(hdr)) => (
                ParsedFlowIps::V6(hdr.src_addr(), hdr.dst_addr()),
                hdr.is_non_initial_fragment(),
            ),
            Some(NetworkHeader::Arp(_)) => return,
            None => return,
        };

        if skip_flow {
            return;
        }

        let (src_port, dst_port, protocol, flags, seq, ack, seq_len) = match &packet.transport {
            Some(TransportHeader::Tcp(hdr)) => (
                hdr.src_port(),
                hdr.dst_port(),
                FlowProtocol::Tcp,
                Some(TcpFlags::from_tcp(hdr)),
                Some(hdr.sequence_number()),
                if hdr.ack() {
                    Some(hdr.ack_number())
                } else {
                    None
                },
                Some(tcp_sequence_len(hdr, packet.network.as_ref())),
            ),
            Some(TransportHeader::Udp(hdr)) => (
                hdr.src_port(),
                hdr.dst_port(),
                FlowProtocol::Udp,
                None,
                None,
                None,
                None,
            ),
            _ => return,
        };

        let compact_key = match ips {
            ParsedFlowIps::V4(src, dst) => {
                CompactFlowKey::V4(FlowKeyV4::new(protocol, src, src_port, dst, dst_port).0)
            }
            ParsedFlowIps::V6(src, dst) => {
                CompactFlowKey::V6(FlowKeyV6::new(protocol, src, src_port, dst, dst_port).0)
            }
        };
        let is_new = !self.contains_compact_key(compact_key);
        if self.max_flows > 0 {
            if is_new {
                while self.len() >= self.max_flows {
                    self.evict_one(ts, out.as_deref_mut());
                }
                self.eviction_clock.push_back(compact_key);
            }
            self.referenced.insert(compact_key);
        }
        match &mut self.store {
            FlowStore::Full(flows) => {
                let (src_ip, dst_ip) = match ips {
                    ParsedFlowIps::V4(src, dst) => (IpAddr::V4(src), IpAddr::V4(dst)),
                    ParsedFlowIps::V6(src, dst) => (IpAddr::V6(src), IpAddr::V6(dst)),
                };

                let src = Endpoint {
                    ip: src_ip,
                    port: src_port,
                };
                let dst = Endpoint {
                    ip: dst_ip,
                    port: dst_port,
                };

                let (key, direction) = FlowKey::new(protocol, src, dst);
                let entry = flows
                    .entry(key)
                    .or_insert_with(|| FlowEntry::new(ts, protocol));
                entry.observe(ts, direction, wire_len, flags);
                if protocol == FlowProtocol::Tcp
                    && let (Some(seq), Some(seq_len)) = (seq, seq_len)
                    && (self.track_rtt || self.track_retrans || self.track_out_of_order)
                {
                    entry.observe_tcp(
                        ts,
                        direction,
                        seq,
                        ack,
                        seq_len,
                        self.track_rtt,
                        self.track_retrans,
                        self.track_out_of_order,
                    );
                }
            }
            FlowStore::Scale { flows_v4, flows_v6 } => match ips {
                ParsedFlowIps::V4(src_ip, dst_ip) => {
                    let (key, direction) =
                        FlowKeyV4::new(protocol, src_ip, src_port, dst_ip, dst_port);
                    let entry = flows_v4
                        .entry(key)
                        .or_insert_with(|| ScaleFlowEntry::new(ts, protocol));
                    entry.observe(ts, direction, wire_len, flags);
                }
                ParsedFlowIps::V6(src_ip, dst_ip) => {
                    let (key, direction) =
                        FlowKeyV6::new(protocol, src_ip, src_port, dst_ip, dst_port);
                    let entry = flows_v6
                        .entry(key)
                        .or_insert_with(|| ScaleFlowEntry::new(ts, protocol));
                    entry.observe(ts, direction, wire_len, flags);
                }
            },
        }

        if is_new {
            self.stats.created = self.stats.created.saturating_add(1);
        }
    }

    fn contains_compact_key(&self, key: CompactFlowKey) -> bool {
        match (&self.store, key) {
            (FlowStore::Full(flows), key) => flows.contains_key(&key.to_flow_key()),
            (FlowStore::Scale { flows_v4, .. }, CompactFlowKey::V4(key)) => {
                flows_v4.contains_key(&key)
            }
            (FlowStore::Scale { flows_v6, .. }, CompactFlowKey::V6(key)) => {
                flows_v6.contains_key(&key)
            }
        }
    }

    // A bounded second-chance clock keeps recently used flows without sorting
    // the entire table for every insert. Each reference buys one extra pass.
    fn evict_one(&mut self, ts: f64, out: Option<&mut Vec<ExpiredFlowEvent>>) {
        loop {
            let key = self
                .eviction_clock
                .pop_front()
                .expect("nonempty bounded flow clock");
            if self.referenced.remove(&key) {
                self.eviction_clock.push_back(key);
                continue;
            }
            let flow_key = key.to_flow_key();
            let snapshot = match (&mut self.store, key) {
                (FlowStore::Full(flows), _) => flows
                    .remove(&flow_key)
                    .map(|entry| FlowSnapshot::from_entry(&flow_key, &entry)),
                (FlowStore::Scale { flows_v4, .. }, CompactFlowKey::V4(key)) => flows_v4
                    .remove(&key)
                    .map(|entry| FlowSnapshot::from_scale_entry(&flow_key, &entry)),
                (FlowStore::Scale { flows_v6, .. }, CompactFlowKey::V6(key)) => flows_v6
                    .remove(&key)
                    .map(|entry| FlowSnapshot::from_scale_entry(&flow_key, &entry)),
            };
            if let Some(flow) = snapshot {
                self.stats.evicted = self.stats.evicted.saturating_add(1);
                if let Some(out) = out {
                    out.push(ExpiredFlowEvent {
                        ts,
                        reason: ExpiredFlowReason::Eviction,
                        flow,
                    });
                }
                return;
            }
        }
    }

    pub fn maybe_expire(&mut self, now: f64) -> usize {
        self.maybe_expire_inner(now, None)
    }

    pub fn maybe_expire_collect(&mut self, now: f64, out: &mut Vec<ExpiredFlowEvent>) -> usize {
        self.maybe_expire_inner(now, Some(out))
    }

    fn maybe_expire_inner(
        &mut self,
        now: f64,
        mut out: Option<&mut Vec<ExpiredFlowEvent>>,
    ) -> usize {
        if now < self.last_prune {
            self.last_prune = now;
            return 0;
        }
        if now - self.last_prune < 1.0 {
            return 0;
        }
        self.last_prune = now;

        let (stats_expired, stats_evicted) = (&mut self.stats.expired, &mut self.stats.evicted);
        let mut record_expired = |reason: ExpiredFlowReason, flow: FlowSnapshot| {
            match reason {
                ExpiredFlowReason::Timeout => {
                    *stats_expired = stats_expired.saturating_add(1);
                }
                ExpiredFlowReason::Eviction => {
                    *stats_evicted = stats_evicted.saturating_add(1);
                }
            }
            if let Some(buf) = out.as_mut() {
                (**buf).push(ExpiredFlowEvent {
                    ts: now,
                    reason,
                    flow,
                });
            }
        };

        let mut removed = 0;
        match &mut self.store {
            FlowStore::Full(flows) => {
                if self.timeout_secs > 0.0 {
                    let timeout_keys: Vec<FlowKey> = flows
                        .iter()
                        .filter_map(|(key, entry)| {
                            if now - entry.last_seen > self.timeout_secs {
                                Some(key.clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for key in timeout_keys {
                        if let Some(entry) = flows.remove(&key) {
                            removed += 1;
                            record_expired(
                                ExpiredFlowReason::Timeout,
                                FlowSnapshot::from_entry(&key, &entry),
                            );
                        }
                    }
                }

                if self.max_flows > 0 && flows.len() > self.max_flows {
                    let mut entries: Vec<(FlowKey, f64)> = flows
                        .iter()
                        .map(|(key, entry)| (key.clone(), entry.last_seen))
                        .collect();
                    entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
                    let excess = flows.len() - self.max_flows;
                    for (key, _) in entries.into_iter().take(excess) {
                        if let Some(entry) = flows.remove(&key) {
                            removed += 1;
                            record_expired(
                                ExpiredFlowReason::Eviction,
                                FlowSnapshot::from_entry(&key, &entry),
                            );
                        }
                    }
                }
            }
            FlowStore::Scale { flows_v4, flows_v6 } => {
                if self.timeout_secs > 0.0 {
                    let mut timeout_keys: Vec<CompactFlowKey> =
                        Vec::with_capacity(flows_v4.len() + flows_v6.len());
                    timeout_keys.extend(flows_v4.iter().filter_map(|(key, entry)| {
                        if now - entry.last_seen() > self.timeout_secs {
                            Some(CompactFlowKey::V4(*key))
                        } else {
                            None
                        }
                    }));
                    timeout_keys.extend(flows_v6.iter().filter_map(|(key, entry)| {
                        if now - entry.last_seen() > self.timeout_secs {
                            Some(CompactFlowKey::V6(*key))
                        } else {
                            None
                        }
                    }));

                    for key in timeout_keys {
                        match key {
                            CompactFlowKey::V4(v4) => {
                                if let Some(entry) = flows_v4.remove(&v4) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V4(v4).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Timeout,
                                        FlowSnapshot::from_scale_entry(&flow_key, &entry),
                                    );
                                }
                            }
                            CompactFlowKey::V6(v6) => {
                                if let Some(entry) = flows_v6.remove(&v6) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V6(v6).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Timeout,
                                        FlowSnapshot::from_scale_entry(&flow_key, &entry),
                                    );
                                }
                            }
                        }
                    }
                }

                let total_len = flows_v4.len() + flows_v6.len();
                if self.max_flows > 0 && total_len > self.max_flows {
                    let mut entries: Vec<(CompactFlowKey, f64)> = Vec::with_capacity(total_len);
                    entries.extend(
                        flows_v4
                            .iter()
                            .map(|(key, entry)| (CompactFlowKey::V4(*key), entry.last_seen())),
                    );
                    entries.extend(
                        flows_v6
                            .iter()
                            .map(|(key, entry)| (CompactFlowKey::V6(*key), entry.last_seen())),
                    );
                    entries.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
                    let excess = total_len - self.max_flows;
                    for (key, _) in entries.into_iter().take(excess) {
                        match key {
                            CompactFlowKey::V4(v4) => {
                                if let Some(entry) = flows_v4.remove(&v4) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V4(v4).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Eviction,
                                        FlowSnapshot::from_scale_entry(&flow_key, &entry),
                                    );
                                }
                            }
                            CompactFlowKey::V6(v6) => {
                                if let Some(entry) = flows_v6.remove(&v6) {
                                    removed += 1;
                                    let flow_key = CompactFlowKey::V6(v6).to_flow_key();
                                    record_expired(
                                        ExpiredFlowReason::Eviction,
                                        FlowSnapshot::from_scale_entry(&flow_key, &entry),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        if removed > 0 {
            let mut clock = std::mem::take(&mut self.eviction_clock);
            clock.retain(|key| self.contains_compact_key(*key));
            let active: AHashSet<_> = clock.iter().copied().collect();
            self.referenced.retain(|key| active.contains(key));
            self.eviction_clock = clock;
        }
        removed
    }

    pub fn top_flows_by_delta(&mut self, n: usize) -> Vec<FlowDelta> {
        if n == 0 {
            return Vec::new();
        }
        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut deltas: Vec<FlowDelta> = flows
                    .iter()
                    .filter_map(|(key, entry)| {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_stats);
                        if delta > 0 {
                            Some(FlowDelta {
                                key: key.clone(),
                                delta_bytes: delta,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| {
                        b.delta_bytes.cmp(&a.delta_bytes)
                    });
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));

                for d in &deltas {
                    if let Some(entry) = flows.get_mut(&d.key) {
                        entry.last_report_bytes_stats = entry.total_bytes();
                    }
                }
                deltas
            }
            FlowStore::Scale {
                flows_v4, flows_v6, ..
            } => {
                let mut deltas: Vec<(CompactFlowKey, u64)> = Vec::new();
                deltas.extend(flows_v4.iter().filter_map(|(key, entry)| {
                    let delta = entry.stats_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V4(*key), delta))
                    } else {
                        None
                    }
                }));
                deltas.extend(flows_v6.iter().filter_map(|(key, entry)| {
                    let delta = entry.stats_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V6(*key), delta))
                    } else {
                        None
                    }
                }));

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| b.1.cmp(&a.1));
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.1.cmp(&a.1));

                for (key, _) in &deltas {
                    match key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                entry.mark_stats_reported();
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                entry.mark_stats_reported();
                            }
                        }
                    }
                }

                deltas
                    .into_iter()
                    .map(|(key, delta_bytes)| FlowDelta {
                        key: key.to_flow_key(),
                        delta_bytes,
                    })
                    .collect()
            }
        }
    }

    /// Return top-N flows by delta bytes, paired with their full snapshot.
    ///
    /// This resets the delta counters for the returned flows (same as
    /// `top_flows_by_delta`) but also produces the `FlowSnapshot` the web
    /// dashboard needs.
    pub fn top_flows_with_snapshot(&mut self, n: usize) -> Vec<(FlowDelta, FlowSnapshot)> {
        if n == 0 {
            return Vec::new();
        }
        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut deltas: Vec<FlowDelta> = flows
                    .iter()
                    .filter_map(|(key, entry)| {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_web);
                        if delta > 0 {
                            Some(FlowDelta {
                                key: key.clone(),
                                delta_bytes: delta,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| {
                        b.delta_bytes.cmp(&a.delta_bytes)
                    });
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.delta_bytes.cmp(&a.delta_bytes));

                let mut result = Vec::with_capacity(deltas.len());
                for d in deltas {
                    if let Some(entry) = flows.get_mut(&d.key) {
                        entry.last_report_bytes_web = entry.total_bytes();
                        let snap = FlowSnapshot::from_entry(&d.key, entry);
                        result.push((d, snap));
                    }
                }
                result
            }
            FlowStore::Scale { flows_v4, flows_v6 } => {
                let mut deltas: Vec<(CompactFlowKey, u64)> = Vec::new();
                deltas.extend(flows_v4.iter().filter_map(|(key, entry)| {
                    let delta = entry.web_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V4(*key), delta))
                    } else {
                        None
                    }
                }));
                deltas.extend(flows_v6.iter().filter_map(|(key, entry)| {
                    let delta = entry.web_delta();
                    if delta > 0 {
                        Some((CompactFlowKey::V6(*key), delta))
                    } else {
                        None
                    }
                }));

                let top_n = n.min(deltas.len());
                if top_n > 0 && top_n < deltas.len() {
                    deltas.select_nth_unstable_by(top_n - 1, |a, b| b.1.cmp(&a.1));
                    deltas.truncate(top_n);
                }
                deltas.sort_unstable_by(|a, b| b.1.cmp(&a.1));

                let mut result = Vec::with_capacity(deltas.len());
                for (compact_key, delta_bytes) in deltas {
                    match compact_key {
                        CompactFlowKey::V4(key) => {
                            if let Some(entry) = flows_v4.get_mut(&key) {
                                entry.mark_web_reported();
                                let flow_key = CompactFlowKey::V4(key).to_flow_key();
                                let snap = FlowSnapshot::from_scale_entry(&flow_key, entry);
                                result.push((
                                    FlowDelta {
                                        key: flow_key,
                                        delta_bytes,
                                    },
                                    snap,
                                ));
                            }
                        }
                        CompactFlowKey::V6(key) => {
                            if let Some(entry) = flows_v6.get_mut(&key) {
                                entry.mark_web_reported();
                                let flow_key = CompactFlowKey::V6(key).to_flow_key();
                                let snap = FlowSnapshot::from_scale_entry(&flow_key, entry);
                                result.push((
                                    FlowDelta {
                                        key: flow_key,
                                        delta_bytes,
                                    },
                                    snap,
                                ));
                            }
                        }
                    }
                }
                result
            }
        }
    }

    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        let mut flows: Vec<FlowSnapshot> = match &self.store {
            FlowStore::Full(table) => table
                .iter()
                .map(|(key, entry)| FlowSnapshot::from_entry(key, entry))
                .collect(),
            FlowStore::Scale {
                flows_v4, flows_v6, ..
            } => {
                let mut out = Vec::with_capacity(flows_v4.len() + flows_v6.len());
                out.extend(flows_v4.iter().map(|(key, entry)| {
                    let flow_key = CompactFlowKey::V4(*key).to_flow_key();
                    FlowSnapshot::from_scale_entry(&flow_key, entry)
                }));
                out.extend(flows_v6.iter().map(|(key, entry)| {
                    let flow_key = CompactFlowKey::V6(*key).to_flow_key();
                    FlowSnapshot::from_scale_entry(&flow_key, entry)
                }));
                out
            }
        };
        flows.sort_by(|a, b| b.bytes_total.cmp(&a.bytes_total));
        flows
    }

    /// Build exact web deltas + snapshots for a specific set of candidate keys.
    ///
    /// This keeps the web-path cost proportional to the candidate set size
    /// rather than the full flow table, while preserving exact displayed rates.
    pub fn top_flows_with_snapshot_for_keys(
        &mut self,
        keys: &[FlowKey],
        n: usize,
    ) -> Vec<(FlowDelta, FlowSnapshot)> {
        let compact_keys: Vec<CompactFlowKey> = keys
            .iter()
            .filter_map(CompactFlowKey::from_flow_key)
            .collect();
        self.top_flows_with_snapshot_for_compact_keys(&compact_keys, n)
    }

    pub(crate) fn top_flows_with_snapshot_for_compact_keys(
        &mut self,
        keys: &[CompactFlowKey],
        n: usize,
    ) -> Vec<(FlowDelta, FlowSnapshot)> {
        if n == 0 {
            return Vec::new();
        }

        match &mut self.store {
            FlowStore::Full(flows) => {
                let mut seen = AHashSet::with_capacity(keys.len());
                let mut out = Vec::with_capacity(keys.len());
                for compact_key in keys {
                    if !seen.insert(*compact_key) {
                        continue;
                    }
                    let key = compact_key.to_flow_key();
                    if let Some(entry) = flows.get_mut(&key) {
                        let total = entry.total_bytes();
                        let delta = total.saturating_sub(entry.last_report_bytes_web);
                        if delta > 0 {
                            out.push((
                                FlowDelta {
                                    key: key.clone(),
                                    delta_bytes: delta,
                                },
                                FlowSnapshot::from_entry(&key, entry),
                            ));
                        }
                    }
                }

                out.sort_unstable_by(|a, b| b.0.delta_bytes.cmp(&a.0.delta_bytes));
                out.truncate(n.min(out.len()));

                for (delta, _) in &out {
                    if let Some(entry) = flows.get_mut(&delta.key) {
                        entry.last_report_bytes_web = entry.total_bytes();
                    }
                }

                out
            }
            FlowStore::Scale { flows_v4, flows_v6 } => {
                let mut seen = AHashSet::with_capacity(keys.len());
                let mut out: Vec<(CompactFlowKey, u64, FlowSnapshot)> =
                    Vec::with_capacity(keys.len());

                for compact_key in keys {
                    if !seen.insert(*compact_key) {
                        continue;
                    }

                    match compact_key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                let delta = entry.web_delta();
                                if delta > 0 {
                                    let flow_key = CompactFlowKey::V4(*k).to_flow_key();
                                    out.push((
                                        CompactFlowKey::V4(*k),
                                        delta,
                                        FlowSnapshot::from_scale_entry(&flow_key, entry),
                                    ));
                                }
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                let delta = entry.web_delta();
                                if delta > 0 {
                                    let flow_key = CompactFlowKey::V6(*k).to_flow_key();
                                    out.push((
                                        CompactFlowKey::V6(*k),
                                        delta,
                                        FlowSnapshot::from_scale_entry(&flow_key, entry),
                                    ));
                                }
                            }
                        }
                    }
                }

                out.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                out.truncate(n.min(out.len()));

                for (compact_key, _, _) in &out {
                    match compact_key {
                        CompactFlowKey::V4(k) => {
                            if let Some(entry) = flows_v4.get_mut(k) {
                                entry.mark_web_reported();
                            }
                        }
                        CompactFlowKey::V6(k) => {
                            if let Some(entry) = flows_v6.get_mut(k) {
                                entry.mark_web_reported();
                            }
                        }
                    }
                }

                out.into_iter()
                    .map(|(compact_key, delta_bytes, snapshot)| {
                        (
                            FlowDelta {
                                key: compact_key.to_flow_key(),
                                delta_bytes,
                            },
                            snapshot,
                        )
                    })
                    .collect()
            }
        }
    }
}
