use ahash::AHashMap;
use serde::Serialize;

use super::{CompactFlowKey, FlowDirection, FlowProtocol, FlowSnapshot};
use crate::protocol::{ParsedPacket, TransportHeader, dns, tls, udp::UDP_HEADER_LEN};

const DNS_TIMEOUT_SECS: f64 = 5.0;
const MAX_PENDING_DNS: usize = 4096;
const MAX_PENDING_DNS_PER_FLOW: usize = 32;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DnsFlowStats {
    pub queries: u64,
    pub matched_responses: u64,
    pub unanswered_queries: u64,
    pub tracking_limit_hits: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    pub response_latency_min_ms: Option<f64>,
    pub response_latency_avg_ms: Option<f64>,
    pub response_latency_max_ms: Option<f64>,
}

impl DnsFlowStats {
    fn record_response(&mut self, latency_ms: f64, rcode: u8) {
        self.matched_responses += 1;
        self.unanswered_queries -= 1;
        self.nxdomain += u64::from(rcode == 3);
        self.servfail += u64::from(rcode == 2);
        let avg = self.response_latency_avg_ms.unwrap_or(latency_ms);
        self.response_latency_avg_ms =
            Some(avg + (latency_ms - avg) / self.matched_responses as f64);
        self.response_latency_min_ms = Some(
            self.response_latency_min_ms
                .map_or(latency_ms, |min| min.min(latency_ms)),
        );
        self.response_latency_max_ms = Some(
            self.response_latency_max_ms
                .map_or(latency_ms, |max| max.max(latency_ms)),
        );
    }
}

#[derive(Debug)]
struct PendingQuery {
    id: u16,
    direction: FlowDirection,
    question: Box<[u8]>,
    ts: f64,
}

// Keep application metadata sparse so ordinary flows retain their compact entries.
#[derive(Debug)]
pub(super) struct ApplicationFlows {
    dns: AHashMap<CompactFlowKey, DnsFlowStats>,
    tls_sni: AHashMap<CompactFlowKey, Box<str>>,
    pending: AHashMap<CompactFlowKey, Vec<PendingQuery>>,
    pending_count: usize,
    oldest_pending_ts: f64,
    watermark: f64,
    last_prune: f64,
}

impl ApplicationFlows {
    pub(super) fn new() -> Self {
        Self {
            dns: AHashMap::new(),
            tls_sni: AHashMap::new(),
            pending: AHashMap::new(),
            pending_count: 0,
            oldest_pending_ts: f64::INFINITY,
            watermark: f64::NEG_INFINITY,
            last_prune: f64::NEG_INFINITY,
        }
    }

    pub(super) fn advance(&mut self, ts: f64) {
        if ts.is_finite() && ts > self.watermark {
            self.watermark = ts;
            if !self.pending.is_empty() && ts - self.last_prune >= 1.0 {
                self.prune_pending();
            }
        }
    }

    fn prune_pending(&mut self) {
        self.last_prune = self.watermark;
        self.oldest_pending_ts = f64::INFINITY;
        self.pending.retain(|_, queries| {
            queries.retain(|query| {
                if self.watermark - query.ts > DNS_TIMEOUT_SECS {
                    self.pending_count -= 1;
                    return false;
                }
                self.oldest_pending_ts = self.oldest_pending_ts.min(query.ts);
                true
            });
            !queries.is_empty()
        });
    }

    fn prune_queries(queries: &mut Vec<PendingQuery>, now: f64, count: &mut usize) {
        let before = queries.len();
        queries.retain(|query| now - query.ts <= DNS_TIMEOUT_SECS);
        *count -= before - queries.len();
    }

    pub(super) fn observe(
        &mut self,
        key: CompactFlowKey,
        direction: FlowDirection,
        ts: f64,
        packet: &ParsedPacket<'_>,
    ) {
        match &packet.transport {
            Some(TransportHeader::Udp(udp))
                if udp.length() as usize == UDP_HEADER_LEN + packet.payload.len() =>
            {
                if let Some(dns) =
                    dns::parse_dns_udp(packet.payload, udp.src_port(), udp.dst_port())
                {
                    self.observe_dns(key, direction, ts, dns);
                }
            }
            Some(TransportHeader::Tcp(_)) => {
                if let Some(hello) = tls::parse_client_hello_sni(packet.payload) {
                    self.tls_sni
                        .entry(key)
                        .or_insert_with(|| hello.sni.into_boxed_str());
                }
            }
            _ => {}
        }
    }

    fn observe_dns(
        &mut self,
        key: CompactFlowKey,
        direction: FlowDirection,
        ts: f64,
        dns: dns::DnsMessage<'_>,
    ) {
        if dns.opcode_raw() != 0 || !ts.is_finite() || self.watermark - ts > DNS_TIMEOUT_SECS {
            return;
        }
        let response = dns.is_response();
        let question = match dns.question_count() {
            1 => match dns.question_key() {
                Ok(question) => Some(question),
                Err(_) => return,
            },
            0 if response && dns.rcode_raw() != 0 => None,
            _ => return,
        };
        let id = dns.id();

        if let Some(queries) = self.pending.get_mut(&key) {
            Self::prune_queries(queries, self.watermark, &mut self.pending_count);
            if response {
                let mut candidates = queries.iter().enumerate().filter(|(_, query)| {
                    query.id == id
                        && query.direction != direction
                        && question.as_ref().is_none_or(|q| *q == query.question)
                });
                if let Some((idx, query)) = candidates.next()
                    && candidates.next().is_none()
                    && ts >= query.ts
                    && dns.parse_sections(0, 0, 0, 0).is_ok()
                {
                    let query = queries.swap_remove(idx);
                    self.pending_count -= 1;
                    self.dns
                        .get_mut(&key)
                        .expect("query has DNS stats")
                        .record_response((ts - query.ts) * 1000.0, dns.rcode_raw());
                }
            } else if queries.iter().any(|query| {
                query.id == id
                    && query.direction == direction
                    && Some(&query.question) == question.as_ref()
            }) {
                // Coalesce repeated queries while awaiting the first response.
                return;
            }
            if queries.is_empty() {
                self.pending.remove(&key);
            }
        }

        if !response {
            // A removal can leave the oldest timestamp stale. It remains a
            // lower bound, so a sweep is needed only if a slot could expire.
            if self.pending_count >= MAX_PENDING_DNS
                && self.watermark - self.oldest_pending_ts > DNS_TIMEOUT_SECS
            {
                self.prune_pending();
            }
            let stats = self.dns.entry(key).or_default();
            if self.pending_count >= MAX_PENDING_DNS {
                stats.tracking_limit_hits += 1;
                return;
            }
            let queries = self.pending.entry(key).or_default();
            if queries.len() >= MAX_PENDING_DNS_PER_FLOW {
                stats.tracking_limit_hits += 1;
                return;
            }
            queries.push(PendingQuery {
                id,
                direction,
                question: question.expect("query has a question"),
                ts,
            });
            self.pending_count += 1;
            self.oldest_pending_ts = self.oldest_pending_ts.min(ts);
            stats.queries += 1;
            stats.unanswered_queries += 1;
        }
    }

    pub(super) fn enrich(&self, key: CompactFlowKey, mut snapshot: FlowSnapshot) -> FlowSnapshot {
        self.fill_snapshot(key, &mut snapshot);
        snapshot
    }

    pub(super) fn fill_snapshot(&self, key: CompactFlowKey, snapshot: &mut FlowSnapshot) {
        match snapshot.protocol {
            FlowProtocol::Udp => snapshot.dns = self.dns.get(&key).copied(),
            FlowProtocol::Tcp => snapshot.tls_sni = self.tls_sni.get(&key).cloned(),
        }
    }

    pub(super) fn remove(&mut self, key: CompactFlowKey, snapshot: Option<&mut FlowSnapshot>) {
        if let Some(snapshot) = snapshot {
            self.fill_snapshot(key, snapshot);
        }
        self.dns.remove(&key);
        self.tls_sni.remove(&key);
        if let Some(queries) = self.pending.remove(&key) {
            self.pending_count -= queries.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowKeyV4;
    use std::net::Ipv4Addr;

    fn key(client_port: u16) -> CompactFlowKey {
        let (key, _) = FlowKeyV4::new(
            FlowProtocol::Udp,
            Ipv4Addr::new(192, 0, 2, 1),
            client_port,
            Ipv4Addr::new(192, 0, 2, 2),
            53,
        );
        CompactFlowKey::V4(key)
    }

    fn message(id: u16, label: &[u8], rcode: Option<u8>) -> Vec<u8> {
        let mut data = vec![0; dns::DNS_HEADER_LEN];
        data[..2].copy_from_slice(&id.to_be_bytes());
        if let Some(rcode) = rcode {
            data[2] = 0x80;
            data[3] = rcode;
        }
        if !label.is_empty() {
            data[5] = 1;
            data.push(label.len() as u8);
            data.extend_from_slice(label);
            data.extend_from_slice(&[0, 0, 1, 0, 1]); // root label, A, IN
        }
        data
    }

    #[test]
    fn dns_pairs_only_the_matching_flow_direction_id_and_question() {
        use FlowDirection::{AtoB, BtoA};

        let mut app = ApplicationFlows::new();
        let client = key(40000);
        let mut observe = |key, direction, ts, id, label: &[u8], rcode| {
            app.advance(ts);
            let data = message(id, label, rcode);
            app.observe_dns(key, direction, ts, dns::DnsMessage::parse(&data).unwrap());
        };
        observe(client, AtoB, 1.0, 42, b"www", None);
        observe(client, AtoB, 1.125, 42, b"WWW", None); // retry
        observe(client, AtoB, 1.25, 42, b"mail", None); // same ID, different question
        observe(client, AtoB, 1.25, 43, b"other", None); // unanswered
        observe(client, BtoA, 1.375, 42, b"", Some(2)); // ambiguous
        observe(key(40001), BtoA, 1.375, 42, b"www", Some(3));
        observe(client, BtoA, 1.375, 41, b"www", Some(3));
        observe(client, AtoB, 1.375, 42, b"www", Some(3));
        observe(client, BtoA, 1.375, 42, b"wrong", Some(3));
        observe(client, BtoA, 0.875, 42, b"www", Some(3)); // backward timestamp
        observe(client, BtoA, 1.5, 42, b"WWW", Some(3));
        observe(client, BtoA, 1.625, 42, b"www", Some(3)); // duplicate response
        observe(client, BtoA, 1.625, 42, b"", Some(2)); // unique candidate

        let stats = app.dns[&client];
        assert_eq!(stats.queries, 3);
        assert_eq!(stats.matched_responses, 2);
        assert_eq!(stats.unanswered_queries, 1);
        assert_eq!(stats.nxdomain, 1);
        assert_eq!(stats.servfail, 1);
        assert_eq!(stats.response_latency_min_ms, Some(375.0));
        assert_eq!(stats.response_latency_avg_ms, Some(437.5));
        assert_eq!(stats.response_latency_max_ms, Some(500.0));
        assert_eq!(app.pending_count, 1);
    }

    #[test]
    fn dns_pending_limits_hold_and_timeout_or_removal_releases_slots() {
        let mut app = ApplicationFlows::new();
        app.advance(1.0);
        let per_flow = MAX_PENDING_DNS_PER_FLOW;
        for i in 0..MAX_PENDING_DNS {
            let flow = key(40000 + (i / per_flow) as u16);
            let data = message(i as u16, b"www", None);
            app.observe_dns(
                flow,
                FlowDirection::AtoB,
                1.0,
                dns::DnsMessage::parse(&data).unwrap(),
            );
        }
        assert_eq!(app.pending_count, MAX_PENDING_DNS);
        let data = message(u16::MAX, b"www", None);
        let query = dns::DnsMessage::parse(&data).unwrap();
        let first = key(40000);
        let next = key(50000);
        app.observe_dns(next, FlowDirection::AtoB, 1.0, query);
        assert_eq!(app.dns[&next].queries, 0);
        assert_eq!(app.dns[&next].tracking_limit_hits, 1);

        app.remove(key(40001), None);
        app.observe_dns(first, FlowDirection::AtoB, 1.0, query);
        assert_eq!(app.dns[&first].tracking_limit_hits, 1);
        assert_eq!(app.pending_count, MAX_PENDING_DNS - per_flow);

        app.advance(1.0 + DNS_TIMEOUT_SECS);
        assert_eq!(app.pending_count, MAX_PENDING_DNS - per_flow);
        app.advance(2.0 + DNS_TIMEOUT_SECS);
        assert_eq!(app.pending_count, 0);
        assert!(app.pending.is_empty());

        let data = message(0, b"www", Some(3));
        app.observe_dns(
            first,
            FlowDirection::BtoA,
            7.0,
            dns::DnsMessage::parse(&data).unwrap(),
        );
        assert_eq!(app.dns[&first].unanswered_queries, per_flow as u64);
        assert_eq!(app.dns[&first].nxdomain, 0);
        app.observe_dns(next, FlowDirection::AtoB, 7.0, query);
        assert_eq!(app.dns[&next].unanswered_queries, 1);
        assert_eq!(app.pending_count, 1);
    }

    #[test]
    fn dns_admission_reclaims_expired_slots_between_sweeps() {
        let mut app = ApplicationFlows::new();
        let data = message(42, b"www", None);
        let query = dns::DnsMessage::parse(&data).unwrap();
        app.advance(1.0);
        for i in 0..MAX_PENDING_DNS {
            app.observe_dns(key(40000 + i as u16), FlowDirection::AtoB, 1.0, query);
        }
        assert_eq!(app.pending_count, MAX_PENDING_DNS);

        app.advance(1.0 + DNS_TIMEOUT_SECS);
        assert_eq!(app.pending_count, MAX_PENDING_DNS);
        let next_ts = 1.25 + DNS_TIMEOUT_SECS;
        app.advance(next_ts);
        let next = key(50000);
        app.observe_dns(next, FlowDirection::AtoB, next_ts, query);
        assert_eq!(app.pending_count, 1);
        assert_eq!(app.dns[&next].queries, 1);
        assert_eq!(app.dns[&next].tracking_limit_hits, 0);
    }

    #[test]
    fn malformed_dns_reply_leaves_the_query_pending() {
        use FlowDirection::{AtoB, BtoA};

        let mut app = ApplicationFlows::new();
        let client = key(40000);
        let mut observe = |direction, ts, data: &[u8]| {
            app.advance(ts);
            app.observe_dns(client, direction, ts, dns::DnsMessage::parse(data).unwrap());
        };
        observe(AtoB, 1.0, &message(42, b"www", None));
        let mut malformed = message(42, b"www", Some(3));
        malformed[7] = 1; // ANCOUNT = 1, with no answer record in the payload
        observe(BtoA, 1.125, &malformed);
        observe(BtoA, 1.25, &message(42, b"www", Some(0)));

        let stats = app.dns[&client];
        assert_eq!(stats.matched_responses, 1);
        assert_eq!(stats.unanswered_queries, 0);
        assert_eq!(stats.nxdomain, 0);
        assert_eq!(stats.response_latency_avg_ms, Some(250.0));
    }

    #[test]
    fn removing_a_flow_exports_unanswered_queries_and_clears_its_pending_matches() {
        use crate::flow::{ExpiredFlowReason, FlowTracker};
        use crate::protocol::{LinkType, parse_packet_with_linktype};

        let mut pcap = pcap::Capture::from_file("examples/pcaps/normal.pcap").unwrap();
        let tcp_frame = pcap.next_packet().unwrap().data.to_vec();
        for _ in 0..5 {
            pcap.next_packet().unwrap();
        }
        let query_frame = pcap.next_packet().unwrap().data.to_vec();
        let response_frame = pcap.next_packet().unwrap().data.to_vec();
        let tcp = parse_packet_with_linktype(&tcp_frame, LinkType::Ethernet).unwrap();
        let query = parse_packet_with_linktype(&query_frame, LinkType::Ethernet).unwrap();
        let response = parse_packet_with_linktype(&response_frame, LinkType::Ethernet).unwrap();

        for deep in [false, true] {
            for reason in [ExpiredFlowReason::Timeout, ExpiredFlowReason::Eviction] {
                let mut tracker = FlowTracker::new(1.0, 1, deep, deep, deep);
                let mut expired = Vec::new();
                tracker.observe(1.0, query_frame.len() as u64, &query);
                match reason {
                    ExpiredFlowReason::Timeout => {
                        tracker.maybe_expire_collect(3.0, &mut expired);
                    }
                    ExpiredFlowReason::Eviction => {
                        tracker.observe_collect(3.0, tcp_frame.len() as u64, &tcp, &mut expired);
                    }
                }
                assert_eq!(expired.len(), 1);
                assert_eq!(expired[0].reason, reason);
                assert_eq!(expired[0].flow.dns.unwrap().unanswered_queries, 1);

                tracker.observe(3.125, response_frame.len() as u64, &response);
                assert!(tracker.snapshot()[0].dns.is_none());
            }
        }
    }
}
