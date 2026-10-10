use crate::protocol::{NetworkHeader, ParsedPacket, TransportHeader};
use std::net::IpAddr;

mod export;
mod key;
mod model;
mod scale;
mod tcp;
mod tracker;

pub use export::{ExpiredFlowCsvSink, write_flow_csv, write_flow_json};
pub(crate) use key::{CompactFlowKey, FlowKeyV4, FlowKeyV6};
pub use key::{Endpoint, FlowDirection, FlowKey, FlowProtocol};
pub use model::{
    ExpiredFlowEvent, ExpiredFlowReason, FlowDelta, FlowEntry, FlowSnapshot, TcpState,
};
pub use tracker::{FlowTracker, FlowTrackerStats};

pub(crate) use model::update_tcp_state_fields;
pub(crate) use scale::ScaleFlowEntry;
pub(crate) use tcp::{SeqStatus, TcpFlags, TcpSeqTracker, tcp_sequence_len};

/// Build a canonical flow key from a parsed packet.
///
/// Returns `None` for packets that are not trackable flows (non-IP,
/// non-initial fragments, or unsupported transport protocols).
pub fn flow_key_from_packet(packet: &ParsedPacket<'_>) -> Option<FlowKey> {
    let (src_ip, dst_ip, skip_flow) = match &packet.network {
        Some(NetworkHeader::Ipv4(hdr)) => {
            let skip = hdr.fragment_offset() != 0;
            (IpAddr::V4(hdr.src_addr()), IpAddr::V4(hdr.dst_addr()), skip)
        }
        Some(NetworkHeader::Ipv6(hdr)) => (
            IpAddr::V6(hdr.src_addr()),
            IpAddr::V6(hdr.dst_addr()),
            hdr.is_non_initial_fragment(),
        ),
        Some(NetworkHeader::Arp(_)) => return None,
        None => return None,
    };

    if skip_flow {
        return None;
    }

    let (src_port, dst_port, protocol) = match &packet.transport {
        Some(TransportHeader::Tcp(hdr)) => (hdr.src_port(), hdr.dst_port(), FlowProtocol::Tcp),
        Some(TransportHeader::Udp(hdr)) => (hdr.src_port(), hdr.dst_port(), FlowProtocol::Udp),
        _ => return None,
    };

    let src = Endpoint {
        ip: src_ip,
        port: src_port,
    };
    let dst = Endpoint {
        ip: dst_ip,
        port: dst_port,
    };

    let (key, _) = FlowKey::new(protocol, src, dst);
    Some(key)
}

pub(crate) fn flow_compact_key_from_packet(packet: &ParsedPacket<'_>) -> Option<CompactFlowKey> {
    flow_key_from_packet(packet).and_then(|key| CompactFlowKey::from_flow_key(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{LinkType, parse_packet_with_linktype};
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn clock_test_frame(ipv6: bool, port: u16, reverse: bool) -> Vec<u8> {
        let (src_port, dst_port) = if reverse { (80, port) } else { (port, 80) };
        if !ipv6 {
            let (src, dst) = if reverse {
                ([10, 0, 0, 2], [10, 0, 0, 1])
            } else {
                ([10, 0, 0, 1], [10, 0, 0, 2])
            };
            return make_tcp_ethernet_frame(src, dst, src_port, dst_port, 1, 0, 0x10, &[]);
        }
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets();
        let (src, dst) = if reverse { (b, a) } else { (a, b) };
        let mut frame = vec![0; 74];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&20u16.to_be_bytes());
        frame[20] = 6;
        frame[21] = 64;
        frame[22..38].copy_from_slice(&src);
        frame[38..54].copy_from_slice(&dst);
        frame[54..56].copy_from_slice(&src_port.to_be_bytes());
        frame[56..58].copy_from_slice(&dst_port.to_be_bytes());
        frame[66] = 0x50;
        frame[67] = 0x10;
        frame
    }

    #[test]
    fn exact_top_reports_keep_cli_and_dashboard_deltas_independent() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(0.0, 100, deep, deep, deep);
            for port in 1..=20 {
                let frame = clock_test_frame(port % 2 == 0, port, false);
                let packet = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
                tracker.observe(1.0, port as u64 * 100, &packet);
            }
            assert!(tracker.top_flows_by_delta(0).is_empty());
            assert!(tracker.top_flows_with_snapshot(0).is_empty());
            let cli = tracker.top_flows_by_delta(3);
            let web = tracker.top_flows_with_snapshot(3);
            assert_eq!(
                cli.iter().map(|flow| flow.delta_bytes).collect::<Vec<_>>(),
                [2000, 1900, 1800]
            );
            assert_eq!(
                web.iter()
                    .map(|(flow, _)| flow.delta_bytes)
                    .collect::<Vec<_>>(),
                [2000, 1900, 1800]
            );
            for (flow, snapshot) in &web {
                assert_eq!(flow.delta_bytes, snapshot.bytes_total);
            }
            assert_eq!(tracker.top_flows_by_delta(1)[0].delta_bytes, 1700);
            assert_eq!(tracker.top_flows_with_snapshot(1)[0].0.delta_bytes, 1700);
            assert_eq!(tracker.top_flows_by_delta(usize::MAX).len(), 16);
            assert_eq!(tracker.top_flows_with_snapshot(usize::MAX).len(), 16);
            assert!(tracker.top_flows_by_delta(1).is_empty());
            assert!(tracker.top_flows_with_snapshot(1).is_empty());
        }
    }

    #[test]
    fn clock_eviction_preserves_reobserved_flows_and_recovers_after_expiry() {
        for deep in [false, true] {
            for ipv6 in [false, true] {
                let mut tracker = FlowTracker::new(60.0, 3, deep, deep, deep);
                let mut events = Vec::new();
                // Filling the clock gives each flow one chance. The fourth
                // insertion clears those references and evicts the first.
                for (port, reverse) in [
                    (1001, false),
                    (1002, false),
                    (1003, false),
                    (1004, false),
                    (1002, true),
                    (1005, false),
                ] {
                    let frame = clock_test_frame(ipv6, port, reverse);
                    let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
                    tracker.observe_collect(1.0, frame.len() as u64, &parsed, &mut events);
                    assert!(tracker.len() <= 3);
                }
                assert_eq!(tracker.stats().created, 5);
                assert_eq!(tracker.stats().evicted, 2);
                let evicted: Vec<_> = events
                    .iter()
                    .map(|event| event.flow.endpoint_a.port)
                    .collect();
                assert_eq!(evicted, [1001, 1003]);
                let retained = tracker
                    .snapshot()
                    .into_iter()
                    .find(|flow| flow.endpoint_a.port == 1002)
                    .unwrap();
                assert_eq!(retained.packets_a_to_b, 1);
                assert_eq!(retained.packets_b_to_a, 1);

                events.clear();
                assert_eq!(tracker.maybe_expire_collect(120.0, &mut events), 3);
                assert_eq!(events.len(), 3);
                assert!(
                    events
                        .iter()
                        .all(|event| event.reason == ExpiredFlowReason::Timeout)
                );
                assert_eq!(tracker.stats().expired, 3);
                // Reusing a previously expired key must start a fresh clock
                // entry; later capacity pressure must still evict one flow.
                for port in 1002..=1005 {
                    let frame = clock_test_frame(ipv6, port, false);
                    let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
                    tracker.observe(121.0, frame.len() as u64, &parsed);
                }
                assert_eq!(tracker.len(), 3);
                assert_eq!(tracker.stats().created, 9);
                assert_eq!(tracker.stats().evicted, 3);
            }
        }
    }

    #[test]
    fn unlimited_flow_admission_counts_each_bidirectional_flow_once() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(60.0, 0, deep, deep, deep);
            for ipv6 in [false, true] {
                for (port, reverse) in [(1001, false), (1001, true), (1002, false)] {
                    let frame = clock_test_frame(ipv6, port, reverse);
                    let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
                    tracker.observe(1.0, frame.len() as u64, &parsed);
                }
            }
            assert_eq!(tracker.len(), 4);
            assert_eq!(tracker.stats().created, 4);
            assert_eq!(tracker.stats().evicted, 0);
            assert_eq!(tracker.maybe_expire(120.0), 4);
            assert_eq!(tracker.stats().expired, 4);
        }
    }

    #[test]
    fn expiry_bound_accounts_for_old_insertions_and_the_timeout_boundary() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(60.0, 0, deep, deep, deep);
            let recent = clock_test_frame(false, 1001, false);
            let old = clock_test_frame(true, 1002, false);
            tracker.observe(
                100.0,
                54,
                &parse_packet_with_linktype(&recent, LinkType::Ethernet).unwrap(),
            );
            assert_eq!(tracker.maybe_expire(101.0), 0);
            tracker.observe(
                1.0,
                74,
                &parse_packet_with_linktype(&old, LinkType::Ethernet).unwrap(),
            );
            assert_eq!(tracker.maybe_expire(102.0), 1);
            assert_eq!(tracker.snapshot()[0].endpoint_a.port, 1001);
            assert_eq!(tracker.maybe_expire(160.0), 0);
            // Checks are still throttled to one per capture-time second.
            assert_eq!(tracker.maybe_expire(161.0), 1);
            assert!(tracker.is_empty());
        }
    }

    #[test]
    fn flow_budget_holds_for_constant_and_backward_timestamps() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(120.0, 2, deep, deep, deep);
            let mut evictions = Vec::new();
            for port in 1..=100u16 {
                let frame =
                    make_tcp_ethernet_frame([10, 0, 0, 1], [10, 0, 0, 2], port, 80, 1, 0, 2, &[]);
                let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
                let ts = if port < 50 {
                    100.0
                } else {
                    100.0 - port as f64
                };
                tracker.observe_collect(ts, frame.len() as u64, &parsed, &mut evictions);
                assert!(tracker.len() <= 2);
            }
            assert_eq!(tracker.stats().created, 100);
            assert_eq!(tracker.stats().evicted, 98);
            assert_eq!(evictions.len(), 98);
            assert!(
                evictions
                    .iter()
                    .all(|event| event.reason == ExpiredFlowReason::Eviction)
            );
            assert_eq!(tracker.maybe_expire(1000.0), 2);
            // New inserts after timeout cleanup must have a consistent clock.
            observe_tcp_segment(
                &mut tracker,
                1001.0,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                200,
                80,
                1,
                0,
                2,
                &[],
            );
            assert_eq!(tracker.len(), 1);
        }
    }

    #[test]
    fn full_and_scale_flows_preserve_early_and_long_range_times() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(120.0, 100, deep, deep, deep);
            for (ts, port) in [
                (100.25, 1000),
                (90.0, 1001),
                (80.5, 1001),
                (5_000_100.125, 1001),
            ] {
                observe_tcp_segment(
                    &mut tracker,
                    ts,
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    port,
                    80,
                    1,
                    0,
                    2,
                    &[],
                );
            }
            let flow = tracker
                .snapshot()
                .into_iter()
                .find(|flow| flow.endpoint_a.port == 1001)
                .unwrap();
            assert_eq!(flow.first_seen, 80.5);
            assert_eq!(flow.last_seen, 5_000_100.125);
            assert_eq!(flow.duration_secs, 5_000_019.625);
            assert_eq!(tracker.maybe_expire(5_000_101.0), 1);
            assert_eq!(tracker.len(), 1);
        }
    }

    #[test]
    fn fin_retransmissions_are_idempotent_in_both_flow_stores() {
        for deep in [false, true] {
            let mut tracker = FlowTracker::new(120.0, 100, deep, deep, deep);
            for ts in [1.0, 1.1, 1.2] {
                observe_tcp_segment(
                    &mut tracker,
                    ts,
                    [10, 0, 0, 1],
                    [10, 0, 0, 2],
                    40000,
                    80,
                    1,
                    0,
                    0x11,
                    &[],
                );
                assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::FinWait));
            }
            for ts in [1.3, 1.4] {
                observe_tcp_segment(
                    &mut tracker,
                    ts,
                    [10, 0, 0, 2],
                    [10, 0, 0, 1],
                    80,
                    40000,
                    1,
                    0,
                    0x11,
                    &[],
                );
                assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::Closed));
            }
            observe_tcp_segment(
                &mut tracker,
                1.5,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                40000,
                80,
                1,
                0,
                0x14,
                &[],
            );
            observe_tcp_segment(
                &mut tracker,
                1.6,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                40000,
                80,
                1,
                0,
                0x11,
                &[],
            );
            assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::Reset));
        }
    }

    fn make_ethernet_arp_frame() -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x06, // EtherType = ARP
        ];

        frame.extend_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // op = request
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sha
        frame.extend_from_slice(&[192, 168, 1, 10]); // spa
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // tha
        frame.extend_from_slice(&[192, 168, 1, 1]); // tpa
        frame
    }

    #[allow(clippy::too_many_arguments)]
    fn make_tcp_ethernet_frame(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = vec![
            0x02, 0, 0, 0, 0, 1, // destination MAC
            0x02, 0, 0, 0, 0, 2, // source MAC
            0x08, 0x00, // IPv4
            0x45, 0, // version, IHL, DSCP
            0, 0, // total length, filled below
            0, 1, 0, 0, // identification, flags/fragment offset
            64, 6, 0, 0, // TTL, TCP, checksum
            src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
        ];
        let ip_length = (20 + 20 + payload.len()) as u16;
        frame[16..18].copy_from_slice(&ip_length.to_be_bytes());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ack.to_be_bytes());
        frame.extend_from_slice(&[0x50, flags]); // data offset and flags
        frame.extend_from_slice(&4096u16.to_be_bytes()); // window
        frame.extend_from_slice(&[0, 0, 0, 0]); // checksum and urgent pointer
        frame.extend_from_slice(payload);
        frame
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_tcp_segment(
        tracker: &mut FlowTracker,
        ts: f64,
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let frame = make_tcp_ethernet_frame(src, dst, src_port, dst_port, seq, ack, flags, payload);
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet)
            .expect("test TCP segment should parse");
        tracker.observe(ts, frame.len() as u64, &parsed);
    }

    #[test]
    fn flow_key_is_directionless() {
        let a = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 1234,
        };
        let b = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 80,
        };
        let (key_ab, dir_ab) = FlowKey::new(FlowProtocol::Tcp, a, b);
        let (key_ba, dir_ba) = FlowKey::new(FlowProtocol::Tcp, b, a);
        assert_eq!(key_ab, key_ba);
        assert_ne!(dir_ab, dir_ba);
    }

    #[test]
    fn flow_key_orders_ipv4_before_ipv6() {
        let v4 = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 443,
        };
        let v6 = Endpoint {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 443,
        };
        let (key, dir) = FlowKey::new(FlowProtocol::Udp, v6, v4);
        assert_eq!(key.a, v4);
        assert_eq!(key.b, v6);
        assert_eq!(dir, FlowDirection::BtoA);
    }

    #[test]
    fn flow_key_from_packet_returns_none_for_arp() {
        let frame = make_ethernet_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
        assert!(flow_key_from_packet(&parsed).is_none());
    }

    #[test]
    fn observe_ignores_arp_packets() {
        let frame = make_ethernet_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
        let mut tracker = FlowTracker::new(60.0, 1024, false, false, false);

        tracker.observe(1.0, frame.len() as u64, &parsed);

        assert!(tracker.is_empty());
    }

    #[test]
    fn compact_v4_key_matches_canonical_flow_key() {
        let a_ip = Ipv4Addr::new(10, 1, 2, 3);
        let b_ip = Ipv4Addr::new(10, 9, 8, 7);
        let a_port = 44444;
        let b_port = 443;

        let (compact_ab, dir_ab) = FlowKeyV4::new(FlowProtocol::Tcp, a_ip, a_port, b_ip, b_port);
        let (compact_ba, dir_ba) = FlowKeyV4::new(FlowProtocol::Tcp, b_ip, b_port, a_ip, a_port);
        assert_eq!(compact_ab, compact_ba);
        assert_ne!(dir_ab, dir_ba);

        let a = Endpoint {
            ip: IpAddr::V4(a_ip),
            port: a_port,
        };
        let b = Endpoint {
            ip: IpAddr::V4(b_ip),
            port: b_port,
        };
        let (full, _) = FlowKey::new(FlowProtocol::Tcp, a, b);
        assert_eq!(compact_ab.to_flow_key(), full);
    }

    #[test]
    fn compact_v6_key_matches_canonical_flow_key() {
        let a_ip = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let b_ip = Ipv6Addr::new(0x2001, 0xdb8, 9, 8, 7, 6, 5, 4);
        let a_port = 5353;
        let b_port = 443;

        let (compact_ab, dir_ab) = FlowKeyV6::new(FlowProtocol::Udp, a_ip, a_port, b_ip, b_port);
        let (compact_ba, dir_ba) = FlowKeyV6::new(FlowProtocol::Udp, b_ip, b_port, a_ip, a_port);
        assert_eq!(compact_ab, compact_ba);
        assert_ne!(dir_ab, dir_ba);

        let a = Endpoint {
            ip: IpAddr::V6(a_ip),
            port: a_port,
        };
        let b = Endpoint {
            ip: IpAddr::V6(b_ip),
            port: b_port,
        };
        let (full, _) = FlowKey::new(FlowProtocol::Udp, a, b);
        assert_eq!(compact_ab.to_flow_key(), full);
    }

    #[test]
    fn flow_tracker_uses_scale_store_when_deep_tcp_features_disabled() {
        let tracker = FlowTracker::new(60.0, 1000, false, false, false);
        assert!(tracker.is_scale_mode());

        let tracker_full = FlowTracker::new(60.0, 1000, true, false, false);
        assert!(!tracker_full.is_scale_mode());
    }

    #[test]
    fn maybe_expire_collect_reports_timeout_reason() {
        let mut tracker = FlowTracker::new(1.0, 1000, false, false, false);
        tracker.insert_synthetic_ipv4_flows(1);

        let mut events = Vec::new();
        let removed = tracker.maybe_expire_collect(2.0, &mut events);
        assert_eq!(removed, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, ExpiredFlowReason::Timeout);
        assert_eq!(tracker.stats().created, 1);
        assert_eq!(tracker.stats().expired, 1);
        assert_eq!(tracker.stats().evicted, 0);
    }

    #[test]
    fn maybe_expire_collect_reports_eviction_reason() {
        let mut tracker = FlowTracker::new(0.0, 1, false, false, false);
        tracker.insert_synthetic_ipv4_flows(2);

        let mut events = Vec::new();
        let removed = tracker.maybe_expire_collect(2.0, &mut events);
        assert_eq!(removed, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, ExpiredFlowReason::Eviction);
        assert_eq!(tracker.stats().created, 2);
        assert_eq!(tracker.stats().expired, 0);
        assert_eq!(tracker.stats().evicted, 1);
    }

    #[test]
    fn scale_flow_entry_tracks_compact_state_and_deltas() {
        assert_eq!(std::mem::size_of::<ScaleFlowEntry>(), 64);
        let mut entry = ScaleFlowEntry::new(1.0, FlowProtocol::Tcp);
        entry.observe(
            2.0,
            FlowDirection::AtoB,
            128,
            Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            }),
        );

        let total = entry.total_bytes();
        assert_eq!(entry.stats_delta(), 128);
        assert_eq!(entry.web_delta(), 128);
        assert_eq!(entry.tcp_state(), Some(TcpState::SynSent));
        assert_eq!(entry.client(), Some(FlowDirection::AtoB));
        assert_eq!(entry.first_seen(), 1.0);
        assert_eq!(entry.last_seen(), 2.0);

        entry.mark_stats_reported();
        entry.mark_web_reported();

        assert_eq!(entry.total_bytes(), total);
        assert_eq!(entry.stats_delta(), 0);
        assert_eq!(entry.web_delta(), 0);
    }

    #[test]
    fn tcp_state_basic_transitions() {
        let mut entry = FlowEntry::new(0.0, FlowProtocol::Tcp);
        entry.update_tcp_state(
            TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            },
            FlowDirection::AtoB,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::SynSent));
        entry.update_tcp_state(
            TcpFlags {
                syn: true,
                ack: true,
                fin: false,
                rst: false,
            },
            FlowDirection::BtoA,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::SynAck));
        entry.update_tcp_state(
            TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
            },
            FlowDirection::AtoB,
        );
        assert_eq!(entry.tcp_state, Some(TcpState::Established));
    }

    #[test]
    fn tcp_seq_tracker_detects_retransmission() {
        let mut tracker = TcpSeqTracker {
            max_seq_end: Some(200),
            last_ack: Some(200),
            in_flight: VecDeque::new(),
        };

        let status = tracker.on_segment(150, tracker.last_ack);
        assert_eq!(status, SeqStatus::Retransmission);
    }

    #[test]
    fn tcp_seq_tracker_rtt_sample() {
        let mut tracker = TcpSeqTracker::new();
        tracker.push_sample(1100, 1.0);
        let mut samples = Vec::new();
        tracker.on_ack(1.05, 1100, |rtt| samples.push(rtt));
        assert_eq!(samples.len(), 1);
        assert!(samples[0] >= 50.0);
    }

    #[test]
    fn flow_direction_tcp_state_sequence_observations_and_timestamp_gap_are_consistent() {
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let mut tracker = FlowTracker::new(5.0, 1024, true, true, true);

        observe_tcp_segment(
            &mut tracker,
            1.0,
            client,
            server,
            40000,
            443,
            100,
            0,
            0x02,
            &[],
        ); // SYN
        observe_tcp_segment(
            &mut tracker,
            1.1,
            server,
            client,
            443,
            40000,
            500,
            101,
            0x12,
            &[],
        ); // SYN-ACK
        observe_tcp_segment(
            &mut tracker,
            1.2,
            client,
            server,
            40000,
            443,
            101,
            501,
            0x10,
            &[],
        ); // ACK

        let mut snapshot = tracker
            .snapshot()
            .pop()
            .expect("handshake creates one flow");
        assert_eq!(snapshot.tcp_state, Some(TcpState::Established));
        assert_eq!(snapshot.client, Some(FlowDirection::AtoB));
        assert_eq!((snapshot.packets_a_to_b, snapshot.packets_b_to_a), (2, 1));

        observe_tcp_segment(
            &mut tracker,
            1.3,
            client,
            server,
            40000,
            443,
            101,
            501,
            0x18,
            b"0123456789",
        );
        observe_tcp_segment(
            &mut tracker,
            1.4,
            server,
            client,
            443,
            40000,
            501,
            111,
            0x10,
            &[],
        );
        observe_tcp_segment(
            &mut tracker,
            1.5,
            client,
            server,
            40000,
            443,
            101,
            501,
            0x18,
            b"0123456789",
        ); // retransmission
        observe_tcp_segment(
            &mut tracker,
            1.6,
            client,
            server,
            40000,
            443,
            121,
            501,
            0x18,
            b"abcdefghij",
        ); // advance
        observe_tcp_segment(
            &mut tracker,
            1.7,
            client,
            server,
            40000,
            443,
            111,
            501,
            0x18,
            b"abcdefghij",
        ); // out of order

        snapshot = tracker
            .snapshot()
            .pop()
            .expect("packets retain the canonical flow");
        assert_eq!((snapshot.packets_a_to_b, snapshot.packets_b_to_a), (6, 2));
        assert_eq!(snapshot.retransmissions, 1);
        assert_eq!(snapshot.out_of_order, 1);
        assert_eq!(snapshot.rtt_samples, 3);
        assert!(
            (snapshot
                .rtt_last_ms
                .expect("ACKs should produce RTT samples")
                - 100.0)
                .abs()
                < 1e-6
        );
        assert_eq!(snapshot.tcp_state, Some(TcpState::Established));

        observe_tcp_segment(
            &mut tracker,
            2.0,
            client,
            server,
            40000,
            443,
            131,
            501,
            0x11,
            &[],
        ); // FIN
        assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::FinWait));
        observe_tcp_segment(
            &mut tracker,
            2.1,
            server,
            client,
            443,
            40000,
            502,
            131,
            0x11,
            &[],
        ); // peer FIN
        assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::Closed));
        observe_tcp_segment(
            &mut tracker,
            2.2,
            server,
            client,
            443,
            40000,
            503,
            131,
            0x04,
            &[],
        ); // RST
        assert_eq!(tracker.snapshot()[0].tcp_state, Some(TcpState::Reset));
        assert_eq!(tracker.snapshot()[0].first_seen, 1.0);
        assert_eq!(tracker.snapshot()[0].last_seen, 2.2);

        assert_eq!(tracker.maybe_expire(8.0), 1);
        assert!(
            tracker.is_empty(),
            "timestamp gap expires the inactive flow"
        );
    }
}
