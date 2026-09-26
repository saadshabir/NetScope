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
pub(crate) use scale::{ScaleFlowEntry, scale_base_ms};
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
        let time_base_ms = scale_base_ms(1.0);
        let mut entry = ScaleFlowEntry::new(1.0, FlowProtocol::Tcp, time_base_ms);
        entry.observe(
            2.0,
            time_base_ms,
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
        assert_eq!(entry.first_seen(time_base_ms), 1.0);
        assert_eq!(entry.last_seen(time_base_ms), 2.0);

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
}
