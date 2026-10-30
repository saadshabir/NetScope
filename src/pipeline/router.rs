//! Minimal packet key extraction for shard routing.
//!
//! We need to compute a hash of the canonical flow key (protocol + endpoints)
//! from raw bytes *without* doing a full parse. This keeps the capture thread
//! as lean as possible.

use std::hash::{Hash, Hasher};

use crate::protocol::{
    LinkType, ipv6::locate_ipv6_payload, sll::SLL_HEADER_LEN, sll2::SLL2_HEADER_LEN,
};

/// Compute the shard index for a raw Ethernet frame.
///
/// Returns `shard = hash(5-tuple) % num_shards`. Falls back to a simple
/// byte-based hash if the packet cannot be quickly classified.
#[inline]
pub fn shard_for_packet(data: &[u8], num_shards: usize) -> usize {
    shard_for_packet_with_linktype(data, num_shards, LinkType::Ethernet)
}

/// Compute the shard index for packet bytes using an explicit link type.
#[inline]
pub fn shard_for_packet_with_linktype(
    data: &[u8],
    num_shards: usize,
    link_type: LinkType,
) -> usize {
    if num_shards == 0 {
        return 0;
    }

    // Unsupported datalinks are forced to shard 0 to preserve flow coherence.
    if matches!(link_type, LinkType::Unsupported(_)) {
        return 0;
    }

    let hash = fast_flow_hash_with_linktype(data, link_type);
    (hash as usize) % num_shards
}

/// Extract a hash of the canonical 5-tuple from raw Ethernet frame bytes.
///
/// This intentionally does minimal validation — it just reads fixed offsets
/// and produces a hash. Malformed packets get a non-ideal but still valid
/// hash (worst case: uneven shard distribution, not correctness issues).
#[inline]
fn fast_flow_hash_with_linktype(data: &[u8], link_type: LinkType) -> u64 {
    match link_type {
        LinkType::Ethernet => fast_flow_hash_ethernet(data),
        LinkType::LinuxSll => fast_flow_hash_linux_sll(data),
        LinkType::LinuxSll2 => fast_flow_hash_linux_sll2(data),
        LinkType::LoopbackNull | LinkType::LoopbackLoop => fast_flow_hash_ip_at_offset(data, 4),
        LinkType::RawIp => fast_flow_hash_ip_at_offset(data, 0),
        LinkType::Unsupported(_) => byte_hash(data),
    }
}

#[inline]
fn fast_flow_hash_ethernet(data: &[u8]) -> u64 {
    // Ethernet header: 14 bytes (6 dst + 6 src + 2 ethertype)
    if data.len() < 14 {
        return byte_hash(data);
    }

    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    fast_flow_hash_ether_type(data, ether_type, 14)
}

#[inline]
fn fast_flow_hash_linux_sll(data: &[u8]) -> u64 {
    // Linux cooked capture v1: protocol at byte 14, payload at byte 16.
    if data.len() < SLL_HEADER_LEN {
        return byte_hash(data);
    }

    let ether_type = u16::from_be_bytes([data[14], data[15]]);
    fast_flow_hash_ether_type(data, ether_type, SLL_HEADER_LEN)
}

#[inline]
fn fast_flow_hash_linux_sll2(data: &[u8]) -> u64 {
    // Linux cooked capture v2: protocol at byte 0, payload at byte 20.
    if data.len() < SLL2_HEADER_LEN {
        return byte_hash(data);
    }

    let ether_type = u16::from_be_bytes([data[0], data[1]]);
    fast_flow_hash_ether_type(data, ether_type, SLL2_HEADER_LEN)
}

#[inline]
fn fast_flow_hash_ether_type(data: &[u8], mut ether_type: u16, mut ip_offset: usize) -> u64 {
    // Optional 802.1Q / 802.1ad VLAN tags in the payload.
    while ether_type == 0x8100 || ether_type == 0x88A8 {
        if data.len() < ip_offset + 4 {
            return byte_hash(data);
        }
        ether_type = u16::from_be_bytes([data[ip_offset + 2], data[ip_offset + 3]]);
        ip_offset += 4;
    }

    match ether_type {
        0x0800 => hash_ipv4(data, ip_offset),
        0x86DD => hash_ipv6(data, ip_offset),
        _ => byte_hash(data),
    }
}

#[inline]
fn fast_flow_hash_ip_at_offset(data: &[u8], ip_offset: usize) -> u64 {
    if data.len() <= ip_offset {
        return byte_hash(data);
    }

    match data[ip_offset] >> 4 {
        4 => hash_ipv4(data, ip_offset),
        6 => hash_ipv6(data, ip_offset),
        _ => byte_hash(data),
    }
}

#[inline]
fn hash_ipv4(data: &[u8], offset: usize) -> u64 {
    // IPv4 minimum: 20 bytes. We need: protocol (offset+9), src (offset+12..16), dst (offset+16..20)
    if data.len() < offset + 20 {
        return byte_hash(data);
    }

    let protocol = data[offset + 9];
    let ihl = (data[offset] & 0x0F) as usize * 4;
    let src_ip = &data[offset + 12..offset + 16];
    let dst_ip = &data[offset + 16..offset + 20];

    let transport_offset = offset + ihl;

    let (src_port, dst_port) = extract_ports(data, transport_offset, protocol);

    // Canonical ordering: always hash (min, max) so both directions map to same shard.
    let mut hasher = ahash::AHasher::default();
    protocol.hash(&mut hasher);
    if (src_ip, src_port) <= (dst_ip, dst_port) {
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
    } else {
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
    }
    hasher.finish()
}

#[inline]
fn hash_ipv6(data: &[u8], offset: usize) -> u64 {
    // IPv6 fixed header: 40 bytes. src (offset+8..24), dst (offset+24..40)
    if data.len() < offset + 40 {
        return byte_hash(data);
    }

    let src_ip = &data[offset + 8..offset + 24];
    let dst_ip = &data[offset + 24..offset + 40];

    let payload_info = match locate_ipv6_payload(&data[offset..]) {
        Some(info) => info,
        None => return byte_hash(data),
    };

    let next_header = payload_info.next_header;
    let transport_offset = offset + payload_info.transport_offset;
    let (src_port, dst_port) = if payload_info.non_initial_fragment {
        // Non-initial fragments do not contain transport ports.
        (0, 0)
    } else {
        extract_ports(data, transport_offset, next_header)
    };

    let mut hasher = ahash::AHasher::default();
    next_header.hash(&mut hasher);
    if (src_ip, src_port) <= (dst_ip, dst_port) {
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
    } else {
        dst_ip.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        src_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
    }
    hasher.finish()
}

/// Extract src/dst ports for TCP (6) and UDP (17). Returns (0,0) otherwise.
#[inline]
fn extract_ports(data: &[u8], transport_offset: usize, ip_protocol: u8) -> (u16, u16) {
    if (ip_protocol == 6 || ip_protocol == 17) && data.len() >= transport_offset + 4 {
        let src = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
        let dst = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
        (src, dst)
    } else {
        (0, 0)
    }
}

/// Fallback: hash the raw bytes (for non-IP or truncated packets).
#[inline]
fn byte_hash(data: &[u8]) -> u64 {
    let mut hasher = ahash::AHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_sll2_fixture_hashes_inner_flows_in_both_directions() {
        let packets = crate::protocol::sll2::fixture_packets();
        for (pair, ip_offset) in packets[..6].chunks_exact(2).zip([20, 20, 28]) {
            let expected = fast_flow_hash_with_linktype(&pair[0][ip_offset..], LinkType::RawIp);
            for packet in pair {
                // Compare full hashes so a shard collision cannot hide bad offsets
                // or an implementation that sends every SLL2 packet to shard zero.
                assert_eq!(
                    fast_flow_hash_with_linktype(packet, LinkType::LinuxSll2),
                    expected
                );
                for workers in [1, 2, 3, 8, 17] {
                    assert_eq!(
                        shard_for_packet_with_linktype(packet, workers, LinkType::LinuxSll2),
                        (expected as usize) % workers
                    );
                }

                let mut changed_metadata = packet.clone();
                changed_metadata[2..20].fill(0xff);
                assert_eq!(
                    fast_flow_hash_with_linktype(&changed_metadata, LinkType::LinuxSll2),
                    expected,
                    "SLL2 link metadata must not affect the flow hash"
                );

                let mut sll1 = vec![0u8; SLL_HEADER_LEN];
                sll1[14..16].copy_from_slice(&packet[..2]);
                sll1.extend_from_slice(&packet[SLL2_HEADER_LEN..]);
                assert_eq!(
                    fast_flow_hash_with_linktype(&sll1, LinkType::LinuxSll),
                    expected
                );
            }
        }
    }

    #[test]
    fn linux_sll2_fixture_truncations_and_non_ip_payloads_route_safely() {
        let packets = crate::protocol::sll2::fixture_packets();
        for packet in &packets {
            for len in 0..=packet.len() {
                let truncated = &packet[..len];
                assert!(shard_for_packet_with_linktype(truncated, 7, LinkType::LinuxSll2) < 7);
                assert_eq!(
                    shard_for_packet_with_linktype(truncated, 0, LinkType::LinuxSll2),
                    0
                );
                if len < SLL2_HEADER_LEN {
                    assert_eq!(fast_flow_hash_linux_sll2(truncated), byte_hash(truncated));
                }
            }
        }
        for packet in &packets[6..] {
            assert_eq!(fast_flow_hash_linux_sll2(packet), byte_hash(packet));
        }
    }

    fn make_tcp_ipv4_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20];

        // IPv4: version=4, ihl=5, protocol=6 (TCP)
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);

        // TCP: src_port, dst_port
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());

        pkt
    }

    /// A minimal valid TCP/IPv4 Ethernet frame (SYN, no payload).
    fn make_tcp_ipv4_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14];

        // Ethernet: dst mac, src mac, ethertype 0x0800
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&make_tcp_ipv4_payload(src_ip, dst_ip, src_port, dst_port));

        frame
    }

    fn make_tcp_ipv4_qinq_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        outer_vlan: u16,
        inner_vlan: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14];

        // Ethernet ethertype 0x88A8 (802.1ad)
        frame[12] = 0x88;
        frame[13] = 0xA8;

        // Outer TCI + inner TPID (0x8100)
        frame.extend_from_slice(&outer_vlan.to_be_bytes());
        frame.extend_from_slice(&[0x81, 0x00]);

        // Inner TCI + inner EtherType (IPv4)
        frame.extend_from_slice(&inner_vlan.to_be_bytes());
        frame.extend_from_slice(&[0x08, 0x00]);

        frame.extend_from_slice(&make_tcp_ipv4_payload(src_ip, dst_ip, src_port, dst_port));

        frame
    }

    fn make_tcp_ipv4_sll_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x00, // packet type = host
            0x00, 0x01, // ARPHRD = ethernet
            0x00, 0x06, // address length
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // addr[8]
            0x08, 0x00, // protocol = IPv4
        ];
        pkt.extend_from_slice(&make_tcp_ipv4_payload(src_ip, dst_ip, src_port, dst_port));
        pkt
    }

    fn make_tcp_ipv4_loopback_null_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&2u32.to_ne_bytes()); // AF_INET
        pkt.extend_from_slice(&make_tcp_ipv4_payload(src_ip, dst_ip, src_port, dst_port));
        pkt
    }

    fn make_tcp_ipv4_raw_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        make_tcp_ipv4_payload(src_ip, dst_ip, src_port, dst_port)
    }

    #[test]
    fn same_flow_same_shard() {
        let frame_ab = make_tcp_ipv4_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let frame_ba = make_tcp_ipv4_frame([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345);

        let shard_ab = shard_for_packet(&frame_ab, 4);
        let shard_ba = shard_for_packet(&frame_ba, 4);
        assert_eq!(
            shard_ab, shard_ba,
            "both directions of a flow must map to the same shard"
        );
    }

    #[test]
    fn qinq_vlan_preserves_shard_routing() {
        let base = make_tcp_ipv4_frame([10, 2, 0, 1], [10, 2, 0, 2], 22222, 443);
        let qinq = make_tcp_ipv4_qinq_frame([10, 2, 0, 1], [10, 2, 0, 2], 22222, 443, 100, 200);

        let shard_base = shard_for_packet(&base, 8);
        let shard_qinq = shard_for_packet(&qinq, 8);

        assert_eq!(shard_base, shard_qinq);
    }

    #[test]
    fn short_packet_no_panic() {
        let shard = shard_for_packet(&[0x08, 0x00], 4);
        assert!(shard < 4);
    }

    #[test]
    fn linux_sll_same_flow_same_shard() {
        let pkt_ab = make_tcp_ipv4_sll_packet([10, 1, 0, 1], [10, 1, 0, 2], 53000, 443);
        let pkt_ba = make_tcp_ipv4_sll_packet([10, 1, 0, 2], [10, 1, 0, 1], 443, 53000);

        let shard_ab = shard_for_packet_with_linktype(&pkt_ab, 8, LinkType::LinuxSll);
        let shard_ba = shard_for_packet_with_linktype(&pkt_ba, 8, LinkType::LinuxSll);
        assert_eq!(shard_ab, shard_ba);
    }

    #[test]
    fn loopback_null_same_flow_same_shard() {
        let pkt_ab =
            make_tcp_ipv4_loopback_null_packet([127, 0, 0, 1], [127, 0, 0, 1], 60000, 8080);
        let pkt_ba =
            make_tcp_ipv4_loopback_null_packet([127, 0, 0, 1], [127, 0, 0, 1], 8080, 60000);

        let shard_ab = shard_for_packet_with_linktype(&pkt_ab, 8, LinkType::LoopbackNull);
        let shard_ba = shard_for_packet_with_linktype(&pkt_ba, 8, LinkType::LoopbackNull);
        assert_eq!(shard_ab, shard_ba);
    }

    #[test]
    fn raw_ip_same_flow_same_shard() {
        let pkt_ab = make_tcp_ipv4_raw_packet([192, 0, 2, 10], [192, 0, 2, 20], 40000, 8443);
        let pkt_ba = make_tcp_ipv4_raw_packet([192, 0, 2, 20], [192, 0, 2, 10], 8443, 40000);

        let shard_ab = shard_for_packet_with_linktype(&pkt_ab, 8, LinkType::RawIp);
        let shard_ba = shard_for_packet_with_linktype(&pkt_ba, 8, LinkType::RawIp);
        assert_eq!(shard_ab, shard_ba);
    }

    fn make_tcp_ipv6_frame_with_hop_by_hop(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Ethernet + IPv6 fixed header + Hop-by-Hop(8 bytes) + TCP(20 bytes)
        let mut frame = vec![0u8; 14 + 40 + 8 + 20];

        // Ethernet ethertype 0x86DD
        frame[12] = 0x86;
        frame[13] = 0xDD;

        let ipv6 = 14;
        frame[ipv6] = 0x60; // Version 6
        // payload length = 8 + 20
        frame[ipv6 + 4..ipv6 + 6].copy_from_slice(&(28u16).to_be_bytes());
        frame[ipv6 + 6] = 0; // Next Header = Hop-by-Hop options
        frame[ipv6 + 7] = 64; // Hop limit
        frame[ipv6 + 8..ipv6 + 24].copy_from_slice(&src_ip);
        frame[ipv6 + 24..ipv6 + 40].copy_from_slice(&dst_ip);

        let hop = ipv6 + 40;
        frame[hop] = 6; // Next Header = TCP
        frame[hop + 1] = 0; // Hdr Ext Len = 0 => 8 bytes total

        let tcp = hop + 8;
        frame[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());

        frame
    }

    #[test]
    fn ipv6_extension_headers_preserve_bidirectional_shard() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let frame_ab = make_tcp_ipv6_frame_with_hop_by_hop(src, dst, 12345, 443);
        let frame_ba = make_tcp_ipv6_frame_with_hop_by_hop(dst, src, 443, 12345);

        let shard_ab = shard_for_packet(&frame_ab, 8);
        let shard_ba = shard_for_packet(&frame_ba, 8);

        assert_eq!(shard_ab, shard_ba);
    }

    fn make_ipv6_non_initial_fragment(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        fragment_id: u32,
    ) -> Vec<u8> {
        // Ethernet + IPv6 fixed header + Fragment(8) + fragment payload(12)
        let mut frame = vec![0u8; 14 + 40 + 8 + 12];

        frame[12] = 0x86;
        frame[13] = 0xDD;

        let ipv6 = 14;
        frame[ipv6] = 0x60;
        frame[ipv6 + 4..ipv6 + 6].copy_from_slice(&(20u16).to_be_bytes());
        frame[ipv6 + 6] = 44; // Fragment
        frame[ipv6 + 7] = 64;
        frame[ipv6 + 8..ipv6 + 24].copy_from_slice(&src_ip);
        frame[ipv6 + 24..ipv6 + 40].copy_from_slice(&dst_ip);

        let frag = ipv6 + 40;
        frame[frag] = 6; // Encapsulated next header = TCP
        // fragment offset = 1 (non-initial fragment)
        let fragment_field = 1u16 << 3;
        frame[frag + 2..frag + 4].copy_from_slice(&fragment_field.to_be_bytes());
        frame[frag + 4..frag + 8].copy_from_slice(&fragment_id.to_be_bytes());

        frame
    }

    #[test]
    fn ipv6_non_initial_fragments_are_bidirectional_stable() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let frame_ab = make_ipv6_non_initial_fragment(src, dst, 1234);
        let frame_ba = make_ipv6_non_initial_fragment(dst, src, 1234);

        let shard_ab = shard_for_packet(&frame_ab, 8);
        let shard_ba = shard_for_packet(&frame_ba, 8);

        assert_eq!(shard_ab, shard_ba);
    }
}
