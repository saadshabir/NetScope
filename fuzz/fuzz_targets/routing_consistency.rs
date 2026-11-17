#![no_main]

use libfuzzer_sys::fuzz_target;
use netscope::pipeline::router::shard_for_packet_with_linktype;
use netscope::protocol::{LinkType, NetworkHeader, TransportHeader, parse_packet_with_linktype};

fuzz_target!(|data: &[u8]| {
    let Some((&shard_count, packet)) = data.split_first() else {
        return;
    };
    let num_shards = usize::from(shard_count);
    let link_types = [
        LinkType::Ethernet,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
        LinkType::LoopbackNull,
        LinkType::LoopbackLoop,
        LinkType::RawIp,
        LinkType::Unsupported(-1),
    ];
    for link in link_types {
        let shard = shard_for_packet_with_linktype(packet, num_shards, link);
        assert!(shard < num_shards.max(1));
    }

    let Ok(parsed) = parse_packet_with_linktype(packet, LinkType::RawIp) else {
        return;
    };
    if !matches!(
        parsed.transport,
        Some(TransportHeader::Tcp(_) | TransportHeader::Udp(_))
    ) {
        return;
    }
    let (addresses, transport_offset, ether_type, family) = match parsed.network {
        Some(NetworkHeader::Ipv4(header)) => (12..20, header.header_len(), [0x08, 0x00], 2u32),
        Some(NetworkHeader::Ipv6(header)) => {
            (8..40, header.transport_offset(), [0x86, 0xdd], 30u32)
        }
        _ => unreachable!("TCP and UDP require an IP header"),
    };
    let mut reversed = packet.to_vec();
    swap_halves(&mut reversed[addresses]);
    swap_halves(&mut reversed[transport_offset..transport_offset + 4]);

    // Repeat with a nontrivial shard count even when the input selects 0 or 1.
    let num_shards = 257 + num_shards;
    let expected = shard_for_packet_with_linktype(packet, num_shards, LinkType::RawIp);
    assert_eq!(
        shard_for_packet_with_linktype(&reversed, num_shards, LinkType::RawIp),
        expected
    );

    let mut ethernet = [0u8; 14];
    ethernet[12..14].copy_from_slice(&ether_type);
    let mut qinq = [0u8; 22];
    qinq[12..20].copy_from_slice(&[0x88, 0xa8, 0, 1, 0x81, 0x00, 0, 2]);
    qinq[20..22].copy_from_slice(&ether_type);
    let mut sll = [0u8; 16];
    sll[14..16].copy_from_slice(&ether_type);
    let mut sll2 = [0u8; 20];
    sll2[..2].copy_from_slice(&ether_type);
    let loopback_null = family.to_ne_bytes();
    let loopback_loop = family.to_be_bytes();

    for (link, header) in [
        (LinkType::Ethernet, ethernet.as_slice()),
        (LinkType::Ethernet, qinq.as_slice()),
        (LinkType::LinuxSll, sll.as_slice()),
        (LinkType::LinuxSll2, sll2.as_slice()),
        (LinkType::LoopbackNull, loopback_null.as_slice()),
        (LinkType::LoopbackLoop, loopback_loop.as_slice()),
    ] {
        let mut frame = Vec::with_capacity(header.len() + packet.len());
        frame.extend_from_slice(header);
        frame.extend_from_slice(packet);
        assert_eq!(
            shard_for_packet_with_linktype(&frame, num_shards, link),
            expected
        );
        frame[header.len()..].copy_from_slice(&reversed);
        assert_eq!(
            shard_for_packet_with_linktype(&frame, num_shards, link),
            expected
        );
    }
});

fn swap_halves(bytes: &mut [u8]) {
    let (left, right) = bytes.split_at_mut(bytes.len() / 2);
    left.swap_with_slice(right);
}
