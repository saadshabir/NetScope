//! Zero-copy parser for Linux cooked capture v2 (DLT_LINUX_SLL2).
//!
//! The 20-byte header contains a protocol (2 bytes), reserved field (2),
//! interface index (4), ARPHRD type (2), packet type (1), address length (1),
//! and link-layer address (8). Multibyte fields use network byte order.

use super::{EtherType, ParseError};
use std::fmt;

pub const SLL2_HEADER_LEN: usize = 20;

#[derive(Debug)]
pub struct LinuxSll2Header<'a> {
    data: &'a [u8],
}

impl<'a> LinuxSll2Header<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < SLL2_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: SLL2_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(Self { data })
    }

    #[inline]
    pub fn protocol_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    #[inline]
    pub fn protocol(&self) -> EtherType {
        EtherType::from(self.protocol_raw())
    }

    #[inline]
    pub fn interface_index(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    #[inline]
    pub fn arphrd_type_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[8], self.data[9]])
    }

    #[inline]
    pub fn packet_type_raw(&self) -> u8 {
        self.data[10]
    }

    #[inline]
    pub fn address_length(&self) -> u8 {
        self.data[11]
    }

    #[inline]
    pub fn address(&self) -> &'a [u8] {
        let len = (self.address_length() as usize).min(8);
        &self.data[12..12 + len]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[SLL2_HEADER_LEN..]
    }

    pub fn packet_type_label(&self) -> &'static str {
        match self.packet_type_raw() {
            0 => "host",
            1 => "broadcast",
            2 => "multicast",
            3 => "otherhost",
            4 => "outgoing",
            _ => "unknown",
        }
    }
}

impl fmt::Display for LinuxSll2Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Linux SLL2 {} ifindex={} hatype={} addr={} proto={}",
            self.packet_type_label(),
            self.interface_index(),
            self.arphrd_type_raw(),
            super::sll::format_addr(self.address()),
            self.protocol()
        )
    }
}

#[cfg(test)]
pub(crate) fn fixture_packets() -> Vec<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/pcaps/linux-sll2.pcap"
    );
    let mut capture = pcap::Capture::from_file(path).expect("SLL2 fixture should open");
    assert_eq!(capture.get_datalink().0, 276);
    let mut packets = Vec::new();
    loop {
        match capture.next_packet() {
            Ok(packet) => packets.push(packet.data.to_vec()),
            Err(pcap::Error::NoMorePackets) => break,
            Err(error) => panic!("SLL2 fixture read failed: {error}"),
        }
    }
    assert_eq!(packets.len(), 8);
    packets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        LinkHeader, LinkType, NetworkHeader, TransportHeader, parse_packet_with_linktype,
    };

    #[test]
    fn fixture_header_fields_use_sll2_offsets_and_network_byte_order() {
        let packets = fixture_packets();
        let packet = &packets[0];
        let header = LinuxSll2Header::parse(packet).unwrap();
        assert_eq!(header.protocol_raw(), 0x0800);
        assert_eq!(header.protocol(), EtherType::Ipv4);
        assert_eq!(header.interface_index(), 0x01020304);
        assert_eq!(header.arphrd_type_raw(), 1);
        assert_eq!(header.packet_type_raw(), 4);
        assert_eq!(header.packet_type_label(), "outgoing");
        assert_eq!(header.address_length(), 6);
        assert_eq!(header.address(), &[2, 0, 0, 0, 0, 2]);
        assert_eq!(header.payload(), &packet[20..]);
        assert_eq!(header.payload().as_ptr(), packet[20..].as_ptr());
        assert!(
            header
                .to_string()
                .contains("Linux SLL2 outgoing ifindex=16909060")
        );
    }

    #[test]
    fn short_headers_are_rejected_and_addresses_stay_within_the_fixed_field() {
        let mut packet = fixture_packets().remove(0);
        for len in 0..SLL2_HEADER_LEN {
            for result in [
                LinuxSll2Header::parse(&packet[..len]).map(|_| ()),
                parse_packet_with_linktype(&packet[..len], LinkType::LinuxSll2).map(|_| ()),
            ] {
                assert!(
                    matches!(result, Err(ParseError::TooShort { expected: 20, actual }) if actual == len)
                );
            }
        }
        assert!(
            LinuxSll2Header::parse(&packet[..20])
                .unwrap()
                .payload()
                .is_empty()
        );
        for length in [0, 6, 8, 255] {
            packet[11] = length;
            let header = LinuxSll2Header::parse(&packet).unwrap();
            assert_eq!(header.address_length(), length);
            assert_eq!(
                header.address(),
                &packet[12..12 + usize::from(length.min(8))]
            );
        }
        for (value, label) in [
            (0, "host"),
            (1, "broadcast"),
            (2, "multicast"),
            (3, "otherhost"),
            (4, "outgoing"),
            (255, "unknown"),
        ] {
            packet[10] = value;
            assert_eq!(
                LinuxSll2Header::parse(&packet).unwrap().packet_type_label(),
                label
            );
        }
    }

    #[test]
    fn fixture_decodes_ipv4_ipv6_qinq_and_non_ip_payloads() {
        let packets = fixture_packets();
        for (index, pair) in packets[..6].chunks_exact(2).enumerate() {
            let mut keys = Vec::new();
            for packet in pair {
                let parsed = parse_packet_with_linktype(packet, LinkType::LinuxSll2).unwrap();
                assert!(matches!(parsed.link, LinkHeader::LinuxSll2(_)));
                assert!(!parsed.unsupported);
                assert!(parsed.transport_parse_error.is_none());
                if index == 1 {
                    assert!(matches!(parsed.network, Some(NetworkHeader::Ipv6(_))));
                } else {
                    assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
                }
                if index == 0 {
                    assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
                } else {
                    assert!(matches!(parsed.transport, Some(TransportHeader::Udp(_))));
                }
                if index == 2 {
                    let stack = parsed.vlan_stack.as_ref().unwrap();
                    assert_eq!(
                        stack
                            .as_slice()
                            .iter()
                            .map(|tag| tag.vlan_id)
                            .collect::<Vec<_>>(),
                        [100, 200]
                    );
                    assert_eq!(parsed.payload, b"sll2-qinq");
                } else {
                    assert!(parsed.vlan_stack.is_none());
                }
                keys.push(crate::flow::flow_key_from_packet(&parsed).unwrap());
            }
            assert_eq!(keys[0], keys[1], "both directions must decode to one flow");
            assert_eq!(keys[0].a.port, [53000, 54000, 55000][index]);
            assert_eq!(keys[0].b.port, [443, 9000, 9001][index]);
        }

        let arp = parse_packet_with_linktype(&packets[6], LinkType::LinuxSll2).unwrap();
        assert!(matches!(arp.network, Some(NetworkHeader::Arp(_))));
        assert!(arp.transport.is_none());
        assert!(!arp.unsupported);
        let unknown = parse_packet_with_linktype(&packets[7], LinkType::LinuxSll2).unwrap();
        assert!(unknown.network.is_none());
        assert!(unknown.transport.is_none());
        assert!(unknown.unsupported);
        assert_eq!(unknown.payload, b"sll2-unsupported");
        assert_eq!(
            crate::packet_format::summarise_packet(&unknown, None, None).0,
            "Unknown(0x88b5)"
        );

        for len in 20..=28 {
            assert!(matches!(
                parse_packet_with_linktype(&packets[4][..len], LinkType::LinuxSll2),
                Err(ParseError::TooShort { .. })
            ));
        }
    }

    #[cfg(feature = "dashboard")]
    #[test]
    fn dashboard_packet_details_include_sll2_interface_and_direction() {
        let packet = fixture_packets().remove(0);
        let parsed = parse_packet_with_linktype(&packet, LinkType::LinuxSll2).unwrap();
        let (sample, stored) = crate::build_packet_data(1, 1.0, &packet, &parsed, 64);
        assert_eq!(sample.protocol, "TCP");
        assert_eq!(sample.src, "192.0.2.10:53000");
        assert_eq!(sample.dst, "198.51.100.20:443");
        assert_eq!(stored.layers[0].name, "Linux SLL2");
        for (name, value) in [
            ("Interface Index", "16909060"),
            ("Packet Type", "outgoing (4)"),
            ("Address", "02:00:00:00:00:02"),
            ("Protocol", "IPv4"),
        ] {
            assert!(
                stored.layers[0]
                    .fields
                    .contains(&(name.into(), value.into()))
            );
        }
    }
}
