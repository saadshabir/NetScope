use crate::protocol::{self, LinkHeader, ParsedPacket, TransportHeader};
use std::fmt::Write as _;

pub fn parse_dns_and_tls<'a>(
    parsed: &'a ParsedPacket<'a>,
) -> (
    Option<protocol::dns::DnsMessage<'a>>,
    Option<protocol::tls::TlsClientHelloInfo>,
) {
    let dns = match &parsed.transport {
        Some(TransportHeader::Udp(hdr)) => {
            protocol::dns::parse_dns_udp(parsed.payload, hdr.src_port(), hdr.dst_port())
        }
        _ => None,
    };
    let tls = match &parsed.transport {
        Some(TransportHeader::Tcp(_)) => protocol::tls::parse_client_hello_sni(parsed.payload),
        _ => None,
    };
    (dns, tls)
}

pub fn summarise_packet(
    parsed: &ParsedPacket<'_>,
    dns: Option<&protocol::dns::DnsMessage<'_>>,
    tls: Option<&protocol::tls::TlsClientHelloInfo>,
) -> (String, String, String, String) {
    let mut proto;
    let mut src = String::new();
    let mut dst = String::new();
    let mut info = String::new();

    if let Some(net) = &parsed.network {
        match net {
            protocol::NetworkHeader::Ipv4(hdr) => {
                proto = "IPv4".to_string();
                src = format!("{}", hdr.src_addr());
                dst = format!("{}", hdr.dst_addr());
            }
            protocol::NetworkHeader::Ipv6(hdr) => {
                proto = "IPv6".to_string();
                src = format!("{}", hdr.src_addr());
                dst = format!("{}", hdr.dst_addr());
            }
            protocol::NetworkHeader::Arp(hdr) => {
                proto = "ARP".to_string();
                src = hdr.sender_protocol_display();
                dst = hdr.target_protocol_display();
                info = format!("{}", hdr);
            }
        }
    } else {
        proto = match &parsed.link {
            LinkHeader::Ethernet(hdr) => format!("{}", hdr.ether_type()),
            LinkHeader::LinuxSll(hdr) => format!("{}", hdr.protocol()),
            LinkHeader::LinuxSll2(hdr) => format!("{}", hdr.protocol()),
            LinkHeader::Loopback(hdr) => format!("Loopback {}", hdr.family_label()),
            LinkHeader::RawIp => "IP".to_string(),
        };
    }

    if let Some(transport) = &parsed.transport {
        match transport {
            protocol::TransportHeader::Tcp(hdr) => {
                if let Some(tls) = tls {
                    proto = "TLS".into();
                    info = format!("ClientHello sni={}", tls.sni);
                } else {
                    proto = "TCP".into();
                    info = format!(
                        "{} seq={} ack={} win={}",
                        hdr.flags_string(),
                        hdr.sequence_number(),
                        hdr.ack_number(),
                        hdr.window_size()
                    );
                }
                let _ = write!(src, ":{}", hdr.src_port());
                let _ = write!(dst, ":{}", hdr.dst_port());
            }
            protocol::TransportHeader::Udp(hdr) => {
                if let Some(dns) = dns {
                    proto = "DNS".into();
                    info = protocol::dns::brief_summary(dns);
                } else {
                    proto = "UDP".into();
                    info = format!("len={}", hdr.length());
                }
                let _ = write!(src, ":{}", hdr.src_port());
                let _ = write!(dst, ":{}", hdr.dst_port());
            }
            protocol::TransportHeader::Icmp(hdr) => {
                proto = "ICMP".into();
                info = format!("{}", hdr);
            }
            protocol::TransportHeader::Icmpv6(hdr) => {
                proto = "ICMPv6".into();
                info = format!("{}", hdr);
            }
        }
    }

    (proto, src, dst, info)
}

pub fn format_hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for offset in (0..data.len()).step_by(16) {
        let end = (offset + 16).min(data.len());
        let chunk = &data[offset..end];

        let _ = write!(out, "{:04x}  ", offset);

        for (i, byte) in chunk.iter().enumerate() {
            let _ = write!(out, "{:02x} ", byte);
            if i == 7 {
                out.push(' ');
            }
        }
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

pub fn format_timestamp(ts: f64) -> String {
    let secs = ts as u64;
    let micros = ((ts - secs as f64) * 1_000_000.0) as u32;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}.{:06}", hours, minutes, seconds, micros)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{LinkType, parse_packet_with_linktype};

    fn make_non_ipv4_arp_frame() -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x06, // EtherType = ARP
        ];

        frame.extend_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        frame.extend_from_slice(&0x86ddu16.to_be_bytes()); // ptype = IPv6
        frame.push(6); // hlen
        frame.push(16); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // op = request
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sha
        frame.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]); // spa
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // tha
        frame.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]); // tpa

        frame
    }

    #[test]
    fn summarise_non_ipv4_arp_formats_protocol_addresses_as_hex() {
        let frame = make_non_ipv4_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();

        let (proto, src, dst, info) = summarise_packet(&parsed, None, None);
        assert_eq!(proto, "ARP");
        assert_eq!(src, "20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:01");
        assert_eq!(dst, "20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:02");
        assert!(info.contains("who-has"));
    }
}
