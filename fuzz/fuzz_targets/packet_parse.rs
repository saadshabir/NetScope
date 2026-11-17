#![no_main]

use libfuzzer_sys::fuzz_target;
use netscope::packet_format::{parse_dns_and_tls, summarise_packet};
use netscope::protocol::{LinkType, parse_packet_with_linktype};

fuzz_target!(|frame: &[u8]| {
    for link_type in [
        LinkType::Ethernet,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
        LinkType::LoopbackNull,
        LinkType::LoopbackLoop,
        LinkType::RawIp,
    ] {
        if let Ok(parsed) = parse_packet_with_linktype(frame, link_type) {
            assert!(parsed.payload.len() <= frame.len());
            assert!(parsed.transport.is_none() || parsed.transport_parse_error.is_none());
            let (dns, tls) = parse_dns_and_tls(&parsed);
            let _ = summarise_packet(&parsed, dns.as_ref(), tls.as_ref());
        }
    }
});
