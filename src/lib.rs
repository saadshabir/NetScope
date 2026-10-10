//! NetScope library crate — re-exports modules for benchmarks and tests.

pub mod analysis;
pub mod capture;
pub mod config;
pub mod display;
pub mod flow;
pub mod jsonl;
pub mod metrics;
pub mod output_file;
pub mod packet_format;
pub mod pipeline;
pub mod protocol;
pub mod run_summary;
pub mod sinks;
#[cfg(feature = "dashboard")]
pub mod web;

#[cfg(feature = "dashboard")]
pub use web::packet_data::build_packet_data;

// ---------------------------------------------------------------------------
// Shared helper functions used by both the binary (main.rs) and the pipeline
// workers. Placed here so they're accessible from the library crate.
// ---------------------------------------------------------------------------

/// Extract anomaly-relevant fields from a parsed packet and feed them to the
/// anomaly detector.
pub fn maybe_analyze_anomaly(
    detector: &mut analysis::anomaly::AnomalyDetector,
    ts: f64,
    packet: &protocol::ParsedPacket<'_>,
) -> Result<Vec<analysis::anomaly::Alert>, std::io::Error> {
    detector.advance_time(ts);
    let (src_ip, dst_ip, skip_flow) = match &packet.network {
        Some(protocol::NetworkHeader::Ipv4(hdr)) => {
            let skip = hdr.fragment_offset() != 0;
            (
                std::net::IpAddr::V4(hdr.src_addr()),
                std::net::IpAddr::V4(hdr.dst_addr()),
                skip,
            )
        }
        Some(protocol::NetworkHeader::Ipv6(hdr)) => (
            std::net::IpAddr::V6(hdr.src_addr()),
            std::net::IpAddr::V6(hdr.dst_addr()),
            hdr.is_non_initial_fragment(),
        ),
        Some(protocol::NetworkHeader::Arp(_)) => return Ok(Vec::new()),
        None => return Ok(Vec::new()),
    };

    if skip_flow {
        return Ok(Vec::new());
    }

    let (src_port, dst_port, proto, tcp_syn, tcp_ack) = match &packet.transport {
        Some(protocol::TransportHeader::Tcp(hdr)) => (
            hdr.src_port(),
            hdr.dst_port(),
            flow::FlowProtocol::Tcp,
            hdr.syn(),
            hdr.ack(),
        ),
        Some(protocol::TransportHeader::Udp(hdr)) => (
            hdr.src_port(),
            hdr.dst_port(),
            flow::FlowProtocol::Udp,
            false,
            false,
        ),
        _ => return Ok(Vec::new()),
    };

    let src = flow::Endpoint {
        ip: src_ip,
        port: src_port,
    };
    let dst = flow::Endpoint {
        ip: dst_ip,
        port: dst_port,
    };

    detector.observe(ts, proto, src, dst, tcp_syn, tcp_ack)
}
