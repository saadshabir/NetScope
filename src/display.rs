//! Packet display / pretty-printing for the CLI.
//!
//! Formats parsed packets into human-readable one-line summaries
//! and optional detailed views with hex dumps.

use crate::packet_format;
use crate::protocol::{self, LinkHeader, NetworkHeader, ParsedPacket, TransportHeader, ethernet};

fn build_packet_summary_line(
    index: u64,
    timestamp: f64,
    packet: &ParsedPacket<'_>,
    dns: Option<&protocol::dns::DnsMessage<'_>>,
    tls: Option<&protocol::tls::TlsClientHelloInfo>,
) -> String {
    let ts = packet_format::format_timestamp(timestamp);

    // Build the summary line
    let mut summary = format!("#{:<6} {} Link: {}", index, ts, packet.link);

    // VLAN info
    if let Some(vlan) = &packet.vlan_stack {
        let tags = vlan.as_slice();
        if !tags.is_empty() {
            summary.push_str(" VLAN:");
            for (idx, tag) in tags.iter().enumerate() {
                if idx > 0 {
                    summary.push('/');
                }
                summary.push_str(&tag.vlan_id.to_string());
            }
            if vlan.is_truncated() {
                summary.push_str(" (truncated)");
            }
        }
    }

    // Network layer
    if let Some(net) = &packet.network {
        match net {
            NetworkHeader::Ipv4(hdr) => {
                summary.push_str(&format!(" | IPv4: {}", hdr));
            }
            NetworkHeader::Ipv6(hdr) => {
                summary.push_str(&format!(" | IPv6: {}", hdr));
            }
            NetworkHeader::Arp(hdr) => {
                summary.push_str(&format!(" | ARP: {}", hdr));
            }
        }
    }

    // Transport layer
    if let Some(transport) = &packet.transport {
        match transport {
            TransportHeader::Tcp(hdr) => {
                summary.push_str(&format!(" | TCP {}", hdr));
                if let Some(tls) = tls {
                    summary.push_str(&format!(" | TLS ClientHello sni={}", tls.sni));
                }
            }
            TransportHeader::Udp(hdr) => {
                summary.push_str(&format!(" | UDP {}", hdr));
                if let Some(dns) = dns {
                    summary.push_str(&format!(" | DNS {}", protocol::dns::brief_summary(dns)));
                }
            }
            TransportHeader::Icmp(hdr) => {
                summary.push_str(&format!(" | ICMP {}", hdr));
            }
            TransportHeader::Icmpv6(hdr) => {
                summary.push_str(&format!(" | ICMPv6 {}", hdr));
            }
        }
    }

    if let Some(error) = &packet.transport_parse_error {
        summary.push_str(&format!(" | malformed transport: {}", error));
    } else if packet.unsupported {
        summary.push_str(" | unsupported protocol payload");
    }

    // Payload size
    if !packet.payload.is_empty() {
        summary.push_str(&format!(" | payload: {} bytes", packet.payload.len()));
    }

    summary
}

/// Print a one-line summary of a parsed packet.
pub fn print_packet_summary(index: u64, timestamp: f64, packet: &ParsedPacket<'_>) {
    let (dns_msg, tls_info) = packet_format::parse_dns_and_tls(packet);

    let summary = build_packet_summary_line(
        index,
        timestamp,
        packet,
        dns_msg.as_ref(),
        tls_info.as_ref(),
    );
    println!("{}", summary);
}

/// Print a detailed view of a parsed packet, including hex dump.
pub fn print_packet_detail(index: u64, timestamp: f64, raw_data: &[u8], packet: &ParsedPacket<'_>) {
    let (dns_msg, tls_info) = packet_format::parse_dns_and_tls(packet);

    println!("{}", "=".repeat(80));
    let summary = build_packet_summary_line(
        index,
        timestamp,
        packet,
        dns_msg.as_ref(),
        tls_info.as_ref(),
    );
    println!("{}", summary);
    println!("{}", "-".repeat(80));

    // Link-layer details
    println!("  Link:");
    match &packet.link {
        LinkHeader::Ethernet(hdr) => {
            println!("    Type:        Ethernet");
            println!("    Source:      {}", ethernet::format_mac(hdr.src_mac()));
            println!("    Destination: {}", ethernet::format_mac(hdr.dst_mac()));
            println!(
                "    EtherType:   {} (0x{:04x})",
                hdr.ether_type(),
                hdr.ether_type_raw()
            );
        }
        LinkHeader::LinuxSll(hdr) => {
            println!("    Type:        Linux SLL");
            println!(
                "    Packet Type: {} ({})",
                hdr.packet_type_label(),
                hdr.packet_type_raw()
            );
            println!("    ARPHRD:      {}", hdr.arphrd_type_raw());
            println!("    Address:     {}", format_link_address(hdr.address()));
            println!(
                "    Protocol:    {} (0x{:04x})",
                hdr.protocol(),
                hdr.protocol_raw()
            );
        }
        LinkHeader::Loopback(hdr) => {
            println!("    Type:        Loopback");
            println!(
                "    Family:      {} ({})",
                hdr.family_label(),
                hdr.family_raw()
            );
            let encoding = match hdr.byte_order() {
                protocol::loopback::LoopbackByteOrder::Native => "native-endian",
                protocol::loopback::LoopbackByteOrder::BigEndian => "big-endian",
            };
            println!("    Encoding:    {}", encoding);
        }
        LinkHeader::RawIp => {
            println!("    Type:        Raw IP");
        }
    }

    if let Some(vlan) = &packet.vlan_stack {
        let tags = vlan.as_slice();
        if !tags.is_empty() {
            println!("  VLAN:");
            for (idx, tag) in tags.iter().enumerate() {
                println!("    Tag {}:", idx + 1);
                println!("      ID:       {}", tag.vlan_id);
                println!("      Priority: {}", tag.priority);
                println!("      DEI:      {}", tag.dei);
            }
            if vlan.is_truncated() {
                println!("    (truncated)");
            }
        }
    }

    // Network layer details
    if let Some(net) = &packet.network {
        match net {
            NetworkHeader::Ipv4(hdr) => {
                println!("  IPv4:");
                println!("    Source:       {}", hdr.src_addr());
                println!("    Destination:  {}", hdr.dst_addr());
                println!(
                    "    Protocol:     {} ({})",
                    hdr.protocol(),
                    hdr.protocol_raw()
                );
                println!("    TTL:          {}", hdr.ttl());
                println!("    Total Length: {}", hdr.total_length());
                println!("    ID:           0x{:04x}", hdr.identification());
                println!(
                    "    Flags:        DF={} MF={}",
                    hdr.dont_fragment(),
                    hdr.more_fragments()
                );
                println!("    Frag Offset:  {}", hdr.fragment_offset());
                println!("    DSCP:         {}", hdr.dscp());
                println!("    ECN:          {}", hdr.ecn());
                println!(
                    "    Checksum:     0x{:04x} (valid: {})",
                    hdr.checksum(),
                    hdr.verify_checksum()
                );
            }
            NetworkHeader::Ipv6(hdr) => {
                println!("  IPv6:");
                println!("    Source:       {}", hdr.src_addr());
                println!("    Destination:  {}", hdr.dst_addr());
                println!(
                    "    Next Header:  {} ({})",
                    hdr.next_header(),
                    hdr.next_header_raw()
                );
                println!("    Hop Limit:    {}", hdr.hop_limit());
                println!("    Payload Len:  {}", hdr.payload_length());
                println!("    Traffic Class:{}", hdr.traffic_class());
                println!("    Flow Label:   0x{:05x}", hdr.flow_label());
            }
            NetworkHeader::Arp(hdr) => {
                println!("  ARP:");
                println!(
                    "    Hardware Type:{} ({})",
                    hdr.hardware_type_label(),
                    hdr.hardware_type()
                );
                println!(
                    "    Protocol Type:{} (0x{:04x})",
                    hdr.protocol_type_label(),
                    hdr.protocol_type()
                );
                println!(
                    "    Address Lens: hlen={} plen={}",
                    hdr.hardware_len(),
                    hdr.protocol_len()
                );
                println!(
                    "    Operation:    {} ({})",
                    hdr.operation(),
                    hdr.operation_raw()
                );
                println!("    Sender HW:    {}", hdr.sender_hardware_display());
                println!("    Sender Proto: {}", hdr.sender_protocol_display());
                println!("    Target HW:    {}", hdr.target_hardware_display());
                println!("    Target Proto: {}", hdr.target_protocol_display());
            }
        }
    }

    // Transport layer details
    if let Some(transport) = &packet.transport {
        match transport {
            TransportHeader::Tcp(hdr) => {
                println!("  TCP:");
                println!("    Source Port:  {}", hdr.src_port());
                println!("    Dest Port:    {}", hdr.dst_port());
                println!("    Seq:          {}", hdr.sequence_number());
                println!("    Ack:          {}", hdr.ack_number());
                println!("    Flags:        {}", hdr.flags_string());
                println!("    Window:       {}", hdr.window_size());
                println!("    Checksum:     0x{:04x}", hdr.checksum());
                println!(
                    "    Data Offset:  {} ({} bytes)",
                    hdr.data_offset(),
                    hdr.header_len()
                );

                if let Some(tls) = &tls_info {
                    println!("  TLS:");
                    println!("    Type:         ClientHello");
                    println!("    Legacy Ver:   0x{:04x}", tls.legacy_version);
                    println!("    SNI:          {}", tls.sni);
                }
            }
            TransportHeader::Udp(hdr) => {
                println!("  UDP:");
                println!("    Source Port:  {}", hdr.src_port());
                println!("    Dest Port:    {}", hdr.dst_port());
                println!("    Length:       {}", hdr.length());
                println!("    Checksum:     0x{:04x}", hdr.checksum());

                if let Some(dns) = &dns_msg {
                    println!("  DNS:");
                    println!("    ID:           0x{:04x}", dns.id());
                    println!(
                        "    Message Type: {}",
                        if dns.is_response() {
                            "Response"
                        } else {
                            "Query"
                        }
                    );
                    println!(
                        "    Opcode/RCode: {}/{}",
                        dns.opcode_name(),
                        dns.rcode_name()
                    );
                    println!("    Flags:        {}", dns.flags_string());
                    println!(
                        "    Counts:       qd={} an={} ns={} ar={}",
                        dns.question_count(),
                        dns.answer_count(),
                        dns.authority_count(),
                        dns.additional_count()
                    );

                    match dns.parse_sections(2, 3, 0, 0) {
                        Ok(sections) => {
                            for (i, q) in sections.questions.iter().enumerate() {
                                let qname =
                                    q.name().unwrap_or_else(|_| "<invalid-name>".to_string());
                                println!(
                                    "    Question {}:   {} {} ({})",
                                    i + 1,
                                    q.qtype_label(),
                                    qname,
                                    q.qclass_label()
                                );
                            }

                            for (i, rr) in sections.answers.iter().enumerate() {
                                println!("    Answer {}:     {}", i + 1, rr.summary());
                            }
                        }
                        Err(err) => {
                            println!("    Parse Note:    section parse failed: {}", err);
                        }
                    }
                }
            }
            TransportHeader::Icmp(hdr) => {
                println!("  ICMP:");
                println!(
                    "    Type:     {} ({})",
                    hdr.icmp_type(),
                    hdr.icmp_type_raw()
                );
                println!("    Code:     {}", hdr.code());
                println!("    Checksum: 0x{:04x}", hdr.checksum());
            }
            TransportHeader::Icmpv6(hdr) => {
                println!("  ICMPv6:");
                println!(
                    "    Type:     {} ({})",
                    hdr.icmp_type(),
                    hdr.icmp_type_raw()
                );
                println!("    Code:     {}", hdr.code());
                println!("    Checksum: 0x{:04x}", hdr.checksum());
                if matches!(
                    hdr.icmp_type(),
                    protocol::icmpv6::Icmpv6Type::EchoRequest
                        | protocol::icmpv6::Icmpv6Type::EchoReply
                ) {
                    println!("    ID:       {}", hdr.identifier());
                    println!("    Seq:      {}", hdr.sequence());
                }
            }
        }
    }

    // Hex dump of the raw packet
    println!("  Hex Dump ({} bytes):", raw_data.len());
    print_hex_dump(raw_data);
    println!();
}

/// Print a hex dump with offsets, hex values, and ASCII representation.
fn print_hex_dump(data: &[u8]) {
    let display_len = data.len().min(256);
    let hex = packet_format::format_hex_dump(&data[..display_len]);
    for line in hex.lines() {
        println!("    {}", line);
    }
    if display_len < data.len() {
        println!("    ... ({} bytes remaining)", data.len() - display_len);
    }
}

fn format_link_address(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }

    if bytes.len() == 6 {
        return ethernet::format_mac(bytes);
    }

    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Print a compact one-line summary for a packet that failed to parse.
pub fn print_parse_error(
    index: u64,
    timestamp: f64,
    data_len: usize,
    error: &protocol::ParseError,
) {
    let ts = packet_format::format_timestamp(timestamp);
    println!(
        "#{:<6} {} [PARSE ERROR] {} bytes: {}",
        index, ts, data_len, error
    );
}
