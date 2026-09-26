//! NetScope library crate — re-exports modules for benchmarks and tests.

pub mod analysis;
pub mod capture;
pub mod config;
pub mod display;
pub mod flow;
pub mod jsonl;
pub mod memory;
pub mod metrics;
pub mod packet_format;
pub mod pipeline;
pub mod protocol;
pub mod run_summary;
pub mod sinks;
pub mod web;

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

/// Build a `PacketSample` + `StoredPacket` pair for the web dashboard.
pub fn build_packet_data(
    id: u64,
    ts: f64,
    raw_data: &[u8],
    parsed: &protocol::ParsedPacket<'_>,
    max_payload_bytes: usize,
) -> (web::messages::PacketSample, web::messages::StoredPacket) {
    let (dns, tls) = packet_format::parse_dns_and_tls(parsed);
    let (proto_str, src_str, dst_str, info_str) =
        packet_format::summarise_packet(parsed, dns.as_ref(), tls.as_ref());

    let sample = web::messages::PacketSample {
        id,
        ts,
        len: raw_data.len(),
        protocol: proto_str,
        src: src_str,
        dst: dst_str,
        info: info_str,
    };

    let mut layers = Vec::new();

    // Link layer
    push_link_layer(&mut layers, &parsed.link);

    // VLAN
    push_vlan_layer(&mut layers, parsed.vlan_stack.as_ref());

    // Network
    push_network_layer(&mut layers, parsed.network.as_ref());

    // Transport
    push_transport_layers(
        &mut layers,
        parsed.transport.as_ref(),
        dns.as_ref(),
        tls.as_ref(),
    );

    // Hex dump (truncated)
    let dump_len = raw_data.len().min(max_payload_bytes);
    let hex_dump = packet_format::format_hex_dump(&raw_data[..dump_len]);

    let stored = web::messages::StoredPacket {
        id,
        ts,
        layers,
        hex_dump,
    };

    (sample, stored)
}

fn push_link_layer<'a>(
    layers: &mut Vec<web::messages::LayerDetail>,
    link: &protocol::LinkHeader<'a>,
) {
    match link {
        protocol::LinkHeader::Ethernet(eth) => {
            layers.push(web::messages::LayerDetail {
                name: "Ethernet".into(),
                fields: vec![
                    (
                        "Source".into(),
                        protocol::ethernet::format_mac(eth.src_mac()),
                    ),
                    (
                        "Destination".into(),
                        protocol::ethernet::format_mac(eth.dst_mac()),
                    ),
                    ("EtherType".into(), format!("{}", eth.ether_type())),
                ],
            });
        }
        protocol::LinkHeader::LinuxSll(sll) => {
            layers.push(web::messages::LayerDetail {
                name: "Linux SLL".into(),
                fields: vec![
                    (
                        "Packet Type".into(),
                        format!("{} ({})", sll.packet_type_label(), sll.packet_type_raw()),
                    ),
                    ("ARPHRD".into(), format!("{}", sll.arphrd_type_raw())),
                    ("Address Length".into(), format!("{}", sll.address_length())),
                    ("Protocol".into(), format!("{}", sll.protocol())),
                ],
            });
        }
        protocol::LinkHeader::Loopback(loopback) => {
            let encoding = match loopback.byte_order() {
                protocol::loopback::LoopbackByteOrder::Native => "native-endian",
                protocol::loopback::LoopbackByteOrder::BigEndian => "big-endian",
            };
            layers.push(web::messages::LayerDetail {
                name: "Loopback".into(),
                fields: vec![
                    (
                        "Family".into(),
                        format!("{} ({})", loopback.family_label(), loopback.family_raw()),
                    ),
                    ("Encoding".into(), encoding.to_string()),
                ],
            });
        }
        protocol::LinkHeader::RawIp => {
            layers.push(web::messages::LayerDetail {
                name: "Raw IP".into(),
                fields: vec![("Encapsulation".into(), "None (L3 starts at byte 0)".into())],
            });
        }
    }
}

fn vlan_tag_kind(tag_type: protocol::EtherType) -> Option<&'static str> {
    match tag_type {
        protocol::EtherType::VlanTagged => Some("802.1Q"),
        protocol::EtherType::VlanService => Some("802.1ad"),
        _ => None,
    }
}

fn vlan_layer_name(idx: usize, tag_type: protocol::EtherType, total: usize) -> String {
    let kind = vlan_tag_kind(tag_type);
    if total == 1 {
        match kind {
            Some(kind) => format!("VLAN ({})", kind),
            None => "VLAN".to_string(),
        }
    } else {
        match kind {
            Some(kind) => format!("VLAN Tag {} ({})", idx + 1, kind),
            None => format!("VLAN Tag {}", idx + 1),
        }
    }
}

fn push_vlan_layer(
    layers: &mut Vec<web::messages::LayerDetail>,
    vlan: Option<&protocol::VlanStack>,
) {
    if let Some(vlan) = vlan {
        let tags = vlan.as_slice();
        if tags.is_empty() {
            return;
        }

        for (idx, (tag, tag_type)) in tags.iter().zip(vlan.tag_types().iter()).enumerate() {
            layers.push(web::messages::LayerDetail {
                name: vlan_layer_name(idx, *tag_type, tags.len()),
                fields: vec![
                    ("VLAN ID".into(), format!("{}", tag.vlan_id)),
                    ("Priority".into(), format!("{}", tag.priority)),
                    ("DEI".into(), format!("{}", tag.dei)),
                ],
            });
        }

        if vlan.is_truncated() {
            layers.push(web::messages::LayerDetail {
                name: "VLAN Tags".into(),
                fields: vec![(
                    "Truncated".into(),
                    format!("true (max {})", protocol::VLAN_STACK_CAPACITY),
                )],
            });
        }
    }
}

fn push_network_layer<'a>(
    layers: &mut Vec<web::messages::LayerDetail>,
    network: Option<&protocol::NetworkHeader<'a>>,
) {
    if let Some(net) = network {
        match net {
            protocol::NetworkHeader::Ipv4(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "IPv4".into(),
                    fields: vec![
                        ("Source".into(), format!("{}", hdr.src_addr())),
                        ("Destination".into(), format!("{}", hdr.dst_addr())),
                        ("Protocol".into(), format!("{}", hdr.protocol())),
                        ("TTL".into(), format!("{}", hdr.ttl())),
                        ("Total Length".into(), format!("{}", hdr.total_length())),
                        ("ID".into(), format!("0x{:04x}", hdr.identification())),
                        (
                            "Flags".into(),
                            format!("DF={} MF={}", hdr.dont_fragment(), hdr.more_fragments()),
                        ),
                        (
                            "Fragment Offset".into(),
                            format!("{}", hdr.fragment_offset()),
                        ),
                        (
                            "Checksum".into(),
                            format!(
                                "0x{:04x} ({})",
                                hdr.checksum(),
                                if hdr.verify_checksum() {
                                    "valid"
                                } else {
                                    "invalid"
                                }
                            ),
                        ),
                    ],
                });
            }
            protocol::NetworkHeader::Ipv6(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "IPv6".into(),
                    fields: vec![
                        ("Source".into(), format!("{}", hdr.src_addr())),
                        ("Destination".into(), format!("{}", hdr.dst_addr())),
                        ("Next Header".into(), format!("{}", hdr.next_header())),
                        ("Hop Limit".into(), format!("{}", hdr.hop_limit())),
                        ("Payload Length".into(), format!("{}", hdr.payload_length())),
                        ("Flow Label".into(), format!("0x{:05x}", hdr.flow_label())),
                    ],
                });
            }
            protocol::NetworkHeader::Arp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "ARP".into(),
                    fields: vec![
                        (
                            "Hardware Type".into(),
                            format!("{} ({})", hdr.hardware_type_label(), hdr.hardware_type()),
                        ),
                        (
                            "Protocol Type".into(),
                            format!(
                                "{} (0x{:04x})",
                                hdr.protocol_type_label(),
                                hdr.protocol_type()
                            ),
                        ),
                        (
                            "Address Lengths".into(),
                            format!("hlen={} plen={}", hdr.hardware_len(), hdr.protocol_len()),
                        ),
                        (
                            "Operation".into(),
                            format!("{} ({})", hdr.operation(), hdr.operation_raw()),
                        ),
                        ("Sender Hardware".into(), hdr.sender_hardware_display()),
                        ("Sender Protocol".into(), hdr.sender_protocol_display()),
                        ("Target Hardware".into(), hdr.target_hardware_display()),
                        ("Target Protocol".into(), hdr.target_protocol_display()),
                    ],
                });
            }
        }
    }
}

fn push_transport_layers<'a>(
    layers: &mut Vec<web::messages::LayerDetail>,
    transport: Option<&protocol::TransportHeader<'a>>,
    dns: Option<&protocol::dns::DnsMessage<'a>>,
    tls: Option<&protocol::tls::TlsClientHelloInfo>,
) {
    if let Some(transport) = transport {
        match transport {
            protocol::TransportHeader::Tcp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "TCP".into(),
                    fields: vec![
                        ("Source Port".into(), format!("{}", hdr.src_port())),
                        ("Destination Port".into(), format!("{}", hdr.dst_port())),
                        ("Sequence".into(), format!("{}", hdr.sequence_number())),
                        ("Acknowledgment".into(), format!("{}", hdr.ack_number())),
                        ("Flags".into(), hdr.flags_string()),
                        ("Window".into(), format!("{}", hdr.window_size())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });

                if let Some(tls) = tls {
                    layers.push(web::messages::LayerDetail {
                        name: "TLS".into(),
                        fields: vec![
                            ("Type".into(), "ClientHello".into()),
                            (
                                "Legacy Version".into(),
                                format!("0x{:04x}", tls.legacy_version),
                            ),
                            ("SNI".into(), tls.sni.clone()),
                        ],
                    });
                }
            }
            protocol::TransportHeader::Udp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "UDP".into(),
                    fields: vec![
                        ("Source Port".into(), format!("{}", hdr.src_port())),
                        ("Destination Port".into(), format!("{}", hdr.dst_port())),
                        ("Length".into(), format!("{}", hdr.length())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });

                if let Some(dns) = dns {
                    let mut fields = vec![
                        ("ID".into(), format!("0x{:04x}", dns.id())),
                        (
                            "Message Type".into(),
                            if dns.is_response() {
                                "Response".to_string()
                            } else {
                                "Query".to_string()
                            },
                        ),
                        ("Opcode".into(), dns.opcode_name().to_string()),
                        ("RCode".into(), dns.rcode_name().to_string()),
                        ("Flags".into(), dns.flags_string()),
                        ("Questions".into(), format!("{}", dns.question_count())),
                        ("Answers".into(), format!("{}", dns.answer_count())),
                        ("Authorities".into(), format!("{}", dns.authority_count())),
                        ("Additionals".into(), format!("{}", dns.additional_count())),
                    ];

                    match dns.parse_sections(2, 2, 1, 1) {
                        Ok(sections) => {
                            if let Some(question) = sections.questions.first() {
                                let qname = question
                                    .name()
                                    .unwrap_or_else(|_| "<invalid-name>".to_string());
                                fields.push((
                                    "Question".into(),
                                    format!("{} {}", question.qtype_label(), qname),
                                ));
                                fields.push(("QClass".into(), question.qclass_label()));
                            }

                            if !sections.answers.is_empty() {
                                let answer_summaries: Vec<String> =
                                    sections.answers.iter().map(|rr| rr.summary()).collect();
                                fields.push((
                                    "Answers (sample)".into(),
                                    answer_summaries.join(" | "),
                                ));
                            }
                        }
                        Err(err) => {
                            fields.push((
                                "Parse Note".into(),
                                format!("section parse failed: {}", err),
                            ));
                        }
                    }

                    layers.push(web::messages::LayerDetail {
                        name: "DNS".into(),
                        fields,
                    });
                }
            }
            protocol::TransportHeader::Icmp(hdr) => {
                layers.push(web::messages::LayerDetail {
                    name: "ICMP".into(),
                    fields: vec![
                        ("Type".into(), format!("{}", hdr.icmp_type())),
                        ("Code".into(), format!("{}", hdr.code())),
                        ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                    ],
                });
            }
            protocol::TransportHeader::Icmpv6(hdr) => {
                let mut fields = vec![
                    ("Type".into(), format!("{}", hdr.icmp_type())),
                    ("Code".into(), format!("{}", hdr.code())),
                    ("Checksum".into(), format!("0x{:04x}", hdr.checksum())),
                ];

                if matches!(
                    hdr.icmp_type(),
                    protocol::icmpv6::Icmpv6Type::EchoRequest
                        | protocol::icmpv6::Icmpv6Type::EchoReply
                ) {
                    fields.push(("Identifier".into(), format!("{}", hdr.identifier())));
                    fields.push(("Sequence".into(), format!("{}", hdr.sequence())));
                }

                layers.push(web::messages::LayerDetail {
                    name: "ICMPv6".into(),
                    fields,
                });
            }
        }
    }
}
