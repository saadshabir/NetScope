pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod loopback;
pub mod sll;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::fmt;
use std::net::IpAddr;

/// Supported datalink types for packet parsing/routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    LinuxSll,
    LoopbackNull,
    LoopbackLoop,
    RawIp,
    Unsupported(i32),
}

impl LinkType {
    pub fn from_pcap_value(value: i32) -> Self {
        match value {
            1 => LinkType::Ethernet,
            113 => LinkType::LinuxSll,
            0 => LinkType::LoopbackNull,
            108 => LinkType::LoopbackLoop,
            12 | 101 => LinkType::RawIp,
            other => LinkType::Unsupported(other),
        }
    }

    pub fn as_pcap_value(self) -> i32 {
        match self {
            LinkType::Ethernet => 1,
            LinkType::LinuxSll => 113,
            LinkType::LoopbackNull => 0,
            LinkType::LoopbackLoop => 108,
            LinkType::RawIp => 12,
            LinkType::Unsupported(value) => value,
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkType::Ethernet => write!(f, "Ethernet"),
            LinkType::LinuxSll => write!(f, "Linux SLL"),
            LinkType::LoopbackNull => write!(f, "Loopback (NULL)"),
            LinkType::LoopbackLoop => write!(f, "Loopback (LOOP)"),
            LinkType::RawIp => write!(f, "Raw IP"),
            LinkType::Unsupported(value) => write!(f, "Unsupported({})", value),
        }
    }
}

/// EtherType constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
    Arp = 0x0806,
    VlanTagged = 0x8100,
    VlanService = 0x88A8,
    Mpls = 0x8847,
    MplsMulticast = 0x8848,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x8100 => EtherType::VlanTagged,
            0x88A8 => EtherType::VlanService,
            0x8847 => EtherType::Mpls,
            0x8848 => EtherType::MplsMulticast,
            other => EtherType::Unknown(other),
        }
    }
}

// Remove repr(u16) since we have a variant with data
impl EtherType {
    pub fn as_u16(&self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::VlanTagged => 0x8100,
            EtherType::VlanService => 0x88A8,
            EtherType::Mpls => 0x8847,
            EtherType::MplsMulticast => 0x8848,
            EtherType::Unknown(v) => *v,
        }
    }

    pub fn is_vlan_tag(self) -> bool {
        matches!(self, EtherType::VlanTagged | EtherType::VlanService)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp => write!(f, "ARP"),
            EtherType::VlanTagged => write!(f, "802.1Q VLAN"),
            EtherType::VlanService => write!(f, "802.1ad VLAN"),
            EtherType::Mpls => write!(f, "MPLS"),
            EtherType::MplsMulticast => write!(f, "MPLS Multicast"),
            EtherType::Unknown(v) => write!(f, "Unknown(0x{:04x})", v),
        }
    }
}

/// IP Protocol numbers (subset relevant to our use case)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Fragment,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            44 => IpProtocol::Fragment,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::Icmp => write!(f, "ICMP"),
            IpProtocol::Tcp => write!(f, "TCP"),
            IpProtocol::Udp => write!(f, "UDP"),
            IpProtocol::Icmpv6 => write!(f, "ICMPv6"),
            IpProtocol::Fragment => write!(f, "IPv6-Fragment"),
            IpProtocol::Unknown(v) => write!(f, "Proto({})", v),
        }
    }
}

/// Errors from protocol parsing
#[derive(Debug)]
pub enum ParseError {
    /// Not enough bytes to parse the header
    TooShort { expected: usize, actual: usize },
    /// Invalid header values
    InvalidHeader(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { expected, actual } => {
                write!(
                    f,
                    "packet too short: need {} bytes, got {}",
                    expected, actual
                )
            }
            ParseError::InvalidHeader(msg) => write!(f, "invalid header: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// A fully parsed packet, referencing the original byte slice
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub link: LinkHeader<'a>,
    pub vlan: Option<VlanTag>,
    pub vlan_stack: Option<VlanStack>,
    pub network: Option<NetworkHeader<'a>>,
    pub transport: Option<TransportHeader<'a>>,
    /// A malformed recognized transport header, retained alongside the valid
    /// link/network headers so callers can report partial decoding accurately.
    pub transport_parse_error: Option<ParseError>,
    /// The frame carried an EtherType or IP protocol this parser does not
    /// support. A recognized link/network header may still be available.
    pub unsupported: bool,
    pub payload: &'a [u8],
}

/// Parsed link-layer header.
#[derive(Debug)]
pub enum LinkHeader<'a> {
    Ethernet(ethernet::EthernetHeader<'a>),
    LinuxSll(sll::LinuxSllHeader<'a>),
    Loopback(loopback::LoopbackHeader<'a>),
    RawIp,
}

impl fmt::Display for LinkHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkHeader::Ethernet(h) => write!(f, "{}", h),
            LinkHeader::LinuxSll(h) => write!(f, "{}", h),
            LinkHeader::Loopback(h) => write!(f, "{}", h),
            LinkHeader::RawIp => write!(f, "Raw IP"),
        }
    }
}

/// VLAN tag (802.1Q or 802.1ad)
#[derive(Debug, Clone, Copy, Default)]
pub struct VlanTag {
    pub priority: u8,
    pub dei: bool,
    pub vlan_id: u16,
}

pub const VLAN_STACK_CAPACITY: usize = 4;

/// Fixed-capacity VLAN tag stack (outer -> inner).
#[derive(Debug, Clone, Copy)]
pub struct VlanStack {
    tags: [VlanTag; VLAN_STACK_CAPACITY],
    tag_types: [EtherType; VLAN_STACK_CAPACITY],
    len: usize,
    truncated: bool,
}

impl Default for VlanStack {
    fn default() -> Self {
        Self::new()
    }
}

impl VlanStack {
    pub fn new() -> Self {
        Self {
            tags: [VlanTag::default(); VLAN_STACK_CAPACITY],
            tag_types: [EtherType::VlanTagged; VLAN_STACK_CAPACITY],
            len: 0,
            truncated: false,
        }
    }

    pub fn push(&mut self, tag: VlanTag) {
        let _ = self.push_with_type(tag, EtherType::VlanTagged);
    }

    pub fn push_with_type(&mut self, tag: VlanTag, tag_type: EtherType) -> bool {
        if self.len < VLAN_STACK_CAPACITY {
            self.tags[self.len] = tag;
            self.tag_types[self.len] = tag_type;
            self.len += 1;
            true
        } else {
            self.truncated = true;
            false
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[VlanTag] {
        &self.tags[..self.len]
    }

    pub fn tag_types(&self) -> &[EtherType] {
        &self.tag_types[..self.len]
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Network layer header
#[derive(Debug)]
pub enum NetworkHeader<'a> {
    Ipv4(ipv4::Ipv4Header<'a>),
    Ipv6(ipv6::Ipv6Header<'a>),
    Arp(arp::ArpPacket<'a>),
}

impl<'a> NetworkHeader<'a> {
    pub fn src_ip(&self) -> Option<IpAddr> {
        match self {
            NetworkHeader::Ipv4(h) => Some(IpAddr::V4(h.src_addr())),
            NetworkHeader::Ipv6(h) => Some(IpAddr::V6(h.src_addr())),
            NetworkHeader::Arp(h) => h.sender_ipv4_addr().map(IpAddr::V4),
        }
    }

    pub fn dst_ip(&self) -> Option<IpAddr> {
        match self {
            NetworkHeader::Ipv4(h) => Some(IpAddr::V4(h.dst_addr())),
            NetworkHeader::Ipv6(h) => Some(IpAddr::V6(h.dst_addr())),
            NetworkHeader::Arp(h) => h.target_ipv4_addr().map(IpAddr::V4),
        }
    }

    pub fn protocol(&self) -> Option<IpProtocol> {
        match self {
            NetworkHeader::Ipv4(h) => Some(h.protocol()),
            NetworkHeader::Ipv6(h) => Some(h.next_header()),
            NetworkHeader::Arp(_) => None,
        }
    }
}

/// Transport layer header
#[derive(Debug)]
pub enum TransportHeader<'a> {
    Tcp(tcp::TcpHeader<'a>),
    Udp(udp::UdpHeader<'a>),
    Icmp(icmp::IcmpHeader<'a>),
    Icmpv6(icmpv6::Icmpv6Header<'a>),
}

/// Parse a complete packet from raw bytes.
/// This is the main entry point for the protocol stack.
#[inline]
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    parse_packet_with_linktype(data, LinkType::Ethernet)
}

/// Parse a complete packet from raw bytes using a specific link type.
#[inline]
pub fn parse_packet_with_linktype(
    data: &[u8],
    link_type: LinkType,
) -> Result<ParsedPacket<'_>, ParseError> {
    let (link, mut remaining, mut ether_type) = match link_type {
        LinkType::Ethernet => {
            let eth = ethernet::EthernetHeader::parse(data)?;
            let payload = eth.payload();
            let ether_type = eth.ether_type();
            (LinkHeader::Ethernet(eth), payload, Some(ether_type))
        }
        LinkType::LinuxSll => {
            let sll = sll::LinuxSllHeader::parse(data)?;
            let payload = sll.payload();
            let ether_type = sll.protocol();
            (LinkHeader::LinuxSll(sll), payload, Some(ether_type))
        }
        LinkType::LoopbackNull => {
            let loopback = loopback::LoopbackHeader::parse_null(data)?;
            let payload = loopback.payload();
            (LinkHeader::Loopback(loopback), payload, None)
        }
        LinkType::LoopbackLoop => {
            let loopback = loopback::LoopbackHeader::parse_loop(data)?;
            let payload = loopback.payload();
            (LinkHeader::Loopback(loopback), payload, None)
        }
        LinkType::RawIp => (LinkHeader::RawIp, data, None),
        LinkType::Unsupported(value) => {
            return Err(ParseError::InvalidHeader(format!(
                "unsupported link type {}",
                value
            )));
        }
    };

    let mut vlan_stack: Option<VlanStack> = None;

    // Handle VLAN tagging (802.1Q / 802.1ad) for link types that surface EtherType.
    while let Some(link_ether_type) = ether_type {
        if !link_ether_type.is_vlan_tag() {
            break;
        }

        if remaining.len() < 4 {
            return Err(ParseError::TooShort {
                expected: 4,
                actual: remaining.len(),
            });
        }

        let tci = u16::from_be_bytes([remaining[0], remaining[1]]);
        let tag_type = link_ether_type;
        let tag = VlanTag {
            priority: (tci >> 13) as u8,
            dei: (tci >> 12) & 1 == 1,
            vlan_id: tci & 0x0FFF,
        };

        match vlan_stack.as_mut() {
            Some(stack) => {
                stack.push_with_type(tag, tag_type);
            }
            None => {
                let mut stack = VlanStack::new();
                stack.push_with_type(tag, tag_type);
                vlan_stack = Some(stack);
            }
        }

        ether_type = Some(EtherType::from(u16::from_be_bytes([
            remaining[2],
            remaining[3],
        ])));
        remaining = &remaining[4..];
    }

    let unsupported_link_payload = ether_type
        .is_some_and(|value| !matches!(value, EtherType::Ipv4 | EtherType::Ipv6 | EtherType::Arp));
    let (network, l4_data, ip_proto) = if let Some(link_ether_type) = ether_type {
        parse_network_from_ether_type(link_ether_type, remaining)?
    } else {
        parse_network_from_ip_payload(remaining)?
    };

    let non_initial_fragment = match &network {
        Some(NetworkHeader::Ipv4(header)) => header.fragment_offset() != 0,
        Some(NetworkHeader::Ipv6(header)) => header.is_non_initial_fragment(),
        Some(NetworkHeader::Arp(_)) | None => false,
    };
    let unsupported_network_payload = ether_type.is_none() && network.is_none();

    // Layer 4: Transport
    let (transport, payload, transport_parse_error) = if non_initial_fragment {
        // Later fragments do not contain the transport header. Keep their
        // network decode and payload, but do not report a malformed L4 header.
        (None, l4_data, None)
    } else {
        parse_transport(ip_proto, l4_data)
    };
    let unsupported_ip_protocol = matches!(
        ip_proto,
        Some(IpProtocol::Unknown(_) | IpProtocol::Fragment)
    );

    let vlan = vlan_stack
        .as_ref()
        .and_then(|stack| stack.as_slice().first().copied());

    Ok(ParsedPacket {
        link,
        vlan,
        vlan_stack,
        network,
        transport,
        transport_parse_error,
        unsupported: unsupported_link_payload
            || unsupported_network_payload
            || unsupported_ip_protocol
            || non_initial_fragment,
        payload,
    })
}

type NetworkParseResult<'a> =
    Result<(Option<NetworkHeader<'a>>, &'a [u8], Option<IpProtocol>), ParseError>;

#[inline]
fn parse_network_from_ether_type<'a>(
    ether_type: EtherType,
    remaining: &'a [u8],
) -> NetworkParseResult<'a> {
    let parsed = match ether_type {
        EtherType::Ipv4 => {
            let hdr = ipv4::Ipv4Header::parse(remaining)?;
            let proto = hdr.protocol();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv4(hdr)), payload, Some(proto))
        }
        EtherType::Ipv6 => {
            let hdr = ipv6::Ipv6Header::parse(remaining)?;
            let proto = hdr.next_header();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv6(hdr)), payload, Some(proto))
        }
        EtherType::Arp => {
            let hdr = arp::ArpPacket::parse(remaining)?;
            let payload = hdr.payload();
            (Some(NetworkHeader::Arp(hdr)), payload, None)
        }
        _ => (None, remaining, None),
    };

    Ok(parsed)
}

#[inline]
fn parse_network_from_ip_payload<'a>(remaining: &'a [u8]) -> NetworkParseResult<'a> {
    if remaining.is_empty() {
        return Err(ParseError::TooShort {
            expected: 1,
            actual: 0,
        });
    }

    let parsed = match remaining[0] >> 4 {
        4 => {
            let hdr = ipv4::Ipv4Header::parse(remaining)?;
            let proto = hdr.protocol();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv4(hdr)), payload, Some(proto))
        }
        6 => {
            let hdr = ipv6::Ipv6Header::parse(remaining)?;
            let proto = hdr.next_header();
            let payload = hdr.payload();
            (Some(NetworkHeader::Ipv6(hdr)), payload, Some(proto))
        }
        _ => (None, remaining, None),
    };

    Ok(parsed)
}

#[inline]
fn parse_transport<'a>(
    ip_proto: Option<IpProtocol>,
    l4_data: &'a [u8],
) -> (Option<TransportHeader<'a>>, &'a [u8], Option<ParseError>) {
    match ip_proto {
        Some(IpProtocol::Tcp) => match tcp::TcpHeader::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Tcp(hdr)), payload, None)
            }
            Err(err) => (None, l4_data, Some(err)),
        },
        Some(IpProtocol::Udp) => match udp::UdpHeader::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Udp(hdr)), payload, None)
            }
            Err(err) => (None, l4_data, Some(err)),
        },
        Some(IpProtocol::Icmp) => match icmp::IcmpHeader::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Icmp(hdr)), payload, None)
            }
            Err(err) => (None, l4_data, Some(err)),
        },
        Some(IpProtocol::Icmpv6) => match icmpv6::Icmpv6Header::parse(l4_data) {
            Ok(hdr) => {
                let payload = hdr.payload();
                (Some(TransportHeader::Icmpv6(hdr)), payload, None)
            }
            Err(err) => (None, l4_data, Some(err)),
        },
        _ => (None, l4_data, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_arp_payload_request() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
        payload.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
        payload.push(6); // hlen
        payload.push(4); // plen
        payload.extend_from_slice(&1u16.to_be_bytes()); // op = request
        payload.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sha
        payload.extend_from_slice(&[192, 168, 1, 10]); // spa
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // tha
        payload.extend_from_slice(&[192, 168, 1, 1]); // tpa
        payload
    }

    fn make_ethernet_arp_frame() -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x06, // EtherType = ARP
        ];
        frame.extend_from_slice(&make_arp_payload_request());
        frame
    }

    fn make_vlan_arp_frame() -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x81, 0x00, // EtherType = 802.1Q VLAN
            0x00, 0x2a, // TCI (vlan id 42)
            0x08, 0x06, // inner EtherType = ARP
        ];
        frame.extend_from_slice(&make_arp_payload_request());
        frame
    }

    fn make_qinq_arp_frame() -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x88, 0xa8, // EtherType = 802.1ad VLAN (S-tag)
            0x00, 0x64, // outer TCI (vlan id 100)
            0x81, 0x00, // inner EtherType = 802.1Q VLAN (C-tag)
            0x00, 0xc8, // inner TCI (vlan id 200)
            0x08, 0x06, // inner EtherType = ARP
        ];
        frame.extend_from_slice(&make_arp_payload_request());
        frame
    }

    fn make_tcp_ipv4_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20];
        pkt[0] = 0x45; // version + IHL
        pkt[2] = 0x00;
        pkt[3] = 0x28; // total length = 40 bytes
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50; // TCP data offset = 5 (20-byte header)
        pkt
    }

    fn make_ipv4_with_payload(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&[192, 0, 2, 10]);
        pkt[16..20].copy_from_slice(&[192, 0, 2, 20]);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn make_icmpv6_ipv6_payload(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        identifier: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + 8];
        pkt[0] = 0x60; // version
        pkt[4] = 0x00;
        pkt[5] = 0x08; // payload length = 8-byte ICMPv6 header
        pkt[6] = 58; // next header = ICMPv6
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src_ip);
        pkt[24..40].copy_from_slice(&dst_ip);

        // ICMPv6 echo request header
        pkt[40] = 128;
        pkt[41] = 0;
        pkt[44..46].copy_from_slice(&identifier.to_be_bytes());
        pkt[46..48].copy_from_slice(&sequence.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_raw_ip_ipv4_tcp() {
        let raw = make_tcp_ipv4_payload([192, 0, 2, 10], [192, 0, 2, 20], 12000, 443);
        let parsed = parse_packet_with_linktype(&raw, LinkType::RawIp).unwrap();

        assert!(matches!(parsed.link, LinkHeader::RawIp));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
        assert!(parsed.transport_parse_error.is_none());
        assert!(!parsed.unsupported);
    }

    #[test]
    fn malformed_tcp_and_udp_keep_partial_network_decode_and_are_classified() {
        let truncated_tcp = make_ipv4_with_payload(6, &[0x30, 0x39, 0x00, 0x50]);
        let tcp = parse_packet_with_linktype(&truncated_tcp, LinkType::RawIp).unwrap();
        assert!(matches!(tcp.network, Some(NetworkHeader::Ipv4(_))));
        assert!(tcp.transport.is_none());
        assert!(tcp.transport_parse_error.is_some());
        assert!(!tcp.unsupported);

        let truncated_udp = make_ipv4_with_payload(17, &[0x30, 0x39, 0x00, 0x35]);
        let udp = parse_packet_with_linktype(&truncated_udp, LinkType::RawIp).unwrap();
        assert!(matches!(udp.network, Some(NetworkHeader::Ipv4(_))));
        assert!(udp.transport.is_none());
        assert!(udp.transport_parse_error.is_some());
        assert!(!udp.unsupported);
    }

    #[test]
    fn non_initial_ipv4_fragment_is_unsupported_without_malformed_transport() {
        let mut fragment = make_ipv4_with_payload(6, &[0x30, 0x39, 0x00, 0x50]);
        fragment[6..8].copy_from_slice(&1u16.to_be_bytes());

        let parsed = parse_packet_with_linktype(&fragment, LinkType::RawIp).unwrap();

        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(parsed.transport.is_none());
        assert!(parsed.transport_parse_error.is_none());
        assert!(parsed.unsupported);
    }

    #[test]
    fn raw_ip_with_unrecognized_version_is_unsupported() {
        let parsed = parse_packet_with_linktype(&[0x70, 0, 0, 0], LinkType::RawIp).unwrap();

        assert!(parsed.network.is_none());
        assert!(parsed.transport_parse_error.is_none());
        assert!(parsed.unsupported);
    }

    #[test]
    fn truncated_vlan_is_a_parse_error() {
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x81, 0x00,
            0x00, 0x2a,
        ];
        let err = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { .. }));
    }

    #[test]
    fn parse_loopback_null_ipv4_tcp() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&2u32.to_ne_bytes()); // AF_INET
        pkt.extend_from_slice(&make_tcp_ipv4_payload(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            50000,
            8080,
        ));

        let parsed = parse_packet_with_linktype(&pkt, LinkType::LoopbackNull).unwrap();

        assert!(matches!(parsed.link, LinkHeader::Loopback(_)));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
    }

    #[test]
    fn parse_linux_sll_ipv4_tcp() {
        let mut pkt = vec![
            0x00, 0x00, // packet type = host
            0x00, 0x01, // ARPHRD = ethernet
            0x00, 0x06, // addr len = 6
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // addr
            0x08, 0x00, // protocol = IPv4
        ];
        pkt.extend_from_slice(&make_tcp_ipv4_payload(
            [10, 10, 0, 1],
            [10, 10, 0, 2],
            23456,
            80,
        ));

        let parsed = parse_packet_with_linktype(&pkt, LinkType::LinuxSll).unwrap();

        assert!(matches!(parsed.link, LinkHeader::LinuxSll(_)));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv4(_))));
        assert!(matches!(parsed.transport, Some(TransportHeader::Tcp(_))));
    }

    #[test]
    fn parse_raw_ip_ipv6_icmpv6() {
        let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let raw = make_icmpv6_ipv6_payload(src_ip, dst_ip, 0x1234, 0x000a);

        let parsed = parse_packet_with_linktype(&raw, LinkType::RawIp).unwrap();

        assert!(matches!(parsed.link, LinkHeader::RawIp));
        assert!(matches!(parsed.network, Some(NetworkHeader::Ipv6(_))));

        match parsed.transport {
            Some(TransportHeader::Icmpv6(hdr)) => {
                assert_eq!(hdr.icmp_type(), icmpv6::Icmpv6Type::EchoRequest);
                assert_eq!(hdr.identifier(), 0x1234);
                assert_eq!(hdr.sequence(), 0x000a);
            }
            _ => panic!("expected ICMPv6 transport header"),
        }
    }

    #[test]
    fn parse_ethernet_arp() {
        let frame = make_ethernet_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();

        match parsed.network {
            Some(NetworkHeader::Arp(hdr)) => {
                assert_eq!(hdr.operation(), arp::ArpOperation::Request);
                assert_eq!(hdr.sender_ipv4_addr().unwrap().octets(), [192, 168, 1, 10]);
                assert_eq!(hdr.target_ipv4_addr().unwrap().octets(), [192, 168, 1, 1]);
            }
            _ => panic!("expected ARP network header"),
        }

        assert!(parsed.transport.is_none());
    }

    #[test]
    fn parse_vlan_arp() {
        let frame = make_vlan_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();

        let vlan = parsed.vlan.expect("expected vlan tag");
        let stack = parsed.vlan_stack.expect("expected vlan stack");
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.as_slice()[0].vlan_id, 42);
        assert_eq!(vlan.vlan_id, 42);
        match parsed.network {
            Some(NetworkHeader::Arp(hdr)) => {
                assert_eq!(hdr.operation(), arp::ArpOperation::Request);
            }
            _ => panic!("expected ARP network header"),
        }

        assert!(parsed.transport.is_none());
    }

    #[test]
    fn parse_qinq_arp() {
        let frame = make_qinq_arp_frame();
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();

        let vlan = parsed.vlan.expect("expected vlan tag");
        let stack = parsed.vlan_stack.expect("expected vlan tags");
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.as_slice()[0].vlan_id, 100);
        assert_eq!(stack.as_slice()[1].vlan_id, 200);
        assert_eq!(vlan.vlan_id, 100);

        match parsed.network {
            Some(NetworkHeader::Arp(hdr)) => {
                assert_eq!(hdr.operation(), arp::ArpOperation::Request);
            }
            _ => panic!("expected ARP network header"),
        }

        assert!(parsed.transport.is_none());
    }

    fn make_multi_vlan_arp_frame(tags: &[u16]) -> Vec<u8> {
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x81, 0x00, // EtherType = 802.1Q VLAN
        ];

        for (idx, tag) in tags.iter().enumerate() {
            frame.extend_from_slice(&tag.to_be_bytes());
            if idx + 1 == tags.len() {
                frame.extend_from_slice(&[0x08, 0x06]); // ARP
            } else {
                frame.extend_from_slice(&[0x81, 0x00]); // next VLAN tag
            }
        }

        frame.extend_from_slice(&make_arp_payload_request());
        frame
    }

    #[test]
    fn vlan_stack_overflow_is_reported() {
        let frame = make_multi_vlan_arp_frame(&[1, 2, 3, 4, 5]);
        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();

        let stack = parsed.vlan_stack.expect("expected vlan tags");
        assert_eq!(stack.len(), VLAN_STACK_CAPACITY);
        assert!(stack.is_truncated());
        assert_eq!(stack.as_slice()[0].vlan_id, 1);
        assert_eq!(stack.as_slice()[3].vlan_id, 4);

        let vlan = parsed.vlan.expect("expected vlan tag");
        assert_eq!(vlan.vlan_id, 1);
    }

    #[test]
    fn network_header_helpers_arp_non_ipv4_are_not_applicable() {
        let mut frame = make_ethernet_arp_frame();
        frame[16] = 0x86;
        frame[17] = 0xdd;

        let parsed = parse_packet_with_linktype(&frame, LinkType::Ethernet).unwrap();
        let net = parsed
            .network
            .as_ref()
            .expect("expected ARP network header");

        assert!(net.src_ip().is_none());
        assert!(net.dst_ip().is_none());
        assert!(net.protocol().is_none());
    }

    #[test]
    fn network_header_helpers_ipv4_are_populated() {
        let raw = make_tcp_ipv4_payload([192, 0, 2, 10], [192, 0, 2, 20], 12000, 443);
        let parsed = parse_packet_with_linktype(&raw, LinkType::RawIp).unwrap();
        let net = parsed
            .network
            .as_ref()
            .expect("expected IPv4 network header");

        assert_eq!(net.src_ip(), Some(IpAddr::V4([192, 0, 2, 10].into())));
        assert_eq!(net.dst_ip(), Some(IpAddr::V4([192, 0, 2, 20].into())));
        assert_eq!(net.protocol(), Some(IpProtocol::Tcp));
    }
}
