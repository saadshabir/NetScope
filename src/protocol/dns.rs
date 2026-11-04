//! Zero-copy DNS message parser (RFC 1035).
//!
//! This parser is intentionally focused on safe, bounded parsing for
//! packet-inspection use cases. It is designed for DNS-over-UDP payloads.

use super::ParseError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS fixed header length in bytes.
pub const DNS_HEADER_LEN: usize = 12;

const MAX_NAME_POINTER_JUMPS: usize = 32;
const MAX_NAME_LABELS: usize = 128;
const MAX_NAME_LEN: usize = 255;
const MAX_SECTION_ENTRIES: usize = 1024;

/// Determine whether a UDP flow is likely DNS based on well-known port 53.
#[inline]
pub fn is_dns_udp_port(src_port: u16, dst_port: u16) -> bool {
    src_port == 53 || dst_port == 53
}

/// Parse DNS from a UDP payload when the flow endpoints indicate DNS.
#[inline]
pub fn parse_dns_udp<'a>(
    payload: &'a [u8],
    src_port: u16,
    dst_port: u16,
) -> Option<DnsMessage<'a>> {
    if !is_dns_udp_port(src_port, dst_port) {
        return None;
    }
    DnsMessage::parse(payload).ok()
}

/// Human-readable one-line DNS summary for packet lists.
pub fn brief_summary(msg: &DnsMessage<'_>) -> String {
    if msg.is_response() {
        return format!(
            "id=0x{:04x} R {} Q={} A={} NS={} AR={}",
            msg.id(),
            msg.rcode_name(),
            msg.question_count(),
            msg.answer_count(),
            msg.authority_count(),
            msg.additional_count()
        );
    }

    // For query summaries, decode only the first question (if present) to keep
    // per-packet work bounded.
    if msg.question_count() == 0 {
        return format!("id=0x{:04x} Q QD=0", msg.id());
    }

    match decode_name(msg.data, DNS_HEADER_LEN).and_then(|(qname, consumed)| {
        let fields_offset = DNS_HEADER_LEN
            .checked_add(consumed)
            .ok_or_else(|| ParseError::InvalidHeader("dns question offset overflow".into()))?;
        ensure_len(msg.data, fields_offset, 4)?;
        let qtype = read_u16(msg.data, fields_offset);
        Ok((qname, qtype))
    }) {
        Ok((qname, qtype)) => format!("id=0x{:04x} Q {} {}", msg.id(), rr_type_label(qtype), qname),
        Err(_) => format!("id=0x{:04x} Q QD={}", msg.id(), msg.question_count()),
    }
}

/// Parsed DNS message (header + helpers for parsing sections).
#[derive(Debug, Clone, Copy)]
pub struct DnsMessage<'a> {
    data: &'a [u8],
}

impl<'a> DnsMessage<'a> {
    /// Parse a DNS message from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < DNS_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: DNS_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(DnsMessage { data })
    }

    #[inline]
    pub fn id(&self) -> u16 {
        read_u16(self.data, 0)
    }

    #[inline]
    pub fn flags(&self) -> u16 {
        read_u16(self.data, 2)
    }

    #[inline]
    pub fn is_response(&self) -> bool {
        self.flags() & 0x8000 != 0
    }

    #[inline]
    pub fn opcode_raw(&self) -> u8 {
        ((self.flags() >> 11) & 0x0F) as u8
    }

    #[inline]
    pub fn opcode_name(&self) -> &'static str {
        opcode_name(self.opcode_raw())
    }

    #[inline]
    pub fn rcode_raw(&self) -> u8 {
        (self.flags() & 0x0F) as u8
    }

    #[inline]
    pub fn rcode_name(&self) -> &'static str {
        rcode_name(self.rcode_raw())
    }

    #[inline]
    pub fn authoritative_answer(&self) -> bool {
        self.flags() & 0x0400 != 0
    }

    #[inline]
    pub fn truncated(&self) -> bool {
        self.flags() & 0x0200 != 0
    }

    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.flags() & 0x0100 != 0
    }

    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.flags() & 0x0080 != 0
    }

    #[inline]
    pub fn authenticated_data(&self) -> bool {
        self.flags() & 0x0020 != 0
    }

    #[inline]
    pub fn checking_disabled(&self) -> bool {
        self.flags() & 0x0010 != 0
    }

    #[inline]
    pub fn question_count(&self) -> u16 {
        read_u16(self.data, 4)
    }

    /// Match the first question by its labels, type, and class. Length prefixes
    /// preserve label boundaries even when a label contains a literal dot.
    pub(crate) fn question_key(&self) -> Result<Box<[u8]>, ParseError> {
        let mut key = Vec::new();
        let consumed = visit_name(self.data, DNS_HEADER_LEN, |label| {
            key.push(label.len() as u8);
            key.extend(label.iter().map(u8::to_ascii_lowercase));
        })?;
        let fields_offset = DNS_HEADER_LEN + consumed;
        ensure_len(self.data, fields_offset, 4)?;
        key.push(0);
        key.extend_from_slice(&self.data[fields_offset..fields_offset + 4]);
        Ok(key.into_boxed_slice())
    }

    #[inline]
    pub fn answer_count(&self) -> u16 {
        read_u16(self.data, 6)
    }

    #[inline]
    pub fn authority_count(&self) -> u16 {
        read_u16(self.data, 8)
    }

    #[inline]
    pub fn additional_count(&self) -> u16 {
        read_u16(self.data, 10)
    }

    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.is_response() {
            flags.push("QR");
        }
        if self.authoritative_answer() {
            flags.push("AA");
        }
        if self.truncated() {
            flags.push("TC");
        }
        if self.recursion_desired() {
            flags.push("RD");
        }
        if self.recursion_available() {
            flags.push("RA");
        }
        if self.authenticated_data() {
            flags.push("AD");
        }
        if self.checking_disabled() {
            flags.push("CD");
        }

        if flags.is_empty() {
            "-".to_string()
        } else {
            flags.join(" ")
        }
    }

    /// Parse DNS sections and return up to N items per section.
    ///
    /// The parser still validates/skips all section items according to the
    /// header counts, even when `*_limit` truncates what is returned.
    pub fn parse_sections(
        &self,
        question_limit: usize,
        answer_limit: usize,
        authority_limit: usize,
        additional_limit: usize,
    ) -> Result<DnsSections<'a>, ParseError> {
        let mut offset = DNS_HEADER_LEN;

        let qd = self.question_count() as usize;
        let an = self.answer_count() as usize;
        let ns = self.authority_count() as usize;
        let ar = self.additional_count() as usize;
        let total = qd.saturating_add(an).saturating_add(ns).saturating_add(ar);
        if total > MAX_SECTION_ENTRIES {
            return Err(ParseError::InvalidHeader(format!(
                "dns section counts too large: qd={} an={} ns={} ar={}",
                qd, an, ns, ar
            )));
        }

        let mut questions = Vec::new();
        for idx in 0..qd {
            let (question, next) = parse_question(self.data, offset)?;
            if idx < question_limit {
                questions.push(question);
            }
            offset = next;
        }

        let mut answers = Vec::new();
        for idx in 0..an {
            let (record, next) = parse_record(self.data, offset)?;
            if idx < answer_limit {
                answers.push(record);
            }
            offset = next;
        }

        let mut authorities = Vec::new();
        for idx in 0..ns {
            let (record, next) = parse_record(self.data, offset)?;
            if idx < authority_limit {
                authorities.push(record);
            }
            offset = next;
        }

        let mut additionals = Vec::new();
        for idx in 0..ar {
            let (record, next) = parse_record(self.data, offset)?;
            if idx < additional_limit {
                additionals.push(record);
            }
            offset = next;
        }

        Ok(DnsSections {
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

/// Parsed DNS sections.
#[derive(Debug)]
pub struct DnsSections<'a> {
    pub questions: Vec<DnsQuestion<'a>>,
    pub answers: Vec<DnsRecord<'a>>,
    pub authorities: Vec<DnsRecord<'a>>,
    pub additionals: Vec<DnsRecord<'a>>,
}

/// A DNS question section entry.
#[derive(Debug, Clone, Copy)]
pub struct DnsQuestion<'a> {
    name: DnsName<'a>,
    qtype: u16,
    qclass: u16,
}

impl<'a> DnsQuestion<'a> {
    #[inline]
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    #[inline]
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    #[inline]
    pub fn qtype_label(&self) -> String {
        rr_type_label(self.qtype)
    }

    #[inline]
    pub fn qclass_label(&self) -> String {
        rr_class_label(self.qclass)
    }

    #[inline]
    pub fn name(&self) -> Result<String, ParseError> {
        self.name.to_string()
    }
}

/// A DNS resource record.
#[derive(Debug, Clone, Copy)]
pub struct DnsRecord<'a> {
    msg: &'a [u8],
    name: DnsName<'a>,
    rr_type: u16,
    class: u16,
    ttl: u32,
    rdata: &'a [u8],
    rdata_offset: usize,
}

impl<'a> DnsRecord<'a> {
    #[inline]
    pub fn rr_type(&self) -> u16 {
        self.rr_type
    }

    #[inline]
    pub fn class(&self) -> u16 {
        self.class
    }

    #[inline]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    #[inline]
    pub fn rdata(&self) -> &'a [u8] {
        self.rdata
    }

    #[inline]
    pub fn rr_type_label(&self) -> String {
        rr_type_label(self.rr_type)
    }

    #[inline]
    pub fn class_label(&self) -> String {
        rr_class_label(self.class)
    }

    #[inline]
    pub fn name(&self) -> Result<String, ParseError> {
        self.name.to_string()
    }

    /// Best-effort RDATA formatting for common RR types.
    pub fn rdata_display(&self) -> String {
        match self.rr_type {
            // A
            1 if self.rdata.len() == 4 => {
                let ip = Ipv4Addr::new(self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]);
                ip.to_string()
            }
            // AAAA
            28 if self.rdata.len() == 16 => match <[u8; 16]>::try_from(self.rdata) {
                Ok(bytes) => Ipv6Addr::from(bytes).to_string(),
                Err(_) => "<invalid-aaaa>".to_string(),
            },
            // NS / CNAME / PTR
            2 | 5 | 12 => decode_name(self.msg, self.rdata_offset)
                .map(|(name, _)| name)
                .unwrap_or_else(|_| "<invalid-name>".to_string()),
            // MX
            15 => {
                if self.rdata.len() < 3 {
                    return "<invalid-mx>".to_string();
                }
                let pref = u16::from_be_bytes([self.rdata[0], self.rdata[1]]);
                match decode_name(self.msg, self.rdata_offset + 2) {
                    Ok((exchange, _)) => format!("preference={} exchange={}", pref, exchange),
                    Err(_) => "<invalid-mx>".to_string(),
                }
            }
            // TXT
            16 => format_txt_rdata(self.rdata),
            _ => format!("0x{}", hex_prefix(self.rdata, 24)),
        }
    }

    pub fn summary(&self) -> String {
        let name = self.name().unwrap_or_else(|_| "<invalid-name>".to_string());
        format!(
            "{} {} -> {} (ttl={})",
            self.rr_type_label(),
            name,
            self.rdata_display(),
            self.ttl()
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct DnsName<'a> {
    msg: &'a [u8],
    offset: usize,
}

impl<'a> DnsName<'a> {
    fn to_string(self) -> Result<String, ParseError> {
        decode_name(self.msg, self.offset).map(|(name, _)| name)
    }
}

fn parse_question<'a>(
    data: &'a [u8],
    offset: usize,
) -> Result<(DnsQuestion<'a>, usize), ParseError> {
    let consumed = visit_name(data, offset, |_| {})?;
    let fields_offset = offset
        .checked_add(consumed)
        .ok_or_else(|| ParseError::InvalidHeader("dns question offset overflow".into()))?;
    ensure_len(data, fields_offset, 4)?;

    let qtype = read_u16(data, fields_offset);
    let qclass = read_u16(data, fields_offset + 2);
    let next = fields_offset
        .checked_add(4)
        .ok_or_else(|| ParseError::InvalidHeader("dns question next offset overflow".into()))?;

    Ok((
        DnsQuestion {
            name: DnsName { msg: data, offset },
            qtype,
            qclass,
        },
        next,
    ))
}

fn parse_record<'a>(data: &'a [u8], offset: usize) -> Result<(DnsRecord<'a>, usize), ParseError> {
    let consumed = visit_name(data, offset, |_| {})?;
    let fields_offset = offset
        .checked_add(consumed)
        .ok_or_else(|| ParseError::InvalidHeader("dns rr offset overflow".into()))?;
    ensure_len(data, fields_offset, 10)?;

    let rr_type = read_u16(data, fields_offset);
    let class = read_u16(data, fields_offset + 2);
    let ttl = read_u32(data, fields_offset + 4);
    let rdlen = read_u16(data, fields_offset + 8) as usize;
    let rdata_offset = fields_offset
        .checked_add(10)
        .ok_or_else(|| ParseError::InvalidHeader("dns rr rdata offset overflow".into()))?;
    ensure_len(data, rdata_offset, rdlen)?;

    let next = rdata_offset
        .checked_add(rdlen)
        .ok_or_else(|| ParseError::InvalidHeader("dns rr next offset overflow".into()))?;
    Ok((
        DnsRecord {
            msg: data,
            name: DnsName { msg: data, offset },
            rr_type,
            class,
            ttl,
            rdata: &data[rdata_offset..next],
            rdata_offset,
        },
        next,
    ))
}

fn decode_name(data: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut labels = Vec::new();
    let consumed = visit_name(data, start, |label| labels.push(format_label(label)))?;
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, consumed))
}

fn visit_name(
    data: &[u8],
    start: usize,
    mut visit_label: impl FnMut(&[u8]),
) -> Result<usize, ParseError> {
    ensure_len(data, start, 1)?;

    let mut cursor = start;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut labels_seen = 0usize;
    let mut total_name_len = 0usize;

    loop {
        ensure_len(data, cursor, 1)?;
        let len = data[cursor];

        if (len & 0xC0) == 0xC0 {
            ensure_len(data, cursor, 2)?;
            let ptr = ((((len as u16) & 0x3F) << 8) | data[cursor + 1] as u16) as usize;
            if ptr >= data.len() {
                return Err(ParseError::InvalidHeader(format!(
                    "dns name pointer out of bounds: {}",
                    ptr
                )));
            }

            // RFC1035 compression pointers should point to a prior location in the message.
            if ptr >= cursor {
                return Err(ParseError::InvalidHeader(
                    "dns name pointer points forward".to_string(),
                ));
            }

            if !jumped {
                consumed = cursor + 2 - start;
                jumped = true;
            }

            cursor = ptr;
            jumps += 1;
            if jumps > MAX_NAME_POINTER_JUMPS {
                return Err(ParseError::InvalidHeader(
                    "dns name compression pointer loop detected".to_string(),
                ));
            }
            continue;
        }

        if (len & 0xC0) != 0 {
            return Err(ParseError::InvalidHeader(format!(
                "invalid dns label length prefix: 0x{:02x}",
                len
            )));
        }

        cursor += 1;
        if len == 0 {
            if !jumped {
                consumed = cursor - start;
            }
            break;
        }

        let label_len = len as usize;
        if label_len > 63 {
            return Err(ParseError::InvalidHeader(format!(
                "dns label length {} exceeds 63",
                label_len
            )));
        }
        ensure_len(data, cursor, label_len)?;

        labels_seen += 1;
        if labels_seen > MAX_NAME_LABELS {
            return Err(ParseError::InvalidHeader(
                "dns name has too many labels".to_string(),
            ));
        }

        if labels_seen > 1 {
            total_name_len += 1;
        }
        total_name_len += label_len;
        if total_name_len > MAX_NAME_LEN {
            return Err(ParseError::InvalidHeader(
                "dns name exceeds maximum length".to_string(),
            ));
        }

        visit_label(&data[cursor..cursor + label_len]);
        cursor += label_len;
    }

    Ok(consumed)
}

#[inline]
fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn ensure_len(data: &[u8], offset: usize, needed: usize) -> Result<(), ParseError> {
    let expected = offset
        .checked_add(needed)
        .ok_or_else(|| ParseError::InvalidHeader("dns offset overflow".to_string()))?;
    if data.len() < expected {
        return Err(ParseError::TooShort {
            expected,
            actual: data.len(),
        });
    }
    Ok(())
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "UNKNOWN",
    }
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

fn format_label(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}

fn format_txt_rdata(data: &[u8]) -> String {
    if data.is_empty() {
        return "\"\"".to_string();
    }

    let mut i = 0usize;
    let mut chunks = Vec::new();
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return "<invalid-txt>".to_string();
        }
        let chunk = format_label(&data[i..i + len]);
        chunks.push(format!("\"{}\"", chunk));
        i += len;
    }
    chunks.join(" ")
}

fn hex_prefix(data: &[u8], max_bytes: usize) -> String {
    let end = data.len().min(max_bytes);
    let mut encoded = hex::encode(&data[..end]);
    if end < data.len() {
        encoded.push_str("...");
    }
    encoded
}

/// Format a DNS RR type as a compact label (e.g., `A`, `AAAA`, `TYPE65280`).
pub fn rr_type_label(rr_type: u16) -> String {
    match rr_type {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        41 => "OPT".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{}", other),
    }
}

/// Format a DNS class as a compact label (e.g., `IN`, `CLASS255`).
pub fn rr_class_label(class: u16) -> String {
    match class {
        1 => "IN".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        255 => "ANY".to_string(),
        other => format!("CLASS{}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query_example_com() -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        pkt.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ]);
        pkt
    }

    fn dns_response_a_compressed() -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: response + RD + RA + NOERROR
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        pkt.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // NAME pointer to question name
            0x00, 0x01, // TYPE A
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x01, 0x2C, // TTL 300
            0x00, 0x04, // RDLEN
            0x01, 0x02, 0x03, 0x04, // RDATA
        ]);
        pkt
    }

    #[test]
    fn parse_valid_dns_query() {
        let pkt = dns_query_example_com();
        let msg = DnsMessage::parse(&pkt).unwrap();
        assert_eq!(msg.id(), 0x1234);
        assert!(!msg.is_response());
        assert_eq!(msg.question_count(), 1);
        assert_eq!(msg.answer_count(), 0);

        let sections = msg.parse_sections(4, 4, 4, 4).unwrap();
        assert_eq!(sections.questions.len(), 1);
        let q = &sections.questions[0];
        assert_eq!(q.qtype(), 1);
        assert_eq!(q.qclass(), 1);
        assert_eq!(q.name().unwrap(), "example.com");
        assert_eq!(q.qtype_label(), "A");
        assert_eq!(brief_summary(&msg), "id=0x1234 Q A example.com");
    }

    #[test]
    fn parse_valid_dns_response_with_compression() {
        let pkt = dns_response_a_compressed();
        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.rcode_name(), "NOERROR");

        let sections = msg.parse_sections(4, 4, 4, 4).unwrap();
        assert_eq!(sections.questions.len(), 1);
        assert_eq!(sections.answers.len(), 1);

        let answer = &sections.answers[0];
        assert_eq!(answer.name().unwrap(), "example.com");
        assert_eq!(answer.rr_type(), 1);
        assert_eq!(answer.class(), 1);
        assert_eq!(answer.ttl(), 300);
        assert_eq!(answer.rdata_display(), "1.2.3.4");
    }

    #[test]
    fn reject_short_dns_header() {
        let pkt = [0u8; 11];
        assert!(DnsMessage::parse(&pkt).is_err());
    }

    #[test]
    fn reject_truncated_name() {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00, // id + flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // an
            0x00, 0x00, // ns
            0x00, 0x00, // ar
        ];
        pkt.extend_from_slice(&[0x03, b'w', b'w']); // truncated label
        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.parse_sections(1, 0, 0, 0).is_err());
    }

    #[test]
    fn reject_record_with_rdlen_overflow() {
        let mut pkt = vec![
            0x00, 0x01, 0x81, 0x80, // id + response flags
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        pkt.extend_from_slice(&[
            0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01, // question: a. A IN
            0xC0, 0x0C, // answer name pointer
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x01, // ttl
            0x00, 0x04, // rdlen claims 4
            0x01, 0x02, // only 2 bytes available
        ]);

        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.parse_sections(1, 1, 0, 0).is_err());
    }

    #[test]
    fn reject_compression_pointer_loop() {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00, // id + flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // an
            0x00, 0x00, // ns
            0x00, 0x00, // ar
        ];
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // pointer to itself (loop)
            0x00, 0x01, // qtype
            0x00, 0x01, // qclass
        ]);

        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.parse_sections(1, 0, 0, 0).is_err());
    }

    #[test]
    fn reject_compression_pointer_out_of_bounds() {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00, // id + flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // an
            0x00, 0x00, // ns
            0x00, 0x00, // ar
        ];
        pkt.extend_from_slice(&[
            0xC0, 0xFF, // invalid pointer
            0x00, 0x01, // qtype
            0x00, 0x01, // qclass
        ]);

        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.parse_sections(1, 0, 0, 0).is_err());
    }

    #[test]
    fn reject_forward_compression_pointer() {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00, // id + flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // an
            0x00, 0x00, // ns
            0x00, 0x00, // ar
        ];
        // QNAME is a pointer that points forward into the QTYPE/QCLASS area.
        pkt.extend_from_slice(&[
            0xC0, 0x0E, // pointer to offset 14 (forward)
            0x00, 0x01, // qtype
            0x00, 0x01, // qclass
            0x00,
        ]);

        let msg = DnsMessage::parse(&pkt).unwrap();
        assert!(msg.parse_sections(1, 0, 0, 0).is_err());
    }

    #[test]
    fn parse_dns_udp_helper_checks_ports() {
        let pkt = dns_query_example_com();
        assert!(parse_dns_udp(&pkt, 53, 55555).is_some());
        assert!(parse_dns_udp(&pkt, 55555, 53).is_some());
        assert!(parse_dns_udp(&pkt, 12345, 12346).is_none());
    }
}
