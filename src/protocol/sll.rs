//! Zero-copy parser for Linux cooked capture (SLL v1).
//!
//! Header layout (16 bytes):
//! - packet type:      2 bytes
//! - ARPHRD type:      2 bytes
//! - link-layer length:2 bytes
//! - link-layer addr:  8 bytes
//! - protocol:         2 bytes (EtherType-compatible)

use super::{EtherType, ParseError};
use std::fmt;

pub const SLL_HEADER_LEN: usize = 16;

#[derive(Debug)]
pub struct LinuxSllHeader<'a> {
    data: &'a [u8],
}

impl<'a> LinuxSllHeader<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < SLL_HEADER_LEN {
            return Err(ParseError::TooShort {
                expected: SLL_HEADER_LEN,
                actual: data.len(),
            });
        }
        Ok(Self { data })
    }

    #[inline]
    pub fn packet_type_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    #[inline]
    pub fn arphrd_type_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    #[inline]
    pub fn address_length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    #[inline]
    pub fn address(&self) -> &'a [u8] {
        let len = (self.address_length() as usize).min(8);
        &self.data[6..6 + len]
    }

    #[inline]
    pub fn protocol_raw(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    #[inline]
    pub fn protocol(&self) -> EtherType {
        EtherType::from(self.protocol_raw())
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[SLL_HEADER_LEN..]
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

pub(crate) fn format_addr(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

impl fmt::Display for LinuxSllHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Linux SLL {} hatype={} addr={} proto={}",
            self.packet_type_label(),
            self.arphrd_type_raw(),
            format_addr(self.address()),
            self.protocol()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_sll_header() {
        let data = [
            0x00, 0x00, // packet type: host
            0x00, 0x01, // hatype: Ethernet
            0x00, 0x06, // addr len: 6
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x00, 0x00, // addr (8-byte field)
            0x08, 0x00, // protocol: IPv4
            0x45, 0x00, 0x00, 0x14, // payload
        ];

        let hdr = LinuxSllHeader::parse(&data).unwrap();
        assert_eq!(hdr.packet_type_raw(), 0);
        assert_eq!(hdr.arphrd_type_raw(), 1);
        assert_eq!(hdr.address_length(), 6);
        assert_eq!(hdr.address(), &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(hdr.protocol(), EtherType::Ipv4);
        assert_eq!(hdr.payload(), &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn reject_too_short_sll_header() {
        let data = [0u8; 15];
        assert!(LinuxSllHeader::parse(&data).is_err());
    }
}
