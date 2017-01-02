use info::InfoElement;
use parser::{Parser, ParseError, ParseResult};
use std::collections::hash_set::{HashSet};

// TODO: Add message type too.
// TODO: This started out as a direct translation of the protocol type,
//       but some of the fields are likely only required for parsing,
//       e.g. flags and length and can be removed.
#[derive(Debug)]
pub struct Gtp<'a> {
    pub version: Version,
    pub protocol: Protocol,
    pub flags: Flags,
    pub length: Length,
    pub teid: TunnelEid,
    pub seq_num: Option<SequenceNumber>,
    pub npdu_num: Option<NPduNumber>,
    pub ext_hdrs: Vec<ExtensionHeader<'a>>,
}

impl<'a> Gtp<'a> {
    pub fn parse(p: &mut Parser<'a>) -> ParseResult<Gtp<'a>> {
        let top   = p.parse_u8()?;
        let ver   = Version::parse(top)?;
        let proto = Protocol::parse(top)?;
        let flags = Flags::parse(top)?;
        let len   = Length::parse(p)?;
        let teid  = TunnelEid::parse(p)?;
        let seq_num = flags.parse_seq_num(p)?;
        let npdu_num = flags.parse_npdu(p)?;
        let ext_hdrs = flags.parse_ext_hdrs(p)?;
        Ok(Gtp {
            version: ver,
            protocol: proto,
            flags: flags,
            length: len,
            teid: teid,
            seq_num: seq_num,
            npdu_num: npdu_num,
            ext_hdrs: ext_hdrs
        })
    }
}

#[derive(Eq, Debug, PartialEq)]
pub struct Version(u8);

impl Version {
    pub fn parse(b: u8) -> ParseResult<Version>{
        Ok(Version(b >> 5))
    }
}

#[derive(Debug)]
pub enum Protocol {
    Gtp,
    GtpPrime,
}

impl Protocol {
    pub fn parse(b: u8) -> ParseResult<Protocol> {
        match b & 0b00100000 {
            0 => Ok(Protocol::GtpPrime),
            _ => Ok(Protocol::Gtp),
        }
    }
}

#[derive(Debug)]
pub struct Flags(HashSet<Flag>);

impl Flags {
    pub fn parse(b: u8) -> ParseResult<Self> {
        let mut res = HashSet::new();
        if Flag::has_npdu_number(b) { res.insert(Flag::NPduNumber); }
        if Flag::has_sequence_number(b) { res.insert(Flag::SequenceNumber); }
        if Flag::has_extension_header(b) { res.insert(Flag::ExtensionHeader); }
        Ok(Flags(res))
    }

    fn parse_seq_num(&self, p: &mut Parser)
                     -> ParseResult<Option<SequenceNumber>> {
        if self.contains(&Flag::SequenceNumber) {
            SequenceNumber::parse(p).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn parse_npdu(&self, p: &mut Parser)
                      -> ParseResult<Option<NPduNumber>> {
        if self.contains(&Flag::NPduNumber) {
            NPduNumber::parse(p).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn parse_ext_hdrs<'a>(&self, p: &mut Parser<'a>)
                              -> ParseResult<Vec<ExtensionHeader<'a>>> {
        if self.contains(&Flag::ExtensionHeader) {
            let kind = ExtHeaderType::parse(p)?;
            let mut res = Vec::with_capacity(2);
            ExtensionHeader::parse(p, kind, &mut res)?;
            Ok(res)
        } else {
            Ok(Vec::with_capacity(0))
        }
    }

    pub fn contains(&self, flag: &Flag) -> bool {
        self.0.contains(flag)
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Flag {
    NPduNumber,
    SequenceNumber,
    ExtensionHeader,
}

impl Flag {
    pub fn has_npdu_number(b: u8) -> bool {
        b & 0b00000001 != 0
    }

    pub fn has_sequence_number(b: u8) -> bool {
        b & 0b00000010 != 0
    }

    pub fn has_extension_header(b: u8) -> bool {
        b & 0b00000100 != 0
    }
}

pub enum MessageType {
    EchoRequest,   // TS29281, 7.2.1
    EchoResponse,  // TS29281, 7.2.2

}

#[derive(Debug, Eq, PartialEq)]
pub struct Length(u16);

impl Length {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u16().map(Length)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct TunnelEid(u32);

impl TunnelEid {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u32().map(TunnelEid)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SequenceNumber(u16);

impl SequenceNumber {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u16().map(SequenceNumber)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NPduNumber(u8);

impl NPduNumber {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u8().map(NPduNumber)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExtHeaderType {
    EndReached,
    MbmsSupport,
    MsInfoChangeReporting,
    UdpPort,
    PdcpPdu,
    SuspendRequest,
    SuspendResponse,
}

impl ExtHeaderType {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        let t = p.parse_u8()?;
        match t {
            0b00000000 => Ok(ExtHeaderType::EndReached),
            0b00000001 => Ok(ExtHeaderType::MbmsSupport),
            0b00000010 => Ok(ExtHeaderType::MsInfoChangeReporting),
            0b01000000 => Ok(ExtHeaderType::UdpPort),
            0b11000000 => Ok(ExtHeaderType::PdcpPdu),
            0b11000001 => Ok(ExtHeaderType::SuspendRequest),
            0b11000010 => Ok(ExtHeaderType::SuspendResponse),
            _          => Err(ParseError::UnsupportedExtensionHeader(t))
        }
    }
}

#[derive(Debug)]
pub struct ExtensionHeader<'a> {
    pub kind: ExtHeaderType,
    pub content: &'a [u8],
}

impl<'a> ExtensionHeader<'a> {
    fn new(kind: ExtHeaderType, content: &'a [u8]) -> Self {
        ExtensionHeader {
            kind: kind,
            content: content
        }
    }

    pub fn parse(p: &mut Parser<'a>,
                 kind: ExtHeaderType,
                 res: &mut Vec<ExtensionHeader<'a>>)
                 -> ParseResult<()> {
        let length = p.parse_u8().map(|l| l * 4)?;
        let content = p.parse(length as usize)?;
        let next = ExtHeaderType::parse(p)?;
        res.push(ExtensionHeader::new(kind, content));
        if next != ExtHeaderType::EndReached {
            ExtensionHeader::parse(p, next, res)?;
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use parser::Parser;
    use super::*;

    #[test]
    fn parse_minimal_header() {
        let raw = [0b00110000, 0, 0, 1, 0, 0, 0, 0];
        let mut p = Parser::new(&raw);
        let parsed = Gtp::parse(&mut p).unwrap();
        assert!(parsed.flags.0.is_empty());
        assert_eq!(parsed.version, Version(1));
        assert_eq!(parsed.length, Length(0));
        assert_eq!(parsed.teid, TunnelEid(1));
    }

    #[test]
    fn parse_basic_header() {
        let raw = [0b00110011, 0, 0, 1, 0, 0, 0, 14, 0, 5, 0];
        let mut p = Parser::new(&raw);
        let parsed = Gtp::parse(&mut p).unwrap();
        assert!(!parsed.flags.0.is_empty());
        assert_eq!(parsed.seq_num, Some(SequenceNumber(14)));
        assert_eq!(parsed.npdu_num, Some(NPduNumber(5)));
    }
}
