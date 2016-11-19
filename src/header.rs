use std::collections::hash_set::{HashSet};

pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub enum ParseError {
    PrematureEnd,
    UnsupportedVersion,
}

pub type ParseResult<T> = Result<T, ParseError>;

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8]) -> Parser<'a> {
        Parser { bytes: bytes, pos: 0 }
    }

    pub fn parse(&mut self, len: usize) -> ParseResult<&'a [u8]> {
        if self.pos + len > self.bytes.len() {
            return Err(ParseError::PrematureEnd);
        }
        self.pos = self.pos + len;
        Ok(&self.bytes[self.pos-len..self.pos])
    }

    pub fn parse_u8(&mut self) -> ParseResult<u8> {
        self.parse(1).map(|r| r[0])
    }
}

#[derive(Debug)]
pub struct Gtp {
    pub version: Version,
    pub protocol: Protocol,
    pub flags: Flags,
    pub teid: TunnelEid,
    pub seq_num: Option<SequenceNumber>,
    pub next_ext_type: Option<NextExtHeaderType>,
    // TODO: Implement support for extension headers.
}

impl Gtp {
    pub fn parse(p: &mut Parser) -> ParseResult<Gtp> {
        let top   = p.parse_u8()?;
        let ver   = Version::parse(top)?;
        let proto = Protocol::parse(top)?;
        let flags = Flags::parse(top)?;
        let teid  = TunnelEid::parse(p)?;
        Ok(Gtp {
            version: ver,
            protocol: proto,
            flags: flags,
            teid: teid,
            seq_num: None,
            next_ext_type: None
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
            0b00000000 => Ok(Protocol::GtpPrime),
            0b00100000 => Ok(Protocol::Gtp),
            x => panic!("Impossible GTP protocol {}.", x),
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

#[derive(Debug, Eq, PartialEq)]
pub struct Length(u64);

#[derive(Debug, Eq, PartialEq)]
pub struct TunnelEid([u8; 4]);

impl TunnelEid {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        // TODO: Maybe replace cumbersomeness with array_ref! from arrayref
        p.parse(4).map(|bs| TunnelEid([bs[0], bs[1], bs[2], bs[3]]))
    }
}

#[derive(Debug)]
pub struct SequenceNumber(u64);

#[derive(Debug)]
pub struct NPduNumber(u32);

#[derive(Debug)]
pub enum NextExtHeaderType {
    EndReached,
    MbmsSupport,
    MsInfoChangeReporting,
    Reserved,
    PdbpPdu,
    SuspendRequest,
    SuspendResponse,
}

#[derive(Debug)]
pub struct NextExtensionHeader {
    pub length: u8,
    pub content: Vec<u8>,
    pub next_ext_type: NextExtHeaderType
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header() {
        let raw = [0b00110000, 1, 0, 0, 0, 0];
        let mut p = Parser::new(&raw);
        let parsed = Gtp::parse(&mut p).unwrap();
        assert_eq!(parsed.flags.0.is_empty(), true);
        assert_eq!(parsed.version, Version(1));
        assert_eq!(parsed.teid, TunnelEid([1, 0, 0, 0]));
    }
}
