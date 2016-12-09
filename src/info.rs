use byteorder::{ByteOrder, LittleEndian};
use parser::{Parser, ParseResult};

pub enum InfoElement<'a> {
    //  14, TS29281, 8.2
    // The Restart Counter value is unused and shall be zeroed/ignored.
    Recovery(RestartCounter),

    // 16, TS29281, 8.3
    // UNCLEAR: I have no idea what this is used for.
    TeiData(TeiData),

    // 133, TS29281, 8.4
    GtpPeerAddr(InetAddr<'a>),

    // 141, TS29281, 8.5
    ExtHeader(Comprehension, ExtType),

    // 255, TS29281, 8.6
//    PrivateExt(Length, ExtId, ExtVal),
}

impl<'a> InfoElement<'a> {
    pub fn parse(p: &'a mut Parser) -> ParseResult<Self> {
        let ie_type = p.parse_u8()?;
        if ie_type & 0b1000000 == 0 {
            Self::parse_fixed(ie_type, p)
        } else {
            Self::parse_variable(ie_type & 0b01111111, p)
        }
    }

    fn parse_fixed(ie_type: u8, p: &mut Parser) -> ParseResult<Self> {
        match ie_type {
            14 => RestartCounter::parse(p).map(InfoElement::Recovery),
            16 => TeiData::parse(p).map(InfoElement::TeiData),
            _  => unimplemented!()
        }
    }

    fn parse_variable(ie_type: u8, p: &'a mut Parser) -> ParseResult<Self> {
        let len = p.parse_u8()?;
        match ie_type {
            133 => Self::parse_peer_address(len, p),
            _   => unimplemented!()
        }
    }

    fn parse_peer_address(len: u8, p: &'a mut Parser) -> ParseResult<Self> {
        match len {
            4  => InetAddr::parse_v4(p).map(InfoElement::GtpPeerAddr),
            16 => InetAddr::parse_v6(p).map(InfoElement::GtpPeerAddr),
            _  => unimplemented!()
        }
    }
}

pub struct RestartCounter(u8);

impl RestartCounter {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u8().map(RestartCounter)
    }
}

pub struct TeiData(u32);

impl TeiData {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u32().map(TeiData)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Length(u16);

impl Length {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        p.parse_u16().map(Length)
    }
}

// TS29281, 5.2.2
pub enum ExtType {
    UdpPort(u16),
    PdcpPduNumber(u32)
}

impl ExtType {
    pub fn parse(p: &mut Parser) -> ParseResult<Self> {
        let len = p.parse_u8()?;
        let content = p.parse(len as usize * 4)?;
        let etype = p.parse_u8()?;
        //        Ok(Comprehension::parse(etype), ExtType::UdpPort(1234))
        unimplemented!()
    }
}

// TS29281, 5.2.1
pub enum Comprehension {
    Optional,      // Forward unknown headers
    Discard,       // Discard unknown haders
    Receiver,      // Comprehension required by the receiver
    Unconditional  // Comprehension required by all nodes
}

impl Comprehension {
    pub fn parse(b: u8) -> ParseResult<Self> {
        Ok(match (b & 0b10000000 != 0, b & 0b01000000 != 0) {
            (false, false) => Comprehension::Optional,
            (false, true)  => Comprehension::Discard,
            (true, false)  => Comprehension::Receiver,
            (true, true)   => Comprehension::Unconditional
        })
    }
}

pub enum InetAddr<'a> {
    V4(u32),
    V6(Box<&'a [u8]>)
}

impl<'a> InetAddr<'a> {
    pub fn parse_v4(p: &mut Parser<'a>) -> ParseResult<Self> {
        p.parse(4).map(|s| InetAddr::V4(LittleEndian::read_u32(s)))
    }

    pub fn parse_v6(p: &mut Parser<'a>) -> ParseResult<Self> {
        p.parse(16).map(|s| InetAddr::V6(Box::new(s)))
    }
}

pub struct PrivateExt<'a> {
    id: u8,
    value: Box<&'a [u8]>
}

impl<'a> PrivateExt<'a> {

}
