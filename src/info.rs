use byteorder::{ByteOrder, LittleEndian};
use parser::{Parser, ParseError, ParseResult};

pub enum InfoElement<'a> {
    // 14, TS29281, 8.2
    // The Restart Counter value is unused and shall be zeroed/ignored.
    Recovery(RestartCounter),

    // 16, TS29281, 8.3
    // UNCLEAR: I have no idea what this is used for.
    TeiData(TeiData),

    // 133, TS29281, 8.4
    GtpPeerAddr(InetAddr<'a>),

    // 141, TS29281, 8.5
    ExtHeader(ExtHeader),

    // 255, TS29281, 8.6
//    PrivateExt(Length, ExtId, ExtVal),
}

impl<'a> InfoElement<'a> {
    pub fn parse(p: &'a mut Parser<'a>) -> ParseResult<Self> {
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
            _  => Err(ParseError::UnsupportedInformationElement(ie_type))
        }
    }

    fn parse_variable(ie_type: u8, p: &'a mut Parser<'a>) -> ParseResult<Self> {
        let len = p.parse_u8()?;
        match ie_type {
            133 => InetAddr::parse(len, p).map(InfoElement::GtpPeerAddr),
            _   => Err(ParseError::UnsupportedInformationElement(ie_type))
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

// TS29281, 5.2
pub struct ExtHeader {
    pub comprehension: Comprehension,
    pub header: ExtType
}

impl ExtHeader {
    pub fn parse(t: u8, p: &mut Parser) -> ParseResult<Self> {
        let compr = Comprehension::parse(t)?;
        let len = p.parse_u8()?;
        let etype = ExtType::parse(t, len, p)?;
        // Is the length even needed? Both extension headers currently defined
        // has a fixed length of one.
//        let content = p.parse(len as usize * 4)?;
        Ok(ExtHeader {
            comprehension: compr,
            header: etype,
        })
    }
}

// TS29281, 5.2.2
pub enum ExtType {
    UdpPort(u16),
    PdcpPduNumber(u32),
}

impl ExtType {
    pub fn parse(t: u8, len: u8, p: &mut Parser) -> ParseResult<Self> {
        match t {
            0b00000000 => unimplemented!(), // Should probably never be reached?
            0b01000000 => Self::parse_udp_port(len, p),
            0b11000000 => p.parse_u32().map(ExtType::PdcpPduNumber),
            _          => Err(ParseError::UnsupportedExtensionHeader(t))
        }
    }

    fn parse_udp_port(len: u8, p: &mut Parser) -> ParseResult<Self> {
        let port = p.parse(len as usize * 4).map(LittleEndian::read_u32)?;
        if port > 2^16 {
            Err(ParseError::BadUdpPort(port))
        } else {
            Ok(ExtType::UdpPort(port as u16))
        }
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
    fn parse(len: u8, p: &'a mut Parser<'a>) -> ParseResult<Self> {
        match len {
            4  => Self::parse_v4(p),
            16 => Self::parse_v6(p),
            _  => Err(ParseError::BadIpAddress)
        }
    }

    fn parse_v4(p: &mut Parser<'a>) -> ParseResult<Self> {
        p.parse(4).map(|s| InetAddr::V4(LittleEndian::read_u32(s)))
    }

    fn parse_v6(p: &mut Parser<'a>) -> ParseResult<Self> {
        p.parse(16).map(|s| InetAddr::V6(Box::new(s)))
    }
}

pub struct PrivateExt<'a> {
    id: u8,
    value: Box<&'a [u8]>
}

impl<'a> PrivateExt<'a> {

}
