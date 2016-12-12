use byteorder::{ByteOrder, LittleEndian};

pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub enum ParseError {
    PrematureEnd,
    UnsupportedVersion,
    UnsupportedInformationElement(u8),
    UnsupportedExtensionHeader(u8),
    BadIpAddress,
    BadUdpPort(u32),
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

    pub fn parse_u16(&mut self) -> ParseResult<u16> {
        self.parse(2).map(LittleEndian::read_u16)
    }

    pub fn parse_u32(&mut self) -> ParseResult<u32> {
        self.parse(4).map(LittleEndian::read_u32)
    }
}
