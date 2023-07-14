use super::{Input, ParseResult};
use super::{ResultCode, byte_packet_buffer::BytePacketBuffer};
use super::BitParsable;

use nom::bits::bits;
use nom::number::complete::be_u16;

use nom::sequence::tuple;
use ux::u4;

const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, PartialEq)]
pub struct DnsHeaderFlags {
    pub response: bool,             // 1 bit
    pub opcode: u4,                 // 4 bits TODO: make it enum
    pub authoritative_answer: bool, // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub recursion_desired: bool,    // 1 bit

    pub recursion_available: bool, // 1 bit
    pub z: bool,                   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub checking_disabled: bool,   // 1 bit
    pub rescode: ResultCode,       // 4 bits
}

impl DnsHeaderFlags {
    fn new() -> Self {
        Self {
            response: false,
            opcode: u4::new(0),
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,

            recursion_available: false,
            z: false,
            authed_data: false,
            checking_disabled: false,
            rescode: ResultCode::NoError,
        }
    }

    fn parse(i: Input) -> ParseResult<Self> {
        // 1st byte of flags
        let (
            i,
            (response, opcode, authoritative_answer, truncated_message, recursion_desired)
        ) = bits(tuple(
            (bool::parse, u4::parse, bool::parse, bool::parse, bool::parse)
        ))(i)?;

        // 2nd byte of flags
        let (
            i,
            (recursion_available, z, authed_data, checking_disabled, rescode)
        ) = bits(tuple(
            (bool::parse, bool::parse, bool::parse, bool::parse, u4::parse)
        ))(i)?;

        Ok((
            i,
            Self {
                recursion_desired,
                truncated_message,
                authoritative_answer,
                opcode,
                response,
                rescode: ResultCode::from(rescode),
                checking_disabled,
                authed_data,
                z,
                recursion_available,
            }
        ))
    }
}


#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsHeaderFlags,      // 16 bits
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        Self {
            id: 0,
            flags: DnsHeaderFlags::new(),
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn parse(i: Input) -> ParseResult<Self> {
        let (
            i,
            (id, flags, questions, answers, authoritative_entries, resource_entries)
        ) = tuple(
            (be_u16, DnsHeaderFlags::parse, be_u16, be_u16, be_u16, be_u16)
        )(i)?;

        Ok((
            i,
            Self {
                id,
                flags,
                questions,
                answers,
                authoritative_entries,
                resource_entries,
            }
        ))
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.flags.recursion_desired as u8)
                | ((self.flags.truncated_message as u8) << 1)
                | ((self.flags.authoritative_answer as u8) << 2)
                | (u8::from(self.flags.opcode) << 3)
                | ((self.flags.response as u8) << 7) as u8
        )?;

        buffer.write_u8(
            (self.flags.rescode as u8)
                | ((self.flags.checking_disabled as u8) << 4)
                | ((self.flags.authed_data as u8) << 5)
                | ((self.flags.z as u8) << 6)
                | ((self.flags.recursion_available as u8) << 7)
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::packet::{ResultCode, dns_header::DNS_HEADER_LEN};
    use super::DnsHeader;

    use ux::u4;

    #[test]
    fn parse_bad_buffer() {
        let data = [0; 2 * DNS_HEADER_LEN];

        for i in 0..data.len() {
            if i < DNS_HEADER_LEN {
                assert!(DnsHeader::parse(&data[..i]).is_err());
            } else {
                assert!(DnsHeader::parse(&data[..i]).is_ok());
            }
        }
    }

    #[test]
    fn parse_one_query() {
        let data = [0x17, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (i, header) = DnsHeader::parse(&data).unwrap();

        assert_eq!(i.len(), 0);

        assert_eq!(header.id, 0x1734);
        assert_eq!(header.flags.recursion_desired, true);
        assert_eq!(header.flags.truncated_message, false);
        assert_eq!(header.flags.authoritative_answer, false);
        assert_eq!(header.flags.opcode, u4::new(0));
        assert_eq!(header.flags.response, false);
        assert_eq!(header.flags.rescode, ResultCode::NoError);
        assert_eq!(header.flags.checking_disabled, false);
        assert_eq!(header.flags.authed_data, true);
        assert_eq!(header.flags.z, false);
        assert_eq!(header.flags.recursion_available, false);
        assert_eq!(header.questions, 1);
        assert_eq!(header.answers, 0);
        assert_eq!(header.authoritative_entries, 0);
        assert_eq!(header.resource_entries, 0);
    }

    #[test]
    fn parse_one_response() {
        let data = [0x17, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00];
        let (i, header) = DnsHeader::parse(&data).unwrap();

        assert_eq!(i.len(), 0);

        assert_eq!(header.id, 0x1734);
        assert_eq!(header.flags.recursion_desired, true);
        assert_eq!(header.flags.truncated_message, false);
        assert_eq!(header.flags.authoritative_answer, false);
        assert_eq!(header.flags.opcode, u4::new(0));
        assert_eq!(header.flags.response, true);
        assert_eq!(header.flags.rescode, ResultCode::NoError);
        assert_eq!(header.flags.checking_disabled, false);
        assert_eq!(header.flags.authed_data, false);
        assert_eq!(header.flags.z, false);
        assert_eq!(header.flags.recursion_available, true);
        assert_eq!(header.questions, 1);
        assert_eq!(header.answers, 6);
        assert_eq!(header.authoritative_entries, 0);
        assert_eq!(header.resource_entries, 0);
    }
}
