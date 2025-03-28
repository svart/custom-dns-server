use std::io;

use super::ResultCode;
use super::parse::{BitParsable, BitSerialize, Input, ParseResult, write_bits};

use cookie_factory as cf;
use nom::Parser;
use nom::bits::bits;
use nom::number::complete::be_u16;
use ux::u4;

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
        let (
            i,
            (
                response,
                opcode,
                authoritative_answer,
                truncated_message,
                recursion_desired,
                recursion_available,
                z,
                authed_data,
                checking_disabled,
                rescode,
            ),
        ) = bits((
            // 1st byte of flags
            bool::parse,
            u4::parse,
            bool::parse,
            bool::parse,
            bool::parse,
            // 2nd byte of flags
            bool::parse,
            bool::parse,
            bool::parse,
            bool::parse,
            u4::parse,
        ))
        .parse(i)?;

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
            },
        ))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        write_bits(move |b| {
            self.response.write(b);
            self.opcode.write(b);
            self.authoritative_answer.write(b);
            self.truncated_message.write(b);
            self.recursion_desired.write(b);
            self.recursion_available.write(b);
            self.z.write(b);
            self.authed_data.write(b);
            self.checking_disabled.write(b);
            u4::from(self.rescode).write(b);
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsHeaderFlags, // 16 bits
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
        let (i, (id, flags, questions, answers, authoritative_entries, resource_entries)) = (
            be_u16,
            DnsHeaderFlags::parse,
            be_u16,
            be_u16,
            be_u16,
            be_u16,
        )
            .parse(i)?;

        Ok((
            i,
            Self {
                id,
                flags,
                questions,
                answers,
                authoritative_entries,
                resource_entries,
            },
        ))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((
            be_u16(self.id),
            self.flags.serialize(),
            be_u16(self.questions),
            be_u16(self.answers),
            be_u16(self.authoritative_entries),
            be_u16(self.resource_entries),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::DnsHeader;
    use crate::packet::ResultCode;

    use cookie_factory as cf;
    use ux::u4;

    const DNS_HEADER_LEN: usize = 12;

    #[test]
    fn parse_buffer_variate_len() {
        let data = [0; 2 * DNS_HEADER_LEN];

        for len in 0..data.len() {
            let i = &data[..len];

            if len < DNS_HEADER_LEN {
                assert!(DnsHeader::parse(i).is_err());
            } else {
                let (i, _) = DnsHeader::parse(i).unwrap();
                assert_eq!(i.len(), len - DNS_HEADER_LEN);
            }
        }
    }

    #[test]
    fn check_one_query() {
        let data = [
            0x17, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (i, header) = DnsHeader::parse(&data).unwrap();
        assert_eq!(i.len(), 0);

        assert_eq!(header.id, 0x1734);
        assert!(header.flags.recursion_desired);
        assert!(!header.flags.truncated_message);
        assert!(!header.flags.authoritative_answer);
        assert_eq!(header.flags.opcode, u4::new(0));
        assert!(!header.flags.response);
        assert_eq!(header.flags.rescode, ResultCode::NoError);
        assert!(!header.flags.checking_disabled);
        assert!(header.flags.authed_data);
        assert!(!header.flags.z);
        assert!(!header.flags.recursion_available);
        assert_eq!(header.questions, 1);
        assert_eq!(header.answers, 0);
        assert_eq!(header.authoritative_entries, 0);
        assert_eq!(header.resource_entries, 0);

        let serialized = cf::gen_simple(header.serialize(), Vec::new()).unwrap();
        assert_eq!(&data, serialized.as_slice());
    }

    #[test]
    fn check_one_response() {
        let data = [
            0x17, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
        ];

        let (i, header) = DnsHeader::parse(&data).unwrap();
        assert_eq!(i.len(), 0);

        assert_eq!(header.id, 0x1734);
        assert!(header.flags.recursion_desired);
        assert!(!header.flags.truncated_message);
        assert!(!header.flags.authoritative_answer);
        assert_eq!(header.flags.opcode, u4::new(0));
        assert!(header.flags.response);
        assert_eq!(header.flags.rescode, ResultCode::NoError);
        assert!(!header.flags.checking_disabled);
        assert!(!header.flags.authed_data);
        assert!(!header.flags.z);
        assert!(header.flags.recursion_available);
        assert_eq!(header.questions, 1);
        assert_eq!(header.answers, 6);
        assert_eq!(header.authoritative_entries, 0);
        assert_eq!(header.resource_entries, 0);

        let serialized = cf::gen_simple(header.serialize(), Vec::new()).unwrap();
        assert_eq!(&data, serialized.as_slice());
    }
}
