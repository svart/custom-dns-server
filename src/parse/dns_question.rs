use std::io;

use super::{
    byte_message_buffer::ByteMessageBuffer, dns_qname::Qname, dns_query_type::QueryType, Input,
    ParseError, ParseResult,
};

use cookie_factory as cf;
use nom::{number::complete::be_u16, sequence::tuple};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsQuestionError {
    #[error("qclass is not IN, value is {0}, should be 1")]
    ParseClassError(u16),
}

impl<I> From<(I, DnsQuestionError)> for ParseError<I> {
    fn from(value: (I, DnsQuestionError)) -> Self {
        Self::DnsQuestion(value)
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub name: Qname,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn parse<'a>(i: Input<'a>, buf: &'a ByteMessageBuffer) -> ParseResult<'a, Self> {
        let (i, (name, qtype, qclass)) =
            tuple((buf.read_qname(), QueryType::parse, be_u16))(i)?;

        if qclass != 1 {
            return Err(nom::Err::Failure(ParseError::DnsQuestion((
                i,
                DnsQuestionError::ParseClassError(qclass),
            ))));
        }

        Ok((i, Self { name, qtype }))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((self.name.serialize(), self.qtype.serialize(), be_u16(1)))
    }
}
