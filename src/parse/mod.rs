use std::io;

use bitvec::{prelude::Msb0, vec::BitVec, view::BitView};
use cookie_factory as cf;
use nom::bits::complete::take;
use nom::combinator::map;
use nom::error::ErrorKind as NomErrorKind;
use ux::u4;

use self::byte_message_buffer::ByteBufferError;
use self::dns_qname::QnameError;
use self::dns_question::DnsQuestionError;

pub mod byte_message_buffer;
mod dns_header;
pub mod dns_packet;
pub mod dns_qname;
pub mod dns_query_type;
pub mod dns_question;
pub mod dns_record;

// Parsing

type Input<'a> = &'a [u8];
type ParseResult<'a, T> = nom::IResult<Input<'a>, T, ParseError<Input<'a>>>;

type BitInput<'a> = (&'a [u8], usize);
type BitResult<'a, T> = nom::IResult<BitInput<'a>, T, ParseError<BitInput<'a>>>;

#[derive(Debug)]
pub enum ParseError<I> {
    Nom((I, NomErrorKind)),
    ByteBuffer((I, ByteBufferError)),
    Qname((I, QnameError)),
    DnsQuestion((I, DnsQuestionError)),
}

impl<I> nom::error::ParseError<I> for ParseError<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        Self::Nom((input, kind))
    }

    fn append(_input: I, _kind: NomErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> nom::ErrorConvert<ParseError<I>> for ParseError<(I, usize)> {
    fn convert(self) -> ParseError<I> {
        // TODO: Recheck its validity
        match self {
            Self::Nom((i, e)) => ParseError::Nom((i.0, e)),
            Self::ByteBuffer((i, e)) => ParseError::ByteBuffer((i.0, e)),
            Self::Qname((i, e)) => ParseError::Qname((i.0, e)),
            Self::DnsQuestion((i, e)) => ParseError::DnsQuestion((i.0, e)),
        }
    }
}

trait BitParsable
where
    Self: Sized,
{
    fn parse(i: BitInput) -> BitResult<Self>;
}

impl BitParsable for u4 {
    fn parse(i: BitInput) -> BitResult<Self> {
        map(take(4_usize), Self::new)(i)
    }
}

impl BitParsable for bool {
    fn parse(i: BitInput) -> BitResult<Self> {
        map(take(1_usize), |x: u8| x != 0)(i)
    }
}

// Serialization

type BitOutput = BitVec<u8, Msb0>;

fn write_bits<W, F>(f: F) -> impl cf::SerializeFn<W>
where
    W: io::Write,
    F: Fn(&mut BitOutput),
{
    move |mut out: cf::WriteContext<W>| {
        let mut bo = BitOutput::new();
        f(&mut bo);

        io::Write::write(&mut out, bo.as_raw_slice())?;
        Ok(out)
    }
}

trait WriteLastNBits {
    fn write_last_n_bits<B: BitView>(&mut self, b: B, num_bits: usize);
}

impl WriteLastNBits for BitOutput {
    fn write_last_n_bits<B: BitView>(&mut self, b: B, num_bits: usize) {
        let bitslice = b.view_bits::<Msb0>();
        let start = bitslice.len() - num_bits;
        self.extend_from_bitslice(&bitslice[start..])
    }
}

trait BitSerialize {
    fn write(&self, b: &mut BitOutput);
}

impl BitSerialize for u4 {
    fn write(&self, b: &mut BitOutput) {
        // use u8 here because bitvec implements its traits only for standard types
        b.write_last_n_bits(u8::from(*self), 4)
    }
}

impl BitSerialize for bool {
    fn write(&self, b: &mut BitOutput) {
        b.write_last_n_bits(u8::from(*self), 1)
    }
}

// Structs

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ResultCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NoTimp = 4,
    Refused = 5,
}

impl From<u4> for ResultCode {
    fn from(value: u4) -> Self {
        match u8::from(value) {
            1 => ResultCode::FormErr,
            2 => ResultCode::ServFail,
            3 => ResultCode::NxDomain,
            4 => ResultCode::NoTimp,
            5 => ResultCode::Refused,
            0 | _ => ResultCode::NoError,
        }
    }
}

impl From<ResultCode> for u4 {
    fn from(value: ResultCode) -> Self {
        match value {
            ResultCode::FormErr => u4::new(1),
            ResultCode::ServFail => u4::new(2),
            ResultCode::NxDomain => u4::new(3),
            ResultCode::NoTimp => u4::new(4),
            ResultCode::Refused => u4::new(5),
            ResultCode::NoError => u4::new(0),
        }
    }
}
