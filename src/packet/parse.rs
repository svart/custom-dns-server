use std::io;

use bitvec::{prelude::Msb0, vec::BitVec, view::BitView};
use cookie_factory as cf;
use nom::Parser;
use nom::bits::complete::take;
use nom::combinator::map;
use nom::error::ErrorKind as NomErrorKind;
use ux::u4;

use super::byte_buffer::ByteBufferError;
use super::qname::QnameError;
use super::question::DnsQuestionError;

// Parsing

pub type Input<'a> = &'a [u8];
pub type ParseResult<'a, T> = nom::IResult<Input<'a>, T, ParseError<Input<'a>>>;

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

pub trait BitParsable
where
    Self: Sized,
{
    fn parse(i: BitInput) -> BitResult<Self>;
}

impl BitParsable for u4 {
    fn parse(i: BitInput) -> BitResult<Self> {
        map(take(4_usize), Self::new).parse(i)
    }
}

impl BitParsable for bool {
    fn parse(i: BitInput) -> BitResult<Self> {
        map(take(1_usize), |x: u8| x != 0).parse(i)
    }
}

// Serialization

type BitOutput = BitVec<u8, Msb0>;

pub fn write_bits<W, F>(f: F) -> impl cf::SerializeFn<W>
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

pub trait BitSerialize {
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
