use std::{net::Ipv4Addr, io};

use nom::combinator::map;
use nom::bits::complete::take;
use ux::u4;
use bitvec::{view::BitView, vec::BitVec, prelude::Msb0};
use cookie_factory as cf;

use self::{byte_packet_buffer::BytePacketBuffer, dns_header::DnsHeader, dns_question::DnsQuestion, dns_record::DnsRecord};

pub mod byte_packet_buffer;
pub mod dns_question;
pub mod dns_record;
mod dns_header;

// Parsing

type Input<'a> = &'a[u8];
type ParseResult<'a, T> = nom::IResult<Input<'a>, T, ()>;

type BitInput<'a> = (&'a[u8], usize);
type BitResult<'a, T> = nom::IResult<BitInput<'a>, T, ()>;


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
        map(take(1_usize), |x: u8| { x != 0 })(i)
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


#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,     // a host address
    NS,    // an authoritative name server
    CNAME, // the canonical name for an alias
    // SOA,   // marks the start of a zone of authority
    // WKS,   // a well known service description
    // PTR,   // a domain name pointer
    MX,    // mail exchange
    AAAA,  // 28
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            // 6 => QueryType::SOA,
            // 11 => QueryType::WKS,
            // 12 => QueryType::PTR,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::Unknown(value),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            // QueryType::SOA => 6,
            // QueryType::WKS => 11,
            // QueryType::PTR => 12,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}


#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self, String> {
        let mut result = DnsPacket::new();
        let (_, h) = DnsHeader::parse(&buffer.buf).unwrap();
        buffer.seek(12).unwrap();
        result.header = h;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        let serialized_header = cf::gen_simple(self.header.serialize(), Vec::new()).map_err(|_|{ "cannot serialize header".to_owned() })?;
        for i in 0..dns_header::DNS_HEADER_LEN {
            buffer.write_u8(serialized_header[i])?;
        }

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .find_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard server which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .copied()
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname)
            .map(|(_, host)| host)
            .next()
    }
}
