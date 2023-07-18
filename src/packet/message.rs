use std::net::Ipv4Addr;

use cookie_factory as cf;
use nom::{multi::count, sequence::tuple};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsPacketError {
    #[error("cannot parse from buffer: {0}")]
    ParseOther(#[from] ByteBufferError),
}

use super::{
    byte_buffer::{ByteBuffer, ByteBufferError},
    header::DnsHeader,
    parse::{Input, ParseResult},
    qname::Qname,
    question::DnsQuestion,
    record::DnsRecord,
};

#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn update_header(&mut self) {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;
    }

    pub fn parse<'a>(i: Input<'a>, buf: &'a ByteBuffer) -> ParseResult<'a, Self> {
        let (i, header) = DnsHeader::parse(i)?;
        let (i, (questions, answers, authorities, resources)) = tuple((
            count(|x| DnsQuestion::parse(x, buf), header.questions as usize),
            count(|x| DnsRecord::parse(x, buf), header.answers as usize),
            count(
                |x| DnsRecord::parse(x, buf),
                header.authoritative_entries as usize,
            ),
            count(
                |x| DnsRecord::parse(x, buf),
                header.resource_entries as usize,
            ),
        ))(i)?;

        Ok((
            i,
            Self {
                header,
                questions,
                answers,
                authorities,
                resources,
            },
        ))
    }

    pub fn serialize<'a, W: std::io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{multi::all, sequence::tuple};

        tuple((
            self.header.serialize(),
            all(self.questions.iter().map(|x| x.serialize())),
            all(self.answers.iter().map(|x| x.serialize())),
            all(self.authorities.iter().map(|x| x.serialize())),
            all(self.resources.iter().map(|x| x.serialize())),
        ))
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn get_ns<'a>(&'a self, qname: &'a Qname) -> impl Iterator<Item = (&'a Qname, &'a Qname)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain, host)),
                _ => None,
            })
            // Discard server which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(domain))
    }

    pub fn get_resolved_ns(&self, qname: &Qname) -> Option<Ipv4Addr> {
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

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a Qname) -> Option<&'a Qname> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::packet::byte_buffer::ByteBuffer;

    use super::DnsMessage;

    fn get_data(path: &str) -> Vec<u8> {
        let path = Path::new(path);
        let data = std::fs::read(path).expect("cannot read file");
        data
    }

    #[test]
    fn parse_1() {
        let data = get_data("test_data/reply_1.bin");
        let buffer = ByteBuffer::new(&data);

        let (i, packet) = DnsMessage::parse(&data, &buffer).unwrap();

        assert_eq!(i.len(), 0);

        assert_eq!(packet.header.answers as usize, packet.answers.len());
    }
}
