use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    sequence::tuple,
};

use super::{
    byte_buffer::ByteBuffer,
    qname::Qname,
    query_type::QueryType,
    parse::{Input, ParseResult},
};

#[derive(Debug)]
pub enum DnsRecord {
    Unknown {
        domain: Qname,
        qtype: QueryType,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: Qname,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: Qname,
        host: Qname,
        ttl: u32,
    },
    CNAME {
        domain: Qname,
        host: Qname,
        ttl: u32,
    },
    MX {
        domain: Qname,
        priority: u16,
        host: Qname,
        ttl: u32,
    },
    AAAA {
        domain: Qname,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn parse<'a>(i: Input<'a>, buf: &'a ByteBuffer) -> ParseResult<'a, Self> {
        let (i, (domain, qtype, _, ttl, data_len)) =
            tuple((buf.read_qname(), QueryType::parse, be_u16, be_u32, be_u16))(i)?;

        match qtype {
            QueryType::A => {
                let (i, raw_addr) = take(4usize)(i)?;
                let addr = Ipv4Addr::from(<&[u8] as TryInto<[u8; 4]>>::try_into(raw_addr).unwrap());

                Ok((i, DnsRecord::A { domain, addr, ttl }))
            }
            QueryType::AAAA => {
                let (i, raw_addr) = take(16usize)(i)?;
                let addr =
                    Ipv6Addr::from(<&[u8] as TryInto<[u8; 16]>>::try_into(raw_addr).unwrap());
                Ok((i, DnsRecord::AAAA { domain, addr, ttl }))
            }
            QueryType::NS => {
                let (i, host) = buf.read_qname()(i)?;
                Ok((i, DnsRecord::NS { domain, host, ttl }))
            }
            QueryType::CNAME => {
                let (i, host) = buf.read_qname()(i)?;
                Ok((i, DnsRecord::CNAME { domain, host, ttl }))
            }
            QueryType::MX => {
                let (i, (priority, host)) = tuple((be_u16, buf.read_qname()))(i)?;
                Ok((
                    i,
                    DnsRecord::MX {
                        domain,
                        priority,
                        host,
                        ttl,
                    },
                ))
            }
            QueryType::Unknown(_) => {
                let (i, _) = take(data_len)(i)?;
                Ok((
                    i,
                    DnsRecord::Unknown {
                        domain,
                        qtype,
                        data_len,
                        ttl,
                    },
                ))
            }
        }
    }

    pub fn serialize<'a, W: std::io::Write + 'a>(
        &'a self,
    ) -> Box<dyn cookie_factory::SerializeFn<W> + 'a> {
        use cookie_factory::{
            bytes::{be_u16, be_u32},
            combinator::slice,
            sequence::tuple,
        };

        match *self {
            DnsRecord::A {
                ref domain,
                addr,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::A.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(4),
                slice(addr.octets()),
            ))),
            DnsRecord::AAAA {
                ref domain,
                addr,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::AAAA.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(16),
                slice(addr.octets()),
            ))),
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::NS.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size()),
                host.serialize(),
            ))),
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::CNAME.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size()),
                host.serialize(),
            ))),
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::MX.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size() + 2),
                be_u16(priority),
                host.serialize(),
            ))),
            DnsRecord::Unknown { .. } => {
                // println!("Skipping record: {:?}", self);
                // TODO: Think how to just skip this
                unimplemented!("Unknown record processing is not implemented")
            }
        }
    }
}
