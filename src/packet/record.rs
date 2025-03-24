use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
    Parser,
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

use super::{
    byte_buffer::ByteBuffer,
    parse::{Input, ParseResult},
    qname::Qname,
    query_type::QueryType,
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
    Ns {
        domain: Qname,
        host: Qname,
        ttl: u32,
    },
    Cname {
        domain: Qname,
        host: Qname,
        ttl: u32,
    },
    Soa {
        domain: Qname,
        ttl: u32,
        primary_ns: Qname,
        email: Qname,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        min_ttl: u32,
    },
    Mx {
        domain: Qname,
        priority: u16,
        host: Qname,
        ttl: u32,
    },
    Aaaa {
        domain: Qname,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn parse<'a>(i: Input<'a>, buf: &'a ByteBuffer) -> ParseResult<'a, Self> {
        let (i, (domain, qtype, _, ttl, data_len)) =
            (buf.read_qname(), QueryType::parse, be_u16, be_u32, be_u16).parse(i)?;

        match qtype {
            QueryType::A => {
                let (i, raw_addr) = take(4usize)(i)?;
                let addr = Ipv4Addr::from(<&[u8] as TryInto<[u8; 4]>>::try_into(raw_addr).unwrap());

                Ok((i, DnsRecord::A { domain, addr, ttl }))
            }
            QueryType::Aaaa => {
                let (i, raw_addr) = take(16usize)(i)?;
                let addr =
                    Ipv6Addr::from(<&[u8] as TryInto<[u8; 16]>>::try_into(raw_addr).unwrap());
                Ok((i, DnsRecord::Aaaa { domain, addr, ttl }))
            }
            QueryType::Ns => {
                let (i, host) = buf.read_qname()(i)?;
                Ok((i, DnsRecord::Ns { domain, host, ttl }))
            }
            QueryType::Cname => {
                let (i, host) = buf.read_qname()(i)?;
                Ok((i, DnsRecord::Cname { domain, host, ttl }))
            }
            QueryType::Soa => {
                let (i, (primary_ns, email, serial, refresh, retry, expire, min_ttl)) = (
                    buf.read_qname(),
                    buf.read_qname(),
                    be_u32,
                    be_u32,
                    be_u32,
                    be_u32,
                    be_u32,
                )
                    .parse(i)?;
                Ok((
                    i,
                    DnsRecord::Soa {
                        domain,
                        ttl,
                        primary_ns,
                        email,
                        serial,
                        refresh,
                        retry,
                        expire,
                        min_ttl,
                    },
                ))
            }
            QueryType::Mx => {
                let (i, (priority, host)) = (be_u16, buf.read_qname()).parse(i)?;
                Ok((
                    i,
                    DnsRecord::Mx {
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
            DnsRecord::Aaaa {
                ref domain,
                addr,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::Aaaa.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(16),
                slice(addr.octets()),
            ))),
            DnsRecord::Ns {
                ref domain,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::Ns.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size()),
                host.serialize(),
            ))),
            DnsRecord::Cname {
                ref domain,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::Cname.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size()),
                host.serialize(),
            ))),
            DnsRecord::Soa {
                ref domain,
                ttl,
                ref primary_ns,
                ref email,
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::Soa.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(primary_ns.serialized_size() + email.serialized_size() + 5 * 4),
                primary_ns.serialize(),
                email.serialize(),
                be_u32(serial),
                be_u32(refresh),
                be_u32(retry),
                be_u32(expire),
                be_u32(min_ttl),
            ))),
            DnsRecord::Mx {
                ref domain,
                priority,
                ref host,
                ttl,
            } => Box::new(tuple((
                domain.serialize(),
                QueryType::Mx.serialize(),
                be_u16(1),
                be_u32(ttl),
                be_u16(host.serialized_size() + 2),
                be_u16(priority),
                host.serialize(),
            ))),
            DnsRecord::Unknown { .. } => {
                println!("Skipping record serialization: {:?}", self);
                Box::new(Ok)
            }
        }
    }
}
