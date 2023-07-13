use std::net::{Ipv4Addr, Ipv6Addr};

use super::{byte_packet_buffer::BytePacketBuffer, QueryType};


#[derive(Debug)]
pub enum DnsRecord {
    Unknown {
        _domain: String,
        _qtype: u16,
        _data_len: u16,
        _ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, String> {
        let domain = buffer.read_qname()?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xff) as u8,
                    ((raw_addr >> 16) & 0xff) as u8,
                    ((raw_addr >> 8) & 0xff) as u8,
                    ((raw_addr >> 0) & 0xff) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xffff) as u16,
                    ((raw_addr1 >> 0) & 0xffff) as u16,
                    ((raw_addr2 >> 16) & 0xffff) as u16,
                    ((raw_addr2 >> 0) & 0xffff) as u16,
                    ((raw_addr3 >> 16) & 0xffff) as u16,
                    ((raw_addr3 >> 0) & 0xffff) as u16,
                    ((raw_addr4 >> 16) & 0xffff) as u16,
                    ((raw_addr4 >> 0) & 0xffff) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                Ok(DnsRecord::NS {
                    domain,
                    host: buffer.read_qname()?,
                    ttl
                })
            }
            QueryType::CNAME => {
                Ok(DnsRecord::CNAME {
                    domain,
                    host: buffer.read_qname()?,
                    ttl
                })
            }
            QueryType::MX => {
                Ok(DnsRecord::MX {
                    domain,
                    priority: buffer.read_u16()?,
                    host: buffer.read_qname()?,
                    ttl
                })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown {
                    _domain: domain,
                    _qtype: qtype_num,
                    _data_len: data_len,
                    _ttl: ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, String> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::Unknown { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
