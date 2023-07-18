use super::parse::{Input, ParseResult};

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,     // a host address
    NS,    // an authoritative name server
    CNAME, // the canonical name for an alias
    // SOA,   // marks the start of a zone of authority
    // WKS,   // a well known service description
    // PTR,   // a domain name pointer
    MX,   // mail exchange
    AAAA, // 28
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

impl QueryType {
    pub fn parse(i: Input) -> ParseResult<Self> {
        let (i, qtype) = nom::number::complete::be_u16(i)?;
        Ok((i, Self::from(qtype)))
    }

    pub fn serialize<'a, W: std::io::Write + 'a>(&'a self) -> impl cookie_factory::SerializeFn<W> + 'a {
        cookie_factory::bytes::be_u16((*self).into())
    }
}
