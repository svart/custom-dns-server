use super::parse::{Input, ParseResult};

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,     // a host address
    Ns,    // an authoritative name server
    Cname, // the canonical name for an alias
    Soa,   // marks the start of a zone of authority
    // WKS,   // a well known service description
    // PTR,   // a domain name pointer
    Mx,   // mail exchange
    Aaaa, // 28
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::Ns,
            5 => QueryType::Cname,
            6 => QueryType::Soa,
            // 11 => QueryType::WKS,
            // 12 => QueryType::PTR,
            15 => QueryType::Mx,
            28 => QueryType::Aaaa,
            _ => QueryType::Unknown(value),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
            QueryType::Soa => 6,
            // QueryType::WKS => 11,
            // QueryType::PTR => 12,
            QueryType::Mx => 15,
            QueryType::Aaaa => 28,
        }
    }
}

impl QueryType {
    pub fn parse(i: Input) -> ParseResult<Self> {
        let (i, qtype) = nom::number::complete::be_u16(i)?;
        Ok((i, Self::from(qtype)))
    }

    pub fn serialize<'a, W: std::io::Write + 'a>(
        &'a self,
    ) -> impl cookie_factory::SerializeFn<W> + 'a {
        cookie_factory::bytes::be_u16((*self).into())
    }
}
