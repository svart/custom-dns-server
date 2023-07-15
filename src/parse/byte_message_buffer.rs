use super::{
    dns_qname::{Qname, QnameError},
    Input, ParseError, ParseResult,
};

use thiserror::Error;

pub const MAX_DNS_MSG_SIZE: usize = 512;
const MAX_JUMPS: usize = 5;

#[derive(Debug, Error)]
pub enum ByteBufferError {
    #[error("attempt to read out of buffer bounds: {index} >= {buf_len}")]
    BoundError { buf_len: usize, index: usize },
    #[error("jump limit exceeded ({}) during qname unpacking", MAX_JUMPS)]
    JumpLimitExceeded,
    #[error("invalid qname: {0}")]
    QnameError(#[from] QnameError),
}

impl<I> From<(I, ByteBufferError)> for ParseError<I> {
    fn from(value: (I, ByteBufferError)) -> Self {
        Self::ByteBuffer(value)
    }
}

/// Immutable DNS message buffer to read packed qname with jumping around the buffer.
pub struct ByteMessageBuffer<'a> {
    buf: &'a [u8],
}

impl<'a> ByteMessageBuffer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Get length of underlying byte buffer
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Get single byte try_from buffer with boundary check.
    fn peek_u8(&self, pos: usize) -> Result<u8, ByteBufferError> {
        if pos >= self.buf.len() {
            return Err(ByteBufferError::BoundError {
                buf_len: self.buf.len(),
                index: pos,
            });
        }
        Ok(self.buf[pos])
    }

    /// Get slice of bytes with boundary check.
    fn peek_range(&self, start: usize, len: usize) -> Result<&[u8], ByteBufferError> {
        if start + len >= self.buf.len() {
            return Err(ByteBufferError::BoundError {
                buf_len: self.buf.len(),
                index: start + len,
            });
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read a qname.
    ///
    /// This function performes jumping around the buffer to collect fully
    /// qualified name starting try_from the `pos`.
    pub fn read_qname(&'a self) -> impl FnMut(Input<'a>) -> ParseResult<'a, Qname> {
        |i: Input<'a>| {
            let mut pos = self.len() - i.len();
            let mut jumps_performed = 0;
            let mut qnames = Vec::new();
            let mut consumed: usize = 0;

            loop {
                // DNS packets are untrusted data, so we need to be paranoid. Someone
                // can craft a packet with a cycle in the jump instructions. This guards
                // against such packets.
                if jumps_performed > MAX_JUMPS {
                    return Err(nom::Err::Failure(ParseError::ByteBuffer((
                        i,
                        ByteBufferError::JumpLimitExceeded,
                    ))));
                }

                // Assume that `pos` is pointing to the start of the qname.
                let len = self
                    .peek_u8(pos)
                    .map_err(|e| nom::Err::Failure(ParseError::ByteBuffer((i, e))))?;

                // If `len` has the two most significant bits set, it represents a
                // jump to some other offset in the packet.
                if (len & 0xC0) == 0xC0 {
                    // Read another byte and calculate next position try_from 14 bits.
                    let b2 = self
                        .peek_u8(pos + 1)
                        .map_err(|e| nom::Err::Failure(ParseError::ByteBuffer((i, e))))?
                        as u16;
                    let offset = (((len ^ 0xC0) as u16) << 8) | b2;
                    pos = offset as usize;

                    // Update current reading position in
                    if jumps_performed == 0 {
                        consumed += 1;
                    }

                    // Take into account this jump.
                    jumps_performed += 1;

                    continue;
                }
                // The base scenario, current label represents part of qname.
                else {
                    // Domain names are terminated by an empty label of length 0,
                    // so if the length is zero we're done.
                    if len == 0 {
                        if jumps_performed == 0 {
                            consumed += 1;
                        }
                        break;
                    }

                    // Move a single byte forward to move past the length byte.
                    pos += 1;

                    // Extract actual ASCII bytes for current label
                    let byte_str = self
                        .peek_range(pos, len as usize)
                        .map_err(|e| nom::Err::Failure(ParseError::ByteBuffer((i, e))))?;
                    let string = String::from_utf8_lossy(byte_str).to_lowercase();
                    qnames.push(string);

                    // Move forward for the length of the label.
                    pos += len as usize;
                    if jumps_performed == 0 {
                        consumed += len as usize + 1;
                    }
                }
            }

            Ok((
                &i[consumed..],
                Qname::try_from(qnames)
                    .map_err(|e| nom::Err::Failure(ParseError::Qname((i, e))))?,
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::ByteMessageBuffer;
    use crate::parse::{dns_header::DNS_HEADER_LEN, dns_qname::Qname};

    fn get_data(path: &str) -> Vec<u8> {
        let path = Path::new(path);
        let data = std::fs::read(path).expect("cannot read file");
        data
    }

    #[test]
    fn check_jumping_1() {
        let data = get_data("test_data/reply_1.bin");
        let mut buffer = ByteMessageBuffer::new(&data);

        assert!(buffer.seek(DNS_HEADER_LEN).is_ok());
        // Queries
        assert_eq!(
            buffer.read_qname(DNS_HEADER_LEN).unwrap(),
            Qname::try_from("cns1.secureserver.net").unwrap()
        );
        assert!(buffer.seek(4).is_ok());

        // Authoritative nameservers
        // RR 1
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("e.gtld-servers.net").unwrap()
        );
        // RR 2
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("f.gtld-servers.net").unwrap()
        );
        // RR 3
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("m.gtld-servers.net").unwrap()
        );
        // RR 4
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("i.gtld-servers.net").unwrap()
        );
        // RR 5
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("j.gtld-servers.net").unwrap()
        );
        // RR 6
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("b.gtld-servers.net").unwrap()
        );
        // RR 7
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("a.gtld-servers.net").unwrap()
        );
        // RR 8
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("c.gtld-servers.net").unwrap()
        );
        // RR 9
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("k.gtld-servers.net").unwrap()
        );
        // RR 10
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("h.gtld-servers.net").unwrap()
        );
        // RR 11
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("l.gtld-servers.net").unwrap()
        );
        // RR 12
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("g.gtld-servers.net").unwrap()
        );
        // RR 13
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("net").unwrap()
        );
        assert!(buffer.seek(10).is_ok());
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("d.gtld-servers.net").unwrap()
        );

        // Additional records
        // RR 1
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("e.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(14).is_ok());
        // RR 2
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("e.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(26).is_ok());
        // RR 3
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("f.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(14).is_ok());
        // RR 4
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("f.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(26).is_ok());
        // RR 5
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("m.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(14).is_ok());
        // RR 6
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("m.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(26).is_ok());
        // RR 7
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("i.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(14).is_ok());
        // RR 8
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("i.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(26).is_ok());
        // RR 9
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("j.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(14).is_ok());
        // RR 10
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("j.gtld-servers.net").unwrap()
        );
        assert!(buffer.seek(26).is_ok());
        // RR 11
        assert_eq!(
            buffer.read_qname().unwrap(),
            Qname::try_from("b.gtld-servers.net").unwrap()
        );
    }
}
