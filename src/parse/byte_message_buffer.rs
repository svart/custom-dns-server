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
                        consumed += 2;
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
    use crate::parse::dns_qname::Qname;

    const DNS_HEADER_LEN: usize = 12;

    fn get_data(path: &str) -> Vec<u8> {
        let path = Path::new(path);
        let data = std::fs::read(path).expect("cannot read file");
        data
    }

    #[test]
    fn check_jumping_1() {
        let data = get_data("test_data/reply_1.bin");
        let buffer = ByteMessageBuffer::new(&data);
        let i = &data[DNS_HEADER_LEN..];

        // Queries
        let (i, qname) = buffer.read_qname()(i).unwrap();

        assert_eq!(qname, Qname::try_from("cns1.secureserver.net").unwrap());
        let mut i = &i[4..];

        // Authoritative nameservers
        for letter in ['e', 'f', 'm', 'i', 'j', 'b', 'a', 'c', 'k', 'h', 'l', 'g', 'd'] {
            let (i_in, qname) = buffer.read_qname()(i).unwrap();
            assert_eq!(qname, Qname::try_from("net").unwrap());

            let i_in = &i_in[10..];

            let server_name = letter.to_string() + ".gtld-servers.net";
            let (i_in, qname) = buffer.read_qname()(i_in).unwrap();
            assert_eq!(qname, Qname::try_from(server_name).unwrap());

            i = i_in;
        };
        // Additional records
        for letter in ['e', 'f', 'm', 'i', 'j'] {
            let server_name = letter.to_string() + ".gtld-servers.net";

            // IPv4
            let (i_in, qname) = buffer.read_qname()(i).unwrap();
            assert_eq!(qname, Qname::try_from(server_name.as_str()).unwrap());
            let i_in = &i_in[14..];

            // Ipv6
            let (i_in, qname) = buffer.read_qname()(i_in).unwrap();
            assert_eq!(qname, Qname::try_from(server_name.as_str()).unwrap());
            let i_in = &i_in[26..];
            i = i_in;
        }
        // the last one without pair
        let (_, qname) = buffer.read_qname()(i).unwrap();
        assert_eq!(qname, Qname::try_from("b.gtld-servers.net").unwrap());
    }
}
