use std::io;

use cookie_factory as cf;
use thiserror::Error;

use super::parse::ParseError;

pub const MAX_QNAME_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Error)]
pub enum QnameError {
    #[error("bogus qname label length: {0}, expected < {}", MAX_LABEL_LEN)]
    BadLabelLen(usize),
    #[error("exceeded maximum qname length, expected < {}", MAX_QNAME_LEN)]
    BadTotalLen,
}

impl<I> From<(I, QnameError)> for ParseError<I> {
    fn from(value: (I, QnameError)) -> Self {
        Self::Qname(value)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Qname {
    inner: Vec<String>,
}

impl TryFrom<String> for Qname {
    type Error = QnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: Qname::split_strings(value.as_str())?,
        })
    }
}

impl TryFrom<&str> for Qname {
    type Error = QnameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: Qname::split_strings(value)?,
        })
    }
}

impl TryFrom<Vec<String>> for Qname {
    type Error = QnameError;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let checked_vec = value
            .into_iter()
            .map(|x| {
                if x.len() < MAX_LABEL_LEN {
                    Ok(x.into())
                } else {
                    Err(QnameError::BadLabelLen(x.len()))
                }
            })
            .collect::<Result<Vec<String>, QnameError>>()?;

        let sum: usize = checked_vec.iter().map(|x| x.len() + 1).sum();
        if sum + 1 > MAX_QNAME_LEN {
            return Err(QnameError::BadTotalLen);
        }

        Ok(Self { inner: checked_vec })
    }
}

impl std::fmt::Display for Qname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Qname {{ {} }}", self.inner.join("."))
    }
}

impl Qname {
    fn split_strings(value: &str) -> Result<Vec<String>, QnameError> {
        if value.len() > MAX_QNAME_LEN {
            return Err(QnameError::BadTotalLen);
        }

        value
            .split('.')
            .map(|x| {
                if x.len() < MAX_LABEL_LEN {
                    Ok(x.into())
                } else {
                    Err(QnameError::BadLabelLen(x.len()))
                }
            })
            .collect()
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u8, combinator::string, multi::all, sequence::tuple};
        tuple((
            all(self
                .inner
                .iter()
                .map(|x| tuple((be_u8(x.len() as u8), string(x))))),
            be_u8(0),
        ))
    }

    // TODO: eliminate usage of this method by using cookie_factory methods
    pub fn serialized_size(&self) -> u16 {
        use cf::gen;

        let mut buf = [0u8; MAX_QNAME_LEN];
        let (_, pos) = gen(self.serialize(), &mut buf[..]).unwrap();
        pos as u16
    }

    pub fn ends_with(&self, other: &Qname) -> bool {
        std::iter::zip(self.inner.iter().rev(), other.inner.iter().rev()).all(|(x, y)| x == y)
    }
}
