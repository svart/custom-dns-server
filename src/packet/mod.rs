use ux::u4;

pub mod byte_buffer;
mod header;
pub mod message;
mod parse;
pub mod qname;
pub mod query_type;
pub mod question;
pub mod record;

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
            0 => ResultCode::NoError,
            _ => ResultCode::NoError,
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
