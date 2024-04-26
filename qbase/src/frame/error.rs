use super::{DataFrame, InfoFrame};
use nom::error::{Error, ErrorKind};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DecodingError {
    InvalidFrameType(u8),
    WrongFrame(InfoFrame),
    WrongData(DataFrame),
    Incomplete,
    NomError(ErrorKind),
}

impl From<nom::Err<Error<&[u8]>>> for DecodingError {
    fn from(value: nom::Err<Error<&[u8]>>) -> Self {
        // TODO: log with println is not ok, because it's not cross-platform
        println!("[QUIC][Decoding Frame] nom error: {:?}", value);
        match value {
            nom::Err::Incomplete(_needed) => Self::Incomplete,
            nom::Err::Error(err) | nom::Err::Failure(err) => Self::NomError(err.code),
        }
    }
}

// TODO: conver DecodingError to quic error
