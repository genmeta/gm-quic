use super::{DataFrame, InfoFrame};
use crate::varint::VarInt;
use nom::error::ErrorKind;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DecodingError {
    IncompleteType(String),
    InvalidType(VarInt),
    WrongFrame(InfoFrame),
    WrongData(DataFrame),
    ParseError(VarInt, String),
}

impl From<nom::Err<DecodingError>> for DecodingError {
    fn from(value: nom::Err<DecodingError>) -> Self {
        match value {
            nom::Err::Incomplete(_needed) => {
                unreachable!("Because the parsing of QUIC packets and frames is not stream-based.")
            }
            nom::Err::Error(err) | nom::Err::Failure(err) => err,
        }
    }
}

impl nom::error::ParseError<&[u8]> for DecodingError {
    fn from_error_kind(_input: &[u8], _kind: ErrorKind) -> Self {
        match _kind {
            ErrorKind::Many0 => unreachable!("QUIC frame parsing will never encounter an infinite loop parsing that does not consume any bytes."),
            _ => unimplemented!("never encounter other error kind while parsing QUIC frame.")
        }
    }

    fn append(_input: &[u8], _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

// TODO: conver DecodingError to quic error
