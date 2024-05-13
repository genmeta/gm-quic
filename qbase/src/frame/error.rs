use super::FrameType;
use crate::varint::VarInt;
use nom::error::ErrorKind as NomErrorKind;
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, Error)]
pub enum Error {
    #[error("A packet containing no frames")]
    NoFrames,
    #[error("Incomplete frame type: {0}")]
    IncompleteType(String),
    #[error("Invalid frame type from {0}")]
    InvalidType(VarInt),
    #[error("Incomplete frame {0:?}: {1}")]
    IncompleteFrame(FrameType, String),
    #[error("Error occurred when parsing frame {0:?}: {1}")]
    ParseError(FrameType, String),
    #[error("{1} space does not contain frame {0:?}")]
    WrongFrame(FrameType, &'static str),
    #[error("{1} space does not contain data frame {0:?}")]
    WrongData(FrameType, &'static str),
}

use crate::error::Error as TransportError;
use crate::error::ErrorKind as TransportErrorKind;

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!("never happen.")
    }
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            // An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.
            Error::NoFrames => Self::new(
                TransportErrorKind::ProtocolViolation,
                FrameType::Padding,
                e.to_string(),
            ),
            Error::IncompleteType(_) => Self::new(
                TransportErrorKind::FrameEncoding,
                FrameType::Padding,
                e.to_string(),
            ),
            Error::InvalidType(_) => Self::new(
                TransportErrorKind::FrameEncoding,
                FrameType::Padding,
                e.to_string(),
            ),
            Error::IncompleteFrame(fty, _) => {
                Self::new(TransportErrorKind::FrameEncoding, fty, e.to_string())
            }
            Error::ParseError(fty, _) => {
                Self::new(TransportErrorKind::FrameEncoding, fty, e.to_string())
            }
            Error::WrongFrame(fty, _) => {
                Self::new(TransportErrorKind::ProtocolViolation, fty, e.to_string())
            }
            Error::WrongData(fty, _) => {
                Self::new(TransportErrorKind::ProtocolViolation, fty, e.to_string())
            }
        }
    }
}

impl From<nom::Err<Error>> for Error {
    fn from(value: nom::Err<Error>) -> Self {
        match value {
            nom::Err::Incomplete(_needed) => {
                unreachable!("Because the parsing of QUIC packets and frames is not stream-based.")
            }
            nom::Err::Error(err) | nom::Err::Failure(err) => err,
        }
    }
}

impl nom::error::ParseError<&[u8]> for Error {
    fn from_error_kind(_input: &[u8], _kind: NomErrorKind) -> Self {
        debug_assert_eq!(_kind, NomErrorKind::ManyTill);
        unreachable!("QUIC frame parser must always consume")
    }

    fn append(_input: &[u8], _kind: NomErrorKind, source: Self) -> Self {
        // 在解析帧时遇到了source错误，many_till期望通过ManyTill的错误类型告知
        // 这里，源错误更有意义，所以直接返回源错误
        debug_assert_eq!(_kind, NomErrorKind::ManyTill);
        source
    }
}

// TODO: conver DecodingError to quic error
