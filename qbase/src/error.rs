use crate::{frame::FrameType, varint::VarInt};
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    None,
    Internal,
    ConnectionRefused,
    FlowControl,
    StreamLimit,
    StreamState,
    FinalSize,
    FrameEncoding,
    TransportParameter,
    ConnectionIdLimit,
    ProtocolViolation,
    InvalidToken,
    Application,
    CryptoBufferExceeded,
    KeyUpdate,
    AeadLimitReached,
    NoViablePath,
    Crypto(u8),
}

impl From<ErrorKind> for VarInt {
    fn from(value: ErrorKind) -> Self {
        match value {
            ErrorKind::None => VarInt(0x00),
            ErrorKind::Internal => VarInt(0x01),
            ErrorKind::ConnectionRefused => VarInt(0x02),
            ErrorKind::FlowControl => VarInt(0x03),
            ErrorKind::StreamLimit => VarInt(0x04),
            ErrorKind::StreamState => VarInt(0x05),
            ErrorKind::FinalSize => VarInt(0x06),
            ErrorKind::FrameEncoding => VarInt(0x07),
            ErrorKind::TransportParameter => VarInt(0x08),
            ErrorKind::ConnectionIdLimit => VarInt(0x09),
            ErrorKind::ProtocolViolation => VarInt(0x0a),
            ErrorKind::InvalidToken => VarInt(0x0b),
            ErrorKind::Application => VarInt(0x0c),
            ErrorKind::CryptoBufferExceeded => VarInt(0x0d),
            ErrorKind::KeyUpdate => VarInt(0x0e),
            ErrorKind::AeadLimitReached => VarInt(0x0f),
            ErrorKind::NoViablePath => VarInt(0x10),
            ErrorKind::Crypto(x) => VarInt(0x0100 + x as u64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("QUIC transport error occured in {frame_type:?}, kind: {kind:?}, reason: {reason}")]
pub struct Error {
    pub kind: ErrorKind,
    pub frame_type: FrameType,
    pub reason: String,
}

impl Error {
    pub fn new(kind: ErrorKind, frame_type: FrameType, reason: String) -> Self {
        Self {
            kind,
            frame_type,
            reason,
        }
    }
}

impl From<Error> for crate::frame::ConnectionCloseFrame {
    fn from(e: Error) -> Self {
        Self {
            error_code: e.kind.into(),
            frame_type: Some(e.frame_type.into()),
            reason: e.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
