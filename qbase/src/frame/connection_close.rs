use std::borrow::Cow;

use nom::bytes::complete::take;

use super::FrameType;
use crate::{
    error::{ErrorFrameType, ErrorKind},
    frame::be_frame_type,
    varint::{VarInt, be_varint},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCloseFrame {
    error_code: VarInt,
    reason: Cow<'static, str>,
}

impl AppCloseFrame {
    /// Return the error code of the frame.
    pub fn error_code(&self) -> u64 {
        self.error_code.into_inner()
    }

    /// Return the reason of the frame.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicCloseFrame {
    error_kind: ErrorKind,
    frame_type: ErrorFrameType,
    reason: Cow<'static, str>,
}

impl QuicCloseFrame {
    /// Return the error kind of the frame.
    pub fn error_kind(&self) -> ErrorKind {
        self.error_kind
    }

    /// Return the frame type of the frame.
    pub fn frame_type(&self) -> ErrorFrameType {
        self.frame_type
    }

    /// Return the reason of the frame.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// CONNECTION_CLOSE Frame.
///
/// ```text
/// CONNECTION_CLOSE Frame {
///   Type (i) = 0x1c..0x1d,
///   Error Code (i),
///   [Frame Type (i)],
///   Reason Phrase Length (i),
///   Reason Phrase (..),
/// }
/// ```
///
/// See [connection close frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-connection-close-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionCloseFrame {
    App(AppCloseFrame),
    Quic(QuicCloseFrame),
}

const CONNECTION_CLOSE_FRAME_TYPE: u8 = 0x1c;

const QUIC_LAYER: u8 = 1;
const APP_LAYER: u8 = 0;

impl super::GetFrameType for ConnectionCloseFrame {
    fn frame_type(&self) -> FrameType {
        match self {
            ConnectionCloseFrame::App(_) => FrameType::ConnectionClose(APP_LAYER),
            ConnectionCloseFrame::Quic(_) => FrameType::ConnectionClose(QUIC_LAYER),
        }
    }
}

impl super::EncodeFrame for ConnectionCloseFrame {
    fn max_encoding_size(&self) -> usize {
        // reason's length could not exceed 16KB, so it can be encoded in 2 bytes.
        match self {
            ConnectionCloseFrame::App(frame) => 1 + 8 + 2 + frame.reason.len(),
            ConnectionCloseFrame::Quic(frame) => 1 + 8 + 8 + 2 + frame.reason.len(),
        }
    }

    fn encoding_size(&self) -> usize {
        match self {
            ConnectionCloseFrame::App(frame) => {
                1 + frame.error_code.encoding_size()
                    // reason's length could not exceed 16KB.
                    + VarInt::try_from(frame.reason.len()).unwrap().encoding_size()
                    + frame.reason.len()
            }
            ConnectionCloseFrame::Quic(frame) => {
                1 + VarInt::from(frame.error_kind).encoding_size() + 1
                    // reason's length could not exceed 16KB.
                    + VarInt::try_from(frame.reason.len()).unwrap().encoding_size()
                    + frame.reason.len()
            }
        }
    }
}

impl ConnectionCloseFrame {
    /// Create a new `ConnectionCloseFrame` at QUIC layer.
    pub fn new_quic(
        error_kind: ErrorKind,
        frame_type: ErrorFrameType,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::Quic(QuicCloseFrame {
            error_kind,
            frame_type,
            reason: reason.into(),
        })
    }

    /// Create a new `ConnectionCloseFrame` at application layer.
    pub fn new_app(error_code: VarInt, reason: impl Into<Cow<'static, str>>) -> Self {
        Self::App(AppCloseFrame {
            error_code,
            reason: reason.into(),
        })
    }
}

fn be_app_close_frame(input: &[u8]) -> nom::IResult<&[u8], AppCloseFrame> {
    let (remain, error_code) = be_varint(input)?;
    let (remain, reason_length) = be_varint(remain)?;
    let (remain, reason) = take(reason_length.into_inner() as usize)(remain)?;
    let cow = String::from_utf8_lossy(reason).into_owned();
    Ok((
        remain,
        AppCloseFrame {
            error_code,
            reason: Cow::Owned(cow),
        },
    ))
}

fn be_quic_close_frame(input: &[u8]) -> nom::IResult<&[u8], QuicCloseFrame> {
    let (remain, error_code) = be_varint(input)?;
    let error_kind = ErrorKind::try_from(error_code)
        .map_err(|_e| nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt)))?;
    let (remain, frame_type) = be_frame_type(remain)
        .map_err(|_e| nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt)))?;
    let (remain, reason_length) = be_varint(remain)?;
    let (remain, reason) = take(reason_length.into_inner() as usize)(remain)?;
    let cow = String::from_utf8_lossy(reason).into_owned();
    Ok((
        remain,
        QuicCloseFrame {
            error_kind,
            frame_type: frame_type.into(),
            reason: Cow::Owned(cow),
        },
    ))
}

/// Return a parse for a CONNECTION_CLOSE frame with the given layer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn connection_close_frame_at_layer(
    layer: u8,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], ConnectionCloseFrame> {
    move |input: &[u8]| {
        if layer == APP_LAYER {
            be_app_close_frame(input).map(|(remain, app)| (remain, ConnectionCloseFrame::App(app)))
        } else if layer == QUIC_LAYER {
            be_quic_close_frame(input)
                .map(|(remain, quic)| (remain, ConnectionCloseFrame::Quic(quic)))
        } else {
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<ConnectionCloseFrame> for T {
    fn put_frame(&mut self, frame: &ConnectionCloseFrame) {
        match frame {
            ConnectionCloseFrame::App(frame) => {
                use crate::varint::WriteVarInt;
                self.put_u8(CONNECTION_CLOSE_FRAME_TYPE | APP_LAYER);
                self.put_varint(&frame.error_code);
                self.put_varint(&VarInt::from_u32(frame.reason.len() as u32));
                let remaining = self.remaining_mut();
                let reason = frame.reason.as_bytes();
                self.put_slice(&reason[..reason.len().min(remaining)]);
            }
            ConnectionCloseFrame::Quic(frame) => {
                use crate::varint::WriteVarInt;
                self.put_u8(CONNECTION_CLOSE_FRAME_TYPE | QUIC_LAYER);
                self.put_varint(&frame.error_kind.into());
                self.put_varint(&frame.frame_type.into());
                self.put_varint(&VarInt::from_u32(frame.reason.len() as u32));
                let remaining = self.remaining_mut();
                let reason = frame.reason.as_bytes();
                self.put_slice(&reason[..reason.len().min(remaining)]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::ErrorKind,
        frame::{EncodeFrame, FrameType, GetFrameType, io::WriteFrame},
        varint::VarInt,
    };

    #[test]
    fn test_connection_close_frame() {
        let frame = super::ConnectionCloseFrame::new_app(VarInt::from_u32(0x1234), "wrong");
        assert_eq!(
            frame.frame_type(),
            FrameType::ConnectionClose(super::APP_LAYER)
        );
        assert_eq!(frame.max_encoding_size(), 1 + 8 + 2 + 5);
        assert_eq!(frame.encoding_size(), 1 + 2 + 1 + 5);
    }

    #[test]
    fn test_read_connection_close_frame() {
        use nom::{Parser, combinator::flat_map};

        use super::connection_close_frame_at_layer;
        use crate::varint::be_varint;
        let buf = vec![
            super::CONNECTION_CLOSE_FRAME_TYPE,
            0x0c,
            5,
            b'w',
            b'r',
            b'o',
            b'n',
            b'g',
        ];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::CONNECTION_CLOSE_FRAME_TYPE as u64 {
                connection_close_frame_at_layer(0)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            super::ConnectionCloseFrame::new_app(VarInt::from_u32(0x0c), "wrong",)
        );
    }

    #[test]
    fn test_write_connection_close_frame() {
        use super::FrameType;
        let mut buf = Vec::<u8>::new();
        let frame = super::ConnectionCloseFrame::new_quic(
            ErrorKind::FlowControl,
            FrameType::Stream(0b110).into(),
            "wrong",
        );
        buf.put_frame(&frame);
        assert_eq!(
            buf,
            vec![
                super::CONNECTION_CLOSE_FRAME_TYPE | super::QUIC_LAYER,
                0x03,
                0xe,
                5,
                b'w',
                b'r',
                b'o',
                b'n',
                b'g',
            ]
        );
    }
}
