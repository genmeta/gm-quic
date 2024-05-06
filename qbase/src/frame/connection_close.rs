// CONNECTION_CLOSE Frame {
//   Type (i) = 0x1c..0x1d,
//   Error Code (i),
//   [Frame Type (i)],
//   Reason Phrase Length (i),
//   Reason Phrase (..),
// }

use super::FrameType;
use crate::{error::ErrorKind, varint::VarInt};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame {
    pub error_kind: ErrorKind,
    pub frame_type: Option<FrameType>,
    pub reason: Cow<'static, str>, //String,
}

const CONNECTION_CLOSE_FRAME_TYPE: u8 = 0x1c;

const QUIC_LAYER: u8 = 1;
const APP_LAYER: u8 = 0;

impl super::BeFrame for ConnectionCloseFrame {
    fn frame_type(&self) -> FrameType {
        FrameType::ConnectionClose(if self.frame_type.is_some() {
            QUIC_LAYER
        } else {
            APP_LAYER
        })
    }

    fn max_encoding_size(&self) -> usize {
        // reason's length could not exceed 16KB
        1 + 8 + if self.frame_type.is_some() { 8 } else { 0 } + 2 + self.reason.len()
    }

    fn encoding_size(&self) -> usize {
        1 + VarInt::from(self.error_kind).encoding_size()
            + if let Some(frame_type) = self.frame_type {
                VarInt::from(frame_type).encoding_size()
            } else {
                0
            }
            // reason's length could not exceed 16KB
            + VarInt(self.reason.len() as u64).encoding_size()
            + self.reason.len()
    }
}

impl ConnectionCloseFrame {
    pub fn new(
        error_kind: ErrorKind,
        frame_type: Option<FrameType>,
        reason: Cow<'static, str>,
    ) -> Self {
        Self {
            error_kind,
            frame_type,
            reason,
        }
    }
}

pub(super) mod ext {
    use super::{ConnectionCloseFrame, APP_LAYER, CONNECTION_CLOSE_FRAME_TYPE, QUIC_LAYER};
    use crate::{error::ErrorKind, frame::FrameType};

    // nom parser for CONNECTION_CLOSE_FRAME
    pub fn connection_close_frame_at_layer(
        layer: u8,
    ) -> impl Fn(&[u8]) -> nom::IResult<&[u8], ConnectionCloseFrame> {
        use crate::varint::ext::be_varint;
        use nom::bytes::streaming::take;
        use std::borrow::Cow;
        move |input: &[u8]| {
            let (remain, error_code) = be_varint(input)?;
            let kind = ErrorKind::try_from(error_code).map_err(|_e| {
                nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt))
            })?;
            let (remain, frame_type) = if layer == QUIC_LAYER {
                let (remain, frame_type) = be_varint(remain)?;
                (
                    remain,
                    Some(FrameType::try_from(frame_type).map_err(|_e| {
                        nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt))
                    })?),
                )
            } else {
                (remain, None)
            };
            let (remain, rease_length) = be_varint(remain)?;
            let (remain, reason) = take(rease_length.into_inner() as usize)(remain)?;
            let cow = String::from_utf8_lossy(reason).into_owned();
            Ok((
                remain,
                ConnectionCloseFrame {
                    error_kind: kind,
                    frame_type,
                    reason: Cow::Owned(cow),
                },
            ))
        }
    }
    pub trait WriteConnectionCloseFrame {
        fn put_connection_close_frame(&mut self, frame: &ConnectionCloseFrame);
    }

    impl<T: bytes::BufMut> WriteConnectionCloseFrame for T {
        fn put_connection_close_frame(&mut self, frame: &ConnectionCloseFrame) {
            use crate::varint::{ext::BufMutExt as VarIntBufMutExt, VarInt};
            let layer = if frame.frame_type.is_some() {
                QUIC_LAYER
            } else {
                APP_LAYER
            };
            self.put_u8(CONNECTION_CLOSE_FRAME_TYPE | layer);
            self.put_varint(&frame.error_kind.into());
            if let Some(frame_type) = frame.frame_type {
                self.put_varint(&frame_type.into());
            }
            self.put_varint(&VarInt::from_u32(frame.reason.len() as u32));
            self.put_slice(frame.reason.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorKind;

    #[test]
    fn test_read_connection_close_frame() {
        use super::ext::connection_close_frame_at_layer;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
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
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            super::ConnectionCloseFrame {
                error_kind: ErrorKind::Application,
                frame_type: None,
                reason: "wrong".into(),
            }
        );
    }

    #[test]
    fn test_write_connection_close_frame() {
        use super::{ext::WriteConnectionCloseFrame, FrameType};
        let mut buf = Vec::<u8>::new();
        let frame = super::ConnectionCloseFrame {
            error_kind: ErrorKind::FlowControl,
            frame_type: Some(FrameType::Stream(0b110)),
            reason: "wrong".into(),
        };
        buf.put_connection_close_frame(&frame);
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
