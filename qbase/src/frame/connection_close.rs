// CONNECTION_CLOSE Frame {
//   Type (i) = 0x1c..0x1d,
//   Error Code (i),
//   [Frame Type (i)],
//   Reason Phrase Length (i),
//   Reason Phrase (..),
// }

use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame {
    pub error_code: VarInt,
    pub frame_type: Option<VarInt>,
    pub reason: String,
}

pub(super) const CONNECTION_CLOSE_FRAME_TYPE: u8 = 0x1c;

const QUIC_LAYER: u8 = 1;
const APP_LAYER: u8 = 0;

impl super::BeFrame for ConnectionCloseFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::ConnectionClose(if self.frame_type.is_some() {
            QUIC_LAYER
        } else {
            APP_LAYER
        })
    }
}

impl ConnectionCloseFrame {
    pub fn new(error_kind: u64, frame_type: Option<VarInt>, reason: String) -> Self {
        Self {
            error_code: VarInt(error_kind),
            frame_type,
            reason,
        }
    }
}

pub(super) mod ext {
    use super::{ConnectionCloseFrame, APP_LAYER, CONNECTION_CLOSE_FRAME_TYPE, QUIC_LAYER};

    // nom parser for CONNECTION_CLOSE_FRAME
    pub fn connection_close_frame_at(
        layer: u8,
    ) -> impl Fn(&[u8]) -> nom::IResult<&[u8], ConnectionCloseFrame> {
        use crate::varint::ext::be_varint;
        use nom::bytes::streaming::take;
        use nom::combinator::map;
        move |input: &[u8]| {
            let (input, error_code) = be_varint(input)?;
            let (input, frame_type) = if layer == QUIC_LAYER {
                map(be_varint, Some)(input)?
            } else {
                (input, None)
            };
            let (input, rease_length) = be_varint(input)?;
            let (input, reason) = take(rease_length.into_inner() as usize)(input)?;
            Ok((
                input,
                ConnectionCloseFrame {
                    error_code,
                    frame_type,
                    reason: String::from_utf8_lossy(reason).to_string(),
                },
            ))
        }
    }
    pub trait BufMutExt {
        fn put_connection_close_frame(&mut self, frame: &ConnectionCloseFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_connection_close_frame(&mut self, frame: &ConnectionCloseFrame) {
            use crate::varint::{ext::BufMutExt as VarIntBufMutExt, VarInt};
            let layer = if frame.frame_type.is_some() {
                QUIC_LAYER
            } else {
                APP_LAYER
            };
            self.put_u8(CONNECTION_CLOSE_FRAME_TYPE | layer);
            self.put_varint(&frame.error_code);
            if let Some(frame_type) = frame.frame_type {
                self.put_varint(&frame_type);
            }
            self.put_varint(&VarInt::from_u32(frame.reason.len() as u32));
            self.put_slice(frame.reason.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::varint::VarInt;

    #[test]
    fn test_read_connection_close_frame() {
        use super::ext::connection_close_frame_at;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
        let buf = vec![
            super::CONNECTION_CLOSE_FRAME_TYPE,
            0x52,
            0x34,
            5,
            b'w',
            b'r',
            b'o',
            b'n',
            b'g',
        ];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::CONNECTION_CLOSE_FRAME_TYPE as u64 {
                connection_close_frame_at(0)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(
            frame,
            super::ConnectionCloseFrame {
                error_code: VarInt(0x1234),
                frame_type: None,
                reason: String::from("wrong"),
            }
        );
    }

    #[test]
    fn test_write_connection_close_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::<u8>::new();
        let frame = super::ConnectionCloseFrame {
            error_code: VarInt(0x1234),
            frame_type: Some(VarInt(0xe)),
            reason: String::from("wrong"),
        };
        buf.put_connection_close_frame(&frame);
        assert_eq!(
            buf,
            vec![
                super::CONNECTION_CLOSE_FRAME_TYPE | super::QUIC_LAYER,
                0x52,
                0x34,
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
