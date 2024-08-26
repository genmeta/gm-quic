// CONNECTION_CLOSE Frame {
//   Type (i) = 0x1c..0x1d,
//   Error Code (i),
//   [Frame Type (i)],
//   Reason Phrase Length (i),
//   Reason Phrase (..),
// }

use std::borrow::Cow;

use super::FrameType;
use crate::{error::ErrorKind, frame::be_frame_type, packet::r#type::Type, varint::VarInt};

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

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // ih01: Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial or Handshake packets.
        match packet_type {
            Type::Long(V1(Ver1::INITIAL)) => self.frame_type.is_some(),
            Type::Long(V1(Ver1::HANDSHAKE)) => self.frame_type.is_some(),
            Type::Long(V1(Ver1::ZERO_RTT)) => true,
            Type::Short(OneRtt(_)) => true,
            _ => false,
        }
    }

    fn max_encoding_size(&self) -> usize {
        // reason's length could not exceed 16KB
        1 + 8 + if self.frame_type.is_some() { 8 } else { 0 } + 2 + self.reason.len()
    }

    fn encoding_size(&self) -> usize {
        1 + VarInt::from(self.error_kind).encoding_size()
            + self.frame_type.is_some()  as usize
            // reason's length could not exceed 16KB
            + VarInt::try_from(self.reason.len()).unwrap().encoding_size()
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

// nom parser for CONNECTION_CLOSE_FRAME
pub fn connection_close_frame_at_layer(
    layer: u8,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], ConnectionCloseFrame> {
    use nom::bytes::streaming::take;

    use crate::varint::be_varint;
    move |input: &[u8]| {
        let (remain, error_code) = be_varint(input)?;
        let kind = ErrorKind::try_from(error_code).map_err(|_e| {
            nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt))
        })?;
        let (remain, frame_type) = if layer == QUIC_LAYER {
            let (remain, frame_type) = be_frame_type(remain).map_err(|_e| {
                nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Alt))
            })?;
            (remain, Some(frame_type))
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

impl<T: bytes::BufMut> super::io::WriteFrame<ConnectionCloseFrame> for T {
    fn put_frame(&mut self, frame: &ConnectionCloseFrame) {
        use crate::{frame::WriteFrameType, varint::WriteVarInt};
        let layer = if frame.frame_type.is_some() {
            QUIC_LAYER
        } else {
            APP_LAYER
        };
        self.put_u8(CONNECTION_CLOSE_FRAME_TYPE | layer);
        self.put_varint(&frame.error_kind.into());
        if let Some(frame_type) = frame.frame_type {
            self.put_frame_type(frame_type);
        }
        self.put_varint(&VarInt::from_u32(frame.reason.len() as u32));
        self.put_slice(frame.reason.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::ErrorKind, frame::io::WriteFrame};

    #[test]
    fn test_read_connection_close_frame() {
        use nom::combinator::flat_map;

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
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
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
        use super::FrameType;
        let mut buf = Vec::<u8>::new();
        let frame = super::ConnectionCloseFrame {
            error_kind: ErrorKind::FlowControl,
            frame_type: Some(FrameType::Stream(0b110)),
            reason: "wrong".into(),
        };
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
