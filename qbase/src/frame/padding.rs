// PADDING Frame {
//   Type (i) = 0x00,
// }

use crate::packet::r#type::Type;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaddingFrame;

const PADDING_FRAME_TYPE: u8 = 0x00;

impl super::BeFrame for PaddingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Padding
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // IH01
        matches!(
            packet_type,
            Type::Long(V1(Ver1::INITIAL))
                | Type::Long(V1(Ver1::HANDSHAKE))
                | Type::Long(V1(Ver1::ZERO_RTT))
                | Type::Short(OneRtt(_))
        )
    }
}

// nom parser for PADDING_FRAME
#[allow(dead_code)]
pub fn be_padding_frame(input: &[u8]) -> nom::IResult<&[u8], PaddingFrame> {
    Ok((input, PaddingFrame))
}
// BufMut write extension for PADDING_FRAME
pub trait WritePaddingFrame {
    fn put_padding_frame(&mut self);
}

impl<T: bytes::BufMut> WritePaddingFrame for T {
    fn put_padding_frame(&mut self) {
        self.put_u8(PADDING_FRAME_TYPE);
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingFrame, PADDING_FRAME_TYPE};

    #[test]
    fn test_read_padding_frame() {
        use nom::combinator::flat_map;

        use super::be_padding_frame;
        use crate::varint::be_varint;
        let buf = vec![PADDING_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == PADDING_FRAME_TYPE as u64 {
                be_padding_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(frame, PaddingFrame);
    }

    #[test]
    fn test_write_padding_frame() {
        use super::WritePaddingFrame;
        let mut buf = Vec::new();
        buf.put_padding_frame();
        assert_eq!(buf, vec![PADDING_FRAME_TYPE]);
    }
}
