// PADDING Frame {
//   Type (i) = 0x00,
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaddingFrame;

const PADDING_FRAME_TYPE: u8 = 0x00;

impl super::BeFrame for PaddingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Padding
    }
}

#[allow(dead_code)]
pub fn be_padding_frame(input: &[u8]) -> nom::IResult<&[u8], PaddingFrame> {
    Ok((input, PaddingFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<PaddingFrame> for T {
    fn put_frame(&mut self, _: &PaddingFrame) {
        self.put_u8(PADDING_FRAME_TYPE);
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingFrame, PADDING_FRAME_TYPE};
    use crate::frame::io::WriteFrame;

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
        assert!(input.is_empty());
        assert_eq!(frame, PaddingFrame);
    }

    #[test]
    fn test_write_padding_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&PaddingFrame);
        assert_eq!(buf, vec![PADDING_FRAME_TYPE]);
    }
}
