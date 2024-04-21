// PADDING Frame {
//   Type (i) = 0x00,
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaddingFrame;

pub const PADDING_FRAME_TYPE: u8 = 0x00;

pub mod ext {
    use super::PaddingFrame;

    // nom parser for PADDING_FRAME
    pub fn be_padding_frame(input: &[u8]) -> nom::IResult<&[u8], PaddingFrame> {
        Ok((input, PaddingFrame))
    }
    // BufMut write extension for PADDING_FRAME
    pub trait BufMutExt {
        fn put_padding_frame(&mut self);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_padding_frame(&mut self) {
            self.put_u8(super::PADDING_FRAME_TYPE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingFrame, PADDING_FRAME_TYPE};

    #[test]
    fn test_read_padding_frame() {
        use super::ext::be_padding_frame;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
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
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        buf.put_padding_frame();
        assert_eq!(buf, vec![PADDING_FRAME_TYPE]);
    }
}
