// PING Frame {
//   Type (i) = 0x01,
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingFrame;

pub const PING_FRAME_TYPE: u8 = 0x01;

pub mod ext {
    use super::PingFrame;

    // nom parser for PING_FRAME
    pub fn be_ping_frame(input: &[u8]) -> nom::IResult<&[u8], PingFrame> {
        Ok((input, PingFrame))
    }

    // BufMut write extension for PING_FRAME
    pub trait BufMutExt {
        fn put_ping_frame(&mut self, frame: &PingFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_ping_frame(&mut self, _frame: &PingFrame) {
            self.put_u8(super::PING_FRAME_TYPE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PingFrame, PING_FRAME_TYPE};

    #[test]
    fn test_read_ping_frame() {
        use super::ext::be_ping_frame;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
        let buf = vec![PING_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == PING_FRAME_TYPE as u64 {
                be_ping_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(frame, PingFrame);
    }

    #[test]
    fn test_write_ping_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        buf.put_ping_frame(&PingFrame);
        assert_eq!(buf, vec![PING_FRAME_TYPE]);
    }
}
