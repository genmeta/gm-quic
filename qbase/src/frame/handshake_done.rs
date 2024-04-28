// HANDSHAKE_DONE Frame {
//   Type (i) = 0x1e,
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeDoneFrame;

pub(super) const HANDSHAKE_DONE_FRAME_TYPE: u8 = 0x1e;

impl super::BeFrame for HandshakeDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::HandshakeDone
    }
}

pub(super) mod ext {
    use super::HandshakeDoneFrame;

    // nom parser for HANDSHAKE_DONE_FRAME
    #[allow(unused)]
    pub fn be_handshake_done_frame(input: &[u8]) -> nom::IResult<&[u8], HandshakeDoneFrame> {
        Ok((input, HandshakeDoneFrame))
    }

    // BufMut write extension for HANDSHAKE_DONE_FRAME
    pub trait BufMutExt {
        fn put_handshake_done_frame(&mut self);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_handshake_done_frame(&mut self) {
            self.put_u8(super::HANDSHAKE_DONE_FRAME_TYPE);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_read_handshake_done_frame() {
        use super::ext::be_handshake_done_frame;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
        let buf = vec![super::HANDSHAKE_DONE_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::HANDSHAKE_DONE_FRAME_TYPE as u64 {
                be_handshake_done_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(frame, super::HandshakeDoneFrame);
    }

    #[test]
    fn test_write_handshake_done_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        buf.put_handshake_done_frame();
        assert_eq!(buf, vec![super::HANDSHAKE_DONE_FRAME_TYPE]);
    }
}
