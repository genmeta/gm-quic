// HANDSHAKE_DONE Frame {
//   Type (i) = 0x1e,
// }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeDoneFrame;

const HANDSHAKE_DONE_FRAME_TYPE: u8 = 0x1e;

impl super::BeFrame for HandshakeDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::HandshakeDone
    }
}

#[allow(unused)]
pub fn be_handshake_done_frame(input: &[u8]) -> nom::IResult<&[u8], HandshakeDoneFrame> {
    Ok((input, HandshakeDoneFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<HandshakeDoneFrame> for T {
    fn put_frame(&mut self, _: &HandshakeDoneFrame) {
        self.put_u8(HANDSHAKE_DONE_FRAME_TYPE);
    }
}

#[cfg(test)]
mod tests {
    use crate::frame::{io::WriteFrame, HandshakeDoneFrame};

    #[test]
    fn test_read_handshake_done_frame() {
        use nom::combinator::flat_map;

        use super::be_handshake_done_frame;
        use crate::varint::be_varint;
        let buf = vec![super::HANDSHAKE_DONE_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::HANDSHAKE_DONE_FRAME_TYPE as u64 {
                be_handshake_done_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, super::HandshakeDoneFrame);
    }

    #[test]
    fn test_write_handshake_done_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&HandshakeDoneFrame);
        assert_eq!(buf, vec![super::HANDSHAKE_DONE_FRAME_TYPE]);
    }
}
