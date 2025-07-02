use super::EncodeSize;

/// HandshakeDone frame
///
/// ```text
/// HANDSHAKE_DONE Frame {
///   Type (i) = 0x1e,
/// }
/// ```
///
/// See [HANDSHAKE_DONE Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-handshake_done-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandshakeDoneFrame;

const HANDSHAKE_DONE_FRAME_TYPE: u8 = 0x1e;

impl super::GetFrameType for HandshakeDoneFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::HandshakeDone
    }
}

impl EncodeSize for HandshakeDoneFrame {}

/// Parse a HANDSHAKE_DONE frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
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
    use crate::frame::{EncodeSize, FrameType, GetFrameType, HandshakeDoneFrame, io::WriteFrame};

    #[test]
    fn test_handshake_done_frame() {
        assert_eq!(HandshakeDoneFrame.frame_type(), FrameType::HandshakeDone);
        assert_eq!(HandshakeDoneFrame.max_encoding_size(), 1);
        assert_eq!(HandshakeDoneFrame.encoding_size(), 1);
    }

    #[test]
    fn test_read_handshake_done_frame() {
        use nom::{Parser, combinator::flat_map};

        use super::be_handshake_done_frame;
        use crate::varint::be_varint;
        let buf = vec![super::HANDSHAKE_DONE_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == super::HANDSHAKE_DONE_FRAME_TYPE as u64 {
                be_handshake_done_frame
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
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
