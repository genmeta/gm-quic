/// PING Frame.
///
/// ```text
/// PING Frame {
///   Type (i) = 0x01,
/// }
/// ```
///
/// See [PING Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-ping-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingFrame;

const PING_FRAME_TYPE: u8 = 0x01;

impl super::GetFrameType for PingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ping
    }
}

impl super::EncodeSize for PingFrame {}

/// Parse a PING frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
#[allow(unused)]
pub fn be_ping_frame(input: &[u8]) -> nom::IResult<&[u8], PingFrame> {
    Ok((input, PingFrame))
}

impl<T: bytes::BufMut> super::io::WriteFrame<PingFrame> for T {
    fn put_frame(&mut self, _: &PingFrame) {
        self.put_u8(PING_FRAME_TYPE);
    }
}
#[cfg(test)]
mod tests {
    use super::{PING_FRAME_TYPE, PingFrame};
    use crate::frame::{EncodeSize, FrameType, GetFrameType, io::WriteFrame};

    #[test]
    fn test_ping_frame() {
        assert_eq!(PingFrame.frame_type(), FrameType::Ping);
        assert_eq!(PingFrame.max_encoding_size(), 1);
        assert_eq!(PingFrame.encoding_size(), 1);
    }

    #[test]
    fn test_read_ping_frame() {
        use nom::{Parser, combinator::flat_map};

        use super::be_ping_frame;
        use crate::varint::be_varint;
        let buf = vec![PING_FRAME_TYPE];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == PING_FRAME_TYPE as u64 {
                be_ping_frame
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, PingFrame);
    }

    #[test]
    fn test_write_ping_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&PingFrame);
        assert_eq!(buf, vec![PING_FRAME_TYPE]);
    }
}
