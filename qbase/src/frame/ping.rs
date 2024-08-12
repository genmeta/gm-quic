// PING Frame {
//   Type (i) = 0x01,
// }

use crate::packet::r#type::Type;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingFrame;

const PING_FRAME_TYPE: u8 = 0x01;

impl super::BeFrame for PingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Ping
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

// nom parser for PING_FRAME
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
    use super::{PingFrame, PING_FRAME_TYPE};
    use crate::frame::io::WriteFrame;

    #[test]
    fn test_read_ping_frame() {
        use nom::combinator::flat_map;

        use super::be_ping_frame;
        use crate::varint::be_varint;
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
        let mut buf = Vec::new();
        buf.put_frame(&PingFrame);
        assert_eq!(buf, vec![PING_FRAME_TYPE]);
    }
}
