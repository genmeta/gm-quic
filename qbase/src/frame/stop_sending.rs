// STOP_SENDING Frame {
//   Type (i) = 0x05,
//   Stream ID (i),
//   Application Protocol Error Code (i),
// }

use crate::{streamid::StreamId, varint::VarInt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSendingFrame {
    pub stream_id: StreamId,
    pub app_err_code: VarInt,
}

pub(super) const STOP_SENDING_FRAME_TYPE: u8 = 0x05;

impl super::BeFrame for StopSendingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StopSending
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.app_err_code.encoding_size()
    }
}

pub(super) mod ext {
    use super::StopSendingFrame;
    use crate::{
        streamid::ext::be_streamid,
        varint::ext::{be_varint, BufMutExt as VarIntBufMutExt},
    };
    use nom::{combinator::map, sequence::tuple};

    // nom parser for STOP_SENDING_FRAME
    pub fn be_stop_sending_frame(input: &[u8]) -> nom::IResult<&[u8], StopSendingFrame> {
        map(
            tuple((be_streamid, be_varint)),
            |(stream_id, app_err_code)| StopSendingFrame {
                stream_id,
                app_err_code,
            },
        )(input)
    }

    // BufMut write extension for STOP_SENDING_FRAME
    pub trait WriteStopSendingFrame {
        fn put_stop_sending_frame(&mut self, frame: &StopSendingFrame);
    }

    impl<T: bytes::BufMut> WriteStopSendingFrame for T {
        fn put_stop_sending_frame(&mut self, frame: &StopSendingFrame) {
            self.put_u8(super::STOP_SENDING_FRAME_TYPE);
            self.put_varint(&frame.stream_id.into());
            self.put_varint(&frame.app_err_code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ext::WriteStopSendingFrame, StopSendingFrame, STOP_SENDING_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_parse_stop_sending_frame() {
        use super::ext::be_stop_sending_frame;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;
        let frame = StopSendingFrame {
            stream_id: VarInt(0x1234).into(),
            app_err_code: VarInt(0x5678),
        };
        let mut buf = Vec::new();
        buf.put_stop_sending_frame(&frame);
        let (input, parsed) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == STOP_SENDING_FRAME_TYPE as u64 {
                be_stop_sending_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(parsed, frame);
    }

    #[test]
    fn test_write_stop_sending_frame() {
        let mut buf = Vec::new();
        let frame = StopSendingFrame {
            stream_id: VarInt(0x1234).into(),
            app_err_code: VarInt(0x5678),
        };
        buf.put_stop_sending_frame(&frame);
        assert_eq!(
            buf,
            vec![STOP_SENDING_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
