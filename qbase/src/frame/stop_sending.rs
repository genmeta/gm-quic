// STOP_SENDING Frame {
//   Type (i) = 0x05,
//   Stream ID (i),
//   Application Protocol Error Code (i),
// }

use crate::{
    packet::r#type::Type,
    streamid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSendingFrame {
    pub stream_id: StreamId,
    pub app_err_code: VarInt,
}

const STOP_SENDING_FRAME_TYPE: u8 = 0x05;

impl super::BeFrame for StopSendingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StopSending
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // __01
        matches!(
            packet_type,
            Type::Long(V1(Ver1::ZERO_RTT)) | Type::Short(OneRtt(_))
        )
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.app_err_code.encoding_size()
    }
}

// nom parser for STOP_SENDING_FRAME
pub fn be_stop_sending_frame(input: &[u8]) -> nom::IResult<&[u8], StopSendingFrame> {
    use nom::{combinator::map, sequence::tuple};
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
        self.put_u8(STOP_SENDING_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_err_code);
    }
}

#[cfg(test)]
mod tests {
    use super::{StopSendingFrame, WriteStopSendingFrame, STOP_SENDING_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_parse_stop_sending_frame() {
        use nom::combinator::flat_map;

        use super::be_stop_sending_frame;
        use crate::varint::be_varint;
        let frame = StopSendingFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            app_err_code: VarInt::from_u32(0x5678),
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
            stream_id: VarInt::from_u32(0x1234).into(),
            app_err_code: VarInt::from_u32(0x5678),
        };
        buf.put_stop_sending_frame(&frame);
        assert_eq!(
            buf,
            vec![STOP_SENDING_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
