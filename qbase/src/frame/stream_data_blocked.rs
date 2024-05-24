// STREAM_DATA_BLOCKED Frame {
//   Type (i) = 0x15,
//   Stream ID (i),
//   Maximum Stream Data (i),
// }

use crate::{streamid::StreamId, varint::VarInt, SpaceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataBlockedFrame {
    pub stream_id: StreamId,
    pub maximum_stream_data: VarInt,
}

const STREAM_DATA_BLOCKED_FRAME_TYPE: u8 = 0x15;

impl super::BeFrame for StreamDataBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StreamDataBlocked
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn belongs_to(&self, space_id: SpaceId) -> bool {
        // __01
        space_id == SpaceId::ZeroRtt || space_id == SpaceId::OneRtt
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.maximum_stream_data.encoding_size()
    }
}

pub(super) mod ext {
    use super::{StreamDataBlockedFrame, STREAM_DATA_BLOCKED_FRAME_TYPE};

    // nom parser for STREAM_DATA_BLOCKED_FRAME
    pub fn be_stream_data_blocked_frame(
        input: &[u8],
    ) -> nom::IResult<&[u8], StreamDataBlockedFrame> {
        use crate::{streamid::ext::be_streamid, varint::ext::be_varint};
        let (input, stream_id) = be_streamid(input)?;
        let (input, maximum_stream_data) = be_varint(input)?;
        Ok((
            input,
            StreamDataBlockedFrame {
                stream_id,
                maximum_stream_data,
            },
        ))
    }

    // BufMut write extension for STREAM_DATA_BLOCKED_FRAME
    pub trait WriteStreamDataBlockedFrame {
        fn put_stream_data_blocked_frame(&mut self, frame: &StreamDataBlockedFrame);
    }

    impl<T: bytes::BufMut> WriteStreamDataBlockedFrame for T {
        fn put_stream_data_blocked_frame(&mut self, frame: &StreamDataBlockedFrame) {
            use crate::streamid::ext::WriteStreamId;
            use crate::varint::ext::WriteVarInt;
            self.put_u8(STREAM_DATA_BLOCKED_FRAME_TYPE);
            self.put_streamid(&frame.stream_id);
            self.put_varint(&frame.maximum_stream_data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamDataBlockedFrame, STREAM_DATA_BLOCKED_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_stream_data_blocked() {
        use super::ext::be_stream_data_blocked_frame;
        let buf = [0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_stream_data_blocked_frame(&buf).unwrap();
        assert_eq!(
            frame,
            StreamDataBlockedFrame {
                stream_id: VarInt(0x1234).into(),
                maximum_stream_data: VarInt(0x5678),
            }
        );
    }

    #[test]
    fn test_write_stream_data_blocked_frame() {
        use super::ext::WriteStreamDataBlockedFrame;
        let mut buf = Vec::new();
        buf.put_stream_data_blocked_frame(&StreamDataBlockedFrame {
            stream_id: VarInt(0x1234).into(),
            maximum_stream_data: VarInt(0x5678),
        });
        assert_eq!(
            buf,
            vec![
                STREAM_DATA_BLOCKED_FRAME_TYPE,
                0x52,
                0x34,
                0x80,
                0,
                0x56,
                0x78
            ]
        );
    }
}
