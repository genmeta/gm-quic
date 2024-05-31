// MAX_STREAM_DATA Frame {
//   Type (i) = 0x11,
//   Stream ID (i),
//   Maximum Stream Data (i),
// }

use crate::{
    packet::r#type::Type,
    streamid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: StreamId,
    pub max_stream_data: VarInt,
}

const MAX_STREAM_DATA_FRAME_TYPE: u8 = 0x11;

impl super::BeFrame for MaxStreamDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreamData
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
        1 + self.stream_id.encoding_size() + self.max_stream_data.encoding_size()
    }
}

// nom parser for MAX_STREAM_DATA_FRAME
pub fn be_max_stream_data_frame(input: &[u8]) -> nom::IResult<&[u8], MaxStreamDataFrame> {
    use nom::{combinator::map, sequence::pair};
    map(
        pair(be_streamid, be_varint),
        |(stream_id, max_stream_data)| MaxStreamDataFrame {
            stream_id,
            max_stream_data,
        },
    )(input)
}

// BufMut write extension for MAX_STREAM_DATA_FRAME
pub trait WriteMaxStreamDataFrame {
    fn put_max_stream_data_frame(&mut self, frame: &MaxStreamDataFrame);
}

impl<T: bytes::BufMut> WriteMaxStreamDataFrame for T {
    fn put_max_stream_data_frame(&mut self, frame: &MaxStreamDataFrame) {
        self.put_u8(MAX_STREAM_DATA_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.max_stream_data);
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxStreamDataFrame, MAX_STREAM_DATA_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_max_stream_data_frame() {
        use super::be_max_stream_data_frame;
        let buf = vec![0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_max_stream_data_frame(&buf).unwrap();
        assert_eq!(frame.stream_id, VarInt(0x1234).into());
        assert_eq!(frame.max_stream_data, VarInt(0x5678));
    }

    #[test]
    fn test_write_max_stream_data_frame() {
        use super::WriteMaxStreamDataFrame;
        let mut buf = Vec::new();
        buf.put_max_stream_data_frame(&MaxStreamDataFrame {
            stream_id: VarInt(0x1234).into(),
            max_stream_data: VarInt(0x5678),
        });
        assert_eq!(
            buf,
            vec![MAX_STREAM_DATA_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
