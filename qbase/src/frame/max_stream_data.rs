use crate::{
    sid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

/// MAX_STREAM_DATA frame.
///
/// ```text
/// MAX_STREAM_DATA Frame {
///   Type (i) = 0x11,
///   Stream ID (i),
///   Maximum Stream Data (i),
/// }
/// ```
///
/// See [MAX_STREAM_DATA Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: StreamId,
    pub max_stream_data: VarInt,
}

const MAX_STREAM_DATA_FRAME_TYPE: u8 = 0x11;

impl MaxStreamDataFrame {
    /// Create a new [`MaxStreamDataFrame`].
    pub fn new(stream_id: StreamId, max_stream_data: VarInt) -> Self {
        Self {
            stream_id,
            max_stream_data,
        }
    }
}

impl super::BeFrame for MaxStreamDataFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreamData
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.max_stream_data.encoding_size()
    }
}

/// Parse a MAX_STREAM_DATA frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
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

impl<T: bytes::BufMut> super::io::WriteFrame<MaxStreamDataFrame> for T {
    fn put_frame(&mut self, frame: &MaxStreamDataFrame) {
        self.put_u8(MAX_STREAM_DATA_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.max_stream_data);
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxStreamDataFrame, MAX_STREAM_DATA_FRAME_TYPE};
    use crate::{
        frame::{io::WriteFrame, BeFrame, FrameType},
        varint::VarInt,
    };

    #[test]
    fn test_max_stream_data_frame() {
        let frame =
            MaxStreamDataFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
        assert_eq!(frame.stream_id, VarInt::from_u32(0x1234).into());
        assert_eq!(frame.max_stream_data, VarInt::from_u32(0x5678));
        assert_eq!(frame.frame_type(), FrameType::MaxStreamData);
        assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2 + 4);
    }

    #[test]
    fn test_read_max_stream_data_frame() {
        use super::be_max_stream_data_frame;
        let buf = vec![0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_max_stream_data_frame(&buf).unwrap();
        assert_eq!(frame.stream_id, VarInt::from_u32(0x1234).into());
        assert_eq!(frame.max_stream_data, VarInt::from_u32(0x5678));
    }

    #[test]
    fn test_write_max_stream_data_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&MaxStreamDataFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            max_stream_data: VarInt::from_u32(0x5678),
        });
        assert_eq!(
            buf,
            vec![MAX_STREAM_DATA_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
