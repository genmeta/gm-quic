use crate::{
    streamid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

/// STREAM_DATA_BLOCKED frame.
///
/// ```text
/// STREAM_DATA_BLOCKED Frame {
///   Type (i) = 0x15,
///   Stream ID (i),
///   Maximum Stream Data (i),
/// }
/// ```
///
/// See [STREAM_DATA_BLOCKED Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream_data_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
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

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.maximum_stream_data.encoding_size()
    }
}

/// Parse a STREAM_DATA_BLOCKED frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_stream_data_blocked_frame(input: &[u8]) -> nom::IResult<&[u8], StreamDataBlockedFrame> {
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

impl<T: bytes::BufMut> super::io::WriteFrame<StreamDataBlockedFrame> for T {
    fn put_frame(&mut self, frame: &StreamDataBlockedFrame) {
        self.put_u8(STREAM_DATA_BLOCKED_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.maximum_stream_data);
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamDataBlockedFrame, STREAM_DATA_BLOCKED_FRAME_TYPE};
    use crate::{frame::io::WriteFrame, varint::VarInt};

    #[test]
    fn test_read_stream_data_blocked() {
        use super::be_stream_data_blocked_frame;
        let buf = [0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_stream_data_blocked_frame(&buf).unwrap();
        assert_eq!(
            frame,
            StreamDataBlockedFrame {
                stream_id: VarInt::from_u32(0x1234).into(),
                maximum_stream_data: VarInt::from_u32(0x5678),
            }
        );
    }

    #[test]
    fn test_write_stream_data_blocked_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&StreamDataBlockedFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            maximum_stream_data: VarInt::from_u32(0x5678),
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
