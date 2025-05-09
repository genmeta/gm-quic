use crate::{
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
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
    stream_id: StreamId,
    maximum_stream_data: VarInt,
}

const STREAM_DATA_BLOCKED_FRAME_TYPE: u8 = 0x15;

impl super::GetFrameType for StreamDataBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StreamDataBlocked
    }
}

impl super::EncodeFrame for StreamDataBlockedFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.maximum_stream_data.encoding_size()
    }
}

impl StreamDataBlockedFrame {
    /// Create a new [`StreamDataBlockedFrame`].
    pub fn new(stream_id: StreamId, maximum_stream_data: VarInt) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the maximum stream data of the frame.
    pub fn maximum_stream_data(&self) -> u64 {
        self.maximum_stream_data.into_inner()
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
    use super::{STREAM_DATA_BLOCKED_FRAME_TYPE, StreamDataBlockedFrame};
    use crate::{
        frame::{EncodeFrame, FrameType, GetFrameType, io::WriteFrame},
        varint::VarInt,
    };

    #[test]
    fn test_stream_data_blocked_frame() {
        let frame =
            StreamDataBlockedFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
        assert_eq!(frame.frame_type(), FrameType::StreamDataBlocked);
        assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2 + 4);
        assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
        assert_eq!(frame.maximum_stream_data(), 0x5678);
    }

    #[test]
    fn test_read_stream_data_blocked() {
        use super::be_stream_data_blocked_frame;
        let buf = [0x52, 0x34, 0x80, 0, 0x56, 0x78];
        let (_, frame) = be_stream_data_blocked_frame(&buf).unwrap();
        assert_eq!(
            frame,
            StreamDataBlockedFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678))
        );
    }

    #[test]
    fn test_write_stream_data_blocked_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&StreamDataBlockedFrame::new(
            VarInt::from_u32(0x1234).into(),
            VarInt::from_u32(0x5678),
        ));
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
