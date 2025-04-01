use crate::{
    sid::{StreamId, WriteStreamId, be_streamid},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// STOP_SENDING frame.
///
/// ```text
/// STOP_SENDING Frame {
///   Type (i) = 0x05,
///   Stream ID (i),
///   Application Protocol Error Code (i),
/// }
/// ```
///
/// See [STOP_SENDING Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stop_sending-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopSendingFrame {
    stream_id: StreamId,
    app_err_code: VarInt,
}

const STOP_SENDING_FRAME_TYPE: u8 = 0x05;

impl StopSendingFrame {
    /// Create a new [`StopSendingFrame`].
    pub fn new(stream_id: StreamId, app_err_code: VarInt) -> Self {
        Self {
            stream_id,
            app_err_code,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the application protocol error code of the frame.
    pub fn app_err_code(&self) -> u64 {
        self.app_err_code.into_inner()
    }

    /// Compose a RESET_STREAM frame from the STOP_SENDING frame with the given final size.
    pub fn reset_stream(&self, final_size: VarInt) -> super::ResetStreamFrame {
        super::ResetStreamFrame::new(self.stream_id, self.app_err_code, final_size)
    }
}

impl super::GetFrameType for StopSendingFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StopSending
    }
}

impl super::EncodeFrame for StopSendingFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size() + self.app_err_code.encoding_size()
    }
}

/// Parse a STOP_SENDING frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_stop_sending_frame(input: &[u8]) -> nom::IResult<&[u8], StopSendingFrame> {
    use nom::{Parser, combinator::map};
    map((be_streamid, be_varint), |(stream_id, app_err_code)| {
        StopSendingFrame {
            stream_id,
            app_err_code,
        }
    })
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<StopSendingFrame> for T {
    fn put_frame(&mut self, frame: &StopSendingFrame) {
        self.put_u8(STOP_SENDING_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_err_code);
    }
}

#[cfg(test)]
mod tests {
    use super::{STOP_SENDING_FRAME_TYPE, StopSendingFrame, be_stop_sending_frame};
    use crate::{
        frame::{EncodeFrame, FrameType, GetFrameType, io::WriteFrame},
        varint::{VarInt, be_varint},
    };

    #[test]
    fn test_stop_sending_frame() {
        let frame =
            StopSendingFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
        assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
        assert_eq!(frame.app_err_code(), 0x5678);
        assert_eq!(frame.frame_type(), FrameType::StopSending);
        assert_eq!(frame.max_encoding_size(), 1 + 8 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2 + 4);
    }

    #[test]
    fn test_parse_stop_sending_frame() {
        use nom::{Parser, combinator::flat_map};

        let frame =
            StopSendingFrame::new(VarInt::from_u32(0x1234).into(), VarInt::from_u32(0x5678));
        let mut buf = Vec::new();
        buf.put_frame(&frame);
        let (input, parsed) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == STOP_SENDING_FRAME_TYPE as u64 {
                be_stop_sending_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(parsed, frame);
    }

    #[test]
    fn test_write_stop_sending_frame() {
        let mut buf = Vec::new();
        let frame = StopSendingFrame {
            stream_id: VarInt::from_u32(0x1234).into(),
            app_err_code: VarInt::from_u32(0x5678),
        };
        buf.put_frame(&frame);
        assert_eq!(
            buf,
            vec![STOP_SENDING_FRAME_TYPE, 0x52, 0x34, 0x80, 0, 0x56, 0x78]
        );
    }
}
