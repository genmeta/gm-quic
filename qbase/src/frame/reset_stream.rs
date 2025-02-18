use thiserror::Error;

use crate::{
    sid::{be_streamid, StreamId, WriteStreamId},
    varint::{be_varint, VarInt, WriteVarInt},
};

/// RESET_STREAM frame.
///
/// ```text
/// RESET_STREAM Frame {
///   Type (i) = 0x04,
///   Stream ID (i),
///   Application Protocol Error Code (i),
///   Final Size (i),
/// }
/// ```
///
/// See [RESET_STREAM Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamFrame {
    stream_id: StreamId,
    app_error_code: VarInt,
    final_size: VarInt,
}

const RESET_STREAM_FRAME_TYPE: u8 = 0x04;

impl super::BeFrame for ResetStreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::ResetStream
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.stream_id.encoding_size()
            + self.app_error_code.encoding_size()
            + self.final_size.encoding_size()
    }
}

impl ResetStreamFrame {
    /// Create a new [`ResetStreamFrame`].
    pub fn new(stream_id: StreamId, app_error_code: VarInt, final_size: VarInt) -> Self {
        Self {
            stream_id,
            app_error_code,
            final_size,
        }
    }

    /// Return the stream ID of the frame.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Return the application protocol error code of the frame.
    pub fn app_error_code(&self) -> u64 {
        self.app_error_code.into_inner()
    }

    /// Return the final size of the frame.
    pub fn final_size(&self) -> u64 {
        self.final_size.into_inner()
    }
}

/// Parse a RESET_STREAM frame from the input buffer,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn be_reset_stream_frame(input: &[u8]) -> nom::IResult<&[u8], ResetStreamFrame> {
    use nom::{combinator::map, Parser};
    map(
        (be_streamid, be_varint, be_varint),
        |(stream_id, app_error_code, final_size)| ResetStreamFrame {
            stream_id,
            app_error_code,
            final_size,
        },
    )
    .parse(input)
}

impl<T: bytes::BufMut> super::io::WriteFrame<ResetStreamFrame> for T {
    fn put_frame(&mut self, frame: &ResetStreamFrame) {
        self.put_u8(RESET_STREAM_FRAME_TYPE);
        self.put_streamid(&frame.stream_id);
        self.put_varint(&frame.app_error_code);
        self.put_varint(&frame.final_size);
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("the stream was reset with app error code: {app_error_code}, final size: {final_size}")]
pub struct ResetStreamError {
    app_error_code: VarInt,
    final_size: VarInt,
}

impl ResetStreamError {
    pub fn new(app_error_code: VarInt, final_size: VarInt) -> Self {
        Self {
            app_error_code,
            final_size,
        }
    }

    pub fn error_code(&self) -> u64 {
        self.app_error_code.into_inner()
    }

    pub fn combine(self, sid: StreamId) -> ResetStreamFrame {
        ResetStreamFrame {
            stream_id: sid,
            app_error_code: self.app_error_code,
            final_size: self.final_size,
        }
    }
}

impl From<&ResetStreamFrame> for ResetStreamError {
    fn from(frame: &ResetStreamFrame) -> Self {
        Self {
            app_error_code: frame.app_error_code,
            final_size: frame.final_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::{combinator::flat_map, Parser};

    use super::{ResetStreamError, ResetStreamFrame, RESET_STREAM_FRAME_TYPE};
    use crate::{
        frame::{io::WriteFrame, BeFrame, FrameType},
        varint::{be_varint, VarInt},
    };

    #[test]
    fn test_reset_stream_frame() {
        let frame = ResetStreamFrame::new(
            VarInt::from_u32(0x1234).into(),
            VarInt::from_u32(0x5678),
            VarInt::from_u32(0x9abc),
        );
        assert_eq!(frame.frame_type(), FrameType::ResetStream);
        assert_eq!(frame.max_encoding_size(), 1 + 8 + 8 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2 + 4 + 4);
        assert_eq!(frame.stream_id(), VarInt::from_u32(0x1234).into());
        assert_eq!(frame.app_error_code(), 0x5678);
        assert_eq!(frame.final_size(), 0x9abc);

        let reset_stream_error: ResetStreamError = (&frame).into();
        assert_eq!(
            reset_stream_error,
            ResetStreamError::new(VarInt::from_u32(0x5678), VarInt::from_u32(0x9abc))
        );
    }

    #[test]
    fn test_read_reset_stream_frame() {
        let buf = vec![
            RESET_STREAM_FRAME_TYPE,
            0x52,
            0x34,
            0x80,
            0,
            0x56,
            0x78,
            0x80,
            0,
            0x9a,
            0xbc,
        ];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == RESET_STREAM_FRAME_TYPE as u64 {
                super::be_reset_stream_frame
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            ResetStreamFrame::new(
                VarInt::from_u32(0x1234).into(),
                VarInt::from_u32(0x5678),
                VarInt::from_u32(0x9abc),
            )
        );
    }

    #[test]
    fn test_write_reset_stream_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&ResetStreamFrame::new(
            VarInt::from_u32(0x1234).into(),
            // 0x5678 = 0b01010110 01111000 => 0b10000000 0x00 0x56 0x78
            VarInt::from_u32(0x5678),
            // 0x9abc = 0b10011010 10111100 => 0b10000000 0x00 0x9a 0xbc
            VarInt::from_u32(0x9abc),
        ));
        assert_eq!(
            buf,
            vec![
                RESET_STREAM_FRAME_TYPE,
                0x52,
                0x34,
                0x80,
                0,
                0x56,
                0x78,
                0x80,
                0,
                0x9a,
                0xbc
            ]
        );
    }
}
