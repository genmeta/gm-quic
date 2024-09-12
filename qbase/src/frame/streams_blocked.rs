use crate::streamid::{be_streamid, Dir, StreamId, WriteStreamId};

/// STREAMS_BLOCKED frame.
///
/// ```text
/// STREAMS_BLOCKED Frame {
///   Type (i) = 0x16..0x17,
///   Maximum Streams (i),
/// }
/// ```
///
/// See [STREAMS_BLOCKED Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamsBlockedFrame {
    Bi(StreamId),
    Uni(StreamId),
}

const STREAMS_BLOCKED_FRAME_TYPE: u8 = 0x16;

const DIR_BIT: u8 = 0x1;

impl super::BeFrame for StreamsBlockedFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::StreamsBlocked(match self {
            StreamsBlockedFrame::Bi(_) => 0,
            StreamsBlockedFrame::Uni(_) => 1,
        })
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + match self {
            StreamsBlockedFrame::Bi(stream_id) => stream_id.encoding_size(),
            StreamsBlockedFrame::Uni(stream_id) => stream_id.encoding_size(),
        }
    }
}

/// Return a parser for STREAMS_BLOCKED frame with the given direction,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn streams_blocked_frame_with_dir(
    dir: u8,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamsBlockedFrame> {
    move |input: &[u8]| {
        let (input, stream_id) = be_streamid(input)?;
        Ok((
            input,
            if dir & DIR_BIT == Dir::Bi as u8 {
                StreamsBlockedFrame::Bi(stream_id)
            } else {
                StreamsBlockedFrame::Uni(stream_id)
            },
        ))
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<StreamsBlockedFrame> for T {
    fn put_frame(&mut self, frame: &StreamsBlockedFrame) {
        match frame {
            StreamsBlockedFrame::Bi(stream_id) => {
                self.put_u8(STREAMS_BLOCKED_FRAME_TYPE);
                self.put_streamid(stream_id);
            }
            StreamsBlockedFrame::Uni(stream_id) => {
                self.put_u8(STREAMS_BLOCKED_FRAME_TYPE | 0x1);
                self.put_streamid(stream_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamsBlockedFrame, STREAMS_BLOCKED_FRAME_TYPE};
    use crate::{frame::io::WriteFrame, varint::VarInt};

    #[test]
    fn test_read_streams_blocked_frame() {
        use nom::combinator::flat_map;

        use super::streams_blocked_frame_with_dir;
        use crate::varint::be_varint;

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == STREAMS_BLOCKED_FRAME_TYPE as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234).into())
        );

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE | 0x1, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (STREAMS_BLOCKED_FRAME_TYPE | 0x1) as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(
            frame,
            StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234).into())
        );
    }

    #[test]
    fn test_write_streams_blocked_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234).into()));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34]);

        let mut buf = Vec::new();
        buf.put_frame(&StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234).into()));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE + 1, 0x52, 0x34]);
    }
}
