use crate::{
    sid::Dir,
    varint::{VarInt, WriteVarInt, be_varint},
};

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
    Bi(VarInt),
    Uni(VarInt),
}

const STREAMS_BLOCKED_FRAME_TYPE: u8 = 0x16;

const DIR_BIT: u8 = 0x1;

impl StreamsBlockedFrame {
    pub fn with(dir: Dir, max_streams: VarInt) -> Self {
        match dir {
            Dir::Bi => StreamsBlockedFrame::Bi(max_streams),
            Dir::Uni => StreamsBlockedFrame::Uni(max_streams),
        }
    }
}

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
        let (input, max_streams) = be_varint(input)?;
        Ok((
            input,
            if dir & DIR_BIT == Dir::Bi as u8 {
                StreamsBlockedFrame::Bi(max_streams)
            } else {
                StreamsBlockedFrame::Uni(max_streams)
            },
        ))
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<StreamsBlockedFrame> for T {
    fn put_frame(&mut self, frame: &StreamsBlockedFrame) {
        match frame {
            StreamsBlockedFrame::Bi(max_streams) => {
                self.put_u8(STREAMS_BLOCKED_FRAME_TYPE);
                self.put_varint(max_streams);
            }
            StreamsBlockedFrame::Uni(max_streams) => {
                self.put_u8(STREAMS_BLOCKED_FRAME_TYPE | 0x1);
                self.put_varint(max_streams);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{STREAMS_BLOCKED_FRAME_TYPE, StreamsBlockedFrame};
    use crate::{
        frame::{BeFrame, FrameType, io::WriteFrame},
        varint::VarInt,
    };

    #[test]
    fn test_stream_data_blocked_frame() {
        let frame = StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234));
        assert_eq!(frame.frame_type(), FrameType::StreamsBlocked(0));
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2);

        let frame = StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234));
        assert_eq!(frame.frame_type(), FrameType::StreamsBlocked(1));
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2);
    }

    #[test]
    fn test_read_streams_blocked_frame() {
        use nom::{Parser, combinator::flat_map};

        use super::streams_blocked_frame_with_dir;
        use crate::varint::be_varint;

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == STREAMS_BLOCKED_FRAME_TYPE as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234)));

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE | 0x1, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (STREAMS_BLOCKED_FRAME_TYPE | 0x1) as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234)));
    }

    #[test]
    fn test_write_streams_blocked_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&StreamsBlockedFrame::Bi(VarInt::from_u32(0x1234)));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34]);

        let mut buf = Vec::new();
        buf.put_frame(&StreamsBlockedFrame::Uni(VarInt::from_u32(0x1234)));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE + 1, 0x52, 0x34]);
    }
}
