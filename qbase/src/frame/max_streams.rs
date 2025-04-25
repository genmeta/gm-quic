use crate::{
    sid::{Dir, MAX_STREAMS_LIMIT},
    varint::{VarInt, WriteVarInt, be_varint},
};

/// MAX_STREAMS frame.
///
/// ```text
/// MAX_STREAMS Frame {
///   Type (i) = 0x12..0x13,
///   Maximum Streams (i),
/// }
/// ```
///
/// See [MAX_STREAMS Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxStreamsFrame {
    Bi(VarInt),
    Uni(VarInt),
}

const MAX_STREAMS_FRAME_TYPE: u8 = 0x12;

const DIR_BIT: u8 = 0x1;

impl MaxStreamsFrame {
    pub fn with(dir: Dir, max_streams: VarInt) -> Self {
        match dir {
            Dir::Bi => MaxStreamsFrame::Bi(max_streams),
            Dir::Uni => MaxStreamsFrame::Uni(max_streams),
        }
    }
}

impl super::GetFrameType for MaxStreamsFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreams(match self {
            MaxStreamsFrame::Bi(_) => 0,
            MaxStreamsFrame::Uni(_) => 1,
        })
    }
}

impl super::EncodeFrame for MaxStreamsFrame {
    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + match self {
            MaxStreamsFrame::Bi(max_streams) => max_streams.encoding_size(),
            MaxStreamsFrame::Uni(max_streams) => max_streams.encoding_size(),
        }
    }
}

/// Returns a parser for MAX_STREAMS frame with the given direction,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn max_streams_frame_with_dir(
    dir: u8,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], MaxStreamsFrame> {
    move |input: &[u8]| {
        let (remain, max_streams) = be_varint(input)?;
        if max_streams > MAX_STREAMS_LIMIT {
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            )))
        } else {
            Ok((
                remain,
                if dir & DIR_BIT == Dir::Bi as u8 {
                    MaxStreamsFrame::Bi(max_streams)
                } else {
                    MaxStreamsFrame::Uni(max_streams)
                },
            ))
        }
    }
}

impl<T: bytes::BufMut> super::io::WriteFrame<MaxStreamsFrame> for T {
    fn put_frame(&mut self, frame: &MaxStreamsFrame) {
        match frame {
            MaxStreamsFrame::Bi(max_streams) => {
                self.put_u8(MAX_STREAMS_FRAME_TYPE);
                self.put_varint(max_streams);
            }
            MaxStreamsFrame::Uni(max_streams) => {
                self.put_u8(MAX_STREAMS_FRAME_TYPE | 0x1);
                self.put_varint(max_streams);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use nom::{Parser, combinator::flat_map};

    use super::{MAX_STREAMS_FRAME_TYPE, MaxStreamsFrame, max_streams_frame_with_dir};
    use crate::{
        frame::{EncodeFrame, FrameType, GetFrameType, io::WriteFrame},
        varint::{VarInt, be_varint},
    };

    #[test]
    fn test_max_streams_frame() {
        let frame = MaxStreamsFrame::Bi(VarInt::from_u32(0x1234));
        assert_eq!(frame.frame_type(), FrameType::MaxStreams(0));
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2);

        let frame = MaxStreamsFrame::Uni(VarInt::from_u32(0x1236));
        assert_eq!(frame.frame_type(), FrameType::MaxStreams(1));
        assert_eq!(frame.max_encoding_size(), 1 + 8);
        assert_eq!(frame.encoding_size(), 1 + 2);
    }

    #[test]
    fn test_read_max_streams_frame() {
        let buf = vec![MAX_STREAMS_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_STREAMS_FRAME_TYPE as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, MaxStreamsFrame::Bi(VarInt::from_u32(0x1234)));

        let buf = vec![MAX_STREAMS_FRAME_TYPE | 0x1, 0x52, 0x36];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (MAX_STREAMS_FRAME_TYPE | 0x1) as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, MaxStreamsFrame::Uni(VarInt::from_u32(0x1236)));
    }

    #[test]
    fn test_read_too_large_max_streams_frame() {
        let buf = vec![
            MAX_STREAMS_FRAME_TYPE,
            0xd0,
            0x34,
            0x80,
            0x80,
            0x80,
            0x80,
            0x80,
            0x80,
        ];
        let result = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_STREAMS_FRAME_TYPE as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(buf.as_ref());
        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                &buf[1..],
                nom::error::ErrorKind::TooLarge,
            )))
        );
    }

    #[test]
    fn test_write_max_streams_frame() {
        let mut buf = Vec::new();
        buf.put_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(0x1234)));
        assert_eq!(buf, vec![MAX_STREAMS_FRAME_TYPE, 0x52, 0x34]);
        buf.clear();
        buf.put_frame(&MaxStreamsFrame::Uni(VarInt::from_u32(0x1236)));
        assert_eq!(buf, vec![0x13, 0x52, 0x36]);
    }
}
