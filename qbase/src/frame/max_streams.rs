use crate::{
    streamid::MAX_STREAM_ID,
    varint::{be_varint, VarInt, WriteVarInt},
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

impl super::BeFrame for MaxStreamsFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::MaxStreams(match self {
            MaxStreamsFrame::Bi(_) => 0,
            MaxStreamsFrame::Uni(_) => 1,
        })
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + match self {
            MaxStreamsFrame::Bi(stream_id) => stream_id.encoding_size(),
            MaxStreamsFrame::Uni(stream_id) => stream_id.encoding_size(),
        }
    }
}

/// Returns a parser for MAX_STREAMS frame with the given direction,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
pub fn max_streams_frame_with_dir(
    dir: u8,
) -> impl Fn(&[u8]) -> nom::IResult<&[u8], MaxStreamsFrame> {
    move |input: &[u8]| {
        use crate::streamid::Dir;
        let (remain, max_streams) = be_varint(input)?;
        if max_streams > MAX_STREAM_ID {
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
            MaxStreamsFrame::Bi(stream_id) => {
                self.put_u8(MAX_STREAMS_FRAME_TYPE);
                self.put_varint(stream_id);
            }
            MaxStreamsFrame::Uni(stream_id) => {
                self.put_u8(MAX_STREAMS_FRAME_TYPE | 0x1);
                self.put_varint(stream_id);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{MaxStreamsFrame, MAX_STREAMS_FRAME_TYPE};
    use crate::{
        frame::io::WriteFrame,
        varint::{be_varint, VarInt},
    };

    #[test]
    fn test_read_max_streams_frame() {
        use nom::combinator::flat_map;

        use super::max_streams_frame_with_dir;
        let buf = vec![MAX_STREAMS_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_STREAMS_FRAME_TYPE as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, MaxStreamsFrame::Bi(VarInt::from_u32(0x1234)));

        let buf = vec![MAX_STREAMS_FRAME_TYPE | 0x1, 0x52, 0x36];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (MAX_STREAMS_FRAME_TYPE | 0x1) as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert!(input.is_empty());
        assert_eq!(frame, MaxStreamsFrame::Uni(VarInt::from_u32(0x1236)));
    }

    #[test]
    fn test_read_too_large_max_streams_frame() {
        use nom::combinator::flat_map;

        use super::max_streams_frame_with_dir;
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
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref());
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
