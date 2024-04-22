// MAX_STREAMS Frame {
//   Type (i) = 0x12..0x13,
//   Maximum Streams (i),
// }

use crate::streamid::StreamId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxStreamsFrame {
    Bi(StreamId),
    Uni(StreamId),
}

pub(super) const MAX_STREAMS_FRAME_TYPE: u8 = 0x12;

pub(super) mod ext {
    use super::{MaxStreamsFrame, MAX_STREAMS_FRAME_TYPE};

    // nom parser for MAX_STREAMS_FRAME
    pub fn max_streams_frame_with_dir(
        dir: u8,
    ) -> impl Fn(&[u8]) -> nom::IResult<&[u8], MaxStreamsFrame> {
        move |input: &[u8]| {
            use crate::streamid::ext::be_streamid;
            let (input, stream_id) = be_streamid(input)?;
            Ok((
                input,
                if dir & 0x1 == 0 {
                    MaxStreamsFrame::Bi(stream_id)
                } else {
                    MaxStreamsFrame::Uni(stream_id)
                },
            ))
        }
    }

    pub trait BufMutExt {
        fn put_max_streams_frame(&mut self, frame: &MaxStreamsFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_max_streams_frame(&mut self, frame: &MaxStreamsFrame) {
            use crate::streamid::ext::BufMutExt as StreamIdBufMutExt;
            match frame {
                MaxStreamsFrame::Bi(stream_id) => {
                    self.put_u8(MAX_STREAMS_FRAME_TYPE);
                    self.put_streamid(stream_id);
                }
                MaxStreamsFrame::Uni(stream_id) => {
                    self.put_u8(MAX_STREAMS_FRAME_TYPE | 0x1);
                    self.put_streamid(stream_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxStreamsFrame, MAX_STREAMS_FRAME_TYPE};
    use crate::varint::{ext::be_varint, VarInt};

    #[test]
    fn test_read_max_streams_frame() {
        use super::ext::max_streams_frame_with_dir;
        use nom::combinator::flat_map;
        let buf = vec![MAX_STREAMS_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == MAX_STREAMS_FRAME_TYPE as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[]);
        assert_eq!(frame, MaxStreamsFrame::Bi(VarInt::from_u32(0x1234).into()));

        let buf = vec![MAX_STREAMS_FRAME_TYPE | 0x1, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (MAX_STREAMS_FRAME_TYPE | 0x1) as u64 {
                max_streams_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[]);
        assert_eq!(frame, MaxStreamsFrame::Uni(VarInt::from_u32(0x1234).into()));
    }

    #[test]
    fn test_write_max_streams_frame() {
        use super::ext::BufMutExt;
        let mut buf = Vec::new();
        buf.put_max_streams_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(0x1234).into()));
        assert_eq!(buf, vec![MAX_STREAMS_FRAME_TYPE, 0x52, 0x34]);
        buf.clear();
        buf.put_max_streams_frame(&MaxStreamsFrame::Uni(VarInt::from_u32(0x1234).into()));
        assert_eq!(buf, vec![0x13, 0x52, 0x34]);
    }
}
