// STREAMS_BLOCKED Frame {
//   Type (i) = 0x16..0x17,
//   Maximum Streams (i),
// }

use crate::streamid::StreamId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamsBlockedFrame {
    Bi(StreamId),
    Uni(StreamId),
}

pub(super) const STREAMS_BLOCKED_FRAME_TYPE: u8 = 0x16;

pub(super) mod ext {
    use super::{StreamsBlockedFrame, STREAMS_BLOCKED_FRAME_TYPE};

    // nom parser for STREAMS_BLOCKED_FRAME
    pub fn streams_blocked_frame_with_dir(
        dir: u8,
    ) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamsBlockedFrame> {
        move |input: &[u8]| {
            use crate::streamid::ext::be_streamid;
            let (input, stream_id) = be_streamid(input)?;
            Ok((
                input,
                if dir & 0x1 == 0 {
                    StreamsBlockedFrame::Bi(stream_id)
                } else {
                    StreamsBlockedFrame::Uni(stream_id)
                },
            ))
        }
    }

    // BufMut extension trait for STREAMS_BLOCKED_FRAME
    pub trait BufMutExt {
        fn put_streams_blocked_frame(&mut self, frame: &StreamsBlockedFrame);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_streams_blocked_frame(&mut self, frame: &StreamsBlockedFrame) {
            use crate::streamid::ext::BufMutExt as StreamIdBufMutExt;
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
}

#[cfg(test)]
mod tests {
    use super::{StreamsBlockedFrame, STREAMS_BLOCKED_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_streams_blocked_frame() {
        use super::ext::streams_blocked_frame_with_dir;
        use crate::varint::ext::be_varint;
        use nom::combinator::flat_map;

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == STREAMS_BLOCKED_FRAME_TYPE as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(frame, StreamsBlockedFrame::Bi(VarInt(0x1234).into()));

        let buf = vec![STREAMS_BLOCKED_FRAME_TYPE | 0x1, 0x52, 0x34];
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() == (STREAMS_BLOCKED_FRAME_TYPE | 0x1) as u64 {
                streams_blocked_frame_with_dir(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(buf.as_ref())
        .unwrap();
        assert_eq!(input, &[][..]);
        assert_eq!(frame, StreamsBlockedFrame::Uni(VarInt(0x1234).into()));
    }

    #[test]
    fn test_write_streams_blocked_frame() {
        use super::ext::BufMutExt;

        let mut buf = Vec::new();
        buf.put_streams_blocked_frame(&StreamsBlockedFrame::Bi(VarInt(0x1234).into()));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE, 0x52, 0x34]);

        let mut buf = Vec::new();
        buf.put_streams_blocked_frame(&StreamsBlockedFrame::Uni(VarInt(0x1234).into()));
        assert_eq!(buf, vec![STREAMS_BLOCKED_FRAME_TYPE + 1, 0x52, 0x34]);
    }
}
