// STREAM Frame {
//   Type (i) = 0x08..0x0f,
//   Stream ID (i),
//   [Offset (i)],
//   [Length (i)],
//   Stream Data (..),
// }
// - OFF bit: 0x04
// - LEN bit: 0x02
// - FIN bit: 0x01

use crate::{streamid::StreamId, varint::VarInt};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub id: StreamId,
    pub offset: VarInt,
    pub length: usize,
    pub is_fin: bool,
}

pub(super) const STREAM_FRAME_TYPE: u8 = 0x08;

impl StreamFrame {
    pub fn range(&self) -> Range<u64> {
        self.offset.into_inner()..self.offset.into_inner() + self.length as u64
    }
}

pub(super) mod ext {
    use crate::{
        frame::stream::{StreamFrame, STREAM_FRAME_TYPE},
        varint::VarInt,
    };

    pub fn stream_frame_with_flag(flag: u8) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamFrame> {
        use crate::{streamid::ext::be_streamid, varint::ext::be_varint};
        move |input| {
            let (input, id) = be_streamid(input)?;
            let (input, offset) = if flag & 0x04 != 0 {
                be_varint(input)?
            } else {
                (input, VarInt::default())
            };
            let (input, length) = if flag & 0x02 != 0 {
                let (input, length) = be_varint(input)?;
                (input, length.into_inner() as usize)
            } else {
                (input, input.len())
            };
            Ok((
                input,
                StreamFrame {
                    id,
                    offset,
                    length,
                    is_fin: flag & 0x01 != 0,
                },
            ))
        }
    }

    pub trait BufMutExt {
        fn put_stream_frame(&mut self, frame: &StreamFrame, is_last: bool);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_stream_frame(&mut self, frame: &StreamFrame, is_last: bool) {
            use crate::{
                streamid::ext::BufMutExt as SidBufMutExt, varint::ext::BufMutExt as VarIntBufMutExt,
            };
            let mut stream_type = STREAM_FRAME_TYPE;
            if frame.offset.into_inner() != 0 {
                stream_type |= 0x04;
            }
            if !is_last {
                stream_type |= 0x02;
            }
            if frame.is_fin {
                stream_type |= 0x01;
            }

            self.put_u8(stream_type);
            self.put_streamid(&frame.id);
            if frame.offset.into_inner() != 0 {
                self.put_varint(&frame.offset);
            }
            if !is_last {
                // Generally, a data frame will not exceed 4GB.
                self.put_varint(&VarInt::from_u32(frame.length as u32));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ext::BufMutExt, StreamFrame};
    use crate::{
        frame::stream::{ext::stream_frame_with_flag, STREAM_FRAME_TYPE},
        varint::{ext::be_varint, VarInt},
    };
    use bytes::Bytes;
    use nom::combinator::flat_map;

    #[test]
    fn test_read_stream_frame() {
        let raw = Bytes::from_static(&[
            0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
            b'r', b'l', b'd', 0,
        ]);
        let input = raw.as_ref();
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() >= STREAM_FRAME_TYPE as u64 {
                stream_frame_with_flag(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(input)
        .unwrap();

        assert_eq!(
            input,
            &[b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', 0,][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
                length: 11,
                is_fin: false,
            }
        );
    }

    #[test]
    fn test_read_last_stream_frame() {
        let raw = Bytes::from_static(&[
            0x0c, 0x52, 0x34, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r',
            b'l', b'd',
        ]);
        let input = raw.as_ref();
        let (input, frame) = flat_map(be_varint, |frame_type| {
            if frame_type.into_inner() >= STREAM_FRAME_TYPE as u64 {
                stream_frame_with_flag(frame_type.into_inner() as u8)
            } else {
                panic!("wrong frame type: {}", frame_type)
            }
        })(input)
        .unwrap();

        assert_eq!(
            input,
            &[b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd',][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
                length: 11,
                is_fin: false,
            }
        );
    }

    #[test]
    fn test_write_initial_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0),
            length: 11,
            is_fin: true,
        };
        buf.put_stream_frame(&frame, false);
        assert_eq!(buf, vec![0xb, 0x52, 0x34, 0x0b]);
    }

    #[test]
    fn test_write_last_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0),
            length: 11,
            is_fin: true,
        };
        buf.put_stream_frame(&frame, true);
        assert_eq!(buf, vec![0x9, 0x52, 0x34]);
    }

    #[test]
    fn test_write_eos_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            is_fin: true,
        };
        buf.put_stream_frame(&frame, false);
        assert_eq!(buf, vec![0x0f, 0x52, 0x34, 0x52, 0x34, 0x0b]);
    }

    #[test]
    fn test_write_unfinished_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            is_fin: false,
        };
        buf.put_stream_frame(&frame, false);
        assert_eq!(buf, vec![0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b]);
    }
}
