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
    flag: u8,
}

pub(super) const STREAM_FRAME_TYPE: u8 = 0x08;

const OFF_BIT: u8 = 0x04;
const LEN_BIT: u8 = 0x02;
const FIN_BIT: u8 = 0x01;

impl super::BeFrame for StreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Stream(self.flag)
    }
}

impl StreamFrame {
    pub fn new(id: StreamId, offset: VarInt, length: usize) -> Self {
        Self {
            id,
            offset,
            length,
            flag: OFF_BIT | LEN_BIT,
        }
    }

    pub fn is_fin(&self) -> bool {
        self.flag & FIN_BIT != 0
    }

    pub fn range(&self) -> Range<u64> {
        self.offset.into_inner()..self.offset.into_inner() + self.length as u64
    }

    pub fn be_last_chunk(&mut self) {
        self.flag |= FIN_BIT;
    }

    pub fn write_at_end(&mut self) {
        self.flag &= !LEN_BIT;
    }
}

pub(super) mod ext {
    use crate::{
        frame::stream::{StreamFrame, LEN_BIT, OFF_BIT, STREAM_FRAME_TYPE},
        varint::VarInt,
    };

    pub fn stream_frame_with_flag(flag: u8) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamFrame> {
        use crate::{streamid::ext::be_streamid, varint::ext::be_varint};
        move |input| {
            let (input, id) = be_streamid(input)?;
            let (input, offset) = if flag & OFF_BIT != 0 {
                be_varint(input)?
            } else {
                (input, VarInt::default())
            };
            let (input, length) = if flag & LEN_BIT != 0 {
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
                    flag,
                },
            ))
        }
    }

    pub trait BufMutExt {
        fn put_stream_frame(&mut self, frame: &StreamFrame, data: &[u8]);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_stream_frame(&mut self, frame: &StreamFrame, data: &[u8]) {
            use crate::{
                streamid::ext::BufMutExt as SidBufMutExt, varint::ext::BufMutExt as VarIntBufMutExt,
            };
            let mut stream_type = STREAM_FRAME_TYPE;
            if frame.offset.into_inner() != 0 {
                stream_type |= 0x04;
            }

            self.put_u8(stream_type | frame.flag);
            self.put_streamid(&frame.id);
            if frame.offset.into_inner() != 0 {
                self.put_varint(&frame.offset);
            }
            if frame.flag & LEN_BIT != 0 {
                // Generally, a data frame will not exceed 4GB.
                self.put_varint(&VarInt::from_u32(frame.length as u32));
            }
            self.put_slice(data);
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
                stream_frame_with_flag(frame_type.into_inner() as u8 & 0b111)
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
                id: VarInt(0x1234).into(),
                offset: VarInt(0x1234),
                length: 11,
                flag: 0b110,
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
                stream_frame_with_flag(frame_type.into_inner() as u8 & 0b111)
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
                id: VarInt(0x1234).into(),
                offset: VarInt(0x1234),
                length: 11,
                flag: 0b100,
            }
        );
    }

    #[test]
    fn test_write_initial_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt(0x1234).into(),
            offset: VarInt(0),
            length: 11,
            flag: 0b011,
        };
        buf.put_stream_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0xb, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l',
                b'd'
            ]
        );
    }

    #[test]
    fn test_write_last_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt(0x1234).into(),
            offset: VarInt(0),
            length: 11,
            flag: 0b001,
        };
        buf.put_stream_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![0x9, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd']
        );
    }

    #[test]
    fn test_write_eos_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt(0x1234).into(),
            offset: VarInt(0x1234),
            length: 11,
            flag: 0b111,
        };
        buf.put_stream_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x0f, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
                b'r', b'l', b'd'
            ]
        );
    }

    #[test]
    fn test_write_unfinished_stream_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt(0x1234).into(),
            offset: VarInt(0x1234),
            length: 11,
            flag: 0b110,
        };
        buf.put_stream_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
                b'r', b'l', b'd'
            ]
        );
    }
}
