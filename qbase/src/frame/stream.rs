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

use super::BeFrame;
use crate::{
    packet::r#type::Type,
    streamid::{be_streamid, StreamId, WriteStreamId},
    util::{DescribeData, WriteData},
    varint::{be_varint, VarInt, WriteVarInt, VARINT_MAX},
};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub id: StreamId,
    pub offset: VarInt,
    pub length: usize,
    flag: u8,
}

const STREAM_FRAME_TYPE: u8 = 0x08;

const OFF_BIT: u8 = 0x04;
const LEN_BIT: u8 = 0x02;
const FIN_BIT: u8 = 0x01;

impl BeFrame for StreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Stream(self.flag)
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // __01
        matches!(
            packet_type,
            Type::Long(V1(Ver1::ZERO_RTT)) | Type::Short(OneRtt(_))
        )
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.id.encoding_size()
            + if self.offset.into_inner() != 0 {
                self.offset.encoding_size()
            } else {
                0
            }
            + if self.flag & LEN_BIT != 0 {
                VarInt(self.length as u64).encoding_size()
            } else {
                0
            }
            + self.length
    }
}

pub enum ShouldCarryLength {
    NoProblem,
    PaddingFirst(usize),
    ShouldAfter(usize, usize),
}

impl StreamFrame {
    pub fn new(id: StreamId, offset: u64, length: usize) -> Self {
        assert!(offset <= VARINT_MAX);
        Self {
            id,
            offset: VarInt(offset),
            length,
            flag: 0,
        }
    }

    pub fn is_fin(&self) -> bool {
        self.flag & FIN_BIT != 0
    }

    pub fn range(&self) -> Range<u64> {
        self.offset.into_inner()..self.offset.into_inner() + self.length as u64
    }

    pub fn set_eos_flag(&mut self, is_eos: bool) {
        if is_eos {
            self.flag |= FIN_BIT;
        } else {
            self.flag &= !FIN_BIT;
        }
    }

    /// By default, a stream frame is considered the last frame within a data packet,
    /// allowing it to carry data up to the maximum payload capacity. However, if the
    ///  data does not fill the entire frame and there is sufficient space remaining
    /// in the packet, other data frames can be carried after it. In this case, the
    /// frame is designated as carrying length.
    pub fn should_carry_length(&self, capacity: usize) -> ShouldCarryLength {
        let frame_encoding_size = self.encoding_size();
        assert!(frame_encoding_size <= capacity);
        if frame_encoding_size == capacity {
            ShouldCarryLength::NoProblem
        } else {
            let len_encoding_size = VarInt(self.length as u64).encoding_size();
            let remaining = capacity - frame_encoding_size;
            if remaining <= len_encoding_size {
                ShouldCarryLength::PaddingFirst(remaining)
            } else {
                // Return this result, perhaps by invoking the carry_length function to
                // set the LEN_BIT. This option is left to the packet assembly logic for handling.
                ShouldCarryLength::ShouldAfter(remaining - len_encoding_size, remaining)

                // For further optimization, if there are non-data frames following, the
                // Stream frame can be forced to be placed at the end of the packet,
                // freeing up additional bytes to accommodate other frames.
            }
        }
    }

    pub fn carry_length(&mut self) {
        self.flag |= LEN_BIT;
    }

    pub fn estimate_max_capacity(capacity: usize, sid: StreamId, offset: u64) -> Option<usize> {
        assert!(offset <= VARINT_MAX);
        let mut least = 1 + sid.encoding_size();
        if offset != 0 {
            least += VarInt(offset).encoding_size();
        }
        if capacity <= least {
            None
        } else {
            Some(capacity - least)
        }
    }
}

pub fn stream_frame_with_flag(flag: u8) -> impl Fn(&[u8]) -> nom::IResult<&[u8], StreamFrame> {
    move |input| {
        let (remain, id) = be_streamid(input)?;
        let (remain, offset) = if flag & OFF_BIT != 0 {
            be_varint(remain)?
        } else {
            (remain, VarInt::default())
        };
        let (remain, length) = if flag & LEN_BIT != 0 {
            let (remain, length) = be_varint(remain)?;
            (remain, length.into_inner() as usize)
        } else {
            (remain, remain.len())
        };
        if offset.into_inner() + length as u64 > VARINT_MAX {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::TooLarge,
            )));
        }
        Ok((
            remain,
            StreamFrame {
                id,
                offset,
                length,
                flag,
            },
        ))
    }
}

pub trait WriteStreamFrame<D>: WriteData<D>
where
    D: DescribeData,
{
    fn put_stream_frame(&mut self, frame: &StreamFrame, data: &D);
}

impl<T, D> WriteStreamFrame<D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: DescribeData,
{
    fn put_stream_frame(&mut self, frame: &StreamFrame, data: &D) {
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
        self.put_data(data);
    }
}

#[cfg(test)]
mod tests {
    use super::{stream_frame_with_flag, StreamFrame, WriteStreamFrame, STREAM_FRAME_TYPE};
    use crate::varint::{be_varint, VarInt};
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
