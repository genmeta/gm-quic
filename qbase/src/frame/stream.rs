use std::ops::Range;

use super::GetFrameType;
use crate::{
    frame::EncodeFrame,
    sid::{StreamId, WriteStreamId, be_streamid},
    util::{DescribeData, WriteData},
    varint::{VARINT_MAX, VarInt, WriteVarInt, be_varint},
};

/// STREAM frame.
///
/// ```text
/// STREAM Frame {
///   Type (i) = 0x08..0x0f,
///   Stream ID (i),
///   [Offset (i)],
///   [Length (i)],
///   Stream Data (..),
/// }
/// ```
///
/// The lower 3 bits of the frame type are used to indicate the presence of the following fields:
/// - OFF bit: 0x04
/// - LEN bit: 0x02
/// - FIN bit: 0x01
///
/// See [STREAM Frames](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-frames)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFrame {
    id: StreamId,
    offset: VarInt,
    length: usize,
    flag: u8,
}

const STREAM_FRAME_TYPE: u8 = 0x08;

pub const STREAM_FRAME_MAX_ENCODING_SIZE: usize = 1 + 8 + 8 + 8;

const OFF_BIT: u8 = 0x04;
const LEN_BIT: u8 = 0x02;
const FIN_BIT: u8 = 0x01;

impl GetFrameType for StreamFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Stream(self.flag)
    }
}

impl super::EncodeFrame for StreamFrame {
    fn max_encoding_size(&self) -> usize {
        STREAM_FRAME_MAX_ENCODING_SIZE
    }

    fn encoding_size(&self) -> usize {
        1 + self.id.encoding_size()
            + if self.offset.into_inner() != 0 {
                self.offset.encoding_size()
            } else {
                0
            }
            + if self.flag & LEN_BIT != 0 {
                VarInt::from_u64(self.length as u64)
                    .expect("msg length must be less than 2^62")
                    .encoding_size()
            } else {
                0
            }
    }
}

/// Efficient strategies for encoding stream frames
pub struct EncodingStrategy {
    carry_length: bool,
    padding: usize,
}

impl EncodingStrategy {
    /// Cound the stream frame carry its data's length.
    pub fn carry_length(&self) -> bool {
        self.carry_length
    }

    /// How many padding frames should be put before the stream frame.
    pub fn padding(&self) -> usize {
        self.padding
    }
}

impl StreamFrame {
    /// Create a new stream frame with the given stream id, offset, and length.
    pub fn new(id: StreamId, offset: u64, length: usize) -> Self {
        assert!(offset <= VARINT_MAX);
        Self {
            id,
            offset: VarInt::from_u64(offset)
                .expect("offset of stream frame must be less than 2^62"),
            length,
            flag: if offset != 0 { OFF_BIT } else { 0 },
        }
    }

    /// Return the stream id of this stream frame.
    pub fn stream_id(&self) -> StreamId {
        self.id
    }

    /// Return whether this stream frame is the end of the stream.
    pub fn is_fin(&self) -> bool {
        self.flag & FIN_BIT != 0
    }

    /// Return the offset of this stream frame.
    pub fn offset(&self) -> u64 {
        self.offset.into_inner()
    }

    /// Return the length of this stream frame.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Return whether this stream frame is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return the range of this stream frame covered.
    pub fn range(&self) -> Range<u64> {
        self.offset.into_inner()..self.offset.into_inner() + self.length as u64
    }

    /// Set the end of stream flag of this stream frame.
    pub fn set_eos_flag(&mut self, is_eos: bool) {
        if is_eos {
            self.flag |= FIN_BIT;
        } else {
            self.flag &= !FIN_BIT;
        }
    }

    /// Set the length flag of this stream frame.
    pub fn set_len_flag(&mut self, with_len: bool) {
        if with_len {
            self.flag |= LEN_BIT;
        } else {
            self.flag &= !LEN_BIT;
        }
    }

    /// Returns the most efficient stream frame encoding strategy.
    ///
    /// By default, a stream frame is considered the last frame within a data packet,
    /// allowing it to carry data up to the maximum payload capacity. However, if the
    ///  data does not fill the entire frame and there is sufficient space remaining
    /// in the packet, other data frames can be carried after it. In this case, the
    /// frame is designated as carrying length. However, when a stream frame with a length
    /// is put into the data packet, the remaining space may be too small to put another
    /// stream frame. Filling the remaining space is sometimes more beneficial to taking
    /// advantage of GSO features.
    pub fn encoding_strategy(&self, capacity: usize) -> EncodingStrategy {
        // this method is used to determine the encoding strategy of the stream frame
        debug_assert!(self.flag & LEN_BIT == 0);

        let encoding_size_without_length = self.encoding_size() + self.length;
        assert!(encoding_size_without_length <= capacity);

        let len_encoding_size = VarInt::try_from(self.length)
            .expect("length of stream frame must be less than 2^62")
            .encoding_size();

        let remaining = capacity - encoding_size_without_length;

        if remaining >= len_encoding_size {
            let remaining = remaining - len_encoding_size;
            if remaining < STREAM_FRAME_MAX_ENCODING_SIZE {
                EncodingStrategy {
                    carry_length: true,
                    padding: remaining,
                }
            } else {
                EncodingStrategy {
                    carry_length: true,
                    padding: 0,
                }
            }
        } else {
            EncodingStrategy {
                carry_length: false,
                padding: remaining,
            }
        }
    }

    /// Estimate the maximum capacity that one stream frame with the given capacity,
    /// stream id, and offset can carry.
    pub fn estimate_max_capacity(capacity: usize, sid: StreamId, offset: u64) -> Option<usize> {
        assert!(offset <= VARINT_MAX);
        let mut least = 1 + sid.encoding_size();
        if offset != 0 {
            least += VarInt::from_u64(offset).unwrap().encoding_size();
        }
        if capacity <= least {
            None
        } else {
            Some(capacity - least)
        }
    }
}

/// Return a parser for a stream frame with the given flag,
/// [nom](https://docs.rs/nom/latest/nom/) parser style.
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
            tracing::error!("   Cause by: the stream data size exceeds 2^62");
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

impl<T, D> super::io::WriteDataFrame<StreamFrame, D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: DescribeData,
{
    fn put_data_frame(&mut self, frame: &StreamFrame, data: &D) {
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
    use bytes::Bytes;
    use nom::{Parser, combinator::flat_map};

    use super::{STREAM_FRAME_TYPE, StreamFrame, stream_frame_with_flag};
    use crate::{
        frame::{EncodeFrame, FrameType, GetFrameType, io::WriteDataFrame},
        varint::{VarInt, be_varint},
    };

    #[test]
    fn test_stream_frame() {
        let stream_frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            flag: 0b110,
        };
        assert_eq!(stream_frame.frame_type(), FrameType::Stream(0b110));
        assert_eq!(stream_frame.max_encoding_size(), 1 + 8 + 8 + 8);
        assert_eq!(stream_frame.encoding_size(), 1 + 2 + 2 + 1);
    }

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
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(input)
        .unwrap();

        assert_eq!(
            input,
            &[
                b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', 0,
            ][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
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
                panic!("wrong frame type: {frame_type}")
            }
        })
        .parse(input)
        .unwrap();

        assert_eq!(
            input,
            &[
                b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd',
            ][..]
        );
        assert_eq!(
            frame,
            StreamFrame {
                id: VarInt::from_u32(0x1234).into(),
                offset: VarInt::from_u32(0x1234),
                length: 11,
                flag: 0b100,
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
            flag: 0b011,
        };
        buf.put_data_frame(&frame, b"hello world");
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
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0),
            length: 11,
            flag: 0b001,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x9, 0x52, 0x34, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'
            ]
        );
    }

    #[test]
    fn test_write_eos_frame() {
        let mut buf = Vec::new();
        let frame = StreamFrame {
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            flag: 0b111,
        };
        buf.put_data_frame(&frame, b"hello world");
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
            id: VarInt::from_u32(0x1234).into(),
            offset: VarInt::from_u32(0x1234),
            length: 11,
            flag: 0b110,
        };
        buf.put_data_frame(&frame, b"hello world");
        assert_eq!(
            buf,
            vec![
                0x0e, 0x52, 0x34, 0x52, 0x34, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o',
                b'r', b'l', b'd'
            ]
        );
    }
}
