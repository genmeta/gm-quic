// CRYPTO Frame {
//   Type (i) = 0x06,
//   Offset (i),
//   Length (i),
//   Crypto Data (..),
// }

use std::ops::Range;

use nom::sequence::tuple;

use crate::{
    packet::r#type::Type,
    util::{DescribeData, WriteData},
    varint::{be_varint, VarInt, WriteVarInt, VARINT_MAX},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFrame {
    pub offset: VarInt,
    pub length: VarInt,
}

const CRYPTO_FRAME_TYPE: u8 = 0x06;

impl super::BeFrame for CryptoFrame {
    fn frame_type(&self) -> super::FrameType {
        super::FrameType::Crypto
    }

    fn belongs_to(&self, packet_type: Type) -> bool {
        use crate::packet::r#type::{
            long::{Type::V1, Ver1},
            short::OneRtt,
        };
        // IH_1
        matches!(
            packet_type,
            Type::Long(V1(Ver1::INITIAL))
                | Type::Long(V1(Ver1::HANDSHAKE))
                | Type::Short(OneRtt(_))
        )
    }

    fn max_encoding_size(&self) -> usize {
        1 + 8 + 8
    }

    fn encoding_size(&self) -> usize {
        1 + self.offset.encoding_size()
            + self.length.encoding_size()
            + self.length.into_inner() as usize
    }
}

impl CryptoFrame {
    /// Evaluate the maximum number of bytes of data that can be accommodated,
    /// starting from a certain offset, within a given capacity. If it cannot
    /// accommodate a CryptoFrame header or can only accommodate 0 bytes, return None.
    /// Note: If the offset exceeds 2^62, panic.
    pub fn estimate_max_capacity(capacity: usize, offset: u64) -> Option<usize> {
        assert!(offset <= VARINT_MAX);
        capacity
            // Must accommodate at least one byte, 'len' takes up 1 byte,
            // content takes up 1 byte. If these are not satisfied, return None.
            .checked_sub(1 + VarInt::from_u64(offset).unwrap().encoding_size() + 2)
            .map(|remaining| match remaining {
                // Including the 1 byte already considered in check_sub,
                // 'length' still takes up 1 byte.
                value @ 0..=62 => value + 1,
                // The encoding of 'length' directly takes up 2 bytes, the final 2 bytes
                // subtracted in 'check_sub' are all occupied by the encoding of 'length'.
                // Interestingly, if only 65 bytes are left after removing the encoding of
                // Type and Offset, whether the encoding of 'length' takes up 1 byte or 2
                // bytes, only 63 bytes of data can be carried.
                value @ 0x3F..=0x3F_FF => value,
                // For the following lengths, the encoding of 'length' needs to occupy 4 bytes.
                // When the buffer capacity is 0x4000 or 0x40001, the encoding of 'length'
                // changes to 4 bytes, but the capacity is not enough, so it needs to be rolled back.
                0x40_00..=0x40_01 => 0x3FFF,
                value @ 0x40_02..=0x40_00_00_01 => value - 2,
                // Any longer, a packet exceeding 100 million bytes is already impossible.
                _ => unreachable!("crypto frame length could not be too large"),
            })
    }

    pub fn range(&self) -> Range<u64> {
        let start = self.offset.into_inner();
        let end = start + self.length.into_inner();
        start..end
    }
}

// nom parser for CRYPTO_FRAME
pub fn be_crypto_frame(input: &[u8]) -> nom::IResult<&[u8], CryptoFrame> {
    let (remain, (offset, length)) = tuple((be_varint, be_varint))(input)?;
    if offset.into_inner() + offset.into_inner() > VARINT_MAX {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    Ok((remain, CryptoFrame { offset, length }))
}

impl<T, D> super::io::WriteDataFrame<CryptoFrame, D> for T
where
    T: bytes::BufMut + WriteData<D>,
    D: DescribeData,
{
    fn put_data_frame(&mut self, frame: &CryptoFrame, data: &D) {
        assert_eq!(frame.length.into_inner(), data.len() as u64);
        self.put_u8(CRYPTO_FRAME_TYPE);
        self.put_varint(&frame.offset);
        self.put_varint(&frame.length);
        self.put_data(data);
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoFrame, CRYPTO_FRAME_TYPE};
    use crate::{frame::io::WriteDataFrame, varint::VarInt};

    #[test]
    fn test_read_crypto_frame() {
        use super::be_crypto_frame;
        let buf = vec![0x52, 0x34, 0x80, 0x00, 0x56, 0x78];
        let (remain, frame) = be_crypto_frame(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(
            frame,
            CryptoFrame {
                offset: VarInt::from_u32(0x1234),
                length: VarInt::from_u32(0x5678),
            }
        );
    }

    #[test]
    fn test_write_crypto_frame() {
        let mut buf = bytes::BytesMut::new();
        let frame = CryptoFrame {
            offset: VarInt::from_u32(0x1234),
            length: VarInt::from_u32(0x5),
        };
        buf.put_data_frame(&frame, b"hello");
        assert_eq!(
            buf,
            bytes::Bytes::from_static(&[
                CRYPTO_FRAME_TYPE,
                0x52,
                0x34,
                0x05,
                b'h',
                b'e',
                b'l',
                b'l',
                b'o'
            ])
        );
    }

    #[test]
    fn test_encoding_capacity_estimate() {
        assert_eq!(CryptoFrame::estimate_max_capacity(1, 0), None);
        assert_eq!(CryptoFrame::estimate_max_capacity(4, 0), Some(1));
        assert_eq!(CryptoFrame::estimate_max_capacity(4, 64), None);
        assert_eq!(CryptoFrame::estimate_max_capacity(5, 65), Some(1));
        assert_eq!(CryptoFrame::estimate_max_capacity(67, 65), Some(63));
        assert_eq!(CryptoFrame::estimate_max_capacity(68, 65), Some(63));
        assert_eq!(CryptoFrame::estimate_max_capacity(69, 65), Some(64));
        assert_eq!(CryptoFrame::estimate_max_capacity(16387, 65), Some(16382));
        assert_eq!(CryptoFrame::estimate_max_capacity(16388, 65), Some(16383));
        assert_eq!(CryptoFrame::estimate_max_capacity(16389, 65), Some(16383));
        assert_eq!(CryptoFrame::estimate_max_capacity(16390, 65), Some(16383));
        assert_eq!(CryptoFrame::estimate_max_capacity(16391, 65), Some(16384));
    }

    #[test]
    #[should_panic]
    fn test_encoding_with_offset_exceeded() {
        CryptoFrame::estimate_max_capacity(60, 1 << 62);
    }

    #[test]
    #[should_panic]
    fn test_encoding_with_length_too_large() {
        CryptoFrame::estimate_max_capacity(1 << 31, 20);
    }
}
