// CRYPTO Frame {
//   Type (i) = 0x06,
//   Offset (i),
//   Length (i),
//   Crypto Data (..),
// }

use crate::varint::{VarInt, VARINT_MAX};
use std::ops::Range;

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
            .checked_sub(1 + VarInt(offset).encoding_size() + 2)
            .map(|remaining| match remaining + 2 {
                0..=1 => unreachable!("crypto frame should contain at least one byte"),
                // lenth编码占1字节
                value @ 2..=64 => value - 1,
                // length编码占2字节，其中65时length占1字节或2字节，都只能容纳63字节内容了
                value @ 65..=16385 => value - 2,
                // 以下长度，length编码占4字节反而容量更少，不如length编码占2字节
                16386..=16387 => 16383,
                value @ 16388..=1073741827 => value - 4,
                _ => unreachable!("crypto frame length could not be too large"),
            })
    }

    pub fn range(&self) -> Range<u64> {
        let start = self.offset.into_inner();
        let end = start + self.length.into_inner();
        start..end
    }
}

pub(super) mod ext {
    use super::{CryptoFrame, CRYPTO_FRAME_TYPE};

    // nom parser for CRYPTO_FRAME
    pub fn be_crypto_frame(input: &[u8]) -> nom::IResult<&[u8], CryptoFrame> {
        use crate::varint::{ext::be_varint, VARINT_MAX};
        let raw_input = input;
        let (input, offset) = be_varint(input)?;
        let (input, length) = be_varint(input)?;
        if offset.into_inner() + offset.into_inner() > VARINT_MAX {
            return Err(nom::Err::Error(nom::error::make_error(
                raw_input,
                nom::error::ErrorKind::TooLarge,
            )));
        }
        Ok((input, CryptoFrame { offset, length }))
    }

    // BufMut extension trait for CRYPTO_FRAME
    pub trait WriteCryptoFrame {
        fn put_crypto_frame(&mut self, frame: &CryptoFrame, data: &[u8]);
    }

    impl<T: bytes::BufMut> WriteCryptoFrame for T {
        fn put_crypto_frame(&mut self, frame: &CryptoFrame, data: &[u8]) {
            use crate::varint::ext::BufMutExt as VarIntBufMutExt;
            assert_eq!(frame.length.into_inner(), data.len() as u64);
            self.put_u8(CRYPTO_FRAME_TYPE);
            self.put_varint(&frame.offset);
            self.put_varint(&frame.length);
            self.put_slice(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoFrame, CRYPTO_FRAME_TYPE};
    use crate::varint::VarInt;

    #[test]
    fn test_read_crypto_frame() {
        use super::ext::be_crypto_frame;
        let buf = vec![0x52, 0x34, 0x80, 0x00, 0x56, 0x78];
        let (remain, frame) = be_crypto_frame(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(
            frame,
            CryptoFrame {
                offset: VarInt(0x1234),
                length: VarInt(0x5678),
            }
        );
    }

    #[test]
    fn test_write_crypto_frame() {
        use super::ext::WriteCryptoFrame;
        let mut buf = bytes::BytesMut::new();
        let frame = CryptoFrame {
            offset: VarInt(0x1234),
            length: VarInt(0x5),
        };
        buf.put_crypto_frame(&frame, b"hello");
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
