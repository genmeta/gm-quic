// CRYPTO Frame {
//   Type (i) = 0x06,
//   Offset (i),
//   Length (i),
//   Crypto Data (..),
// }

use crate::varint::VarInt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFrame {
    pub offset: VarInt,
    pub length: VarInt,
}

pub(super) const CRYPTO_FRAME_TYPE: u8 = 0x06;

pub(super) mod ext {
    use super::{CryptoFrame, CRYPTO_FRAME_TYPE};

    // nom parser for CRYPTO_FRAME
    pub fn be_crypto_frame(input: &[u8]) -> nom::IResult<&[u8], CryptoFrame> {
        use crate::varint::ext::be_varint;
        use nom::{combinator::map, sequence::pair};
        map(pair(be_varint, be_varint), |(offset, length)| CryptoFrame {
            offset,
            length,
        })(input)
    }

    // BufMut extension trait for CRYPTO_FRAME
    pub trait BufMutExt {
        fn put_crypto_frame(&mut self, frame: &CryptoFrame, data: &[u8]);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
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
        use super::ext::BufMutExt;
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
}
