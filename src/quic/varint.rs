use std::{convert::TryFrom, fmt};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

use super::coding::{self, Codec, UnexpectedEnd};

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
// It would be neat if we could express to Rust that the top two bits are available for use as enum
// discriminants
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self((1 << 62) - 1);
    /// The largest encoded value length
    pub const MAX_SIZE: usize = 8;

    /// Construct a `VarInt` infallibly
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Succeeds if `x` < 2^62
    pub fn from_u64(x: u64) -> Result<Self, err::Error> {
        if x < (1 << 62) {
            Ok(Self(x))
        } else {
            Err(err::Error::Overflow(x))
        }
    }

    /// Create a VarInt without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub const unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Extract the integer value
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub(crate) fn size(self) -> usize {
        let x = self.0;
        if x < (1 << 6) {
            1
        } else if x < (1 << 14) {
            2
        } else if x < (1 << 30) {
            4
        } else if x < (1 << 62) {
            8
        } else {
            unreachable!("malformed VarInt");
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl TryFrom<u64> for VarInt {
    type Error = err::Error;

    /// Succeeds if `x` < 2^62
    fn try_from(x: u64) -> Result<Self, err::Error> {
        Self::from_u64(x)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = err::Error;

    /// Succeeds if `x` < 2^62
    fn try_from(x: usize) -> Result<Self, err::Error> {
        Self::try_from(x as u64)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub mod err {
    use std::fmt::Debug;
    use thiserror::Error;

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
    pub enum Error {
        /// Error returned when constructing a `VarInt` from a value >= 2^62
        #[error("value({0}) too large for varint encoding")]
        Overflow(u64),
        #[error("parse varint error")]
        ParseError,
    }
}

pub mod ext {
    use super::{err, VarInt};
    use bytes::{Buf, BufMut};
    use nom::{bits::complete::take, combinator::flat_map, error::Error};

    pub(crate) trait BufExtVarint {
        fn get_varint(&mut self) -> Result<VarInt, err::Error>;
    }

    pub(crate) trait BufMutExtVarint {
        fn put_varint(&mut self, value: &VarInt);
    }

    impl<T: Buf> BufExtVarint for T {
        fn get_varint(&mut self) -> Result<VarInt, err::Error> {
            let input = (self.chunk(), 0);
            let remained = self.remaining();
            let result = flat_map(take(2usize), |prefix: u8| match prefix {
                0b00 => take::<&[u8], u64, usize, Error<(&[u8], usize)>>(6),
                0b01 => take::<&[u8], u64, usize, Error<(&[u8], usize)>>(14),
                0b10 => take::<&[u8], u64, usize, Error<(&[u8], usize)>>(30),
                0b11 => take::<&[u8], u64, usize, Error<(&[u8], usize)>>(62),
                _ => unreachable!("malformed VarInt"),
            })(input)
            .map_err(|_e| {
                dbg!("nom parse varint error occured: {}", _e);
                err::Error::ParseError
            })
            .map(move |((_, remaining), value)| (remained - remaining, VarInt(value)));

            result.map(|(consumed, val)| {
                self.advance(consumed);
                val
            })
        }
    }

    // 所有的BufMut都可以调用put_varint来写入VarInt了
    impl<T: BufMut> BufMutExtVarint for T {
        fn put_varint(&mut self, value: &VarInt) {
            let x = value.0;
            if x < 2u64.pow(6) {
                self.put_u8(x as u8);
            } else if x < 2u64.pow(14) {
                self.put_u16(0b01 << 14 | x as u16);
            } else if x < 2u64.pow(30) {
                self.put_u32(0b10 << 30 | x as u32);
            } else if x < 2u64.pow(62) {
                self.put_u64(0b11 << 62 | x);
            } else {
                unreachable!("malformed VarInt")
            }
        }
    }
}

mod tests {
    use super::{
        err,
        ext::{BufExtVarint, BufMutExtVarint},
        VarInt,
    };
    use bytes::{Buf, BufMut};

    #[test]
    fn reading_varint() {
        {
            let mut buf = &[0b01000000u8, 0x06u8][..];
            let r = buf.get_varint();
            assert_eq!(r, Ok(VarInt(6)));
        }
        {
            let mut buf = &[0b11000000u8, 0x06u8][..];
            let r = buf.get_varint();
            assert_eq!(r, Err(err::Error::ParseError));
        }
    }

    #[test]
    fn write_varint() {
        let val = VarInt::from(255u32);
        let mut buf = vec![];
        buf.put_varint(&val);
        buf.put_u16(65535);
        assert_eq!(buf, vec![64, 255, 255, 255]);
    }
}
