use super::coding;
use core::fmt;
use qbase::varint::{
    ext::{BufExt, BufMutExt},
    VarInt,
};

// 这里实现流级别的控制
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(#[doc(hidden)] pub u64);

impl coding::Codec for StreamId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> coding::Result<Self> {
        let ret = buf.get_varint()?;
        Ok(Self(ret.into_inner()))
    }
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        let varint = VarInt::from_u64(self.0);
        if let Ok(varint) = varint {
            buf.put_varint(&varint);
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Dir {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::Bi, Self::Uni].iter().cloned()
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Dir::*;
        f.pad(match *self {
            Bi => "bidirectional",
            Uni => "unidirectional",
        })
    }
}
