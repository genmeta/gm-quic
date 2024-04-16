use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};
use thiserror::Error;

use qbase::varint::{
    err,
    ext::{BufExt as VarIntBufExt, BufMutExt as VarIntBufMutExt},
    VarInt,
};

use nom::{
    multi::count,
    number::complete::{be_u16, be_u32, be_u64, be_u8},
};
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
#[error("unexpected end of buffer")]
pub struct UnexpectedEnd;

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for UnexpectedEnd {
    fn from(err: nom::Err<(&[u8], nom::error::ErrorKind)>) -> UnexpectedEnd {
        dbg!("nom parse error {}", err);
        UnexpectedEnd
    }
}

impl From<err::Error> for UnexpectedEnd {
    fn from(_: err::Error) -> Self {
        UnexpectedEnd
    }
}

pub type Result<T> = ::std::result::Result<T, UnexpectedEnd>;

pub trait Codec: Sized {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self>;
    fn encode<B: BufMut>(&self, buf: &mut B);
}

impl Codec for u8 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, value) = be_u8(input)?;
        buf.advance(1);
        Ok(value)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self);
    }
}

impl Codec for u16 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, value) = be_u16(input)?;
        buf.advance(2);
        Ok(value)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(*self);
    }
}

impl Codec for u32 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, value) = be_u32(input)?;
        buf.advance(4);
        Ok(value)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32(*self);
    }
}

impl Codec for u64 {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, value) = be_u64(input)?;
        buf.advance(8);
        Ok(value)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u64(*self);
    }
}

impl Codec for Ipv4Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, addr) = be_u32(input)?;
        buf.advance(4);
        Ok(Ipv4Addr::from(addr))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

impl Codec for Ipv6Addr {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let input = buf.chunk();
        let (_, addr_segments) = count(be_u16, 8)(input)?;
        let array = <[u16; 8]>::try_from(addr_segments)
            .map_err(|_| nom::Err::Failure((input, nom::error::ErrorKind::TooLarge)))?;
        let addr = Ipv6Addr::from(array);
        buf.advance(16);
        Ok(addr)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets());
    }
}

pub trait BufExt {
    fn get<T: Codec>(&mut self) -> Result<T>;
    fn get_var(&mut self) -> Result<u64>;
}

impl<T: Buf> BufExt for T {
    fn get<U: Codec>(&mut self) -> Result<U> {
        U::decode(self)
    }

    fn get_var(&mut self) -> Result<u64> {
        let ret = self.get_varint()?;
        Ok(ret.into_inner())
    }
}

pub trait BufMutExt {
    fn write<T: Codec>(&mut self, x: T);
    fn write_var(&mut self, x: u64);
}

impl<T: BufMut> BufMutExt for T {
    fn write<U: Codec>(&mut self, x: U) {
        x.encode(self);
    }

    fn write_var(&mut self, x: u64) {
        let ret = VarInt::from_u64(x).unwrap();
        self.put_varint(&ret);
    }
}
