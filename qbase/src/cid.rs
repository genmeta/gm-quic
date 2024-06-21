use bytes::BufMut;
use nom::{number::streaming::be_u8, IResult};

pub const MAX_CID_SIZE: usize = 20;
pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Default, Debug)]
pub struct ConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; MAX_CID_SIZE],
}

pub fn be_connection_id(input: &[u8]) -> nom::IResult<&[u8], ConnectionId> {
    let (remain, len) = be_u8(input)?;
    if len as usize > MAX_CID_SIZE {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    let (remain, bytes) = nom::bytes::streaming::take(len as usize)(remain)?;
    Ok((remain, ConnectionId::from_slice(bytes)))
}

pub trait WriteConnectionId {
    fn put_connection_id(&mut self, cid: &ConnectionId);
}

impl<T: BufMut> WriteConnectionId for T {
    fn put_connection_id(&mut self, cid: &ConnectionId) {
        self.put_u8(cid.len);
        self.put_slice(cid);
    }
}

impl ConnectionId {
    pub fn from_slice(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    pub fn from_buf(input: &[u8], len: usize) -> IResult<&[u8], Self> {
        debug_assert!(len <= MAX_CID_SIZE);
        let (input, bytes) = nom::bytes::complete::take(len)(input)?;
        Ok((input, Self::from_slice(bytes)))
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[0..self.len as usize]
    }
}
