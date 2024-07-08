use nom::{bytes::streaming::take, number::streaming::be_u8, IResult};
use rand::Rng;

pub const MAX_CID_SIZE: usize = 20;
pub const RESET_TOKEN_SIZE: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Default, Debug)]
pub struct ConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub fn encoding_size(&self) -> usize {
        1 + self.len as usize
    }
}

pub fn be_connection_id(input: &[u8]) -> IResult<&[u8], ConnectionId> {
    let (remain, len) = be_u8(input)?;
    if len as usize > MAX_CID_SIZE {
        return Err(nom::Err::Error(nom::error::make_error(
            remain,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    let (remain, bytes) = take(len as usize)(remain)?;
    Ok((remain, ConnectionId::from_slice(bytes)))
}

pub trait WriteConnectionId {
    fn put_connection_id(&mut self, cid: &ConnectionId);
}

impl<T: bytes::BufMut> WriteConnectionId for T {
    fn put_connection_id(&mut self, cid: &ConnectionId) {
        self.put_u8(cid.len);
        self.put_slice(cid);
    }
}

impl ConnectionId {
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Generate a random connection ID of the given length.
    /// The cid maybe not unique, so it should be checked before use.
    pub fn random_gen(len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut bytes = [0; MAX_CID_SIZE];
        rand::thread_rng().fill(&mut bytes[..len]);
        Self {
            len: len as u8,
            bytes,
        }
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[0..self.len as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_connection_id() {
        let buf = vec![0x04, 0x01, 0x02, 0x03, 0x04];
        let (remain, cid) = be_connection_id(&buf).unwrap();
        assert_eq!(remain, &[]);
        assert_eq!(*cid, [0x01, 0x02, 0x03, 0x04],);

        let buf = vec![21, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(
            be_connection_id(&buf),
            Err(nom::Err::Error(nom::error::make_error(
                &buf[1..],
                nom::error::ErrorKind::TooLarge
            )))
        );
    }

    #[test]
    #[should_panic]
    fn test_cid_from_large_slice() {
        ConnectionId::from_slice(&[0; MAX_CID_SIZE + 1]);
    }

    #[test]
    fn test_write_connection_id() {
        use bytes::{Bytes, BytesMut};
        let mut buf = BytesMut::new();
        let cid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
        buf.put_connection_id(&cid);
        assert_eq!(
            buf.freeze(),
            Bytes::from_static(&[0x04, 0x01, 0x02, 0x03, 0x04])
        );
    }
}
