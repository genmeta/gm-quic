use std::{
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut};
use rand::RngCore;

use crate::quic::{coding::BufExt, error::Error, frames::ResetToken};

const MAX_CID_SIZE: usize = 20;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Default)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    pub(crate) fn from_buf(buf: &mut impl Buf, len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        match len > MAX_CID_SIZE || buf.remaining() < len {
            false => Some(Self::from_buf(buf, len)),
            true => None,
        }
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A structure holding a `ConnectionId` and all its related metadata.
#[derive(Debug, Default)]
pub struct ConnectionIdEntry {
    /// The Connection ID.
    pub cid: ConnectionId,

    /// Each connection ID has an associated sequence number to assist in detecting
    /// when NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames refer to the same value
    pub seq: u64,

    /// Its associated reset token. Initial CIDs may not have any reset token.
    pub reset_token: Option<ResetToken>,

    /// The path identifier using this CID, if any.
    pub path_id: Option<usize>,
}

pub trait ConnectionIdGenerator: Send {
    /// Generates a new CID
    ///
    /// Connection IDs MUST NOT contain any information that can be used by
    /// an external observer (that is, one that does not cooperate with the
    /// issuer) to correlate them with other connection IDs for the same
    /// connection.
    fn generate_cid(&mut self) -> ConnectionId;
    /// Returns the length of a CID for connections created by this generator
    fn cid_len(&self) -> usize;
    /// Returns the lifetime of generated Connection IDs
    ///
    /// Connection IDs will be retired after the returned `Duration`, if any. Assumed to be constant.
    fn cid_lifetime(&self) -> Option<Duration>;
}

/// Generates purely random connection IDs of a certain length
#[derive(Debug, Clone, Copy)]
pub struct RandomConnectionIdGenerator {
    cid_len: usize,
    lifetime: Option<Duration>,
}

impl Default for RandomConnectionIdGenerator {
    fn default() -> Self {
        Self {
            cid_len: 8,
            lifetime: None,
        }
    }
}

impl RandomConnectionIdGenerator {
    /// Initialize Random CID generator with a fixed CID length
    ///
    /// The given length must be less than or equal to MAX_CID_SIZE.
    pub fn new(cid_len: usize) -> Self {
        debug_assert!(cid_len <= MAX_CID_SIZE);
        Self {
            cid_len,
            ..Self::default()
        }
    }

    /// Set the lifetime of CIDs created by this generator
    pub fn set_lifetime(&mut self, d: Duration) -> &mut Self {
        self.lifetime = Some(d);
        self
    }
}

impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes_arr = [0; MAX_CID_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes_arr[..self.cid_len]);

        ConnectionId::new(&bytes_arr[..self.cid_len])
    }

    /// Provide the length of dst_cid in short header packet
    fn cid_len(&self) -> usize {
        self.cid_len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        self.lifetime
    }
}
