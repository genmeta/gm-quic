/**
 * QUIC有4种流类型，对应着4个流ID空间，分别是：
 * | 低2位 | 流类型 ｜
 * | 0x00 | 客户端创建的双向流 |
 * | 0x01 | 服务端创建的双向流 |
 * | 0x02 | 客户端创建的单向流 |
 * | 0x03 | 服务端创建的单向流 |
 *
 * 低2位，恰好构成一个大小为4的数组的索引，所以可以用数组来表示流类型的StreamId状态。
 * 每个QUIC连接都维护着一个这样的状态。
 *
 * 一个QUIC连接，同时只能拥有一个角色，对端对应着另外一个角色。
 * 需要注意的是，同一主机的QUIC连接的角色并非一成不变的，比如客户端可以变成服务端。
 *
 * 一个流ID是一个62比特的整数（0~2^62-1），这是为了便于VarInt编码。
 * 低2位又是类型，所以每一个类型的流ID总共有2^60个。
 */
use super::varint::VarInt;
use std::{fmt, ops};

/// ## Example
/// ```
/// use qbase::streamid::Role;
///
/// let local = Role::Client;
/// let peer = !local;
/// let is_client = matches!(local, Role::Client); // true
/// let is_server = matches!(peer, Role::Server); // true
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Role {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}

impl ops::Not for Role {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 2,
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Bi => "bidirectional",
            Self::Uni => "unidirectional",
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} stream {}", self.role(), self.dir(), self.id())
    }
}

impl StreamId {
    const STREAM_ID_LIMIT: u64 = 1 << 60;

    /// It is prohibited to directly create a StreamId from external sources. StreamId can
    /// only be allocated incrementally by the StreamId manager or received from the peer.
    pub(self) fn new(role: Role, dir: Dir, id: u64) -> Self {
        assert!(id < Self::STREAM_ID_LIMIT);
        Self((id << 2) | (role as u64) | (dir as u64))
    }

    pub fn role(&self) -> Role {
        if self.0 & 0x1 == 0 {
            Role::Client
        } else {
            Role::Server
        }
    }

    pub fn dir(&self) -> Dir {
        if self.0 & 2 == 0 {
            Dir::Bi
        } else {
            Dir::Uni
        }
    }

    pub fn id(&self) -> u64 {
        self.0 >> 2
    }

    pub(self) unsafe fn next_unchecked(&self) -> Self {
        Self(self.0 + 4)
    }

    /// Safety: If adding self beyond the maximum range, it will stay within the maximum range.
    pub(self) fn add(&mut self, n: u64) {
        let (mut id, overflow) = self.id().overflowing_add(n);
        if overflow || id >= Self::STREAM_ID_LIMIT {
            id = Self::STREAM_ID_LIMIT - 1;
        }
        self.0 = (id << 2) | (self.0 & 0x3);
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.into_inner())
    }
}

impl From<StreamId> for VarInt {
    fn from(s: StreamId) -> Self {
        unsafe { Self::from_u64_unchecked(s.0) }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    Invalid(Role),
    Limit(StreamId, StreamId),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(role) => write!(f, "invalid role: {role}"),
            Self::Limit(sid, max) => write!(f, "stream id {sid} exceed limit: {max}"),
        }
    }
}

#[derive(Debug)]
pub struct StreamIds {
    role: Role,
    max: [StreamId; 4],
    // maybe exceed 2^62, if so meanings that all stream ids are allocated
    unallocated: [StreamId; 4],
}

#[derive(Debug, PartialEq)]
pub enum AcceptSid {
    Old,
    New(NewStreams),
}

#[derive(Debug, PartialEq)]
pub struct NewStreams {
    start: StreamId,
    end: StreamId,
}

impl Iterator for NewStreams {
    type Item = StreamId;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start > self.end {
            None
        } else {
            // Safety: Since being generated from "StreamIds", they could not overflow.
            let id = self.start;
            self.start = unsafe { self.start.next_unchecked() };
            Some(id)
        }
    }
}

impl StreamIds {
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self {
            role,
            max: [
                StreamId::new(Role::Client, Dir::Bi, max_bi_streams),
                StreamId::new(Role::Server, Dir::Bi, max_bi_streams),
                StreamId::new(Role::Client, Dir::Uni, max_uni_streams),
                StreamId::new(Role::Server, Dir::Uni, max_uni_streams),
            ],
            unallocated: [StreamId(0), StreamId(1), StreamId(2), StreamId(3)],
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// RFC9000: Before a stream is created, all streams of the same type
    /// with lower-numbered stream IDs MUST be created.
    pub fn try_accept_sid(&mut self, id: StreamId) -> Result<AcceptSid, Error> {
        if id.role() == self.role {
            return Err(Error::Invalid(id.role()));
        }
        let max = self.max[(id.dir() as usize) | (!self.role as usize)];
        if id > max {
            return Err(Error::Limit(id, max));
        }
        let cur = &mut self.unallocated[(id.dir() as usize) | (!self.role as usize)];
        if id < *cur {
            Ok(AcceptSid::Old)
        } else {
            let start = *cur;
            *cur = unsafe { id.next_unchecked() };
            Ok(AcceptSid::New(NewStreams { start, end: id }))
        }
    }

    /// Used to set the maximum stream ID of the peer, only allowing an increase from the current value.
    /// The returned value can be used to generate a MaxStreamFrame to inform the peer.
    pub fn add_max_sid(&mut self, dir: Dir, val: u64) -> StreamId {
        let sid = &mut self.max[(dir as usize) | (!self.role as usize)];
        sid.add(val);
        *sid
    }

    /// The maximum stream ID that we can create is determined by our preference, and we agree to let the peer
    /// set it to any larger value. Therefore, it mainly depends on the peer's attitude and is subject to the
    /// MAX_STREAM_FRAME frame sent by the peer.
    pub fn set_max_sid(&mut self, dir: Dir, val: u64) {
        assert!(val < StreamId::STREAM_ID_LIMIT);
        let sid = &mut self.max[(dir as usize) | (self.role as usize)];
        // RFC9000: MAX_STREAMS frames that do not increase the stream limit MUST be ignored.
        if sid.id() < val {
            *sid = StreamId::new(self.role, dir, val);
        }
    }

    /// We are creating a new stream, and it should be incremented based on the previous stream ID. However,
    /// it should not exceed the maximum stream ID limit set by the other party. Returning None indicates
    /// that it is no longer possible to create a new stream, and we need to send a STREAMS_BLOCKED frame
    /// to inform the other party to increase MAX_STREAMS. It is also possible that we have reached the
    /// maximum stream ID and cannot increase it further. In this case, we should close the connection
    /// because sending MAX_STREAMS will not be received and would violate the protocol.
    pub fn allocate_sid(&mut self, dir: Dir) -> Option<StreamId> {
        let cur = &mut self.unallocated[(dir as usize) | (self.role as usize)];
        if *cur <= self.max[(dir as usize) | (self.role as usize)] {
            let id = *cur;
            *cur = unsafe { cur.next_unchecked() };
            Some(id)
        } else {
            None
        }
    }
}

pub mod ext {
    use super::StreamId;

    /// nom parser for stream id
    pub fn be_streamid(input: &[u8]) -> nom::IResult<&[u8], StreamId> {
        use crate::varint::ext::be_varint;
        use nom::combinator::map;
        map(be_varint, StreamId::from)(input)
    }

    pub trait BufMutExt {
        fn put_streamid(&mut self, stream_id: &StreamId);
    }

    impl<T: bytes::BufMut> BufMutExt for T {
        fn put_streamid(&mut self, stream_id: &StreamId) {
            use crate::varint::ext::BufMutExt as VarIntBufMutExt;
            self.put_varint(&(*stream_id).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_new() {
        let sid = StreamId::new(Role::Client, Dir::Bi, 0);
        assert_eq!(sid, StreamId(0));
        assert_eq!(sid.role(), Role::Client);
        assert_eq!(sid.dir(), Dir::Bi);
    }

    #[test]
    fn test_set_max_sid() {
        let mut sids = StreamIds::new(Role::Client, 0, 0);
        sids.set_max_sid(Dir::Bi, 0);
        assert_eq!(sids.allocate_sid(Dir::Bi), Some(StreamId(0)));
        assert_eq!(sids.allocate_sid(Dir::Bi), None);
        sids.set_max_sid(Dir::Bi, 1);
        assert_eq!(sids.allocate_sid(Dir::Bi), Some(StreamId(4)));
        assert_eq!(sids.allocate_sid(Dir::Bi), None);

        sids.set_max_sid(Dir::Uni, 2);
        assert_eq!(sids.allocate_sid(Dir::Uni), Some(StreamId(2)));
        assert_eq!(sids.allocate_sid(Dir::Uni), Some(StreamId(6)));
        assert_eq!(sids.allocate_sid(Dir::Uni), Some(StreamId(10)));
        assert_eq!(sids.allocate_sid(Dir::Uni), None);
    }

    #[test]
    fn test_try_accept_sid() {
        let mut sids = StreamIds::new(Role::Client, 0, 0);
        sids.add_max_sid(Dir::Bi, 10);
        let result = sids.try_accept_sid(StreamId(0));
        assert_eq!(result, Err(Error::Invalid(Role::Client)));

        let result = sids.try_accept_sid(StreamId(21));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NewStreams {
                start: StreamId(1),
                end: StreamId(21)
            }))
        );
        assert_eq!(sids.unallocated[1], StreamId(25));

        let result = sids.try_accept_sid(StreamId(25));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NewStreams {
                start: StreamId(25),
                end: StreamId(25)
            }))
        );
        assert_eq!(sids.unallocated[1], StreamId(29));

        let result = sids.try_accept_sid(StreamId(41));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NewStreams {
                start: StreamId(29),
                end: StreamId(41)
            }))
        );
        assert_eq!(sids.unallocated[1], StreamId(45));
        if let Ok(AcceptSid::New(mut range)) = result {
            assert_eq!(range.next(), Some(StreamId(29)));
            assert_eq!(range.next(), Some(StreamId(33)));
            assert_eq!(range.next(), Some(StreamId(37)));
            assert_eq!(range.next(), Some(StreamId(41)));
            assert_eq!(range.next(), None);
        }

        let result = sids.try_accept_sid(StreamId(45));
        assert_eq!(result, Err(Error::Limit(StreamId(45), StreamId(41))));
    }
}
