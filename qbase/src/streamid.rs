use super::varint::VarInt;
use std::{
    fmt, ops,
    task::{Context, Poll, Waker},
};
use thiserror::Error;

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
        write!(
            f,
            "{} side {} stream {}",
            self.role(),
            self.dir(),
            self.id()
        )
    }
}

pub const MAX_STREAM_ID: u64 = (1 << 60) - 1;

impl StreamId {
    /// It is prohibited to directly create a StreamId from external sources. StreamId can
    /// only be allocated incrementally by the StreamId manager or received from the peer.
    pub(self) fn new(role: Role, dir: Dir, id: u64) -> Self {
        assert!(id <= MAX_STREAM_ID);
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
    pub(self) fn saturating_add(&mut self, n: u64) {
        let (mut id, overflow) = self.id().overflowing_add(n);
        if overflow || id > MAX_STREAM_ID {
            id = MAX_STREAM_ID;
        }
        self.0 = (id << 2) | (self.0 & 0x3);
    }

    pub fn encoding_size(&self) -> usize {
        VarInt(self.0).encoding_size()
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

#[derive(Debug, PartialEq, Error)]
#[error("{0} exceed limit: {1}")]
pub struct ExceedLimitError(StreamId, StreamId);

#[derive(Debug)]
pub struct StreamIds {
    role: Role,
    max: [StreamId; 4],
    // maybe exceed 2^62, if so meanings that all stream ids are allocated
    unallocated: [StreamId; 4],
    concurrency: [u64; 2],
    wakers: [Option<Waker>; 2],
}

#[derive(Debug, PartialEq)]
pub enum AcceptSid {
    Old,
    New(NeedCreate, Option<VarInt>),
}

#[derive(Debug, PartialEq)]
pub struct NeedCreate {
    start: StreamId,
    end: StreamId,
}

impl Iterator for NeedCreate {
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
            concurrency: [max_bi_streams, max_uni_streams],
            wakers: [None, None],
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// RFC9000: Before a stream is created, all streams of the same type
    /// with lower-numbered stream IDs MUST be created.
    pub fn try_accept_sid(&mut self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        debug_assert_ne!(sid.role(), self.role);
        let idx = (sid.dir() as usize) | (!self.role as usize);
        let max = &mut self.max[idx];
        if sid > *max {
            return Err(ExceedLimitError(sid, *max));
        }
        let cur = &mut self.unallocated[idx];
        if sid < *cur {
            Ok(AcceptSid::Old)
        } else {
            let start = *cur;
            *cur = unsafe { sid.next_unchecked() };
            let mut update_max_sid = None;
            let step = self.concurrency[idx] >> 1;
            if sid.id() + step > max.id() {
                max.saturating_add(step);
                update_max_sid = Some(unsafe { VarInt::from_u64_unchecked(max.id()) });
            }
            Ok(AcceptSid::New(
                NeedCreate { start, end: sid },
                update_max_sid,
            ))
        }
    }

    /// The maximum stream ID that we can create is determined by our preference, and we agree to let the peer
    /// set it to any larger value. Therefore, it mainly depends on the peer's attitude and is subject to the
    /// MAX_STREAM_FRAME frame sent by the peer.
    pub fn set_max_sid(&mut self, dir: Dir, val: u64) {
        assert!(val <= MAX_STREAM_ID);
        let sid = &mut self.max[(dir as usize) | (self.role as usize)];
        // RFC9000: MAX_STREAMS frames that do not increase the stream limit MUST be ignored.
        if sid.id() < val {
            *sid = StreamId::new(self.role, dir, val);
            if let Some(waker) = self.wakers[(dir as usize) >> 1].take() {
                waker.wake();
            }
        }
    }

    /// We are creating a new stream, and it should be incremented based on the previous stream ID. However,
    /// it should not exceed the maximum stream ID limit set by the other party. Returning None indicates
    /// that it is no longer possible to create a new stream, and we need to send a STREAMS_BLOCKED frame
    /// to inform the other party to increase MAX_STREAMS. It is also possible that we have reached the
    /// maximum stream ID and cannot increase it further. In this case, we should close the connection
    /// because sending MAX_STREAMS will not be received and would violate the protocol.
    pub fn poll_alloc_sid(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        let idx = (dir as usize) | (self.role as usize);
        let cur = &mut self.unallocated[idx];
        if cur.id() > MAX_STREAM_ID {
            Poll::Ready(None)
        } else if *cur <= self.max[idx] {
            let id = *cur;
            *cur = unsafe { cur.next_unchecked() };
            Poll::Ready(Some(id))
        } else {
            let idx = if dir == Dir::Bi { 0 } else { 1 };
            assert!(self.wakers[idx].is_none());
            // waiting for MAX_STREAMS frame from peer
            self.wakers[idx] = Some(cx.waker().clone());
            // if Poll::Pending is returned, connection can send a STREAMS_BLOCKED frame to peer
            Poll::Pending
        }
    }
}

pub mod ext {
    use super::StreamId;

    /// nom parser for stream id
    pub fn be_streamid(input: &[u8]) -> nom::IResult<&[u8], StreamId> {
        use crate::varint::be_varint;
        use nom::combinator::map;
        map(be_varint, StreamId::from)(input)
    }

    pub trait WriteStreamId {
        fn put_streamid(&mut self, stream_id: &StreamId);
    }

    impl<T: bytes::BufMut> WriteStreamId for T {
        fn put_streamid(&mut self, stream_id: &StreamId) {
            use crate::varint::WriteVarInt;
            self.put_varint(&(*stream_id).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{RawWaker, RawWakerVTable, Waker};

    #[test]
    fn test_stream_id_new() {
        let sid = StreamId::new(Role::Client, Dir::Bi, 0);
        assert_eq!(sid, StreamId(0));
        assert_eq!(sid.role(), Role::Client);
        assert_eq!(sid.dir(), Dir::Bi);
    }

    fn empty_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &EMPTY_WAKER_VTABLE)
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        static EMPTY_WAKER_VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &EMPTY_WAKER_VTABLE)) }
    }

    #[test]
    fn test_set_max_sid() {
        let mut sids = StreamIds::new(Role::Client, 0, 0);
        sids.set_max_sid(Dir::Bi, 0);
        let waker = empty_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            sids.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(0)))
        );
        assert_eq!(sids.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(sids.wakers[0].is_some());
        sids.set_max_sid(Dir::Bi, 1);
        let _ = sids.wakers[0].take();
        assert_eq!(
            sids.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(4)))
        );
        assert_eq!(sids.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(sids.wakers[0].is_some());

        sids.set_max_sid(Dir::Uni, 2);
        assert_eq!(
            sids.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(2)))
        );
        assert_eq!(
            sids.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(6)))
        );
        assert_eq!(
            sids.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(10)))
        );
        assert_eq!(sids.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
        assert!(sids.wakers[1].is_some());
    }

    #[test]
    fn test_try_accept_sid() {
        let mut sids = StreamIds::new(Role::Client, 10, 10);
        let result = sids.try_accept_sid(StreamId(21));
        assert_eq!(
            result,
            Ok(AcceptSid::New(
                NeedCreate {
                    start: StreamId(1),
                    end: StreamId(21)
                },
                None
            ))
        );
        assert_eq!(sids.unallocated[1], StreamId(25));

        let result = sids.try_accept_sid(StreamId(25));
        assert_eq!(
            result,
            Ok(AcceptSid::New(
                NeedCreate {
                    start: StreamId(25),
                    end: StreamId(25)
                },
                Some(VarInt(15))
            ))
        );
        assert_eq!(sids.unallocated[1], StreamId(29));

        let result = sids.try_accept_sid(StreamId(41));
        assert_eq!(
            result,
            Ok(AcceptSid::New(
                NeedCreate {
                    start: StreamId(29),
                    end: StreamId(41)
                },
                None
            ))
        );
        assert_eq!(sids.unallocated[1], StreamId(45));
        if let Ok(AcceptSid::New(mut range, _)) = result {
            assert_eq!(range.next(), Some(StreamId(29)));
            assert_eq!(range.next(), Some(StreamId(33)));
            assert_eq!(range.next(), Some(StreamId(37)));
            assert_eq!(range.next(), Some(StreamId(41)));
            assert_eq!(range.next(), None);
        }

        let result = sids.try_accept_sid(StreamId(65));
        assert_eq!(result, Err(ExceedLimitError(StreamId(65), StreamId(61))));
    }
}
