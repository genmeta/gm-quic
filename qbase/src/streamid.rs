use std::{
    fmt, ops,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use thiserror::Error;

use super::varint::{be_varint, VarInt, WriteVarInt};

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
    Uni = 1,
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

pub const MAX_STREAM_ID: u64 = (1 << 60) - 1;

impl StreamId {
    /// It is prohibited to directly create a StreamId from external sources. StreamId can
    /// only be allocated incrementally by the StreamId manager or received from the peer.
    fn new(role: Role, dir: Dir, id: u64) -> Self {
        assert!(id <= MAX_STREAM_ID);
        Self((((id << 1) | (dir as u64)) << 1) | (role as u64))
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

    unsafe fn next_unchecked(&self) -> Self {
        Self(self.0 + 4)
    }

    /// Safety: If adding self beyond the maximum range, it will stay within the maximum range.
    fn saturating_add(&mut self, n: u64) {
        let (mut id, overflow) = self.id().overflowing_add(n);
        if overflow || id > MAX_STREAM_ID {
            id = MAX_STREAM_ID;
        }
        self.0 = (id << 2) | (self.0 & 0x3);
    }

    pub fn encoding_size(&self) -> usize {
        VarInt::from(*self).encoding_size()
    }
}

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

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.into_inner())
    }
}

impl From<StreamId> for VarInt {
    fn from(s: StreamId) -> Self {
        VarInt::from_u64(s.0).expect("stream id must be less than VARINT_MAX")
    }
}

/// nom parser for stream id
pub fn be_streamid(input: &[u8]) -> nom::IResult<&[u8], StreamId> {
    use nom::combinator::map;
    map(be_varint, StreamId::from)(input)
}

pub trait WriteStreamId {
    fn put_streamid(&mut self, stream_id: &StreamId);
}

impl<T: bytes::BufMut> WriteStreamId for T {
    fn put_streamid(&mut self, stream_id: &StreamId) {
        self.put_varint(&(*stream_id).into());
    }
}

#[derive(Debug, PartialEq, Error)]
#[error("{0} exceed limit: {1}")]
pub struct ExceedLimitError(StreamId, StreamId);

#[derive(Debug, PartialEq)]
pub enum AcceptSid {
    Old,
    New(NeedCreate),
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

#[derive(Debug)]
struct LocalStreamIds {
    role: Role,                 // Our role
    max: [StreamId; 2],         // The maximum stream ID we can create
    unallocated: [StreamId; 2], // The stream ID that we have not used
    wakers: [Option<Waker>; 2], // Used for waiting for the MaxStream frame notification from peer when we have exhausted the creation of stream IDs
}

impl LocalStreamIds {
    fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self {
            role,
            max: [
                StreamId::new(role, Dir::Bi, max_bi_streams),
                StreamId::new(role, Dir::Uni, max_uni_streams),
            ],
            unallocated: [
                StreamId::new(role, Dir::Bi, 0),
                StreamId::new(role, Dir::Uni, 0),
            ],
            wakers: [None, None],
        }
    }

    fn role(&self) -> Role {
        self.role
    }

    fn permit_max_sid(&mut self, dir: Dir, val: u64) {
        assert!(val <= MAX_STREAM_ID);
        let sid = &mut self.max[dir as usize];
        // RFC9000: MAX_STREAMS frames that do not increase the stream limit MUST be ignored.
        if sid.id() < val {
            *sid = StreamId::new(self.role, dir, val);
            if let Some(waker) = self.wakers[dir as usize].take() {
                waker.wake();
            }
        }
    }

    fn poll_alloc_sid(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        let idx = dir as usize;
        let cur = &mut self.unallocated[idx];
        if cur.id() > MAX_STREAM_ID {
            Poll::Ready(None)
        } else if *cur <= self.max[idx] {
            let id = *cur;
            *cur = unsafe { cur.next_unchecked() };
            Poll::Ready(Some(id))
        } else {
            assert!(self.wakers[idx].is_none());
            // waiting for MAX_STREAMS frame from peer
            self.wakers[idx] = Some(cx.waker().clone());
            // if Poll::Pending is returned, connection can send a STREAMS_BLOCKED frame to peer
            Poll::Pending
        }
    }
}

#[derive(Debug)]
struct RemoteStreamIds {
    role: Role,                 // The role of the peer
    max: [StreamId; 2],         // The maximum stream ID that peer can create
    unallocated: [StreamId; 2], // The stream ID that peer has not used
    concurrency: [u64; 2],      // The concurrency of streams that peer can create
    wakers: [Option<Waker>; 2], // When the stream ID created by peer is close to the upper limit, wake us up to update the upper limit in time.
}

impl RemoteStreamIds {
    fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self {
            role,
            max: [
                StreamId::new(role, Dir::Bi, max_bi_streams),
                StreamId::new(role, Dir::Uni, max_uni_streams),
            ],
            unallocated: [
                StreamId::new(role, Dir::Bi, 0),
                StreamId::new(role, Dir::Uni, 0),
            ],
            concurrency: [max_bi_streams, max_uni_streams],
            wakers: [None, None],
        }
    }

    fn role(&self) -> Role {
        self.role
    }

    fn try_accept_sid(&mut self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        debug_assert_eq!(sid.role(), self.role);
        let idx = sid.dir() as usize;
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
            log::debug!("unallocated: {:?}", self.unallocated[idx]);
            let step = self.concurrency[idx] >> 1;
            if sid.id() + step > max.id() {
                if let Some(waker) = self.wakers[idx].take() {
                    waker.wake();
                }
            }
            Ok(AcceptSid::New(NeedCreate { start, end: sid }))
        }
    }

    fn poll_extend_sid(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<VarInt>> {
        let idx = dir as usize;
        let step = self.concurrency[idx] >> 1;
        if self.max[idx].id() > MAX_STREAM_ID {
            Poll::Ready(None)
        } else if self.unallocated[idx].id() + step >= self.max[idx].id() {
            self.max[idx].saturating_add(step);
            Poll::Ready(Some(self.max[idx].into()))
        } else {
            assert!(self.wakers[idx].is_none());
            self.wakers[idx] = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Management of stream IDs created actively by us. The maximum stream ID
/// that can be created is controlled by the MaxStream frame from the peer.
#[derive(Debug, Clone)]
pub struct ArcLocalStreamIds(Arc<Mutex<LocalStreamIds>>);

impl ArcLocalStreamIds {
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self(Arc::new(Mutex::new(LocalStreamIds::new(
            role,
            max_bi_streams,
            max_uni_streams,
        ))))
    }

    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// The maximum stream ID that we can create is limited by peer. Therefore, it mainly
    /// depends on the peer's attitude and is subject to the MAX_STREAM_FRAME frame sent by peer.
    pub fn permit_max_sid(&self, dir: Dir, val: u64) {
        self.0.lock().unwrap().permit_max_sid(dir, val);
    }

    /// We are creating a new stream, and it should be incremented based on the previous stream ID. However,
    /// it should not exceed the maximum stream ID limit set by peer. Returning None indicates
    /// that it is limited to create a new stream, and we need to send a STREAMS_BLOCKED frame
    /// to inform peer to increase MAX_STREAMS. It is also possible that we have reached the
    /// maximum stream ID and cannot increase it further. In this case, we should close the connection
    /// because sending MAX_STREAMS will not be received and would violate the protocol.
    pub fn poll_alloc_sid(&self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        self.0.lock().unwrap().poll_alloc_sid(cx, dir)
    }
}

/// Management of stream IDs used by the peer.
#[derive(Debug, Clone)]
pub struct ArcRemoteStreamIds(Arc<Mutex<RemoteStreamIds>>);

impl ArcRemoteStreamIds {
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self(Arc::new(Mutex::new(RemoteStreamIds::new(
            role,
            max_bi_streams,
            max_uni_streams,
        ))))
    }

    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// RFC9000: Before a stream is created, all streams of the same type
    /// with lower-numbered stream IDs MUST be created.
    pub fn try_accept_sid(&self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        self.0.lock().unwrap().try_accept_sid(sid)
    }

    pub fn poll_extend_sid(&self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<VarInt>> {
        self.0.lock().unwrap().poll_extend_sid(cx, dir)
    }
}

#[derive(Debug, Clone)]
pub struct StreamIds {
    pub local: ArcLocalStreamIds,
    pub remote: ArcRemoteStreamIds,
}

impl StreamIds {
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        // 缺省为0
        let local = ArcLocalStreamIds::new(role, 0, 0);
        let remote = ArcRemoteStreamIds::new(!role, max_bi_streams, max_uni_streams);
        Self { local, remote }
    }
}

#[cfg(test)]
mod tests {
    use std::task::{RawWaker, RawWakerVTable, Waker};

    use super::*;

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
    fn test_permit_max_sid() {
        let StreamIds { local, remote: _ } = StreamIds::new(Role::Client, 10, 2);
        local.permit_max_sid(Dir::Bi, 0);
        let waker = empty_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(0)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(local.0.lock().unwrap().wakers[0].is_some());
        local.permit_max_sid(Dir::Bi, 1);
        let _ = local.0.lock().unwrap().wakers[0].take();
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(4)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(local.0.lock().unwrap().wakers[0].is_some());

        local.permit_max_sid(Dir::Uni, 2);
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(2)))
        );
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(6)))
        );
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(10)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
        assert!(local.0.lock().unwrap().wakers[1].is_some());
    }

    #[test]
    fn test_try_accept_sid() {
        let StreamIds { local: _, remote } = StreamIds::new(Role::Client, 10, 5);
        let result = remote.try_accept_sid(StreamId(21));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(1),
                end: StreamId(21)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(25));

        let result = remote.try_accept_sid(StreamId(25));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(25),
                end: StreamId(25)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(29));

        let result = remote.try_accept_sid(StreamId(41));
        assert_eq!(
            result,
            Ok(AcceptSid::New(NeedCreate {
                start: StreamId(29),
                end: StreamId(41)
            }))
        );
        assert_eq!(remote.0.lock().unwrap().unallocated[0], StreamId(45));
        if let Ok(AcceptSid::New(mut range)) = result {
            assert_eq!(range.next(), Some(StreamId(29)));
            assert_eq!(range.next(), Some(StreamId(33)));
            assert_eq!(range.next(), Some(StreamId(37)));
            assert_eq!(range.next(), Some(StreamId(41)));
            assert_eq!(range.next(), None);
        }

        let result = remote.try_accept_sid(StreamId(65));
        assert_eq!(result, Err(ExceedLimitError(StreamId(65), StreamId(41))));
    }
}
