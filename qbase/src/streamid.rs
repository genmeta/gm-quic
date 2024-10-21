use std::{
    fmt, ops,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use thiserror::Error;

use super::{
    frame::MaxStreamsFrame,
    varint::{be_varint, VarInt, WriteVarInt},
};
use crate::frame::{SendFrame, StreamsBlockedFrame};

/// Roles in the QUIC protocol, including client and server.
///
/// The least significant bit (0x01) of the [`StreamId`] identifies the initiator role of the stream.
/// Client-initiated streams have even-numbered stream IDs (with the bit set to 0),
/// and server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
/// See [section-2.1-3](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-3)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
///
/// # Note
///
/// As a protocol capable of multiplexing streams, QUIC is different from traditional
/// HTTP protocols for clients and servers.
/// In the QUIC protocol, it is not only the client that can actively open a new stream;
/// the server can also actively open a new stream to push some data to the client.
/// In fact, in a new stream, the server can initiate an HTTP3 request to the client,
/// and the client, upon receiving the request, responds back to the server.
/// In this case, the client surprisingly plays the role of the traditional "server",
/// which is quite fascinating.
///
/// # Example
///
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

/// Sum type for stream directions.
///
/// Streams can be unidirectional or bidirectional.
/// Unidirectional streams carry data in one direction: from the initiator of the stream to its peer.
/// Bidirectional streams allow for data to be sent in both directions.
/// See [section-2.1-1](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-1)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
///
/// The second least significant bit (0x02) of the [`StreamId`] distinguishes between
/// bidirectional streams (with the bit set to 0) and unidirectional streams (with the bit set to 1).
/// See [section-2.1-4](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1-4)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html).
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

/// Streams are identified within a connection by a numeric value,
/// referred to as the stream ID.
///
/// A stream ID is a 62-bit integer (0 to 262-1) that is unique for all streams on a connection.
/// Stream IDs are encoded as [`VarInt`].
/// A QUIC endpoint MUST NOT reuse a stream ID within a connection.
///
/// There are four types of streams in QUIC, divided according to the role and direction of the stream.
/// See [Stream ID Types](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-id-types)
/// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

/// Maximum ID for each type of stream.
///
/// [`StreamId`] is encoded with [`VarInt`].
/// After removing the lowest 2 bits for direction and role,
/// the remaining 60 bits are used to represent the actual ID for each type of stream,
/// so its maximum range cannot exceed 2^60.
pub const MAX_STREAM_ID: u64 = (1 << 60) - 1;

impl StreamId {
    /// Create a new stream ID with the given role, direction, and ID.
    ///
    /// It is prohibited to directly create a StreamId from external sources.
    /// StreamId can only be allocated incrementally by proactively creating new streams locally.
    /// or accepting new streams opened by peer.
    fn new(role: Role, dir: Dir, id: u64) -> Self {
        assert!(id <= MAX_STREAM_ID);
        Self((((id << 1) | (dir as u64)) << 1) | (role as u64))
    }

    /// Returns the role of this stream ID.
    pub fn role(&self) -> Role {
        if self.0 & 0x1 == 0 {
            Role::Client
        } else {
            Role::Server
        }
    }

    /// Returns the direction of this stream ID.
    pub fn dir(&self) -> Dir {
        if self.0 & 2 == 0 {
            Dir::Bi
        } else {
            Dir::Uni
        }
    }

    /// Get the actual ID of this stream, removing the lowest 2 bits for direction and role.
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

    /// Return the encoding size of this stream ID.
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

impl From<StreamId> for u64 {
    fn from(s: StreamId) -> Self {
        s.0
    }
}

/// Parse a stream ID from the input bytes,
/// [nom](https://docs.rs/nom/6.2.1/nom/) parser style.
pub fn be_streamid(input: &[u8]) -> nom::IResult<&[u8], StreamId> {
    use nom::combinator::map;
    map(be_varint, StreamId::from)(input)
}

/// A BufMut extension trait for writing a stream ID.
pub trait WriteStreamId: bytes::BufMut {
    /// Write a stream ID to the buffer.
    fn put_streamid(&mut self, stream_id: &StreamId);
}

impl<T: bytes::BufMut> WriteStreamId for T {
    fn put_streamid(&mut self, stream_id: &StreamId) {
        self.put_varint(&(*stream_id).into());
    }
}

/// Exceed the maximum stream ID limit error,
/// similar with [`ErrorKind::StreamLimit`](`crate::error::ErrorKind::StreamLimit`).
///
/// This error occurs when the stream ID in the received stream-related frames
/// exceeds the maximum stream ID limit.
#[derive(Debug, PartialEq, Error)]
#[error("{0} exceed limit: {1}")]
pub struct ExceedLimitError(StreamId, StreamId);

/// Accept the stream ID received from peer,
/// returned by [`ArcRemoteStreamIds::try_accept_sid`].
#[derive(Debug, PartialEq)]
pub enum AcceptSid {
    /// Indicates that the stream ID is already exist.
    Old,
    /// Indicates that the stream ID is new and need to create.
    /// The `NeedCreate` inside indicates the range of stream IDs that need to be created together.
    New(NeedCreate),
}

/// The range of stream IDs that need to be created,
/// see [`ArcRemoteStreamIds::try_accept_sid`] and [`AcceptSid::New`].
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

/// Local stream IDs management.
#[derive(Debug)]
struct LocalStreamIds<BLOCKED> {
    role: Role,                 // Our role
    max: [StreamId; 2],         // The maximum stream ID we can create
    unallocated: [StreamId; 2], // The stream ID that we have not used
    wakers: [Option<Waker>; 2], // Used for waiting for the MaxStream frame notification from peer when we have exhausted the creation of stream IDs
    blocked: BLOCKED,           // The StreamsBlocked frames that will be sent to peer
}

impl<BLOCKED> LocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`LocalStreamIds`] with the given role,
    /// and maximum number of streams that can be created in each [`Dir`].
    fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64, blocked: BLOCKED) -> Self {
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
            blocked,
        }
    }

    /// Returns local role.
    fn role(&self) -> Role {
        self.role
    }

    /// Receive the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer,
    /// update the maximum stream ID that can be opened locally in the given direction.
    fn recv_max_streams_frame(&mut self, frame: &MaxStreamsFrame) {
        let (dir, val) = match frame {
            MaxStreamsFrame::Bi(max) => (Dir::Bi, (*max).into_inner()),
            MaxStreamsFrame::Uni(max) => (Dir::Uni, (*max).into_inner()),
        };
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
            self.blocked
                .send_frame([StreamsBlockedFrame::with(dir, self.max[idx])]);
            Poll::Pending
        }
    }
}

/// Remote stream IDs management.
#[derive(Debug)]
struct RemoteStreamIds {
    role: Role,                 // The role of the peer
    max: [StreamId; 2],         // The maximum stream ID that peer can create
    unallocated: [StreamId; 2], // The stream ID that peer has not used
    concurrency: [u64; 2],      // The concurrency of streams that peer can create
    wakers: [Option<Waker>; 2], // When the stream ID created by peer is close to the upper limit, wake up to update the upper limit in time.
}

impl RemoteStreamIds {
    /// Create a new [`RemoteStreamIds`] with the given role,
    /// and maximum number of streams that can be created by peer in each [`Dir`].
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

    /// Returns the role of the peer.
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

/// Management of stream IDs that can ben allowed to use locally.
///
/// The maximum stream ID that can be created is limited by the
/// [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from the peer.
///
/// When the stream IDs in the `dir` direction are exhausted,
/// a [`StreamsBlockedFrame`](`crate::frame::StreamsBlockedFrame`) will be sent to the peer.
/// The generic parameter `BLOCKED` is the container of the [`StreamsBlockedFrame`]
/// that will be sent to peer, it can be a channel, a queue, or a buffer,
/// as long as it can send the [`StreamsBlockedFrame`] to peer.
#[derive(Debug, Clone)]
pub struct ArcLocalStreamIds<BLOCKED>(Arc<Mutex<LocalStreamIds<BLOCKED>>>);

impl<BLOCKED> ArcLocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`ArcLocalStreamIds`] with the given role,
    /// and maximum number of streams that can be created in each direction,
    /// the `blocked` contains the [`StreamsBlockedFrame`] that will be sent to peer.
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64, blocked: BLOCKED) -> Self {
        Self(Arc::new(Mutex::new(LocalStreamIds::new(
            role,
            max_bi_streams,
            max_uni_streams,
            blocked,
        ))))
    }

    /// Returns local role
    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// Receive the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer,
    /// and then update the maximum stream ID that can be allowed to use locally.
    ///
    /// The maximum stream ID that can be allowed to use is limited by peer.
    /// Therefore, it mainly depends on the peer's attitude
    /// and is subject to the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`)
    /// received from peer.
    pub fn recv_max_streams_frame(&self, frame: &MaxStreamsFrame) {
        self.0.lock().unwrap().recv_max_streams_frame(frame);
    }

    /// Asynchronously allocate the next new [`StreamId`] in the `dir` direction.
    ///
    /// When the application layer wants to proactively open a new stream,
    /// it needs to first apply to allocate the next unused [`StreamId`].
    /// Note that streams on a QUIC connection usually have a maximum concurrency limit,
    /// so when requesting a [`StreamId`], it may not be possible to obtain one due to
    /// reaching the maximum concurrency limit.
    /// However, this is temporary. When the active current streams end,
    /// the peer will expand the maximum stream ID limit through a
    /// [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`),
    /// allowing the allocation of the [`StreamId`] meanwhile.
    ///
    /// Return Pending when the stream IDs in the `dir` direction are exhausted,
    /// until receiving the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer.
    ///
    /// Return None if the stream IDs in the `dir` direction finally exceed 2^60,
    /// but it is very very hard to happen.
    pub fn poll_alloc_sid(&self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        self.0.lock().unwrap().poll_alloc_sid(cx, dir)
    }
}

/// Shared remote stream IDs, mainly controls and monitors the stream IDs
/// in the received stream-related frames from peer.
///
/// Checks whether the stream IDs exceed the limit ,and creates them if necessary.
/// And sends a [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`)
/// to the peer to update the maximum stream ID limit in time.
///
/// # Note
///
/// After receiving the peer's stream-related frames,
/// due to possible out-of-order reception issues,
/// the stream IDs in these frames may have gaps,
/// i.e., they may not be continuous with the previous stream ID of the same type.
/// So before a stream is created,
/// all streams of the same type with lower-numbered stream IDs MUST be created.
/// This ensures that the creation order for streams is consistent on both endpoints
#[derive(Debug, Clone)]
pub struct ArcRemoteStreamIds(Arc<Mutex<RemoteStreamIds>>);

impl ArcRemoteStreamIds {
    /// Create a new [`ArcRemoteStreamIds`] with the given role,
    /// and maximum number of streams that can be created by peer in each direction.
    ///
    /// The maximum number of streams that can be created by peer in each direction
    /// are `initial_max_streams_bidi` and `initial_max_sterams_uni`
    /// in local [`Parameters`](`crate::config::Parameters`).
    /// See [section-18.2-4.21](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.21)
    /// and [section-18.2-4.23](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.23)
    /// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64) -> Self {
        Self(Arc::new(Mutex::new(RemoteStreamIds::new(
            role,
            max_bi_streams,
            max_uni_streams,
        ))))
    }

    /// Returns the role of the peer.
    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// Try to accept the stream ID received from peer.
    ///
    /// Only if this stream ID must be created by peer, this function needs to be called.
    ///
    /// This stream ID may belong to an already existing stream or a new stream that does not yet exist.
    /// If it is the latter, a new stream needs to be created.
    /// Before a stream is created, all streams of the same type
    /// with lower-numbered stream IDs MUST be created.
    /// See [section-3.2-6](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2-6)
    /// of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) for more details.
    ///
    /// # Return
    ///
    /// - Return [`ExceedLimitError`] if the stream ID exceeds the maximum stream ID limit.
    /// - Return [`AcceptSid::Old`] if the stream ID is already exist.
    /// - Return [`AcceptSid::New`] if the stream ID is new and need to create.
    ///   The `NeedCreate` inside indicates the range of stream IDs that need to be created.
    pub fn try_accept_sid(&self, sid: StreamId) -> Result<AcceptSid, ExceedLimitError> {
        self.0.lock().unwrap().try_accept_sid(sid)
    }

    /// Asynchronously extend the maximum stream ID that peer can create in the `dir` direction.
    ///
    /// In fact, when receiving the peer's ResetStreamFrame or sending a ResetStreamFrame,
    /// it signifies the end of a stream.
    /// At that point, it is necessary to check whether the stream was created by the peer
    /// and whether the peer's maximum stream ID needs to be updated.
    /// There is no need to spawn an asynchronous task to constantly check.
    ///
    /// In the future, just update the peer's maximum stream ID limit immediately
    /// when a stream created by the peer ends, and send a MAX_STREAMS frame to the peer.
    #[deprecated]
    pub fn poll_extend_sid(&self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<VarInt>> {
        self.0.lock().unwrap().poll_extend_sid(cx, dir)
    }
}

/// Stream IDs management, including an [`ArcLocalStreamIds`] as local,
/// and an [`ArcRemoteStreamIds`] as remote.
#[derive(Debug, Clone)]
pub struct StreamIds<BLOCKED> {
    pub local: ArcLocalStreamIds<BLOCKED>,
    pub remote: ArcRemoteStreamIds,
}

impl<BLOCKED> StreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`StreamIds`] with the given role, and maximum number of streams of each direction.
    ///
    /// The troublesome part is that the maximum number of streams that can be created locally
    /// is restricted by the peer's `initial_max_streams_uni` and `initial_max_streams_bidi` transport
    /// parameters, which are unknown at the beginning.
    /// Therefore, peer's `initial_max_streams_xx` can be set to 0 initially,
    /// and then updated later after obtaining the peer's `initial_max_streams_xx` setting.
    pub fn new(role: Role, max_bi_streams: u64, max_uni_streams: u64, blocked: BLOCKED) -> Self {
        // 缺省为0
        let local = ArcLocalStreamIds::new(role, 0, 0, blocked);
        let remote = ArcRemoteStreamIds::new(!role, max_bi_streams, max_uni_streams);
        Self { local, remote }
    }
}

#[cfg(test)]
mod tests {
    use deref_derive::Deref;

    use super::*;
    use crate::util::ArcAsyncDeque;

    #[derive(Clone, Deref, Default)]
    struct StreamsBlockedFrameTx(ArcAsyncDeque<StreamsBlockedFrame>);

    impl SendFrame<StreamsBlockedFrame> for StreamsBlockedFrameTx {
        fn send_frame<I: IntoIterator<Item = StreamsBlockedFrame>>(&self, iter: I) {
            (&self.0).extend(iter);
        }
    }

    #[test]
    fn test_stream_id_new() {
        let sid = StreamId::new(Role::Client, Dir::Bi, 0);
        assert_eq!(sid, StreamId(0));
        assert_eq!(sid.role(), Role::Client);
        assert_eq!(sid.dir(), Dir::Bi);
    }

    #[test]
    fn test_permit_max_sid() {
        let StreamIds { local, remote: _ } =
            StreamIds::new(Role::Client, 10, 2, StreamsBlockedFrameTx::default());
        local.recv_max_streams_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(0)));
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(0)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(local.0.lock().unwrap().wakers[0].is_some());
        local.recv_max_streams_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(1)));
        let _ = local.0.lock().unwrap().wakers[0].take();
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(4)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(local.0.lock().unwrap().wakers[0].is_some());

        local.recv_max_streams_frame(&MaxStreamsFrame::Uni(VarInt::from_u32(2)));
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
        let StreamIds { local: _, remote } =
            StreamIds::new(Role::Client, 10, 5, StreamsBlockedFrameTx::default());
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
