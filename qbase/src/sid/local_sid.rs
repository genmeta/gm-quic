use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use super::{Dir, Role, StreamId};
use crate::{
    frame::{MaxStreamsFrame, ReceiveFrame, SendFrame, StreamsBlockedFrame},
    net::tx::{ArcSendWakers, Signals},
    sid::MAX_STREAMS_LIMIT,
    varint::VarInt,
};

/// Local stream IDs management.
#[derive(Debug)]
struct LocalStreamIds<BLOCKED> {
    /// Our role
    role: Role,
    /// The maximum stream ID we can create in each direction.
    max: [u64; 2],
    /// Intiial maximum stream ID for client's 0rtt data.
    init_max: [u64; 2],
    /// Parameters received and/or [`MaxStreamsFrame`] received from the peer.
    new_max_rcvd: bool,
    /// The stream ID that we have not used.
    ///
    /// if the allocated > max, it means 0rtt data was rejected by server
    unallocated: [u64; 2],
    /// Used for waiting for the MaxStream frame notification from peer when we have exhausted the creation of stream IDs
    wakers: [VecDeque<Waker>; 2],
    /// The StreamsBlocked frames that will be sent to peer
    blocked: BLOCKED,
    tx_wakers: ArcSendWakers,
}

impl<BLOCKED> LocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    /// Create a new [`LocalStreamIds`] with the given role,
    /// and maximum number of streams that can be created in each [`Dir`].
    fn new(
        role: Role,
        init_max_bi_streams: u64,
        init_max_uni_streams: u64,
        blocked: BLOCKED,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        debug_assert!(
            role == Role::Client || (init_max_bi_streams == 0 && init_max_uni_streams == 0),
            "Server cannot remember the parameters"
        );
        Self {
            role,
            init_max: [init_max_bi_streams, init_max_uni_streams],
            max: [0, 0],
            new_max_rcvd: false,
            unallocated: [0, 0],
            wakers: [VecDeque::with_capacity(2), VecDeque::with_capacity(2)],
            blocked,
            tx_wakers,
        }
    }

    /// Returns local role.
    fn role(&self) -> Role {
        self.role
    }

    /// Returns the maximum stream ID that can be created in the `dir` direction.
    fn max_streams(&self, dir: Dir, is_0rtt: bool) -> u64 {
        if is_0rtt {
            self.init_max[dir as usize]
        } else {
            self.max[dir as usize]
        }
    }

    /// Receive the [`MaxStreamsFrame`](`crate::frame::MaxStreamsFrame`) from peer,
    /// update the maximum stream ID that can be opened locally in the given direction.
    fn recv_max_streams_frame(&mut self, frame: &MaxStreamsFrame) {
        let (dir, val) = match frame {
            MaxStreamsFrame::Bi(max) => (Dir::Bi, (*max).into_inner()),
            MaxStreamsFrame::Uni(max) => (Dir::Uni, (*max).into_inner()),
        };
        assert!(val <= MAX_STREAMS_LIMIT);
        let max_streams = &mut self.max[dir as usize];
        // RFC9000: MAX_STREAMS frames that do not increase the stream limit MUST be ignored.
        if *max_streams < val {
            // The rejected 0rtt stream can be sent again, as if new data was written.
            if *max_streams < self.unallocated[dir as usize] {
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
            }
            for waker in self.wakers[dir as usize].drain(..) {
                waker.wake();
            }
            *max_streams = val;
        }
    }

    fn poll_alloc_sid(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<StreamId>> {
        let idx = dir as usize;
        let max = if self.new_max_rcvd {
            self.max[idx]
        } else {
            // new value may not be assign this time, but we know that 0rtt is accepted, new max value is greater
            self.max[idx].max(self.init_max[idx])
        };
        let cur = &mut self.unallocated[idx];
        if *cur > MAX_STREAMS_LIMIT {
            Poll::Ready(None)
        } else if *cur < max {
            let id = *cur;
            *cur += 1;
            Poll::Ready(Some(StreamId::new(self.role, dir, id)))
        } else {
            // waiting for MAX_STREAMS frame from peer
            self.wakers[idx].push_back(cx.waker().clone());
            // if Poll::Pending is returned, connection can send a STREAMS_BLOCKED frame to peer
            self.blocked.send_frame([StreamsBlockedFrame::with(
                dir,
                VarInt::from_u64(self.max[idx])
                    .expect("max_streams limit must be less than VARINT_MAX"),
            )]);
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
    pub fn new(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        blocked: BLOCKED,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        Self(Arc::new(Mutex::new(LocalStreamIds::new(
            role,
            max_bi_streams,
            max_uni_streams,
            blocked,
            tx_wakers,
        ))))
    }

    /// Returns local role
    pub fn role(&self) -> Role {
        self.0.lock().unwrap().role()
    }

    /// Returns the maximum stream ID that can be created in the `dir` direction.
    ///
    /// If `is_0rtt` is true, initial maximum stream ID is returned.
    /// If 0rtt is rejected by server, it returns None,
    pub fn max_streams(&self, dir: Dir, is_0rtt: bool) -> u64 {
        self.0.lock().unwrap().max_streams(dir, is_0rtt)
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

impl<BLOCKED> ReceiveFrame<MaxStreamsFrame> for ArcLocalStreamIds<BLOCKED>
where
    BLOCKED: SendFrame<StreamsBlockedFrame> + Clone + Send + 'static,
{
    type Output = ();

    fn recv_frame(&self, frame: &MaxStreamsFrame) -> Result<Self::Output, crate::error::Error> {
        self.recv_max_streams_frame(frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use derive_more::Deref;

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
    fn test_recv_max_stream_frames() {
        let local = ArcLocalStreamIds::new(
            Role::Client,
            0,
            0,
            StreamsBlockedFrameTx::default(),
            ArcSendWakers::default(),
        );
        local.recv_max_streams_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(0)));
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending,);
        assert!(!local.0.lock().unwrap().wakers[0].is_empty());

        local.recv_max_streams_frame(&MaxStreamsFrame::Bi(VarInt::from_u32(1)));
        let _ = local.0.lock().unwrap().wakers[0].pop_front();
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Bi),
            Poll::Ready(Some(StreamId(0)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Bi), Poll::Pending);
        assert!(!local.0.lock().unwrap().wakers[0].is_empty());

        local.recv_max_streams_frame(&MaxStreamsFrame::Uni(VarInt::from_u32(2)));
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(2)))
        );
        assert_eq!(
            local.poll_alloc_sid(&mut cx, Dir::Uni),
            Poll::Ready(Some(StreamId(6)))
        );
        assert_eq!(local.poll_alloc_sid(&mut cx, Dir::Uni), Poll::Pending);
        assert!(!local.0.lock().unwrap().wakers[1].is_empty());
    }
}
