use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use deref_derive::{Deref, DerefMut};

use super::ConnectionId;
use crate::{
    error::Error,
    frame::{BeFrame, NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    token::ResetToken,
    util::{IndexDeque, RawAsyncCell},
    varint::{VarInt, VARINT_MAX},
};

#[derive(Debug)]
pub struct RawRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    // the cid issued by the peer, the sequence number maybe not continuous
    // since the disordered NewConnectionIdFrame
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // The cell of the connection ID, which is in use or waiting to assign or retired
    cid_cells: IndexDeque<ArcCidCell<RETIRED>, VARINT_MAX>,
    // The maximum number of connection IDs which can be stored in local
    active_cid_limit: u64,
    // The position of the cid to be used, and the position of the cell to be assigned.
    cursor: u64,
    // The retired cids, each needs send a RetireConnectionIdFrame to peer
    retired_cids: RETIRED,
}

impl<RETIRED> RawRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        let mut cid_deque = IndexDeque::default();

        let reset_token = ResetToken::default();
        cid_deque
            .push_back(Some((0, initial_dcid, reset_token)))
            .unwrap();

        Self {
            active_cid_limit,
            cid_deque,
            cid_cells: Default::default(),
            cursor: 0,
            retired_cids,
        }
    }

    fn revise_initial_dcid(&mut self, initial_dcid: ConnectionId) {
        let first_dcid = self.cid_deque.get_mut(0).unwrap();
        *first_dcid = Some((0, initial_dcid, ResetToken::default()));

        if let Some(apply) = self.cid_cells.get_mut(0) {
            apply.0.lock().unwrap().state.revise(initial_dcid);
        }
    }

    fn recv_new_cid_frame(
        &mut self,
        frame: &NewConnectionIdFrame,
    ) -> Result<Option<ResetToken>, Error> {
        let seq = frame.sequence.into_inner();
        let retire_prior_to = frame.retire_prior_to.into_inner();
        let active_len = seq.saturating_sub(retire_prior_to);
        if active_len > self.active_cid_limit {
            return Err(Error::new(
                crate::error::ErrorKind::ConnectionIdLimit,
                frame.frame_type(),
                format!(
                    "{active_len} exceed active_cid_limit {}",
                    self.active_cid_limit
                ),
            ));
        }

        // Discard the frame if the sequence number is less than the current offset.
        if frame.sequence < self.cid_deque.offset() {
            return Ok(None);
        }

        let id = frame.id;
        let token = frame.reset_token;
        self.cid_deque.insert(seq, Some((seq, id, token))).unwrap();
        self.retire_prior_to(retire_prior_to);
        self.arrange_idle_cid();

        Ok(Some(token))
    }

    /// Arrange the idle cids to the front of the cid applys
    #[doc(hidden)]
    fn arrange_idle_cid(&mut self) {
        loop {
            let next_unalloced_cell = self.cid_cells.get_mut(self.cursor);
            let next_unused_cid = self.cid_deque.get(self.cursor);

            if let (Some(cell), Some(Some((_, cid, _)))) = (next_unalloced_cell, next_unused_cid) {
                cell.0.lock().unwrap().state.assign(*cid);
                self.cursor += 1;
            } else {
                break;
            }
        }
    }

    /// Eliminate the old cids and inform the peer with a
    /// RetireConnectionIdFrame for each retired cid.
    #[doc(hidden)]
    fn retire_prior_to(&mut self, seq: u64) {
        if seq <= self.cid_cells.offset() {
            return;
        }

        _ = self.cid_deque.drain_to(seq);
        // it is possible that the connection id that has not been used is directly retired,
        // and there is no chance to assign it, this phenomenon is called "jumping retired cid"
        self.cursor = self.cursor.max(seq);

        // reassign the cid that has been assigned to the Path but is facing retirement
        if self.cid_cells.is_empty() {
            // it is not necessary to resize the deque, because all elements will be drained
            // // self.cid_cells.resize(seq, ArcCidCell::default()).expect("");
            self.retired_cids
                .send_frame((self.cid_cells.offset()..seq).map(|seq| {
                    RetireConnectionIdFrame {
                        sequence: VarInt::from_u64(seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    }
                }));
            self.cid_cells.reset_offset(seq);
        } else {
            let max_applied = self.cid_cells.largest();
            let (mut next_apply, max_retired) = if max_applied > seq {
                (max_applied, seq)
            } else {
                (seq, max_applied)
            };
            // retire the cids before seq, including the applied and unapplied
            for seq in self.cid_cells.offset()..max_retired {
                let (_, cell) = self.cid_cells.pop_front().unwrap();
                let mut guard = cell.0.lock().unwrap();

                if guard.is_retired() {
                    continue;
                }
                // reset the cell, and wait for the new cid to be assigned inside
                assert_eq!(guard.seq, seq);
                guard.seq = next_apply;
                guard.state.clear();
                drop(guard);

                // retire the old cid and prepare to inform the peer with a RetireConnectionIdFrame
                self.retired_cids.send_frame([RetireConnectionIdFrame {
                    sequence: VarInt::from_u64(seq)
                        .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                }]);
                // The reason for using insert instead of push_back is to keep the cid and cell consistent,
                // "jumping retired cid" will lead to "jumping allocation", although it is unlikely to happen.
                self.cid_cells
                    .push_back(cell)
                    .expect("Sequence of new connection ID should never exceed the limit");
                next_apply += 1;
            }
            if max_applied < seq {
                self.cid_cells.reset_offset(seq);
                // even the cid that has not been applied is retired right now
                self.retired_cids.send_frame((max_applied..seq).map(|seq| {
                    RetireConnectionIdFrame {
                        sequence: VarInt::from_u64(seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    }
                }));
            }
            // _ = self.cid_cells.drain_to(seq);
        }
    }

    fn apply_dcid(&mut self) -> ArcCidCell<RETIRED> {
        let state = if let Some(Some((_, cid, _))) = self.cid_deque.get(self.cursor) {
            self.cursor += 1;
            CidState(RawAsyncCell::Ready(*cid))
        } else {
            CidState(RawAsyncCell::None)
        };

        let seq = self.cid_cells.largest();
        let cell = ArcCidCell::new(self.retired_cids.clone(), seq, state);
        self.cid_cells
            .push_back(cell.clone())
            .expect("Sequence of new connection ID should never exceed the limit");
        cell
    }
}

#[derive(Debug, Clone)]
pub struct ArcRemoteCids<RETIRED>(Arc<Mutex<RawRemoteCids<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    pub fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RawRemoteCids::new(
            initial_dcid,
            active_cid_limit,
            retired_cids,
        ))))
    }

    /// Only when the client initially connects to the server, a temporary initial dcid is used;
    /// When a response packet is received from the server, the initial dcid should be updated
    /// based on the scid in the response packet.
    pub fn revise_initial_dcid(&self, initial_dcid: ConnectionId) {
        self.0.lock().unwrap().revise_initial_dcid(initial_dcid);
    }

    /// Return a ArcCidCell, which holds the state of the connection ID, included:
    /// - not be allocated yet
    /// - have been allocated
    /// - have been allocated again after retirement of last cid
    /// - have been retired
    pub fn apply_dcid(&self) -> ArcCidCell<RETIRED> {
        self.0.lock().unwrap().apply_dcid()
    }
}

impl<RETIRED> ReceiveFrame<NewConnectionIdFrame> for ArcRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Output = Option<ResetToken>;

    fn recv_frame(&self, frame: &NewConnectionIdFrame) -> Result<Self::Output, Error> {
        self.0.lock().unwrap().recv_new_cid_frame(frame)
    }
}

#[derive(Default, Debug)]
struct CidState(RawAsyncCell<ConnectionId>);

impl CidState {
    fn poll_get_cid(&mut self, cx: &mut Context) -> Poll<Option<ConnectionId>> {
        self.0.poll_get(cx).map(|cid| cid.as_ref().map(|cid| *cid))
    }

    fn revise(&mut self, cid: ConnectionId) {
        _ = self.0.write(cid);
    }

    fn assign(&mut self, cid: ConnectionId) {
        // Only allow transition from None or Demand state to Ready state
        debug_assert!(self.0.is_pending());
        _ = self.0.write(cid);
    }

    fn clear(&mut self) {
        // Allow transition from Ready state to None state, but not from Closed state
        // While meeting Demand state, it will not change && not wake the waker
        self.0.take();
    }

    fn is_retired(&mut self) -> bool {
        self.0.is_invalid()
    }

    fn retire(&mut self) {
        self.0.invalid();
    }
}

#[derive(Debug, Deref, DerefMut)]
struct CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame>,
{
    retired_cids: RETIRED,
    // The sequence number of the connection ID had beed assigned or to be allocated
    seq: u64,
    #[deref]
    state: CidState,
}

#[derive(Debug, Clone)]
pub struct ArcCidCell<RETIRED>(Arc<Mutex<CidCell<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcCidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn new(retired_cids: RETIRED, seq: u64, state: CidState) -> Self {
        Self(Arc::new(Mutex::new(CidCell {
            retired_cids,
            seq,
            state,
        })))
    }

    pub fn poll_get_cid(&self, cx: &mut Context<'_>) -> Poll<Option<ConnectionId>> {
        self.0.lock().unwrap().poll_get_cid(cx)
    }

    /// Getting the connection ID, if it is not ready, return a future
    #[inline]
    pub fn get_cid(&self) -> Self {
        self.clone()
    }

    /// When the Path is invalid, the connection id needs to be retired, and the Cell
    /// is marked as no longer in use, with a RetireConnectionIdFrame being sent to peer.
    #[inline]
    pub fn retire(&self) {
        let mut guard = self.0.lock().unwrap();

        if !guard.state.is_retired() {
            guard.state.retire();
            let sequence = VarInt::try_from(guard.seq)
                .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
            guard
                .retired_cids
                .send_frame([RetireConnectionIdFrame { sequence }]);
        }
    }
}

impl<RETIRED> Future for ArcCidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Output = Option<ConnectionId>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_get_cid(cx)
    }
}

#[cfg(test)]
mod tests {

    use futures::FutureExt;

    use super::*;
    use crate::util::ArcAsyncDeque;

    #[test]
    fn test_remote_cids() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = ArcAsyncDeque::<RetireConnectionIdFrame>::new();
        let mut remote_cids = RawRemoteCids::new(initial_dcid, 8, retired_cids);

        let cid_apply0 = remote_cids.apply_dcid();
        assert_eq!(
            cid_apply0.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(initial_dcid))
        );

        // Will return Pending, because the peer hasn't issue any connection id
        let cid_apply1 = remote_cids.apply_dcid();
        assert_eq!(cid_apply1.get_cid().poll_unpin(&mut cx), Poll::Pending);
        assert!(matches!(
            cid_apply1.0.lock().unwrap().state.0,
            RawAsyncCell::Demand(..)
        ));

        let cid = ConnectionId::random_gen(8);
        let frame = NewConnectionIdFrame {
            sequence: VarInt::from_u32(1),
            retire_prior_to: VarInt::from_u32(0),
            id: cid,
            reset_token: ResetToken::random_gen(),
        };
        assert!(remote_cids.recv_new_cid_frame(&frame).is_ok());
        assert_eq!(remote_cids.cid_deque.len(), 2);

        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cid))
        );

        // Additionally, a new request will be made because if the peer-issued CID is
        // insufficient, it will still return Pending.
        let cid_apply2 = remote_cids.apply_dcid();
        assert_eq!(cid_apply2.get_cid().poll_unpin(&mut cx), Poll::Pending);
    }

    #[test]
    fn test_retire_in_remote_cids() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = ArcAsyncDeque::<RetireConnectionIdFrame>::new();
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame {
                sequence: VarInt::from_u32(seq),
                retire_prior_to: VarInt::from_u32(0),
                id: cid,
                reset_token: ResetToken::random_gen(),
            };
            _ = guard.recv_new_cid_frame(&frame);
        }

        let cid_apply1 = guard.apply_dcid();
        let cid_apply2 = guard.apply_dcid();

        assert_eq!(cid_apply1.0.lock().unwrap().seq, 0);
        assert_eq!(cid_apply2.0.lock().unwrap().seq, 1);
        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[0]))
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[1]))
        );

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.cid_cells.offset(), 4);
        assert_eq!(guard.retired_cids.len(), 4);

        assert_eq!(cid_apply1.0.lock().unwrap().seq, 4);
        assert_eq!(cid_apply2.0.lock().unwrap().seq, 5);

        for i in 0..4 {
            assert_eq!(
                guard.retired_cids.poll_pop(&mut cx),
                Poll::Ready(Some(RetireConnectionIdFrame {
                    sequence: VarInt::from_u32(i),
                }))
            );
        }

        assert_eq!(cid_apply1.get_cid().poll_unpin(&mut cx), Poll::Pending);
        assert_eq!(cid_apply2.get_cid().poll_unpin(&mut cx), Poll::Pending);

        guard.arrange_idle_cid();
        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[4]))
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[5]))
        );

        cid_apply2.retire();
        assert_eq!(guard.retired_cids.len(), 1);
        assert_eq!(
            guard.retired_cids.poll_pop(&mut cx),
            Poll::Ready(Some(RetireConnectionIdFrame {
                sequence: VarInt::from_u32(5),
            }))
        );
    }

    #[test]
    fn test_retire_without_apply() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = ArcAsyncDeque::<RetireConnectionIdFrame>::new();
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame {
                sequence: VarInt::from_u32(seq),
                retire_prior_to: VarInt::from_u32(0),
                id: cid,
                reset_token: ResetToken::random_gen(),
            };
            _ = guard.recv_new_cid_frame(&frame);
        }

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.cid_cells.offset(), 4);
        assert_eq!(guard.retired_cids.len(), 4);

        let cid_apply1 = guard.apply_dcid();
        let cid_apply2 = guard.apply_dcid();
        assert_eq!(cid_apply1.0.lock().unwrap().seq, 4);
        assert_eq!(cid_apply2.0.lock().unwrap().seq, 5);
        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[4]))
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(Some(cids[5]))
        );
    }
}
