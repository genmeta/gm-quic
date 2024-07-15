use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use deref_derive::{Deref, DerefMut};

use super::ConnectionId;
use crate::{
    error::Error,
    frame::{BeFrame, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
    util::{ArcAsyncDeque, IndexDeque},
    varint::{VarInt, VARINT_MAX},
};

#[derive(Debug)]
pub struct RawRemoteCids {
    // the cid issued by the peer, the sequence number maybe not continuous
    // since the disordered NewConnectionIdFrame
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // The cell of the connection ID, which is in use or waiting to assign or retired
    cid_cells: IndexDeque<ArcCidCell, VARINT_MAX>,
    // The maximum number of connection IDs which can be stored in local
    active_cid_limit: u64,
    // The position of the cid to be used, and the position of the cell to be assigned.
    cursor: u64,
    // The retired cids, each needs send a RetireConnectionIdFrame to peer
    retired_cids: ArcAsyncDeque<RetireConnectionIdFrame>,
}

impl RawRemoteCids {
    pub fn with_limit(active_cid_limit: u64) -> Self {
        Self {
            active_cid_limit,
            cid_deque: Default::default(),
            cid_cells: Default::default(),
            cursor: Default::default(),
            retired_cids: Default::default(),
        }
    }

    /// The retired cids, which might be a choice made by a certain Path, or due to
    /// receiving a NewConnectionIdFrame because of its retire_prior_to retire a batch
    /// of cids. For each retired cid, a RetireConnectionIdFrame will be sent to inform
    /// the peer.
    ///
    /// # Example
    ///
    /// ```
    /// use qbase::cid::RawRemoteCids;
    /// use futures::StreamExt;
    ///
    /// # async fn dox() {
    /// let remote_cids = RawRemoteCids::with_limit(8);
    ///
    /// // There will be a task continuously get RetireConnectionIdFrame and
    /// // then send it to peer
    /// let mut retired_cids = remote_cids.retired_cids();
    /// while let Some(_retire_cid_frame) = retired_cids.next().await {
    ///     // send _retire_cid_frame to peer
    /// }
    /// # }
    /// ```
    pub fn retired_cids(&self) -> ArcAsyncDeque<RetireConnectionIdFrame> {
        self.retired_cids.clone()
    }

    pub fn recv_new_cid_frame(
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
                cell.assign(*cid);
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
        _ = self.cid_deque.drain_to(seq);
        // it is possible that the connection id that has not been used is directly retired,
        // and there is no time to assign it, this phenomenon is called "jumping retired cid"
        self.cursor = self.cursor.max(seq);

        if seq <= self.cid_cells.offset() {
            return;
        }

        // reassign the cid that has been assigned to the Path but is facing retirement
        if self.cid_cells.is_empty() {
            // it is not necessary to resize the deque, because all elements will be drained
            // // self.cid_cells.resize(seq, ArcCidCell::default()).expect("");
            let mut retired_cids = self.retired_cids.writer();
            for seq in self.cid_cells.offset()..seq {
                retired_cids.push(RetireConnectionIdFrame {
                    sequence: VarInt::from_u64(seq)
                        .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                });
            }
            self.cid_cells.reset_offset(seq);
        } else {
            let cid_apply_largest = self.cid_cells.largest();
            let (mut next_apply, max_applied) = if cid_apply_largest > seq {
                (cid_apply_largest, seq)
            } else {
                (seq, cid_apply_largest)
            };
            // retire the cids before seq, including the applied and unapplied
            for (i, _) in (self.cid_cells.offset()..max_applied).enumerate() {
                let (_, cell) = self.cid_cells.pop_front().unwrap();
                let mut guard = cell.lock_guard();
                if guard.is_retired() {
                    continue;
                } else {
                    // reset the cell, and wait for the new cid to be assigned inside
                    let origin_seq = guard.seq;
                    guard.seq = seq + i as u64;
                    guard.clear();
                    drop(guard);

                    // retire the old cid and prepare to inform the peer with a RetireConnectionIdFrame
                    self.retired_cids.push(RetireConnectionIdFrame {
                        sequence: VarInt::from_u64(origin_seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    });
                    // The reason for using insert instead of push_back is to keep the cid and cell consistent,
                    // "jumping retired cid" will lead to "jumping allocation", although it is unlikely to happen.
                    self.cid_cells
                        .insert(next_apply, cell)
                        .expect("Sequence of new connection ID should never exceed the limit");
                    next_apply += 1;
                }
            }

            // even the cid that has not been applied is retired right now
            let mut retired_cids = self.retired_cids.writer();
            for seq in max_applied..seq {
                retired_cids.push(RetireConnectionIdFrame {
                    sequence: VarInt::from_u64(seq)
                        .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                });
            }
            _ = self.cid_cells.drain_to(seq);
        }
    }

    /// Returns a ArcCidCell, which holds the state of the connection ID, included:
    /// - not be allocated yet
    /// - have been allocated
    /// - have been allocated again after retirement of last cid
    /// - have been retired
    pub fn apply_cid(&mut self) -> ArcCidCell {
        let state = if let Some(Some((_, cid, _))) = self.cid_deque.get(self.cursor) {
            self.cursor += 1;
            CidState::Ready(*cid)
        } else {
            CidState::None
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
pub struct ArcRemoteCids(Arc<Mutex<RawRemoteCids>>);

impl ArcRemoteCids {
    #[inline]
    pub fn with_limit(active_cid_limit: u64) -> Self {
        Self(Arc::new(Mutex::new(RawRemoteCids::with_limit(
            active_cid_limit,
        ))))
    }

    #[inline]
    pub fn lock_guard(&self) -> MutexGuard<'_, RawRemoteCids> {
        self.0.lock().unwrap()
    }
}

#[derive(Default, Debug, Clone)]
enum CidState {
    None,
    Demand(Waker),
    Ready(ConnectionId),
    #[default]
    Retired,
}

impl CidState {
    fn poll_get_cid(&mut self, cx: &mut Context) -> Poll<ConnectionId> {
        match self {
            CidState::None => {
                *self = CidState::Demand(cx.waker().clone());
                Poll::Pending
            }
            CidState::Demand(waker) => {
                waker.clone_from(cx.waker());
                Poll::Pending
            }
            CidState::Ready(cid) => Poll::Ready(*cid),
            CidState::Retired => unreachable!("CidCell is closed"),
        }
    }

    fn assign(&mut self, cid: ConnectionId) {
        // Only allow transition from None or Demand state to Ready state
        debug_assert!(matches!(self, Self::None | Self::Demand(_)));
        if let CidState::Demand(waker) = std::mem::take(self) {
            waker.wake();
        }
        *self = CidState::Ready(cid);
    }

    fn clear(&mut self) {
        // Allow transition from Ready state to None state, but not from Closed state
        // While meeting Demand state, it will not change && not wake the waker
        match self {
            CidState::Ready(_) => *self = CidState::None,
            CidState::Retired => unreachable!("CidCell is retired"),
            _ => {}
        }
    }

    fn retire(&mut self) {
        *self = CidState::Retired;
    }

    fn is_retired(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[derive(Debug, Default, Deref, DerefMut)]
struct CidCell {
    retired_cids: ArcAsyncDeque<RetireConnectionIdFrame>,
    // The sequence number of the connection ID had beed assigned or to be allocated
    seq: u64,
    #[deref]
    state: CidState,
}

#[derive(Default, Debug, Clone)]
pub struct ArcCidCell(Arc<Mutex<CidCell>>);

impl ArcCidCell {
    fn new(
        retired_cids: ArcAsyncDeque<RetireConnectionIdFrame>,
        seq: u64,
        state: CidState,
    ) -> Self {
        Self(Arc::new(Mutex::new(CidCell {
            retired_cids,
            seq,
            state,
        })))
    }

    fn lock_guard(&self) -> MutexGuard<'_, CidCell> {
        self.0.lock().unwrap()
    }

    fn assign(&self, cid: ConnectionId) {
        self.0.lock().unwrap().assign(cid);
    }

    /// Getting the connection ID, if it is not ready, return a future
    #[inline]
    pub fn get_cid(&self) -> ArcCidCell {
        self.clone()
    }

    /// When the Path is invalid, the connection id needs to be retired, and the Cell
    /// is marked as no longer in use, with a RetireConnectionIdFrame being sent to peer.
    #[inline]
    pub fn retire(&self) {
        let mut guard = self.lock_guard();
        if !guard.is_retired() {
            guard.state.retire();
            guard.retired_cids.push(RetireConnectionIdFrame {
                sequence: VarInt::from_u64(guard.seq).unwrap(),
            });
        }
    }
}

impl Future for ArcCidCell {
    type Output = ConnectionId;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock().unwrap().poll_get_cid(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::{FutureExt, StreamExt};

    use super::*;

    #[test]
    fn test_remote_cids() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut remote_cids = RawRemoteCids::with_limit(8);

        // Will return Pending, because the peer hasn't issue any connection id
        let cid_apply = remote_cids.apply_cid();
        assert_eq!(cid_apply.get_cid().poll_unpin(&mut cx), Poll::Pending);
        assert!(matches!(cid_apply.lock_guard().state, CidState::Demand(_)));

        let cid = ConnectionId::random_gen(8);
        let frame = NewConnectionIdFrame {
            sequence: VarInt::from_u32(0),
            retire_prior_to: VarInt::from_u32(0),
            id: cid,
            reset_token: ResetToken::random_gen(),
        };
        assert!(remote_cids.recv_new_cid_frame(&frame).is_ok());
        assert_eq!(remote_cids.cid_deque.len(), 1);

        assert_eq!(cid_apply.get_cid().poll_unpin(&mut cx), Poll::Ready(cid));

        // Additionally, a new request will be made because if the peer-issued CID is
        // insufficient, it will still return Pending.
        let cid_apply2 = remote_cids.apply_cid();
        assert_eq!(cid_apply2.get_cid().poll_unpin(&mut cx), Poll::Pending);
    }

    #[test]
    fn test_retire_in_remote_cids() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let remote_cids = ArcRemoteCids::with_limit(8);
        let mut guard = remote_cids.lock_guard();

        let mut cids = vec![];
        for seq in 0..8 {
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

        let cid_apply1 = guard.apply_cid();
        let cid_apply2 = guard.apply_cid();
        assert_eq!(cid_apply1.lock_guard().seq, 0);
        assert_eq!(cid_apply2.lock_guard().seq, 1);
        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(cids[0])
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(cids[1])
        );

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.cid_cells.offset(), 4);
        assert_eq!(guard.retired_cids.len(), 4);

        assert_eq!(cid_apply1.lock_guard().seq, 4);
        assert_eq!(cid_apply2.lock_guard().seq, 5);

        for i in 0..4 {
            assert_eq!(
                guard.retired_cids.poll_next_unpin(&mut cx),
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
            Poll::Ready(cids[4])
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(cids[5])
        );

        cid_apply2.retire();
        assert_eq!(guard.retired_cids.len(), 1);
        assert_eq!(
            guard.retired_cids.poll_next_unpin(&mut cx),
            Poll::Ready(Some(RetireConnectionIdFrame {
                sequence: VarInt::from_u32(5),
            }))
        );
    }

    #[test]
    fn test_retire_without_apply() {
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let remote_cids = ArcRemoteCids::with_limit(8);
        let mut guard = remote_cids.lock_guard();

        let mut cids = vec![];
        for seq in 0..8 {
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

        let cid_apply1 = guard.apply_cid();
        let cid_apply2 = guard.apply_cid();
        assert_eq!(cid_apply1.lock_guard().seq, 4);
        assert_eq!(cid_apply2.lock_guard().seq, 5);
        assert_eq!(
            cid_apply1.get_cid().poll_unpin(&mut cx),
            Poll::Ready(cids[4])
        );
        assert_eq!(
            cid_apply2.get_cid().poll_unpin(&mut cx),
            Poll::Ready(cids[5])
        );
    }
}
