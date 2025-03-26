use std::{
    collections::VecDeque,
    ops::Deref,
    sync::{Arc, Mutex},
};

use super::ConnectionId;
use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, NewConnectionIdFrame, ReceiveFrame, RetireConnectionIdFrame, SendFrame},
    net::tx::{ArcSendWaker, Signals},
    token::ResetToken,
    util::IndexDeque,
    varint::{VARINT_MAX, VarInt},
};

/// RemoteCids is used to manage the connection IDs issued by the peer,
/// and to send [`RetireConnectionIdFrame`] to the peer.
#[derive(Debug)]
struct RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    // the cid issued by the peer, the sequence number maybe not continuous
    // since the disordered [`NewConnectionIdFrame`]
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // The cell of the connection ID, which is ready in use
    ready_cells: IndexDeque<ArcCidCell<RETIRED>, VARINT_MAX>,
    // The cell of the connection ID, which needs to be assigned or reassigned
    // They can be retired before being assigned or reassigned.
    pending_cells: VecDeque<ArcCidCell<RETIRED>>,
    // The maximum number of connection IDs which is used to check if the
    // maximum number of connection IDs has been exceeded
    // when receiving a [`NewConnectionIdFrame`]
    active_cid_limit: u64,
    // The position of the cid to be used, and the position of the cell to be assigned.
    cursor: u64,
    // The retired cids, each needs send a [`RetireConnectionIdFrame`] to peer
    retired_cids: RETIRED,
}

impl<RETIRED> RemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a new RemoteCids with the initial dcid, the maximum number of active cids,
    /// and the retired cids.
    ///
    /// As mentioned above, the retired cids can be a deque, a channel, or any buffer,
    /// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
    /// See [`RemoteCids`]
    fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        let mut cid_deque = IndexDeque::default();

        let reset_token = ResetToken::default();
        cid_deque
            .push_back(Some((0, initial_dcid, reset_token)))
            .unwrap();

        Self {
            active_cid_limit,
            cid_deque,
            ready_cells: Default::default(),
            pending_cells: Default::default(),
            cursor: 0,
            retired_cids,
        }
    }

    /// Revise the initial dcid, which is used when the client received the
    /// response packet from the server, and the initial dcid should be updated
    /// based on the scid in the response packet.
    fn revise_initial_dcid(&mut self, responsed_dcid: ConnectionId) {
        let first_dcid = self.cid_deque.get_mut(0).unwrap();
        *first_dcid = Some((0, responsed_dcid, ResetToken::default()));

        if let Some(apply) = self.ready_cells.get_mut(0) {
            apply.revise(responsed_dcid);
        }
    }

    /// Receive a [`NewConnectionIdFrame`] from peer.
    ///
    /// Add the new connection id to the deque, and retire the old cids before
    /// the retire_prior_to in the [`NewConnectionIdFrame`].
    /// Try to arrange the idle cids to the hungry cid applys if exist.
    ///
    /// Return the reset token of this [`NewConnectionIdFrame`] if it is valid.
    fn recv_new_cid_frame(
        &mut self,
        frame: &NewConnectionIdFrame,
    ) -> Result<Option<ResetToken>, Error> {
        let seq = frame.sequence();
        let retire_prior_to = frame.retire_prior_to();
        let active_len = seq.saturating_sub(retire_prior_to);
        if active_len > self.active_cid_limit {
            tracing::error!("   Cause by: received a new issued connection id frame from peer");
            return Err(Error::new(
                ErrorKind::ConnectionIdLimit,
                frame.frame_type(),
                format!(
                    "{active_len} exceed active_cid_limit {}",
                    self.active_cid_limit
                ),
            ));
        }

        // Discard the frame if the sequence number is less than the current offset.
        if seq < self.cid_deque.offset() {
            return Ok(None);
        }

        let id = *frame.connection_id();
        let token = *frame.reset_token();
        self.cid_deque.insert(seq, Some((seq, id, token))).unwrap();
        self.retire_prior_to(retire_prior_to);
        self.arrange_idle_cid();

        Ok(Some(token))
    }

    /// Arrange the idle cids to the front of the cid applys
    #[doc(hidden)]
    fn arrange_idle_cid(&mut self) {
        loop {
            let next_unalloced_cell = self.pending_cells.front();
            if next_unalloced_cell.is_none() {
                break;
            }

            let next_unalloced_cell = next_unalloced_cell.unwrap();
            let mut guard = next_unalloced_cell.0.lock().unwrap();
            if guard.is_retired {
                drop(guard);
                self.pending_cells.pop_front();
                continue;
            }

            let next_unused_cid = self.cid_deque.get(self.cursor);
            if let Some(Some((seq, cid, _))) = next_unused_cid {
                guard.assign(*seq, *cid);
                // Until an unused CID is allocated, the guard cannot be released early.
                drop(guard);

                let apply = self.pending_cells.pop_front().unwrap();
                self.ready_cells
                    .push_back(apply)
                    .expect("Sequence of new connection ID should never exceed the limit");
                self.cursor += 1;
            } else {
                break;
            }
        }
    }

    /// Eliminate the old cids and inform the peer with a
    /// [`RetireConnectionIdFrame`] for each retired connection ID.
    #[doc(hidden)]
    fn retire_prior_to(&mut self, tomb_seq: u64) {
        if tomb_seq <= self.ready_cells.offset() {
            return;
        }

        _ = self.cid_deque.drain_to(tomb_seq);
        // it is possible that the connection id that has not been used is directly retired,
        // and there is no chance to assign it, this phenomenon is called "jumping retire cid"
        self.cursor = self.cursor.max(tomb_seq);

        // reassign the cid that has been assigned to the Path but is facing retirement
        if self.ready_cells.is_empty() {
            // it is not necessary to resize the deque, because all elements will be drained
            // // self.cid_cells.resize(seq, ArcCidCell::default()).expect("");
            self.retired_cids
                .send_frame((self.ready_cells.offset()..tomb_seq).map(|seq| {
                    RetireConnectionIdFrame::new(
                        VarInt::from_u64(seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    )
                }));
            self.ready_cells.reset_offset(tomb_seq);
        } else {
            let actual_applied = self.ready_cells.largest();
            let need_reassigned = actual_applied.min(tomb_seq);
            // retire the cids before seq, including the applied and unapplied
            for _ in self.ready_cells.offset()..need_reassigned {
                let (_, cell) = self.ready_cells.pop_front().unwrap();
                if cell.is_retired() {
                    continue;
                }
                self.pending_cells.push_back(cell);
            }
            if actual_applied < tomb_seq {
                self.ready_cells.reset_offset(tomb_seq);
                // even the cid that has not been applied is retired right now
                self.retired_cids
                    .send_frame((actual_applied..tomb_seq).map(|seq| {
                        RetireConnectionIdFrame::new(
                            VarInt::from_u64(seq).expect(
                                "Sequence of connection id is very hard to exceed VARINT_MAX",
                            ),
                        )
                    }));
            }
        }
    }

    /// Apply for a new connection ID, and return an [`ArcCidCell`], which may be not ready state.
    fn apply_dcid(&mut self) -> ArcCidCell<RETIRED> {
        let cell = ArcCidCell::new(self.retired_cids.clone());
        self.pending_cells.push_back(cell.clone());
        self.arrange_idle_cid();
        cell
    }
}

/// Shared remote connection ID manager. Most of the time, you should use this struct.
///
/// These connection IDs will be assigned to the Path.
/// Every new path needs to apply for a new connection ID from the RemoteCids.
/// Each path may retire the old connection ID proactively, and apply for a new one.
///
/// `RETIRED` stores the [`RetireConnectionIdFrame`], which need to be sent to the peer.
/// It can be a deque, a channel, or any buffer,
/// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
#[derive(Debug, Clone)]
pub struct ArcRemoteCids<RETIRED>(Arc<Mutex<RemoteCids<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcRemoteCids<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a new RemoteCids with the initial dcid, the maximum number of active cids,
    /// and the retired cids.
    ///
    /// As mentioned above, the `retired_cids` can be a deque, a channel, or any buffer,
    /// as long as it can send those [`RetireConnectionIdFrame`] to the peer finally.
    pub fn new(initial_dcid: ConnectionId, active_cid_limit: u64, retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::new(
            initial_dcid,
            active_cid_limit,
            retired_cids,
        ))))
    }

    /// Revise the initial dcid, which is used if and only if the client
    /// received the response packet from the server, and the initial dcid
    /// should be updated based on the scid in the response packet.
    pub fn revise_initial_dcid(&self, initial_dcid: ConnectionId) {
        self.0.lock().unwrap().revise_initial_dcid(initial_dcid);
    }

    /// Apply for a new connection ID, which is used when the Path is created.
    ///
    /// Return an [`ArcCidCell`], which may be not ready state.
    pub fn apply_dcid(&self) -> ArcCidCell<RETIRED> {
        self.0.lock().unwrap().apply_dcid()
    }

    /// Return the latest connection ID issued by the peer.
    ///
    /// The cid is used to assemble the packet that contains a connection close frame. When the
    /// connection is closed, the connection close frame will be sent to the peer.
    pub fn latest_dcid(&self) -> Option<ConnectionId> {
        self.0
            .lock()
            .unwrap()
            .cid_deque
            .iter()
            .rev()
            .flatten()
            .next()
            .map(|(_, cid, _)| *cid)
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

#[derive(Debug)]
struct CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame>,
{
    retired_cids: RETIRED,
    allocated_cids: VecDeque<(u64, ConnectionId)>,
    waker: Option<ArcSendWaker>,
    is_retired: bool,
    is_using: bool,
}

impl<RETIRED> CidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn assign(&mut self, seq: u64, cid: ConnectionId) {
        assert!(!self.is_retired);
        self.allocated_cids.push_front((seq, cid));
        if !self.is_using {
            while self.allocated_cids.len() > 1 {
                let (seq, _) = self.allocated_cids.pop_back().unwrap();
                let sequence = VarInt::try_from(seq)
                    .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
                self.retired_cids
                    .send_frame([RetireConnectionIdFrame::new(sequence)]);
            }
        }

        if let Some(waker) = self.waker.take() {
            waker.wake_by(Signals::CONNECTION_ID);
        }
    }

    fn revise(&mut self, dcid: ConnectionId) {
        assert!(!self.is_retired);
        assert!(!self.allocated_cids.is_empty());
        self.allocated_cids[0].1 = dcid;
    }

    fn borrow_cid(&mut self, tx_waker: ArcSendWaker) -> Result<Option<ConnectionId>, Signals> {
        if self.is_retired {
            return Ok(None);
        }

        if self.allocated_cids.is_empty() {
            self.waker = Some(tx_waker);
            Err(Signals::CONNECTION_ID)
        } else {
            let cid = self.allocated_cids[0].1;
            self.is_using = true;
            Ok(Some(cid))
        }
    }

    fn renew(&mut self) {
        assert!(self.is_using);
        self.is_using = false;
        while self.allocated_cids.len() > 1 {
            let (seq, _) = self.allocated_cids.pop_back().unwrap();
            let sequence = VarInt::try_from(seq)
                .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
            self.retired_cids
                .send_frame([RetireConnectionIdFrame::new(sequence)]);
        }
    }

    fn retire(&mut self) {
        if !self.is_retired {
            self.is_retired = true;

            while let Some((seq, _)) = self.allocated_cids.pop_front() {
                let sequence = VarInt::try_from(seq)
                    .expect("Sequence of connection id is very hard to exceed VARINT_MAX");
                self.retired_cids
                    .send_frame([RetireConnectionIdFrame::new(sequence)]);
            }

            if let Some(waker) = self.waker.take() {
                waker.wake_by(Signals::CONNECTION_ID);
            }
        }
    }
}

/// Shared connection ID cell. Most of the time, you should use this struct.
#[derive(Debug, Clone)]
pub struct ArcCidCell<RETIRED>(Arc<Mutex<CidCell<RETIRED>>>)
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone;

impl<RETIRED> ArcCidCell<RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    /// Create a new CidCell with the retired cids, the sequence number of the connection ID,
    /// and the state of the connection ID.
    ///
    /// It can be created only by the [`ArcRemoteCids::apply_dcid`] method.
    #[doc(hidden)]
    fn new(retired_cids: RETIRED) -> Self {
        Self(Arc::new(Mutex::new(CidCell {
            retired_cids,
            allocated_cids: VecDeque::with_capacity(2),
            waker: None,
            is_retired: false,
            is_using: false,
        })))
    }

    fn is_retired(&self) -> bool {
        self.0.lock().unwrap().is_retired
    }

    fn revise(&self, dcid: ConnectionId) {
        self.0.lock().unwrap().revise(dcid);
    }

    /// Asynchronously get the connection ID, if it is not ready, return Pending.
    ///
    /// If the corresponding path which applied this cid is inactive,
    /// then this cid apply is retired.
    /// In this case, None will be returned.
    pub fn borrow_cid(
        &self,
        tx_waker: ArcSendWaker,
    ) -> Result<Option<BorrowedCid<RETIRED>>, Signals> {
        self.0.lock().unwrap().borrow_cid(tx_waker).map(|cid| {
            cid.map(|cid| BorrowedCid {
                cid_cell: &self.0,
                cid,
            })
        })
    }

    /// When the Path is invalid, the connection id needs to be retired, and this Cell
    /// is marked as no longer in use, with a [`RetireConnectionIdFrame`] being sent to peer.
    pub fn retire(&self) {
        self.0.lock().unwrap().retire();
    }
}

/// A borrowed connection ID, which will be returned back when it is dropped.
///
/// While the connection ID is borrowed, the retired cids will not be truly retired. The retire will be delayed until
/// the [`BorrowedCid`] is dropped, a [`RetireConnectionIdFrame`] will be sent to the peer.
pub struct BorrowedCid<'a, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    cid: ConnectionId,
    cid_cell: &'a Mutex<CidCell<RETIRED>>,
}

impl<RETIRED> Deref for BorrowedCid<'_, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    type Target = ConnectionId;

    fn deref(&self) -> &Self::Target {
        &self.cid
    }
}

impl<RETIRED> Drop for BorrowedCid<'_, RETIRED>
where
    RETIRED: SendFrame<RetireConnectionIdFrame> + Clone,
{
    fn drop(&mut self) {
        self.cid_cell.lock().unwrap().renew();
    }
}

#[cfg(test)]
mod tests {
    use derive_more::Deref;

    use super::*;

    #[derive(Debug, Clone, Default, Deref)]
    struct RetiredCids(Arc<Mutex<Vec<RetireConnectionIdFrame>>>);

    impl SendFrame<RetireConnectionIdFrame> for RetiredCids {
        fn send_frame<I: IntoIterator<Item = RetireConnectionIdFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    #[test]
    fn test_remote_cids() {
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = RetiredCids::default();
        let mut remote_cids = RemoteCids::new(initial_dcid, 8, retired_cids);

        let cid_apply0 = remote_cids.apply_dcid();
        let waker = ArcSendWaker::new();
        assert!(matches!(
         cid_apply0.borrow_cid(waker.clone()),
           Ok(Some(cid)) if *cid == initial_dcid
        ));

        // Will return Pending, because the peer hasn't issue any connection id
        let cid_apply1 = remote_cids.apply_dcid();
        assert!(cid_apply1.borrow_cid(waker.clone()).is_err());

        let cid = ConnectionId::random_gen(8);
        let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(1), VarInt::from_u32(0));
        assert!(remote_cids.recv_new_cid_frame(&frame).is_ok());
        assert_eq!(remote_cids.cid_deque.len(), 2);

        assert!(matches!(
            cid_apply0.borrow_cid(waker.clone()),
            Ok(Some(cid)) if *cid == initial_dcid
        ));

        // Additionally, a new request will be made because if the peer-issued CID is
        // insufficient, it will still return Pending.
        let cid_apply2 = remote_cids.apply_dcid();
        assert!(cid_apply2.borrow_cid(waker.clone()).is_err());
    }

    #[test]
    fn test_retire_in_remote_cids() {
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = RetiredCids::default();
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
            _ = guard.recv_new_cid_frame(&frame);
        }

        let cid_apply1 = guard.apply_dcid();
        let cid_apply2 = guard.apply_dcid();

        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 0);
        assert_eq!(cid_apply2.0.lock().unwrap().allocated_cids[0].0, 1);
        let waker = ArcSendWaker::new();
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Ok(Some(cid)) if *cid == cids[0]
        ));
        assert!(matches!(
            cid_apply2.borrow_cid(waker.clone()),
            Ok(Some(cid)) if *cid == cids[1]
        ));

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.ready_cells.offset(), 4);
        // delay retire cid
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 2);

        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 0);
        assert_eq!(cid_apply2.0.lock().unwrap().allocated_cids[0].0, 1);

        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Ok(Some(cid)) if *cid == cids[0]
        ));
        assert!(matches!(
            cid_apply2.borrow_cid(waker.clone()),
            Ok(Some(cid)) if *cid == cids[1]
        ));

        guard.arrange_idle_cid();
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 4);

        let retired_cids = [1, 0, 3, 2];
        for seq in retired_cids {
            assert_eq!(
                // like a stack, the last in the first out
                guard.retired_cids.0.lock().unwrap().pop(),
                Some(RetireConnectionIdFrame::new(VarInt::from_u32(seq)))
            );
        }

        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
            Ok(Some(r#ref)) if *r#ref == cids[4]
        ));
        assert!(matches!(
            cid_apply2.borrow_cid(waker.clone()),
           Ok(Some(r#ref)) if *r#ref == cids[5]
        ));

        cid_apply2.retire();
        assert_eq!(guard.retired_cids.lock().unwrap().len(), 1);
        assert_eq!(
            guard.retired_cids.0.lock().unwrap().pop(),
            Some(RetireConnectionIdFrame::new(VarInt::from_u32(5)))
        );
    }

    #[test]
    fn test_retire_without_apply() {
        let initial_dcid = ConnectionId::random_gen(8);
        let retired_cids = RetiredCids::default();
        let remote_cids = ArcRemoteCids::new(initial_dcid, 8, retired_cids);
        let mut guard = remote_cids.0.lock().unwrap();

        let mut cids = vec![initial_dcid];
        for seq in 1..8 {
            let cid = ConnectionId::random_gen(8);
            cids.push(cid);
            let frame = NewConnectionIdFrame::new(cid, VarInt::from_u32(seq), VarInt::from_u32(0));
            _ = guard.recv_new_cid_frame(&frame);
        }

        guard.retire_prior_to(4);
        assert_eq!(guard.cid_deque.offset(), 4);
        assert_eq!(guard.ready_cells.offset(), 4);
        assert_eq!(guard.retired_cids.0.lock().unwrap().len(), 4);

        let cid_apply1 = guard.apply_dcid();
        let cid_apply2 = guard.apply_dcid();
        assert_eq!(cid_apply1.0.lock().unwrap().allocated_cids[0].0, 4);
        assert_eq!(cid_apply2.0.lock().unwrap().allocated_cids[0].0, 5);
        let waker = ArcSendWaker::new();
        assert!(matches!(
            cid_apply1.borrow_cid(waker.clone()),
           Ok(Some(r#ref)) if *r#ref == cids[4]
        ));
        assert!(matches!(
            cid_apply2.borrow_cid(waker.clone()),
            Ok(Some(r#ref)) if *r#ref == cids[5]
        ));
    }
}
