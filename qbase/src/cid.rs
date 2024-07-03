use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use deref_derive::{Deref, DerefMut};
use nom::{bytes::streaming::take, number::streaming::be_u8, IResult};
use rand::Rng;

use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, FrameType, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
    util::{ArcAsyncDeque, IndexDeque, IndexError},
    varint::{VarInt, VARINT_MAX},
};

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
            input,
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

/// 我方负责发放足够的cid，poll_issue_cid，将当前有效的cid注册到连接id路由。
/// 当cid不足时，就发放新的连接id，包括增大active_cid_limit，以及对方淘汰旧的cid。
#[derive(Default, Debug)]
pub struct RawLocalCids {
    // If the item in cid_deque is None, it means the connection ID has been retired.
    cid_deque: IndexDeque<Option<(ConnectionId, ResetToken)>, VARINT_MAX>,
    // This is an integer value specifying the maximum number of connection
    // IDs from the peer that an endpoint is willing to store.
    // While the client does not know the server's parameters, it can be set to None.
    // If this transport parameter is absent, a default of 2 is assumed.
    active_cid_limit: Option<u64>,
    // awake the task to issue new cid
    issue_waker: Option<Waker>,
}

impl RawLocalCids {
    // The value of the active_connection_id_limit parameter MUST be at least 2.
    // An endpoint that receives a value less than 2 MUST close the connection
    // with an error of type TRANSPORT_PARAMETER_ERROR.
    pub fn set_limit(&mut self, active_cid_limit: u64) -> Result<(), Error> {
        debug_assert!(self.active_cid_limit.is_none());
        if active_cid_limit < 2 {
            return Err(Error::new(
                ErrorKind::TransportParameter,
                FrameType::Crypto,
                format!("{} < 2", active_cid_limit),
            ));
        }
        self.active_cid_limit = Some(active_cid_limit);
        if let Some(waker) = self.issue_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// Issue a new unique connection ID with the given length.
    /// Returns a new connection ID frame, which must be sent to the peer.
    pub fn poll_issue_cid<P>(
        &mut self,
        cx: &mut Context<'_>,
        len: usize,
        predicate: P,
    ) -> Poll<Result<NewConnectionIdFrame, IndexError>>
    where
        P: Fn(&ConnectionId) -> bool,
    {
        // If this transport parameter is absent, a default of 2 is assumed.
        let limit = self.active_cid_limit.unwrap_or(2);
        let active_len = self.cid_deque.iter().filter(|v| v.is_some()).count();
        if active_len >= limit as usize {
            self.issue_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let id = std::iter::from_fn(|| Some(ConnectionId::random_gen(len)))
            .find(predicate)
            .unwrap();
        let reset_token = ResetToken::random_gen();
        let sequence = match self.cid_deque.push_back(Some((id, reset_token))) {
            Ok(seq) => seq,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let retire_prior_to: u64 = sequence.saturating_sub(limit);
        Poll::Ready(Ok(NewConnectionIdFrame {
            sequence: VarInt::from_u64(sequence).unwrap(),
            retire_prior_to: VarInt::from_u64(retire_prior_to).unwrap(),
            id,
            reset_token,
        }))
    }

    /// When a RetireConnectionIdFrame is acknowledged by the peer, call this method to
    /// retire the connection IDs of the sequence in RetireConnectionIdFrame.
    pub fn recv_retire_cid_frame(
        &mut self,
        frame: &RetireConnectionIdFrame,
    ) -> Option<ConnectionId> {
        let seq = frame.sequence.into_inner();
        if let Some(value) = self.cid_deque.get_mut(seq) {
            if let Some((cid, _)) = value.take() {
                let active_len = self.cid_deque.iter().filter(|v| v.is_some()).count();
                if (active_len as u64) < self.active_cid_limit.unwrap_or(2) {
                    if let Some(waker) = self.issue_waker.take() {
                        waker.wake();
                    }
                }
                Some(cid)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ArcLocalCids(Arc<Mutex<RawLocalCids>>);

impl ArcLocalCids {
    pub fn lock_guard(&self) -> MutexGuard<'_, RawLocalCids> {
        self.0.lock().unwrap()
    }

    pub async fn issue_cid(
        &self,
        len: usize,
        predicate: impl Fn(&ConnectionId) -> bool,
    ) -> Result<NewConnectionIdFrame, IndexError> {
        IssueCid {
            local_cids: self.clone(),
            len,
            predicate,
        }
        .await
    }
}

struct IssueCid<P> {
    local_cids: ArcLocalCids,
    len: usize,
    predicate: P,
}

impl<P> Future for IssueCid<P>
where
    P: Fn(&ConnectionId) -> bool,
{
    type Output = Result<NewConnectionIdFrame, IndexError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.local_cids.lock_guard();
        guard.poll_issue_cid(cx, self.len, &self.predicate)
    }
}

#[derive(Debug)]
pub struct RawRemoteCids {
    // 可能收到的NewConnectionIdFrame，其sequence并不连续
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // 当前有效路径正在使用的cid，伴随cid的退休而重新分配
    cid_cells: IndexDeque<ArcCidCell, VARINT_MAX>,
    // 我方允许对方拥有的活跃cid数量
    active_cid_limit: u64,
    // 待使用的cid的位置，以及待分配的cell的位置，它们共享同一个位置
    cursor: u64,
    // 淘汰的cid，需要将RetireConnectionIdFrame发送给对方
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

    pub fn recv_new_cid_frame(&mut self, frame: &NewConnectionIdFrame) -> Result<(), Error> {
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
            return Ok(());
        }

        let id = frame.id;
        let token = frame.reset_token;
        self.cid_deque
            .insert(seq, Some((seq, id, token)))
            .expect("Sequence of new connection ID should never exceed the limit");
        self.retire_prior_to(retire_prior_to);
        self.arrange_idle_cid();

        Ok(())
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
        // 有可能还没被使用的连接id，被直接淘汰，来不及再分配，此现象称“跳跃式退休cid”
        self.cursor = self.cursor.max(seq);

        if seq <= self.cid_cells.offset() {
            return;
        }

        // 将曾经分配给Path的，但面临淘汰的cid，重新分配（但会延后于新Path的申请）
        if self.cid_cells.is_empty() {
            // 用resize浪费了，因为最终都会drain_to清空所有的元素，所以直接用reset_offset值最佳
            // self.cid_cells.resize(seq, ArcCidCell::default()).expect("");
            self.cid_cells.reset_offset(seq);
        } else {
            let mut next_apply = self.cid_cells.largest().max(seq);
            let end = self.cid_cells.largest().min(seq);
            for _ in self.cid_cells.offset()..end {
                let (_, cell) = self.cid_cells.pop_front().unwrap();
                let mut guard = cell.lock_guard();
                if guard.is_retired() {
                    continue;
                } else {
                    // 内部重新分配新的cid
                    let origin_seq = guard.seq;
                    guard.seq = self.cid_cells.largest();
                    guard.clear();
                    drop(guard);

                    // 将老的cid退休，并准备通知对方
                    self.retired_cids.push(RetireConnectionIdFrame {
                        sequence: VarInt::from_u64(origin_seq)
                            .expect("Sequence of connection id is very hard to exceed VARINT_MAX"),
                    });
                    // 之所以不用push_back而用insert，是为了让待分配的cid和cell保持一致，
                    // "跳跃式退休cid"将导致“跳跃式分配”，虽然大概率不会发生。
                    self.cid_cells
                        .insert(next_apply, cell)
                        .expect("Sequence of new connection ID should never exceed the limit");
                    next_apply += 1;
                }
            }
            _ = self.cid_cells.drain_to(seq);
        }
    }

    /// Return a ArcCidCell, which holds the state of the connection ID, included:
    /// - not be allocated yet
    /// - have been allocated
    /// - have been allocated again after retirement of last cid
    /// - have been closed
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
    pub async fn get_cid(&self) -> ConnectionId {
        self.clone().await
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

#[derive(Debug, Clone)]
pub struct Registry {
    pub local: ArcLocalCids,
    pub remote: ArcRemoteCids,
}

impl Registry {
    #[inline]
    pub fn new(remote_active_cid_limit: u64) -> Self {
        Self {
            local: ArcLocalCids::default(),
            remote: ArcRemoteCids::with_limit(remote_active_cid_limit),
        }
    }
}
