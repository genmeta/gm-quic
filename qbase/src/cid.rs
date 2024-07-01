use std::{
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::Future;
use nom::{bytes::streaming::take, number::streaming::be_u8, IResult};
use rand::Rng;

use crate::{
    error::{Error, ErrorKind},
    frame::{BeFrame, FrameType, NewConnectionIdFrame, RetireConnectionIdFrame},
    token::ResetToken,
    util::{ExceedLimit, IndexDeque},
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
    cid_deque: IndexDeque<(ConnectionId, ResetToken), VARINT_MAX>,
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
    ) -> Poll<Result<NewConnectionIdFrame, ExceedLimit>>
    where
        P: Fn(&ConnectionId) -> bool,
    {
        // If this transport parameter is absent, a default of 2 is assumed.
        let limit = self.active_cid_limit.unwrap_or(2);
        if self.cid_deque.len() >= limit as usize {
            self.issue_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let id = std::iter::from_fn(|| Some(ConnectionId::random_gen(len)))
            .find(predicate)
            .unwrap();
        let reset_token = ResetToken::random_gen();
        let sequence = match self.cid_deque.push_back((id, reset_token)) {
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

    /// When a RetireConnectionIdFrame is acknowledged by the peer,
    /// call this method to retire the connection IDs prior to retire_prior_to.
    pub fn on_cid_retired(
        &mut self,
        frame: &RetireConnectionIdFrame,
    ) -> impl DoubleEndedIterator<Item = (ConnectionId, ResetToken)> + '_ {
        let end = frame.sequence.into_inner();
        if self.cid_deque.largest() < end + self.active_cid_limit.unwrap_or(2) {
            if let Some(waker) = self.issue_waker.take() {
                waker.wake();
            }
        }
        self.cid_deque.drain_to(end)
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
    ) -> Result<NewConnectionIdFrame, ExceedLimit> {
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
    type Output = Result<NewConnectionIdFrame, ExceedLimit>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self.local_cids.lock_guard();
        guard.poll_issue_cid(cx, self.len, &self.predicate)
    }
}

#[derive(Debug)]
pub struct RemoteCids {
    // 可能收到的NewConnectionIdFrame，其sequence并不连续
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    // 当前有效路径正在使用的cid，伴随cid deque的过期而重新分配
    cid_cells: IndexDeque<ArcCidCell, VARINT_MAX>,
    // 我方允许对方拥有的活跃cid数量
    active_cid_limit: u64,
    // 待使用的cid的位置，以及待分配的cell的位置，它们共享同一个位置
    cursor: u64,
}

impl RemoteCids {
    pub fn with_limit(active_cid_limit: u64) -> Self {
        Self {
            active_cid_limit,
            cid_deque: Default::default(),
            cid_cells: Default::default(),
            cursor: Default::default(),
        }
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

        // 开始分配未分配的连接id，给需要分配的cid cell
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

        Ok(())
    }

    /// Actively decide to eliminate the old cid and inform the other party that
    /// a RetireConnectionIdFrame needs to be generated to inform the other party
    pub fn retire_prior_to(&mut self, pos: u64) {
        _ = self.cid_deque.drain_to(pos);
        // 有可能还没被使用的连接id，被直接淘汰，来不及再分配，此现象称“跳跃式过期cid”
        self.cursor = self.cursor.max(pos);

        // 将曾经分配给Path的，但面临淘汰的cid，重新分配（但会延后于新Path的申请）
        let mut idx = self.cid_cells.largest().max(pos + 1);
        for _ in self.cid_cells.offset()..pos {
            let (_, cell) = self.cid_cells.pop_front().unwrap();
            if cell.is_closed() {
                continue;
            } else {
                cell.clear();
                // 之所以不用push_back而用insert，是为了让待分配的cid和cell保持一致，
                // "跳跃式过期cid"将导致“跳跃式分配”，虽然大概率不会发生。
                self.cid_cells
                    .insert(idx, cell)
                    .expect("Sequence of new connection ID should never exceed the limit");
                idx += 1;
            }
        }
    }

    /// Return a ArcCidCell, which holds the state of the connection ID, included:
    /// - not be allocated yet
    /// - have been allocated
    /// - have been allocated again after retirement of last cid
    /// - have been closed
    pub fn alloc_cid_cell(&mut self) -> ArcCidCell {
        let cell = if let Some(Some((_, cid, _))) = self.cid_deque.get(self.cursor) {
            self.cursor += 1;
            ArcCidCell::new(CidCell::Ready(*cid))
        } else {
            ArcCidCell::new(CidCell::None)
        };

        self.cid_cells
            .push_back(cell.clone())
            .expect("Sequence of new connection ID should never exceed the limit");
        cell
    }
}

#[derive(Debug, Clone)]
pub struct ArcRemoteCids(Arc<Mutex<RemoteCids>>);

impl ArcRemoteCids {
    pub fn with_limit(active_cid_limit: u64) -> Self {
        Self(Arc::new(Mutex::new(RemoteCids::with_limit(
            active_cid_limit,
        ))))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RemoteCids> {
        self.0.lock().unwrap()
    }
}

#[derive(Default, Debug, Clone)]
enum CidCell {
    None,
    Demand(Waker),
    Ready(ConnectionId),
    #[default]
    Closed,
}

impl CidCell {
    fn poll_get_cid(&mut self, cx: &mut Context) -> Poll<ConnectionId> {
        match self {
            CidCell::None => {
                *self = CidCell::Demand(cx.waker().clone());
                Poll::Pending
            }
            CidCell::Demand(waker) => {
                waker.clone_from(cx.waker());
                Poll::Pending
            }
            CidCell::Ready(cid) => Poll::Ready(*cid),
            CidCell::Closed => unreachable!("CidCell is closed"),
        }
    }

    fn assign(&mut self, cid: ConnectionId) {
        // Only allow transition from None or Demand state to Ready state
        debug_assert!(matches!(self, Self::None | Self::Demand(_)));
        if let CidCell::Demand(waker) = std::mem::take(self) {
            waker.wake();
        }
        *self = CidCell::Ready(cid);
    }

    fn clear(&mut self) {
        // Allow transition from Ready state to None state, but not from Closed state
        // While meeting Demand state, it will not change && not wake the waker
        match self {
            CidCell::Ready(_) => *self = CidCell::None,
            CidCell::Closed => unreachable!("CidCell is closed"),
            _ => {}
        }
    }

    fn close(&mut self) {
        *self = CidCell::Closed;
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

#[derive(Default, Debug, Clone)]
pub struct ArcCidCell(Arc<Mutex<CidCell>>);

impl ArcCidCell {
    fn new(getter: CidCell) -> Self {
        Self(Arc::new(Mutex::new(getter)))
    }

    fn assign(&self, cid: ConnectionId) {
        self.0.lock().unwrap().assign(cid);
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    pub async fn get_cid(&self) -> ConnectionId {
        self.clone().await
    }

    #[inline]
    pub fn close(&self) {
        self.0.lock().unwrap().close();
    }

    fn is_closed(&self) -> bool {
        self.0.lock().unwrap().is_closed()
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
    pub fn new(remote_active_cid_limit: u64) -> Self {
        Self {
            local: ArcLocalCids::default(),
            remote: ArcRemoteCids::with_limit(remote_active_cid_limit),
        }
    }
}
