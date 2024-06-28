use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use nom::{bytes::streaming::take, number::streaming::be_u8, IResult};
use rand::Rng;

use crate::{
    error::Error,
    frame::{BeFrame, NewConnectionIdFrame, RetireConnectionIdFrame},
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

/// 我方负责发放cid，poll_issue_cid，将当前有效的cid注册到连接id路由
/// 何时颁发新的连接id呢，应该是每经过一段时间，或者距离上次淘汰，累计收到一定数量的数据后，
/// 我方负责淘汰过期的cid，淘汰的序号等对方确认后，将该序号之前的cid从cid路由表删除
/// poll_retire_cid -> seq
/// on_retire_acked(RetireConnectionIdFrame) -> seq
/// index_deque.drain_to(seq) -> Iter
#[derive(Debug)]
pub struct RawLocalCids {
    cid_deque: IndexDeque<(ConnectionId, ResetToken), VARINT_MAX>,
    active_cid_limit: u64,
}

impl RawLocalCids {
    pub fn with_limit(active_cid_limit: u64) -> Self {
        Self {
            // Maybe we need keep the old CIDs for a while after issuing new CIDs
            cid_deque: IndexDeque::with_capacity(active_cid_limit as usize + 2),
            active_cid_limit,
        }
    }

    /// Issue a new unique connection ID with the given length.
    /// Returns a new connection ID frame, which must be sent to the peer.
    pub fn issue<P>(
        &mut self,
        len: usize,
        predicate: P,
    ) -> Result<NewConnectionIdFrame, ExceedLimit>
    where
        P: Fn(&ConnectionId) -> bool,
    {
        let id = std::iter::from_fn(|| Some(ConnectionId::random_gen(len)))
            .find(predicate)
            .unwrap();
        let reset_token = ResetToken::random_gen();
        let sequence = self.cid_deque.push_back((id, reset_token))?;
        let retire_prior_to = sequence.saturating_sub(self.active_cid_limit);
        Ok(NewConnectionIdFrame {
            sequence: VarInt::from_u64(sequence).unwrap(),
            retire_prior_to: VarInt::from_u64(retire_prior_to).unwrap(),
            id,
            reset_token,
        })
    }

    pub fn on_recv_retire_cid(&mut self, retire_cid_frame: &RetireConnectionIdFrame) {
        let seq = retire_cid_frame.sequence.into_inner();
        let _ = self.cid_deque.drain_to(seq);
    }

    /// When a NewConnectionIdFrame or RetireConnectionIdFrame is acknowledged by the peer,
    /// call this method to retire the connection IDs prior to retire_prior_to.
    pub fn retire_prior_to(
        &mut self,
        end: u64,
    ) -> impl DoubleEndedIterator<Item = (ConnectionId, ResetToken)> + '_ {
        self.cid_deque.drain_to(end)
    }
}

#[derive(Debug, Clone)]
pub struct ArcLocalCids(Arc<Mutex<RawLocalCids>>);

impl ArcLocalCids {
    pub fn new(active_cid_limit: u64) -> Self {
        Self(Arc::new(Mutex::new(RawLocalCids::with_limit(
            active_cid_limit,
        ))))
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RawLocalCids> {
        self.0.lock().unwrap()
    }
}

#[derive(Default, Debug)]
struct CidGetters {
    needed: VecDeque<u64>,
    avaliable: BTreeMap<u64, ArcCidGetter>,
}

impl CidGetters {
    fn new_getter(&mut self, cid: ConnectionId, seq: u64) -> ArcCidGetter {
        let getter = ArcCidGetter::new(CidGetter::Ready(cid));
        self.avaliable.insert(seq, getter.clone());
        getter
    }

    fn retire_prior_to(&mut self, end: u64) {
        let remain_avaliable = self.avaliable.split_off(&end);
        for (idx, getter) in std::mem::replace(&mut self.avaliable, remain_avaliable) {
            let mut cid_getter = getter.0.lock().unwrap();
            match &*cid_getter {
                CidGetter::Pending(_) | CidGetter::Ready(_) => {
                    *cid_getter = CidGetter::Pending(None);
                    self.needed.push_back(idx);
                }
                CidGetter::Closed => unreachable!("CidGetter is closed"),
            }
        }
    }

    fn avaliable_new(&mut self, cid: ConnectionId) -> Result<(), ConnectionId> {
        while let Some(front) = self.needed.front() {
            if let Some(getter) = self.avaliable.get(front) {
                match &mut *getter.0.lock().unwrap() {
                    CidGetter::Pending(_) => {
                        *getter.0.lock().unwrap() = CidGetter::Ready(cid);
                        return Ok(());
                    }
                    CidGetter::Ready(_) => unreachable!("CidGetter is closed"),
                    CidGetter::Closed => {}
                }
            }
        }
        Err(cid)
    }
}

#[derive(Debug)]
pub struct RemoteCids {
    // 可能收到的NewConnectionIdFrame，其sequence并不连续
    cid_deque: IndexDeque<Option<(u64, ConnectionId, ResetToken)>, VARINT_MAX>,
    used: u64,
    // 一开始可能为None，意味着并不知道对方的active_cid_limit；后续可以补设置
    active_cid_limit: Option<u64>,
    path_ids: CidGetters,
}

impl Default for RemoteCids {
    fn default() -> Self {
        RemoteCids {
            cid_deque: IndexDeque::with_capacity(8),
            path_ids: CidGetters::default(),
            active_cid_limit: None,
            used: 0,
        }
    }
}

impl RemoteCids {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(limit: usize) -> Self {
        Self {
            cid_deque: IndexDeque::with_capacity(limit),
            path_ids: CidGetters::default(),
            active_cid_limit: Some(limit as u64),
            used: 0,
        }
    }

    pub fn set_limit(&mut self, limit: u64) {
        self.active_cid_limit = Some(limit);
        // TODO: 最好，让cid_queue也能扩容到limit大小，省的多余的扩容
    }

    pub fn on_recv_new_cid(&mut self, new_cid_frame: &NewConnectionIdFrame) -> Result<(), Error> {
        let seq = new_cid_frame.sequence.into_inner();
        let retire_prior_to = new_cid_frame.retire_prior_to.into_inner();
        let active_len = seq.saturating_sub(retire_prior_to);
        let active_cid_limit = self.active_cid_limit.unwrap_or(1);
        if active_len <= active_cid_limit {
            return Err(Error::new(
                crate::error::ErrorKind::ConnectionIdLimit,
                new_cid_frame.frame_type(),
                format!("{active_len} exceed active_cid_limit {active_cid_limit}"),
            ));
        }

        let id = new_cid_frame.id;
        let token = new_cid_frame.reset_token;

        _ = self.cid_deque.drain_to(retire_prior_to);
        self.path_ids.retire_prior_to(retire_prior_to);
        self.used = self.used.max(retire_prior_to.saturating_sub(1));

        match self.path_ids.avaliable_new(id) {
            Ok(()) => {}
            Err(id) => {
                self.cid_deque
                    .insert(seq, Some((seq, id, token)))
                    .expect("Sequence of new connection ID should never exceed the limit");
            }
        }

        Ok(())
    }

    /// return [`None`] when the connection ID is not enough
    pub fn new_path(&mut self) -> Option<ArcCidGetter> {
        if self.used >= self.cid_deque.largest() {
            return None;
        }

        let (seq, cid, _) = self.cid_deque.get(self.used).unwrap().unwrap();
        self.used += 1;

        Some(self.path_ids.new_getter(cid, seq))
    }
}

/// 路径关闭时，将其对应的cid_getter关闭
#[derive(Debug, Clone)]
enum CidGetter {
    Pending(Option<Waker>),
    Ready(ConnectionId),
    Closed,
}

impl CidGetter {
    pub fn poll_get_conn_id(&mut self, ctx: &mut Context) -> Poll<ConnectionId> {
        match self {
            CidGetter::Pending(waker) => {
                waker.replace(ctx.waker().clone());
                Poll::Pending
            }
            CidGetter::Ready(cid) => Poll::Ready(*cid),
            CidGetter::Closed => unreachable!("CidGetter is closed"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArcCidGetter(Arc<Mutex<CidGetter>>);

impl ArcCidGetter {
    fn new(getter: CidGetter) -> Self {
        Self(Arc::new(Mutex::new(getter)))
    }

    #[inline]
    pub fn poll_get_conn_id(&self, ctx: &mut Context) -> Poll<ConnectionId> {
        self.0.lock().unwrap().poll_get_conn_id(ctx)
    }

    #[inline]
    pub fn close(&self) {
        *self.0.lock().unwrap() = CidGetter::Closed;
    }
}
