use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
};

use derive_more::{Deref, DerefMut};
use qbase::{
    error::Error as QuicError,
    sid::{Dir, StreamId},
};

use crate::{recv::Incoming, send::Outgoing};

#[derive(Debug, Clone)]
pub(super) struct IOState(Arc<AtomicU8>);

impl IOState {
    const SENDING: u8 = 0x1;
    const RECEIVING: u8 = 0x2;

    pub fn send_only() -> Self {
        Self(Arc::new(AtomicU8::new(Self::SENDING)))
    }

    pub fn receive_only() -> Self {
        Self(Arc::new(AtomicU8::new(Self::RECEIVING)))
    }

    pub fn bidirection() -> Self {
        Self(Arc::new(AtomicU8::new(Self::SENDING | Self::RECEIVING)))
    }

    pub fn is_terminated(&self) -> bool {
        self.0.load(Ordering::Acquire) == 0
    }

    pub fn shutdown_send(&self) {
        self.0.fetch_and(!Self::SENDING, Ordering::Release);
    }

    pub fn shutdown_receive(&self) {
        self.0.fetch_and(!Self::RECEIVING, Ordering::Release);
    }
}

#[derive(Debug, Clone, Deref, DerefMut)]
pub(super) struct Output<TX> {
    #[deref]
    #[deref_mut]
    pub(super) outgoings: BTreeMap<StreamId, (Outgoing<TX>, IOState)>,
    pub(super) cursor: Option<(StreamId, usize)>,
}

impl<TX> Output<TX> {
    fn new() -> Self {
        Self {
            outgoings: BTreeMap::default(),
            cursor: None,
        }
    }
}

/// ArcOutput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[derive(Debug, Clone)]
pub(super) struct ArcOutput<TX>(Arc<Mutex<Result<Output<TX>, QuicError>>>);

impl<TX> ArcOutput<TX> {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Ok(Output::new()))))
    }

    pub(super) fn streams(&self) -> MutexGuard<'_, Result<Output<TX>, QuicError>> {
        self.0.lock().unwrap()
    }

    pub(super) fn guard(&'_ self) -> Result<ArcOutputGuard<'_, TX>, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ArcOutputGuard(guard)),
            Err(e) => Err(e.clone()),
        }
    }
}

#[derive(Deref, DerefMut)]
pub(super) struct ArcOutputGuard<'a, TX>(MutexGuard<'a, Result<Output<TX>, QuicError>>);

impl<TX> ArcOutputGuard<'_, TX> {
    pub(super) fn insert(&mut self, sid: StreamId, outgoing: Outgoing<TX>, io_state: IOState) {
        match self.0.as_mut() {
            Ok(set) => set.insert(sid, (outgoing, io_state)),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
    }

    pub(super) fn on_0rtt_rejected(
        &mut self,
        init_max_streams_bidi: u64,
        init_max_streams_uni: u64,
    ) {
        match self.0.as_ref() {
            Ok(set) => set
                .iter()
                .filter(|(sid, _)| {
                    (sid.dir() == Dir::Bi && sid.id() < init_max_streams_bidi)
                        || (sid.dir() == Dir::Uni && sid.id() < init_max_streams_uni)
                })
                .for_each(|(_, (o, _))| o.on_0rtt_rejected()),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
    }

    pub(super) fn on_conn_error(&mut self, error: &QuicError) {
        match self.0.as_ref() {
            Ok(set) => set.values().for_each(|(o, _)| o.on_conn_error(error)),
            // 已经遇到过conn error了，不需要再次处理。然而guard()时就已经返回了Err，不会再走到这里来
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.0 = Err(error.clone());
    }
}

/// ArcInput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone)]
pub(super) struct ArcInput<TX>(
    Arc<Mutex<Result<HashMap<StreamId, (Incoming<TX>, IOState)>, QuicError>>>,
);

impl<TX> Default for ArcInput<TX> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Ok(HashMap::new()))))
    }
}

impl<TX> ArcInput<TX> {
    #[allow(clippy::type_complexity)]
    pub(super) fn streams(
        &self,
    ) -> MutexGuard<'_, Result<HashMap<StreamId, (Incoming<TX>, IOState)>, QuicError>> {
        self.0.lock().unwrap()
    }

    pub(super) fn guard(&self) -> Result<ArcInputGuard<'_, TX>, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ArcInputGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }
}

#[allow(clippy::type_complexity)]
pub(super) struct ArcInputGuard<'a, TX> {
    inner: MutexGuard<'a, Result<HashMap<StreamId, (Incoming<TX>, IOState)>, QuicError>>,
}

impl<TX> ArcInputGuard<'_, TX> {
    pub(super) fn insert(&mut self, sid: StreamId, incoming: Incoming<TX>, io_state: IOState) {
        match self.inner.as_mut() {
            Ok(set) => set.insert(sid, (incoming, io_state)),
            Err(e) => unreachable!("input is invalid: {e}"),
        };
    }

    pub(super) fn on_conn_error(&mut self, error: &QuicError) {
        match self.inner.as_ref() {
            Ok(set) => set.values().for_each(|(o, _)| o.on_conn_error(error)),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.inner = Err(error.clone());
    }
}
