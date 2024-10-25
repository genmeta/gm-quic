use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    error::Error as QuicError,
    frame::{ResetStreamFrame, SendFrame},
    sid::StreamId,
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
    pub(super) outgoings: BTreeMap<StreamId, (Outgoing<TX>, IOState)>,
    pub(super) last_sent_stream: Option<(StreamId, usize)>,
}

impl<TX> Output<TX> {
    fn new() -> Self {
        Self {
            outgoings: BTreeMap::default(),
            last_sent_stream: None,
        }
    }
}

/// ArcOutput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[derive(Debug, Clone)]
pub(super) struct ArcOutput<TX>(pub(super) Arc<Mutex<Result<Output<TX>, QuicError>>>);

impl<TX> ArcOutput<TX> {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Ok(Output::new()))))
    }

    pub(super) fn guard(&self) -> Result<ArcOutputGuard<TX>, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ArcOutputGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }
}

pub(super) struct ArcOutputGuard<'a, TX> {
    inner: MutexGuard<'a, Result<Output<TX>, QuicError>>,
}

impl<TX> ArcOutputGuard<'_, TX>
where
    TX: SendFrame<ResetStreamFrame> + Clone + Send + 'static,
{
    pub(super) fn insert(&mut self, sid: StreamId, outgoing: Outgoing<TX>, io_state: IOState) {
        match self.inner.as_mut() {
            Ok(set) => set.insert(sid, (outgoing, io_state)),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
    }

    pub(super) fn on_conn_error(&mut self, err: &QuicError) {
        match self.inner.as_ref() {
            Ok(set) => set.values().for_each(|(o, _)| o.on_conn_error(err)),
            // 已经遇到过conn error了，不需要再次处理。然而guard()时就已经返回了Err，不会再走到这里来
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.inner = Err(err.clone());
    }
}

/// ArcInput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone)]
pub(super) struct ArcInput<TX>(
    pub(super) Arc<Mutex<Result<HashMap<StreamId, (Incoming<TX>, IOState)>, QuicError>>>,
);

impl<TX> Default for ArcInput<TX> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Ok(HashMap::new()))))
    }
}

impl<TX> ArcInput<TX> {
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

    pub(super) fn on_conn_error(&mut self, err: &QuicError) {
        match self.inner.as_ref() {
            Ok(set) => set.values().for_each(|(o, _)| o.on_conn_error(err)),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.inner = Err(err.clone());
    }
}
