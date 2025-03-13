use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
};

use deref_derive::{Deref, DerefMut};
use qbase::{error::Error as QuicError, sid::StreamId};

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
    pub(super) cursor: Option<(StreamId, usize)>,
}

impl<TX> Output<TX> {
    fn new() -> Self {
        Self {
            outgoings: BTreeMap::default(),
            cursor: None,
        }
    }

    pub fn tokens_bucket(
        &mut self,
    ) -> impl Iterator<Item = (StreamId, &(Outgoing<TX>, IOState), usize)> {
        // todo: use core::range instead in newer version of rust 2024
        use core::ops::Bound::*;

        // 该tokens是令牌桶算法的token，为了多条Stream的公平性，给每个流定期地发放tokens，不累积
        // 各流轮流按令牌桶算法发放的tokens来整理数据去发送
        const DEFAULT_TOKENS: usize = 4096;

        enum TokenBucketIter<E, I, F> {
            ExcludeCurrent(E),
            IncludeCurrent(I),
            FullRange(F),
        }

        impl<E, I, F, Item> Iterator for TokenBucketIter<E, I, F>
        where
            E: Iterator<Item = Item>,
            I: Iterator<Item = Item>,
            F: Iterator<Item = Item>,
        {
            type Item = Item;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    TokenBucketIter::ExcludeCurrent(iter) => iter.next(),
                    TokenBucketIter::IncludeCurrent(iter) => iter.next(),
                    TokenBucketIter::FullRange(iter) => iter.next(),
                }
            }

            fn find_map<B, M>(&mut self, f: M) -> Option<B>
            where
                Self: Sized,
                M: FnMut(Self::Item) -> Option<B>,
            {
                match self {
                    TokenBucketIter::ExcludeCurrent(iter) => iter.find_map(f),
                    TokenBucketIter::IncludeCurrent(iter) => iter.find_map(f),
                    TokenBucketIter::FullRange(iter) => iter.find_map(f),
                }
            }
        }

        match &self.cursor {
            // [sid+1..] + [..=sid]
            Some((sid, tokens)) if *tokens == 0 => TokenBucketIter::ExcludeCurrent(
                self.outgoings
                    .range((Excluded(sid), Unbounded))
                    .chain(self.outgoings.range(..=sid))
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS)),
            ),
            // [sid] + [sid+1..] + [..sid]
            Some((sid, tokens)) => TokenBucketIter::IncludeCurrent(
                Option::into_iter(
                    self.outgoings
                        .get(sid)
                        .map(|outgoing| (*sid, outgoing, *tokens)),
                )
                .chain(
                    self.outgoings
                        .range((Excluded(sid), Unbounded))
                        .chain(self.outgoings.range(..sid))
                        .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS)),
                ),
            ),
            // [..]
            None => TokenBucketIter::FullRange(
                self.outgoings
                    .range(..)
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS)),
            ),
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

    pub(super) fn guard(&self) -> Result<ArcOutputGuard<TX>, QuicError> {
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
