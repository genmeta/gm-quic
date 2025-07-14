use std::{
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use dashmap::DashMap;
use derive_more::Deref;
use qbase::{
    Epoch,
    cid::ConnectionId,
    error::{ErrorKind, QuicError},
    net::{route::Pathway, tx::ArcSendWakers},
};
use qcongestion::Transport;
use qevent::telemetry::Instrument;
use qinterface::QuicIO;
use tokio::task::AbortHandle;
use tracing::Instrument as _;

use super::Path;
use crate::{
    ArcRemoteCids,
    events::ArcEventBroker,
    path::{CreatePathFailure, PathDeactivated},
    prelude::{EmitEvent, Event},
};

#[derive(Deref)]
pub struct PathContext {
    #[deref]
    path: Arc<Path>,
    task: AbortHandle,
}

impl Drop for PathContext {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PathContext {
    pub fn new(path: Arc<Path>, task: AbortHandle) -> Self {
        Self { path, task }
    }
}

#[derive(Clone)]
pub struct ArcPathContexts {
    paths: Arc<DashMap<Pathway, PathContext>>,
    tx_wakers: ArcSendWakers,
    broker: ArcEventBroker,
    initial_path: Arc<Mutex<Option<Weak<Path>>>>,
}

impl ArcPathContexts {
    pub fn new(tx_wakers: ArcSendWakers, broker: ArcEventBroker) -> Self {
        Self {
            paths: Default::default(),
            tx_wakers,
            broker,
            initial_path: Arc::default(),
        }
    }

    pub fn assign_handshake_path(
        &self,
        path: &Arc<Path>,
        remote_cids: &ArcRemoteCids,
        initial_dcid: ConnectionId,
    ) -> bool {
        let mut handshake_path = self.initial_path.lock().unwrap();
        if handshake_path.is_some() {
            return false;
        }
        remote_cids.apply_initial_dcid(initial_dcid, &path.dcid_cell);
        *handshake_path = Some(Arc::downgrade(path));
        true
    }

    pub fn handshake_path(&self) -> Option<Arc<Path>> {
        self.initial_path
            .lock()
            .unwrap()
            .clone()
            .expect("unreachable: Handshake packet received before first initial packet processed")
            .upgrade()
    }

    pub fn get_or_try_create_with<T>(
        &self,
        pathway: Pathway,
        try_create: impl FnOnce() -> Result<(Arc<Path>, T), CreatePathFailure>,
    ) -> Result<Arc<Path>, CreatePathFailure>
    where
        T: Future<Output = Result<(), PathDeactivated>> + Send + 'static,
    {
        match self.paths.entry(pathway) {
            dashmap::Entry::Occupied(occupied_entry) => Ok(occupied_entry.get().path.clone()),
            dashmap::Entry::Vacant(vacant_entry) => {
                let (path, task) = try_create()?;
                self.tx_wakers.insert(pathway, path.tx_waker());
                let paths = self.clone();
                let task = tokio::spawn(
                    async move {
                        let reason = task.await.unwrap_err();
                        paths.remove(&pathway, &reason);
                    }
                    .instrument_in_current()
                    .in_current_span(),
                )
                .abort_handle();
                Ok(vacant_entry.insert(PathContext { path, task }).clone())
            }
        }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.paths.get(pathway).map(|p| p.path.clone())
    }

    pub fn remove(&self, pathway: &Pathway, reason: &PathDeactivated) {
        if let Some((_, path)) = self.paths.remove(pathway) {
            self.tx_wakers.remove(pathway);
            self.broker.emit(Event::PathDeactivated(
                path.interface.bind_uri(),
                path.pathway,
                path.link,
            ));
            tracing::warn!(%pathway, %reason, "Path removed");
            if self.is_empty() {
                let error = QuicError::with_default_fty(
                    ErrorKind::NoViablePath,
                    format!("No viable path exist, last path removed because: {reason}"),
                );
                self.broker.emit(Event::Failed(error));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths.iter().map(|p| p.cc().get_pto(Epoch::Data)).max()
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<Path>> + '_ {
        self.paths.iter().map(|p| p.path.clone())
    }

    pub fn discard_initial_and_handshake_space(&self) {
        self.paths.iter().for_each(|p| {
            p.cc().discard_epoch(Epoch::Initial);
            p.cc().discard_epoch(Epoch::Handshake);
        });
    }

    pub fn clear(&self) {
        self.paths.clear();
    }
}
