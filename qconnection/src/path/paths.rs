use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use deref_derive::Deref;
use qbase::{
    Epoch,
    error::{Error, ErrorKind},
};
use qcongestion::CongestionControl;
use qinterface::path::Pathway;
use tokio::task::AbortHandle;

use super::Path;
use crate::{
    events::ArcEventBroker,
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
pub struct ArcPaths {
    inner: Arc<DashMap<Pathway, PathContext>>,
    broker: ArcEventBroker,
}

impl ArcPaths {
    pub fn new(event_broker: ArcEventBroker) -> Self {
        Self {
            inner: Default::default(),
            broker: event_broker,
        }
    }

    pub fn entry(&self, pathway: Pathway) -> dashmap::Entry<'_, Pathway, PathContext> {
        self.inner.entry(pathway)
    }

    pub fn remove(&self, pathway: &Pathway, reason: &str) {
        if let Some((_, path)) = self.inner.remove(pathway) {
            self.broker
                .emit(Event::PathInactivated(path.pathway, path.socket));
            tracing::warn!(%pathway, reason, "removed path");
            if self.is_empty() {
                let error =
                    Error::with_default_fty(ErrorKind::NoViablePath, "no viable path exist");
                self.broker.emit(Event::Failed(error));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.inner
            .iter()
            .map(|p| p.cc().pto_time(Epoch::Data))
            .max()
    }
}
