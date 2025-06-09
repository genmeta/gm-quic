use std::{ops::Deref, sync::Arc};

use qbase::{error::Error, util::Future};

#[derive(Clone)]
pub struct ArcZeroRtt(Option<Arc<Future<Result<bool, Error>>>>);

impl ArcZeroRtt {
    pub fn new(enabled: bool) -> Self {
        Self(enabled.then(Arc::default))
    }

    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    pub async fn is_accepted(&self) -> Result<Option<bool>, Error> {
        match &self.0 {
            Some(fut) => fut.get().await.deref().clone().map(Some),
            None => Ok(None),
        }
    }

    pub(super) fn on_0rtt_rejected(&self) {
        if let Some(fut) = &self.0 {
            debug_assert!(fut.try_get().is_none());
            fut.assign(Ok(false));
        }
    }

    pub(super) fn on_0rtt_accepted(&self) {
        if let Some(fut) = &self.0 {
            debug_assert!(fut.try_get().is_none());
            fut.assign(Ok(true));
        }
    }
}
