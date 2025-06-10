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

    pub fn is_accepted(
        &self,
    ) -> Option<impl futures::Future<Output = Result<bool, Error>> + Send + '_> {
        let fut = self.0.as_ref()?;
        Some(async { fut.get().await.deref().clone() })
    }

    pub(super) fn set(&self, accepetd: bool) {
        if let Some(fut) = self.0.as_ref() {
            fut.assign(Ok(accepetd));
        }
    }
}
