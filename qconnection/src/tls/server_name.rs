use std::{ops::Deref, sync::Arc};

use qbase::{error::Error, util::Future};

#[derive(Default, Debug, Clone)]
pub struct ArcServerName(Arc<Future<Result<String, Error>>>);

impl From<String> for ArcServerName {
    fn from(server_name: String) -> Self {
        ArcServerName(Arc::new(Future::with(Ok(server_name))))
    }
}

impl ArcServerName {
    pub fn assign(&self, server_name: &str) {
        let previous = self.0.assign(Ok(server_name.to_owned()));
        debug_assert!(previous.is_none())
    }

    pub(super) fn is_ready(&self) -> bool {
        self.0.try_get().is_some()
    }

    pub async fn get(&self) -> Result<String, Error> {
        self.0.get().await.deref().clone()
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.0.assign(Err(error.clone()));
    }
}
