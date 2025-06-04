use std::{ops::Deref, sync::Arc};

use qbase::{error::Error, param::ClientParameters, util::Future};

#[derive(Default, Debug, Clone)]
pub struct ArcEndpointName<T>(Arc<Future<Result<T, Error>>>);

impl<T> From<T> for ArcEndpointName<T> {
    fn from(endpoint_name: T) -> Self {
        ArcEndpointName(Arc::new(Future::with(Ok(endpoint_name))))
    }
}

impl<T> ArcEndpointName<T> {
    pub fn assign(&self, server_name: impl ToOwned<Owned = T>) {
        let previous = self.0.assign(Ok(server_name.to_owned()));
        debug_assert!(previous.is_none())
    }

    pub fn try_get(&self) -> Option<Result<T, Error>>
    where
        T: Clone,
    {
        self.0.try_get().map(|r| r.deref().clone())
    }

    pub async fn get(&self) -> Result<T, Error>
    where
        T: Clone,
    {
        self.0.get().await.deref().clone()
    }

    pub fn on_conn_error(&self, error: &Error) {
        self.0.assign(Err(error.clone()));
    }
}

pub type ArcServerName = ArcEndpointName<String>;
pub type ArcClientName = ArcEndpointName<Option<String>>;

impl From<&ClientParameters> for ArcClientName {
    fn from(params: &ClientParameters) -> Self {
        let client_name = params.get_as(super::CLIENT_NAME_PARAM_ID);
        ArcEndpointName(Arc::new(Future::with(Ok(client_name))))
    }
}
