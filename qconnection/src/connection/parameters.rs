use std::{io, sync::Arc};

use futures::lock::Mutex;
use qbase::{config::Parameters, error::Error, util::Future};

type RemoteParametersFuture = Future<Result<Arc<Parameters>, Error>>;

#[derive(Debug, Default, Clone)]
pub struct RemoteParametersReader(Arc<Mutex<Arc<RemoteParametersFuture>>>);

impl RemoteParametersReader {
    pub async fn read(&self) -> io::Result<Arc<Parameters>> {
        Ok(self.0.lock().await.get().await?)
    }
}

#[derive(Debug, Default, Clone)]
pub struct RemoteParametersWriter(Arc<RemoteParametersFuture>);

impl RemoteParametersWriter {
    pub fn write(&self, params: Arc<Parameters>) {
        _ = self.0.assign(Ok(params));
    }
}

#[derive(Debug, Clone)]
pub struct RemoteParameters {
    pub reader: RemoteParametersReader,
    pub writer: RemoteParametersWriter,
}

impl Default for RemoteParameters {
    fn default() -> Self {
        let raw = Arc::<RemoteParametersFuture>::default();
        let writer = RemoteParametersWriter(raw.clone());
        let reader = RemoteParametersReader(Arc::new(Mutex::new(raw)));
        Self { reader, writer }
    }
}

impl RemoteParameters {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct ConnParameters {
    local: Arc<Parameters>,
    remote: RemoteParameters,
}

impl ConnParameters {
    pub fn new(local: Arc<Parameters>, remote: RemoteParameters) -> Self {
        Self { local, remote }
    }

    pub fn remote(&self) -> &RemoteParametersReader {
        &self.remote.reader
    }

    pub fn local(&self) -> &Arc<Parameters> {
        &self.local
    }

    pub fn on_conn_error(&self, error: &Error) {
        _ = self.remote.writer.0.assign(Err(error.clone()));
    }
}
