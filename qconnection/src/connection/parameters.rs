use std::{io, sync::Arc};

use futures::lock::Mutex;
use qbase::{config::Parameters, error::Error, util::Future};

use crate::error::ConnError;

type RemoteParametersFuture = Future<Result<Arc<Parameters>, Error>>;

#[derive(Debug, Default, Clone)]
pub struct RemoteParameters(Arc<Mutex<Arc<RemoteParametersFuture>>>);

impl RemoteParameters {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self) -> io::Result<Arc<Parameters>> {
        Ok(self.0.lock().await.get().await?)
    }

    pub async fn on_conn_established(&self, parameters: Arc<Parameters>) {
        self.0
            .lock()
            .await
            .assign(Ok(parameters))
            .expect("receive parameters twice from peer");
    }
}

#[derive(Debug, Clone)]
pub struct ConnParameters {
    pub local: Arc<Parameters>,
    pub remote: RemoteParameters,
}

impl ConnParameters {
    pub fn new(local: Arc<Parameters>, remote: RemoteParameters, conn_error: ConnError) -> Self {
        tokio::spawn({
            let remote = remote.clone();
            async move {
                let (e, ..) = conn_error.await;
                // 返回Ok -> 握手没有完成，连接就结束了
                // 返回Err -> 握手完成，连接结束
                _ = remote.0.lock().await.assign(Err(e));
            }
        });

        Self { local, remote }
    }
}
