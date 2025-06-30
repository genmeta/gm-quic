use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use gm_quic::QuicClient;
use h3::client::SendRequest;
use qconnection::prelude::ToEndpointAddr;
use tokio::{io, sync::Mutex};

struct ReusableConnection {
    #[allow(unused)]
    quic: Arc<gm_quic::Connection>,
    h3: SendRequest<crate::OpenStreams, Bytes>,
}

/// H3 Connection reuse pool
pub struct H3ConnectionPool {
    quic_client: Arc<QuicClient>,
    h3_clients: Arc<DashMap<String, Mutex<Option<ReusableConnection>>>>,
}

impl H3ConnectionPool {
    /// Creates a new reuse pool, using the given client to create the underlying quic connection.
    ///
    /// If this client is used by multiple [`H3ConnectionPool`] and the client enables [`reuse_connection`], it may cause some problems.
    ///
    /// [`reuse_connection`]: gm_quic::QuicClientBuilder::reuse_connection
    pub fn new(quic_client: Arc<QuicClient>) -> Self {
        Self {
            quic_client,
            h3_clients: Arc::new(DashMap::new()),
        }
    }

    /// Get a connection to the specified server.
    ///
    /// If there is no current connection to the server, the given endpoint addr will be used to create a connection.
    ///
    /// If there is already a connection to the given server, just return the existing connection.
    pub async fn connect(
        &self,
        server_name: impl Into<String>,
        server_ep: impl ToEndpointAddr,
    ) -> io::Result<SendRequest<crate::OpenStreams, Bytes>> {
        let server_name = server_name.into();

        let mut entry = None;

        // Get a shared access so that multiple asynchronous tasks can asynchronously wait for other tasks
        // to create connections
        let entry = loop {
            match entry {
                Some(entry) => break entry,
                None => {
                    self.h3_clients.entry(server_name.clone()).or_default();
                    entry = self.h3_clients.get(&server_name);
                }
            }
        };

        let mut entry = entry.lock().await;

        let connect_or_reuse = async {
            if let Some(send_request) = entry.as_ref() {
                // todo: fresh quic conenc
                return io::Result::Ok(send_request.h3.clone());
            }

            let quic_connection = self.quic_client.connect(server_name.clone(), [server_ep])?;
            let (mut h3_connection, send_request) =
                h3::client::new(crate::QuicConnection::new(quic_connection.clone()))
                    .await
                    .map_err(io::Error::other)?;

            *entry = Some(ReusableConnection {
                quic: quic_connection.clone(),
                h3: send_request.clone(),
            });

            tokio::spawn({
                let h3_clients = self.h3_clients.clone();
                let server_name = server_name.clone();
                async move {
                    _ = h3_connection.wait_idle().await;
                    h3_clients.remove(&server_name);
                }
            });

            Ok(send_request)
        };

        match connect_or_reuse.await {
            Ok(send_request) => Ok(send_request),
            Err(error) => {
                // clean up failed connections
                tokio::task::spawn_blocking({
                    let h3_clients = self.h3_clients.clone();
                    move || h3_clients.remove_if(&server_name, |_, v| v.blocking_lock().is_none())
                });
                Err(error)
            }
        }
    }
}
