use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use draining::DrainingConnection;
use futures::channel::mpsc;
use qbase::{
    cid,
    config::Parameters,
    error::Error,
    packet::{keys::OneRttPacketKeys, DataPacket},
    streamid::Role,
};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qudp::ArcUsc;

use crate::{
    connection::ConnState::{Closing, Draining, Raw},
    path::Pathway,
    router::{ArcRouter, RouterRegistry, ROUTER},
    tls::ArcTlsSession,
};

mod builder;
pub mod closing;
pub mod draining;
pub mod raw;
pub mod scope;
pub mod transmit;

pub type PacketEntry = mpsc::UnboundedSender<(DataPacket, Pathway, ArcUsc)>;
pub type RcvdPackets = mpsc::UnboundedReceiver<(DataPacket, Pathway, ArcUsc)>;

pub type CidRegistry = cid::Registry<RouterRegistry<ArcReliableFrameDeque>, ArcReliableFrameDeque>;
pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;

enum ConnState {
    Raw(raw::RawConnection),
    Closing(closing::ClosingConnection),
    Draining(draining::DrainingConnection),
}

#[derive(Clone)]
pub struct ArcConnection(Arc<Mutex<ConnState>>);

impl Debug for ArcConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "QUIC Connection")
    }
}

impl ArcConnection {
    pub fn new_client(
        server_name: String,
        _address: SocketAddr,
        _token: Option<Vec<u8>>,
        params: Parameters,
        router: ArcRouter,
    ) -> Self {
        let Ok(server_name) = server_name.try_into() else {
            panic!("server_name is not valid")
        };

        let raw_conn = raw::RawConnection::new(
            Role::Client,
            ArcTlsSession::new_client(server_name, &params),
            router,
        );
        let one_rtt_keys = raw_conn.data.one_rtt_keys.clone();
        let pathes = raw_conn.pathes.clone();
        let conn_error = raw_conn.error.clone();
        let conn = ArcConnection(Arc::new(Mutex::new(ConnState::Raw(raw_conn))));
        tokio::spawn({
            let conn = conn.clone();
            async move {
                let (error, is_active) = conn_error.did_error_occur().await;

                let ptos = pathes
                    .iter()
                    .map(|path| path.pto_time())
                    .collect::<Vec<_>>();
                let pto = ptos.iter().sum::<Duration>() / ptos.len() as u32;

                match (one_rtt_keys.invalid(), is_active) {
                    (Some((hpk, pk)), true) => {
                        conn.close((hpk.0, pk), error);
                    }
                    _ => {
                        conn.drain(pto * 3);
                    }
                }
            }
        });
        conn
    }

    /// TODO: 参数不全，其实是QuicServer::accept的返回值
    pub fn new_server(_parameters: Parameters) -> Self {
        todo!("create a new server connection");
    }

    /// Get the streams of the connection, return error if the connection is in closing state or
    /// draining state. Even if the connection will enter closing state in future, the returned
    /// data streams are still available. It doesn't matter, because the returned DataStreams will
    /// be synced into Error state, and do anything about this DataStreams will return an Error.
    pub fn streams(&self) -> Result<DataStreams, std::io::Error> {
        todo!("get the streams of the connection, return error if the connection is in closing state or draining state")
    }

    /// Enter closing state from raw state. There might already be an error within the connection,
    /// in which case the error parameter is not useful.
    /// However, if the app actively closes the connection, the error parameter represents the
    /// reason for the app's active closure.
    /// The app then releases a reference count of the connection, allowing the connection to enter
    /// a self-destruct process.
    pub fn close(
        &self,
        one_rtt_keys: (
            Arc<dyn rustls::quic::HeaderProtectionKey>,
            Arc<Mutex<OneRttPacketKeys>>,
        ),
        error: Error,
    ) {
        let mut guard = self.0.lock().unwrap();
        let (pathes, cid_registry, data_space) = match *guard {
            Raw(ref conn) => conn.enter_closing(),
            _ => return,
        };

        let ptos = pathes
            .iter()
            .map(|path| path.pto_time())
            .collect::<Vec<_>>();

        let pto = ptos.iter().sum::<Duration>() / ptos.len() as u32;

        let closing_conn =
            closing::ClosingConnection::new(pathes, cid_registry, data_space, one_rtt_keys, error);

        tokio::spawn({
            let conn = self.clone();
            let duration = pto * 3;
            let rcvd_ccf = closing_conn.get_rcvd_ccf();
            async move {
                let time = Instant::now();
                match tokio::time::timeout(duration, rcvd_ccf.did_recv()).await {
                    Ok(_) => {
                        conn.drain(duration - time.elapsed());
                    }
                    Err(_) => {
                        conn.die();
                    }
                }
            }
        });

        *guard = Closing(closing_conn);
    }

    /// Enter draining state from raw state or closing state.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn drain(self, remaining: Duration) {
        let mut guard = self.0.lock().unwrap();
        let local_cids = match *guard {
            Raw(ref conn) => conn.cid_registry.local.clone(),
            Closing(ref conn) => conn.cid_registry.local.clone(),
            _ => return,
        };

        tokio::spawn({
            let conn = self.clone();
            async move {
                tokio::time::sleep(remaining).await;
                conn.die();
            }
        });

        *guard = Draining(DrainingConnection::new(local_cids));
    }

    /// Dismiss the connection, remove it from the global router.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn die(self) {
        let local_cids = match *self.0.lock().unwrap() {
            Raw(ref conn) => conn.cid_registry.local.clone(),
            Closing(ref conn) => conn.cid_registry.local.clone(),
            Draining(ref conn) => conn.local_cids().clone(),
        };

        local_cids
            .active_cids()
            .into_iter()
            .for_each(|cid| ROUTER.remove_conn(cid));
    }
}

#[cfg(test)]
mod tests {}
