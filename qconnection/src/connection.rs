use std::{
    fmt::Debug,
    mem,
    net::SocketAddr,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use draining::DrainingConnection;
use futures::channel::mpsc;
use qbase::{cid, config::Parameters, error::Error, packet::DataPacket, streamid::Role};
use qrecovery::{reliable::ArcReliableFrameDeque, streams::DataStreams};
use qudp::ArcUsc;

use crate::{
    connection::ConnState::{Closed, Closing, Draining, Raw},
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
    Closed,
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
        let pathes = raw_conn.pathes.clone();
        let one_rtt_keys = raw_conn.data.one_rtt_keys.clone();
        let conn_error = raw_conn.error.clone();
        let conn = ArcConnection(Arc::new(Mutex::new(ConnState::Raw(raw_conn))));

        tokio::spawn({
            let conn = conn.clone();
            async move {
                if conn_error.did_error_occur().await && one_rtt_keys.invalid().is_some() {
                    conn.close();
                } else {
                    let pto = pathes.iter().map(|p| p.pto_time()).max().unwrap();
                    conn.drain(pto * 3);
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

    /// Gracefully closes the connection.
    ///
    /// This function transitioning connection to a `Closing` state and
    /// initiating a background task to manage the closing handshake. This task awaits
    /// confirmation from the peer (Connection Close Frame) within a timeout derived
    /// from the connection's Path Termination Timeout (PTO).  Upon successful
    /// confirmation, any remaining data is drained.  If the timeout expires without
    /// confirmation, the connection is forcefully terminated.
    fn close(self) {
        let mut guard = self.0.lock().unwrap();

        let ConnState::Raw(raw_conn) = mem::replace(guard.deref_mut(), ConnState::Closed) else {
            unreachable!()
        };

        let pto = raw_conn
            .pathes
            .iter()
            .map(|path| path.pto_time())
            .max()
            .unwrap();

        let closing_conn = closing::ClosingConnection::from(raw_conn);

        tokio::spawn({
            let conn = self.clone();
            let duration = pto * 3;
            let rcvd_ccf = closing_conn.get_rcvd_ccf();
            async move {
                let time = Instant::now();
                if tokio::time::timeout(duration, rcvd_ccf.did_recv())
                    .await
                    .is_ok()
                {
                    conn.drain(duration - time.elapsed());
                } else {
                    conn.die();
                }
            }
        });

        *guard = Closing(closing_conn);
    }

    /// Closes the connection with a specified error.
    /// This function is intended for use by the application layer to signal an
    /// error and initiate the connection closure.
    pub fn close_with_error(&self, error: Error) {
        let guard = self.0.lock().unwrap();
        if let ConnState::Raw(ref raw_conn) = *guard {
            raw_conn.error.set_app_error(error)
        }
    }

    /// Enter draining state from raw state or closing state.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn drain(self, remaining: Duration) {
        let mut guard = self.0.lock().unwrap();
        let draining_conn = match mem::replace(guard.deref_mut(), ConnState::Closed) {
            Raw(conn) => DrainingConnection::from(conn),
            Closing(closing_conn) => DrainingConnection::from(closing_conn),
            _ => unreachable!(),
        };

        tokio::spawn({
            let conn = self.clone();
            async move {
                tokio::time::sleep(remaining).await;
                conn.die();
            }
        });

        *guard = Draining(draining_conn);
    }

    /// Dismiss the connection, remove it from the global router.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn die(self) {
        let mut guard = self.0.lock().unwrap();
        let local_cids = match mem::replace(guard.deref_mut(), ConnState::Closed) {
            Raw(conn) => conn.cid_registry.local,
            Closing(conn) => conn.cid_registry.local,
            Draining(conn) => conn.local_cids().clone(),
            Closed => return,
        };

        local_cids
            .active_cids()
            .into_iter()
            .for_each(|cid| ROUTER.remove_conn(cid));
    }
}

#[cfg(test)]
mod tests {}
