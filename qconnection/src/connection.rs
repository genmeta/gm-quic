use std::{
    borrow::Cow,
    fmt::Debug,
    io, mem,
    ops::DerefMut,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use closing::ClosingConnection;
use draining::DrainingConnection;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::{self, ConnectionId},
    config::Parameters,
    error::{Error, ErrorKind},
    packet::{DataPacket, RetryHeader},
    streamid::Role,
    token::ArcTokenRegistry,
};
use qcongestion::CongestionControl;
use qrecovery::{
    recv::Reader, reliable::ArcReliableFrameDeque, send::Writer, space::Epoch, streams,
};
use qudp::ArcUsc;
use qunreliable::{DatagramReader, DatagramWriter};
use raw::RawConnection;

use crate::{
    connection::ConnState::{Closed, Closing, Draining, Raw},
    path::pathway::Pathway,
    router::{RouterRegistry, ROUTER},
    tls::ArcTlsSession,
};

pub mod closing;
pub mod draining;
pub mod parameters;
pub mod raw;
pub mod scope;
pub mod transmit;

pub type PacketEntry = mpsc::UnboundedSender<(DataPacket, Pathway, ArcUsc)>;
pub type RcvdPackets = mpsc::UnboundedReceiver<(DataPacket, Pathway, ArcUsc)>;

pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;

enum ConnState {
    Raw(RawConnection),
    Closing(ClosingConnection),
    Draining(DrainingConnection),
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
        scid: ConnectionId,
        server_name: String,
        mut parameters: Parameters,
        tls_config: Arc<rustls::ClientConfig>,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        let Ok(server_name) = server_name.try_into() else {
            panic!("server_name is not valid")
        };

        parameters.set_initial_source_connection_id(Some(scid));

        let dcid = ConnectionId::random_gen(8);
        let tls_session = ArcTlsSession::new_client(server_name, tls_config.clone(), &parameters);
        let raw_conn = RawConnection::new(
            Role::Client,
            parameters,
            tls_session,
            scid,
            dcid,
            ArcTlsSession::initial_keys(tls_config.crypto_provider(), rustls::Side::Client, dcid),
            token_registry,
        );
        raw_conn.into()
    }

    pub fn add_initial_path(&self, pathway: Pathway, usc: ArcUsc) {
        let guard = self.0.lock().unwrap();
        if let Raw(ref conn) = *guard {
            _ = conn.pathes.get_or_create(pathway, usc);
        }
    }

    pub fn new_server(
        initial_scid: ConnectionId,
        initial_dcid: ConnectionId,
        mut parameters: Parameters,
        initial_keys: rustls::quic::Keys,
        tls_config: Arc<rustls::ServerConfig>,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        parameters.set_original_destination_connection_id(Some(initial_dcid));

        let tls_session = ArcTlsSession::new_server(tls_config.clone(), &parameters);
        let raw_conn = RawConnection::new(
            Role::Server,
            parameters,
            tls_session,
            initial_scid,
            initial_dcid,
            initial_keys,
            token_registry,
        );
        raw_conn.into()
    }

    // /// Get the streams of the connection, return error if the connection is in closing state or
    // /// draining state. Even if the connection will enter closing state in future, the returned
    // /// data streams are still available. It doesn't matter, because the returned DataStreams will
    // /// be synced into Error state, and do anything about this DataStreams will return an Error.
    // pub fn streams(&self) -> io::Result<DataStreams> {
    //     // TODO: ArcConnection不再暴露赤裸的streams接口，而是根据双方Parameters使用
    //     //      raw_conn.streams().open_bi(...)去异步地创建
    //     let guard = self.0.lock().unwrap();
    //     if let ConnState::Raw(ref raw_conn) = *guard {
    //         Ok(raw_conn.streams.clone())
    //     } else {
    //         Err(io::Error::new(
    //             io::ErrorKind::BrokenPipe,
    //             "Connection is closing or closed",
    //         ))
    //     }
    // }

    pub async fn open_bi_stream(&self) -> io::Result<Option<(Reader, Writer)>> {
        let connection_closed =
            io::Error::new(io::ErrorKind::BrokenPipe, "Connection is closing or closed");
        let (remote_params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let ConnState::Raw(raw_conn) = &*guard else {
                return Err(connection_closed);
            };

            (
                raw_conn.params.remote.clone(),
                raw_conn.streams.clone(),
                raw_conn.error.clone(),
            )
        };

        let remote_params = remote_params.read().await?;

        let result = data_streams
            .open_bi(remote_params.initial_max_stream_data_bidi_remote().into())
            .await
            .inspect_err(|e| conn_error.on_error(e.clone()));
        Ok(result?)
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<Writer>> {
        let connection_closed =
            io::Error::new(io::ErrorKind::BrokenPipe, "Connection is closing or closed");
        let (remote_params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let ConnState::Raw(raw_conn) = &*guard else {
                return Err(connection_closed);
            };

            (
                raw_conn.params.remote.clone(),
                raw_conn.streams.clone(),
                raw_conn.error.clone(),
            )
        };

        let remote_params = remote_params.read().await?;

        let result = data_streams
            .open_uni(remote_params.initial_max_stream_data_uni().into())
            .await
            .inspect_err(|e| conn_error.on_error(e.clone()));
        Ok(result?)
    }

    pub async fn accept_bi_stream(&self) -> io::Result<(Reader, Writer)> {
        let connection_closed =
            io::Error::new(io::ErrorKind::BrokenPipe, "Connection is closing or closed");
        let (remote_params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let ConnState::Raw(raw_conn) = &*guard else {
                return Err(connection_closed);
            };

            (
                raw_conn.params.remote.clone(),
                raw_conn.streams.clone(),
                raw_conn.error.clone(),
            )
        };

        let remote_params = remote_params.read().await?;

        let result = data_streams
            .accept_bi(remote_params.initial_max_stream_data_bidi_local().into())
            .await
            .inspect_err(|e| conn_error.on_error(e.clone()))?;
        Ok(result)
    }

    pub async fn accept_uni_stream(&self) -> io::Result<Reader> {
        let (data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let ConnState::Raw(raw_conn) = &*guard else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Connection is closing or closed",
                ));
            };

            (raw_conn.streams.clone(), raw_conn.error.clone())
        };

        let result = data_streams
            .accept_uni()
            .await
            .inspect_err(|e| conn_error.on_error(e.clone()))?;
        Ok(result)
    }

    pub fn datagram_reader(&self) -> io::Result<DatagramReader> {
        let connection_closed =
            io::Error::new(io::ErrorKind::BrokenPipe, "Connection is closing or closed");
        let guard = self.0.lock().unwrap();
        if let ConnState::Raw(ref raw_conn) = *guard {
            raw_conn.datagrams.reader()
        } else {
            Err(connection_closed)
        }
    }

    pub async fn datagram_writer(&self) -> io::Result<DatagramWriter> {
        let connection_closed =
            io::Error::new(io::ErrorKind::BrokenPipe, "Connection is closing or closed");
        let (remote_params, datagram_flow) = {
            let guard = self.0.lock().unwrap();
            let ConnState::Raw(raw_conn) = &*guard else {
                return Err(connection_closed);
            };

            (raw_conn.params.remote.clone(), raw_conn.datagrams.clone())
        };

        let remote_params = remote_params.read().await?;
        datagram_flow.writer(remote_params.max_datagram_frame_size().into())
    }

    /// Gracefully closes the connection.
    ///
    /// Closes the connection with a specified error.
    /// This function is intended for use by the application layer to signal an
    /// error and initiate the connection closure.
    pub fn close(&self, msg: impl Into<Cow<'static, str>>) {
        let guard = self.0.lock().unwrap();
        if let ConnState::Raw(ref raw_conn) = *guard {
            raw_conn
                .error
                .set_app_error(Error::with_default_fty(ErrorKind::Application, msg));
        }
    }

    /// This function transitioning connection to a `Closing` state and
    /// initiating a background task to manage the closing handshake. This task awaits
    /// confirmation from the peer (Connection Close Frame) within a timeout derived
    /// from the connection's Path Termination Timeout (PTO).  Upon successful
    /// confirmation, any remaining data is drained.  If the timeout expires without
    /// confirmation, the connection is forcefully terminated.
    fn should_enter_closing_with_error(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        let ConnState::Raw(raw_conn) = mem::replace(guard.deref_mut(), ConnState::Closed) else {
            unreachable!()
        };

        raw_conn.datagrams.on_conn_error(&error);
        raw_conn.streams.on_conn_error(&error);
        raw_conn.params.on_conn_error(&error);
        raw_conn.tls_session.abort();

        let pto = raw_conn
            .pathes
            .iter()
            .map(|path| path.cc.pto_time(Epoch::Data))
            .max()
            .unwrap();

        let hs = raw_conn.hs.try_into();
        let one_rtt = raw_conn.data.try_into();
        if hs.is_err() && one_rtt.is_err() {
            // 没法进入到Closing，则直接进入到Draining
            self.enter_draining(pto * 3);
            return;
        }

        let closing_conn = ClosingConnection::new(
            error,
            raw_conn.pathes,
            raw_conn.cid_registry,
            hs.ok(),
            one_rtt.ok(),
        );

        // Redirect the received packets of this connection to ClosingConnection
        raw_conn.notify.notify_waiters();
        for handle in raw_conn.join_handles {
            let mut closing_conn = closing_conn.clone();
            tokio::spawn(async move {
                let mut rcvd_packets = handle.await.unwrap();
                while let Some((packet, pathway, usc)) = rcvd_packets.next().await {
                    closing_conn.recv_packet_via_pathway(packet, pathway, usc);
                }
            });
        }

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
                    conn.enter_draining(duration - time.elapsed());
                } else {
                    conn.die();
                }
            }
        });

        *guard = Closing(closing_conn);
    }

    /// Enter draining state from raw state or closing state.
    /// Can only be called internally, and the app should not care this method.
    pub(crate) fn enter_draining(&self, remaining: Duration) {
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

        local_cids.active_cids().iter().for_each(|cid| {
            ROUTER.remove(cid);
        });
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        let guard = self.0.lock().unwrap();
        if let ConnState::Raw(ref raw_conn) = *guard {
            raw_conn.update_path_recv_time(pathway);
        }
    }

    pub fn recv_retry_packet(&self, retry: &RetryHeader) {
        let guard = self.0.lock().unwrap();
        if let Raw(ref conn) = *guard {
            *conn.token.lock().unwrap() = retry.token.to_vec();
            conn.cid_registry.remote.revise_initial_dcid(retry.scid);
            let sent_record = conn.initial.space.sent_packets();
            let mut guard = sent_record.recv();
            for i in 0..guard.largest_pn() {
                for frame in guard.may_loss_pkt(i) {
                    conn.initial.crypto_stream.outgoing().may_loss_data(&frame);
                }
            }
        }
    }

    pub fn is_active(&self) -> bool {
        let guard = self.0.lock().unwrap();
        !matches!(&*guard, ConnState::Raw(..))
    }
}

impl From<RawConnection> for ArcConnection {
    fn from(raw_conn: RawConnection) -> Self {
        let conn_error = raw_conn.error.clone();
        let pathes = raw_conn.pathes.clone();
        let conn = ArcConnection(Arc::new(Mutex::new(ConnState::Raw(raw_conn))));

        tokio::spawn({
            let conn = conn.clone();
            async move {
                let (err, is_active) = conn_error.did_error_occur().await;
                if is_active {
                    conn.should_enter_closing_with_error(err);
                } else {
                    let pto = pathes
                        .iter()
                        .map(|p| p.cc.pto_time(Epoch::Data))
                        .max()
                        .unwrap();
                    conn.enter_draining(pto * 3);
                }
            }
        });

        conn
    }
}
#[cfg(test)]
mod tests {}
