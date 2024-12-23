use std::{
    borrow::Cow,
    fmt::Debug,
    io,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use closing::ClosingConnection;
use draining::DrainingConnection;
use futures::channel::mpsc;
use qbase::{
    cid::{self, ConnectionId},
    error::{Error, ErrorKind},
    flow,
    packet::{DataPacket, RetryHeader},
    param::{ArcParameters, ClientParameters, CommonParameters, Pair, ServerParameters},
    sid::{Role, StreamId},
    token::ArcTokenRegistry,
};
use qrecovery::{
    recv,
    reliable::ArcReliableFrameDeque,
    send,
    streams::{self, Ext},
};
use qunreliable::{UnreliableReader, UnreliableWriter};
use raw::Connection;
use tokio::task::JoinHandle;

use crate::{
    conn::ConnState::{Closed, Closing, Draining, Invalid, Normal},
    path::Pathway,
    router::{Router, RouterRegistry},
    tls::ArcTlsSession,
    usc::ArcUsc,
};

pub mod closing;
pub mod draining;
pub mod raw;
pub mod space;
pub mod transmit;

pub type PacketEntry = mpsc::UnboundedSender<(DataPacket, Pathway, ArcUsc)>;
pub type RcvdPackets = mpsc::UnboundedReceiver<(DataPacket, Pathway, ArcUsc)>;

pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<ArcReliableFrameDeque>;

// TODO: 巨大提升空间
enum ConnState {
    Normal(Connection),
    Closing(ClosingConnection),
    Draining(DrainingConnection),
    Closed(Error),
    Invalid,
}

impl ConnState {
    fn try_enter_closing(
        &mut self,
        error: Error,
    ) -> Option<([JoinHandle<RcvdPackets>; 4], Duration)> {
        let conn = std::mem::replace(self, Invalid);
        let Normal(connection) = conn else {
            // has been closing/draining
            *self = conn;
            return None;
        };
        connection.abort_with_error(&error);

        let pto_time = connection.max_pto_duration().unwrap();
        // 尝试进入Closing状态
        let hs = connection.hs.try_into().ok();
        let one_rtt = connection.data.try_into().ok();

        let recv_packets = connection.join_handles;

        *self = match (hs, one_rtt) {
            (None, None) => {
                let local_cids = connection.cid_registry.local.active_cids();
                let draining_connection = DrainingConnection::new(local_cids, error);
                Draining(draining_connection)
            }
            (hs, one_rtt) => {
                let local_cids = connection.cid_registry.local.active_cids();
                let initial_scid = connection.initial_scid;
                let last_dcid = connection.cid_registry.remote.latest_dcid();
                let closing_connection =
                    ClosingConnection::new(error, local_cids, hs, one_rtt, initial_scid, last_dcid);
                tokio::spawn({
                    let pathes = connection.paths;
                    let closing_connection = closing_connection.clone();
                    async move {
                        for mut path in pathes.iter_mut() {
                            let (pathway, path) = path.pair_mut();
                            closing_connection.send_ccf(path.usc(), *pathway).await;
                        }
                    }
                });
                Closing(closing_connection)
            }
        };

        Some((recv_packets, pto_time))
    }

    fn enter_draining(&mut self, error: Error) -> Option<Duration> {
        let conn = std::mem::replace(self, Invalid);
        let Normal(connection) = conn else {
            // has been closing/draining
            *self = conn;
            return None;
        };
        connection.abort_with_error(&error);

        let local_cids = connection.cid_registry.local.active_cids();
        *self = Draining(DrainingConnection::new(local_cids, error));

        connection.max_pto_duration()
    }

    fn no_vaiable_path(&mut self) {
        let conn = std::mem::replace(self, Invalid);
        // no need to reset the state to conn
        let Normal(connection) = conn else { return };
        let error = Error::with_default_fty(ErrorKind::NoViablePath, "No viable path");
        connection.abort_with_error(&error);

        let local_cids = &connection.cid_registry.local;
        local_cids.active_cids().iter().for_each(Router::remove);
        *self = Closed(error)
    }

    fn die(&mut self) {
        let conn = std::mem::replace(self, Invalid);
        let local_cids = match &conn {
            Closing(conn) => conn.local_cids(),
            Draining(conn) => conn.local_cids(),
            Closed(..) => return,
            Normal(..) | Invalid => unreachable!(),
        };

        for cid in local_cids {
            Router::remove(cid);
        }
    }
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
        initial_scid: ConnectionId,
        server_name: String,
        parameters: ClientParameters,
        remembered: Option<CommonParameters>,
        streams_ctrl: Box<dyn qbase::sid::ControlConcurrency>,
        tls_config: Arc<rustls::ClientConfig>,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        let Ok(server_name) = server_name.try_into() else {
            panic!("server_name is not valid")
        };

        let initial_dcid = ConnectionId::random_gen(8);
        let parameters = ArcParameters::new_client(parameters, remembered);
        parameters.set_initial_scid(initial_scid);
        parameters.original_dcid_from_server_need_equal(initial_dcid);

        let tls_session = ArcTlsSession::new_client(server_name, tls_config.clone(), &parameters);
        let initial_keys = ArcTlsSession::initial_keys(
            tls_config.crypto_provider(),
            rustls::Side::Client,
            initial_dcid,
        );
        let connection = Connection::new(
            Role::Client,
            parameters,
            tls_session,
            initial_scid,
            initial_dcid,
            initial_keys,
            streams_ctrl,
            token_registry,
        );
        connection.into()
    }

    pub fn add_initial_path(&self, pathway: Pathway, usc: ArcUsc) {
        let guard = self.0.lock().unwrap();
        if let Normal(ref conn) = *guard {
            _ = conn.paths.get_or_create(pathway, usc);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        initial_scid: ConnectionId,
        initial_dcid: ConnectionId,
        origin_dcid: ConnectionId,
        initial_keys: rustls::quic::Keys,
        parameters: ServerParameters,
        streams_ctrl: Box<dyn qbase::sid::ControlConcurrency>,
        tls_config: Arc<rustls::ServerConfig>,
        token_registry: ArcTokenRegistry,
    ) -> Self {
        let parameters = ArcParameters::new_server(parameters);
        parameters.set_initial_scid(initial_scid);
        parameters.set_original_dcid(origin_dcid);

        let tls_session = ArcTlsSession::new_server(tls_config.clone(), &parameters);
        let connection = Connection::new(
            Role::Server,
            parameters,
            tls_session,
            initial_scid,
            initial_dcid,
            initial_keys,
            streams_ctrl,
            token_registry,
        );
        connection.into()
    }

    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let connection = match guard.deref() {
                Normal(connection) => connection,
                Closing(closing) => return Err(closing.error().clone())?,
                Draining(draining) => return Err(draining.error().clone())?,
                Closed(error) => return Err(error.clone())?,
                Invalid => unreachable!(),
            };

            (
                connection.params.clone(),
                connection.data.streams.clone(),
                connection.error.clone(),
            )
        };

        if let Some(Pair { local: _, remote }) = params.await {
            let result = data_streams
                .open_bi(remote.initial_max_stream_data_bidi_remote().into())
                .await
                .inspect_err(|e| conn_error.on_error(e.clone()));
            Ok(result?)
        } else {
            Ok(None)
        }
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        let (params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let connection = match guard.deref() {
                Normal(connection) => connection,
                Closing(closing) => return Err(closing.error().clone())?,
                Draining(draining) => return Err(draining.error().clone())?,
                Closed(error) => return Err(error.clone())?,
                Invalid => unreachable!(),
            };

            (
                connection.params.clone(),
                connection.data.streams.clone(),
                connection.error.clone(),
            )
        };

        if let Some(Pair { local: _, remote }) = params.await {
            let result = data_streams
                .open_uni(remote.initial_max_stream_data_uni().into())
                .await
                .inspect_err(|e| conn_error.on_error(e.clone()));
            Ok(result?)
        } else {
            Ok(None)
        }
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let connection = match guard.deref() {
                Normal(connection) => connection,
                Closing(closing) => return Err(closing.error().clone())?,
                Draining(draining) => return Err(draining.error().clone())?,
                Closed(error) => return Err(error.clone())?,
                Invalid => unreachable!(),
            };

            (
                connection.params.clone(),
                connection.data.streams.clone(),
                connection.error.clone(),
            )
        };

        if let Some(Pair { local: _, remote }) = params.await {
            let result = data_streams
                .accept_bi(remote.initial_max_stream_data_bidi_local().into())
                .await
                .inspect_err(|e| conn_error.on_error(e.clone()))?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub async fn accept_uni_stream(&self) -> io::Result<(StreamId, StreamReader)> {
        let (data_streams, conn_error) = {
            let guard = self.0.lock().unwrap();
            let connection = match guard.deref() {
                Normal(connection) => connection,
                Closing(closing) => return Err(closing.error().clone())?,
                Draining(draining) => return Err(draining.error().clone())?,
                Closed(error) => return Err(error.clone())?,
                Invalid => unreachable!(),
            };

            (connection.data.streams.clone(), connection.error.clone())
        };

        let result = data_streams
            .accept_uni()
            .await
            .inspect_err(|e| conn_error.on_error(e.clone()))?;
        Ok(result)
    }

    pub fn datagram_reader(&self) -> io::Result<UnreliableReader> {
        let guard = self.0.lock().unwrap();

        match guard.deref() {
            Normal(raw) => raw.data.datagrams.reader(),
            Closing(closing) => Err(closing.error().clone())?,
            Draining(draining) => Err(draining.error().clone())?,
            Closed(error) => Err(error.clone())?,
            Invalid => unreachable!(),
        }
    }

    pub async fn datagram_writer(&self) -> io::Result<Option<UnreliableWriter>> {
        let (params, datagram_flow) = {
            let guard = self.0.lock().unwrap();
            let connection = match guard.deref() {
                Normal(connection) => connection,
                Closing(closing) => return Err(closing.error().clone())?,
                Draining(draining) => return Err(draining.error().clone())?,
                Closed(error) => return Err(error.clone())?,
                Invalid => unreachable!(),
            };

            (connection.params.clone(), connection.data.datagrams.clone())
        };

        if let Some(Pair { local: _, remote }) = params.await {
            datagram_flow
                .writer(remote.max_datagram_frame_size().into())
                .map(Option::Some)
        } else {
            Ok(None)
        }
    }

    /// Gracefully closes the connection.
    ///
    /// Closes the connection with a specified error.
    /// This function is intended for use by the application layer to signal an
    /// error and initiate the connection closure.
    pub fn close(&self, msg: impl Into<Cow<'static, str>>) {
        let mut guard = self.0.lock().unwrap();
        if let Normal(connection) = guard.deref_mut() {
            let msg = msg.into();
            log::info!("Connection is closed by application: {}", msg);
            let error = Error::with_default_fty(ErrorKind::Application, msg);
            connection.error.set_app_error(error.clone());
            drop(guard);
            self.should_enter_closing(error);
        }
    }

    /// This function transitioning connection to a `Closing` state and
    /// initiating a background task to manage the closing handshake. This task awaits
    /// confirmation from the peer (Connection Close Frame) within a timeout derived
    /// from the connection's Path Termination Timeout (PTO).  Upon successful
    /// confirmation, any remaining data is drained.  If the timeout expires without
    /// confirmation, the connection is forcefully terminated.
    fn should_enter_closing(&self, error: Error) {
        let mut guard = self.0.lock().unwrap();
        let state = guard.deref_mut();
        if !matches!(state, Normal(..)) {
            return;
        }
        let Some((handles, pto)) = state.try_enter_closing(error) else {
            return;
        };

        match state {
            Closing(closing) => {
                tokio::spawn({
                    let mut closing = closing.clone();
                    async move {
                        use futures::StreamExt;
                        // initial 0rtt handshake 1rtt
                        let [h1, h2, h3, h4] = handles;
                        let (r1, r2, r3, r4) = tokio::try_join!(h1, h2, h3, h4).unwrap();
                        drop((r1, r2)); // ccf in initial is turstless, 0rtt dont transmit ccf
                        let mut rcvd_packets = r3.chain(r4);
                        while let Some((packet, pathway, usc)) = rcvd_packets.next().await {
                            closing.recv_packet_via_pathway(packet, pathway, usc).await;
                        }
                    }
                });
                tokio::spawn({
                    let conn = self.clone();
                    let rcvd_ccf = closing.get_rcvd_ccf();
                    async move {
                        let start = Instant::now();
                        let time = pto * 3;
                        match tokio::time::timeout(time, rcvd_ccf.did_recv()).await {
                            Ok(_) => conn.draining(pto * 3 - start.elapsed()),
                            Err(_) => conn.die(),
                        }
                    }
                });
            }
            Draining(..) => {
                drop(guard);
                drop(handles); // break the channels
                self.draining(pto * 3)
            }
            _ => unreachable!(),
        }
    }

    fn enter_draining(&self, error: Error) {
        let Some(pto) = self.0.lock().unwrap().deref_mut().enter_draining(error) else {
            // has been closed
            return;
        };

        self.draining(pto * 3);
    }

    /// Enter draining state from raw state or closing state.
    /// Can only be called internally, and the app should not care this method.
    fn draining(&self, remaining: Duration) {
        assert!(matches!(self.0.lock().unwrap().deref_mut(), Draining(..)));

        tokio::spawn({
            let conn = self.clone();
            async move {
                tokio::time::sleep(remaining).await;
                conn.die();
            }
        });
    }

    pub(crate) fn no_vaiable_path(self) {
        self.0.lock().unwrap().no_vaiable_path();
    }

    /// Dismiss the connection, remove it from the global router.
    /// Can only be called internally, and the app should not care this method.
    ///
    /// When the connection "die", is must enter the closing state or draining state first.
    fn die(self) {
        self.0.lock().unwrap().die();
    }

    pub fn update_path_recv_time(&self, pathway: Pathway) {
        let guard = self.0.lock().unwrap();
        if let ConnState::Normal(ref connection) = *guard {
            connection.update_path_recv_time(pathway);
        }
    }

    pub fn recv_retry_packet(&self, retry: &RetryHeader) {
        let guard = self.0.lock().unwrap();
        if let Normal(ref connection) = *guard {
            *connection.token.lock().unwrap() = retry.token.to_vec();
            connection
                .cid_registry
                .remote
                .revise_initial_dcid(retry.scid);
            let sent_journal = connection.initial.journal.of_sent_packets();
            let mut guard = sent_journal.rotate();
            for i in 0..guard.largest_pn() {
                for frame in guard.may_loss_pkt(i) {
                    connection
                        .initial
                        .crypto_stream
                        .outgoing()
                        .may_loss_data(&frame);
                }
            }
        }
    }

    pub fn is_active(&self) -> bool {
        let guard = self.0.lock().unwrap();
        !matches!(&*guard, ConnState::Normal(..))
    }
}

impl From<Connection> for ArcConnection {
    fn from(normal_conn: Connection) -> Self {
        let conn_error = normal_conn.error.clone();
        let connection = ArcConnection(Arc::new(Mutex::new(ConnState::Normal(normal_conn))));

        tokio::spawn({
            let conn = connection.clone();
            async move {
                let (err, kind) = conn_error.did_error_occur().await;
                if kind != crate::error::ConnErrorSource::Application {
                    log::error!("Connection is closed unexpectedly: {}", err)
                };
                match kind {
                    crate::error::ConnErrorSource::Application => {} // resolved by ArcConnection::close
                    crate::error::ConnErrorSource::Transport => conn.should_enter_closing(err),
                    crate::error::ConnErrorSource::ReceivedCcf => conn.enter_draining(err),
                    crate::error::ConnErrorSource::NoViablePath => conn.no_vaiable_path(),
                }
            }
        });

        connection
    }
}
#[cfg(test)]
mod tests {}
