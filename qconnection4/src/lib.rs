pub mod events;
pub mod path;
pub mod space;
pub mod termination;
pub mod tls;
pub mod tx;

pub mod prelude {
    pub use qbase::{frame::ConnectionCloseFrame, sid::StreamId, varint::VarInt};
    pub use qinterface::{
        path::{Endpoint, Pathway},
        router::{QuicListener, QuicProto},
        QuicInterface,
    };
    pub use qunreliable::{UnreliableReader, UnreliableWriter};

    pub use crate::{events::Event, Connection, StreamReader, StreamWriter};
}

pub mod builder;

use std::{
    io,
    sync::{Arc, RwLock},
};

use events::EmitEvent;
use path::{entry::PacketEntry, ArcPaths};
use qbase::{
    cid,
    error::Error,
    flow,
    frame::ConnectionCloseFrame,
    param::{self, ArcParameters},
    sid::StreamId,
    token::ArcTokenRegistry,
};
use qinterface::{conn::ConnInterface, path::Pathway, router::RouterRegistry};
use qrecovery::{
    recv,
    reliable::ArcReliableFrameDeque,
    send,
    streams::{self, Ext},
};
use qunreliable::{UnreliableReader, UnreliableWriter};
use space::Spaces;
use tls::ArcTlsSession;

pub type ArcLocalCids = cid::local_cid2::ArcLocalCids<RouterRegistry<ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<ArcReliableFrameDeque>;
pub type ArcPacketEntry = Arc<path::entry::PacketEntry>;

#[derive(Clone)]
pub struct Components {
    parameters: ArcParameters,
    tls_session: ArcTlsSession,
    handshake: Handshake,
    token_registry: ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
}

#[derive(Clone)]
pub struct CoreConnection {
    components: Components,
    packet_entry: ArcPacketEntry,
    paths: ArcPaths,
    spaces: Spaces,
    conn_iface: Arc<ConnInterface>,
}

#[derive(Clone)]
pub struct Termination {
    // for generate io::Error
    error: Error,
    // keep this to keep the routing
    _local_cids: ArcLocalCids,
    // for closing space to enter draining state
    packet_entry: Arc<PacketEntry>,
    is_draining: bool,
}

pub struct Connection(RwLock<Result<CoreConnection, Termination>>);

impl Connection {
    pub fn enter_closing<EE>(&self, ccf: ConnectionCloseFrame, event_broker: EE)
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let mut conn = self.0.write().unwrap();
        if let Ok(core_conn) = conn.as_mut() {
            *conn = Err(core_conn.clone().enter_closing(ccf, event_broker));
        }
    }

    pub fn enter_draining<EE>(&self, ccf: ConnectionCloseFrame, event_broker: EE)
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let error = ccf.into();
        let mut conn = self.0.write().unwrap();
        match conn.as_mut() {
            Ok(core_conn) => *conn = Err(core_conn.clone().enter_draining(error, event_broker)),
            Err(closing_conn) if !closing_conn.is_draining => closing_conn.enter_draining(),
            Err(_draining) => {}
        }
    }

    fn map<T>(&self, map: impl Fn(&CoreConnection) -> T) -> io::Result<T> {
        let guard = self.0.read().unwrap();
        guard.as_ref().map(map).map_err(|e| e.error.clone().into())
    }

    pub async fn open_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams.clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_bi(remote.initial_max_stream_data_bidi_remote().into())
            .await;
        Ok(result?)
    }

    pub async fn open_uni_stream(&self) -> io::Result<Option<(StreamId, StreamWriter)>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams.clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .open_uni(remote.initial_max_stream_data_uni().into())
            .await;
        Ok(result?)
    }

    pub async fn accept_bi_stream(
        &self,
    ) -> io::Result<Option<(StreamId, (StreamReader, StreamWriter))>> {
        let (params, streams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.streams.clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        let result = streams
            .accept_bi(remote.initial_max_stream_data_bidi_local().into())
            .await;
        Ok(Some(result?))
    }

    pub async fn accept_uni_stream(&self) -> io::Result<Option<(StreamId, StreamReader)>> {
        let (streams,) = self.map(|core_conn| (core_conn.spaces.data.streams.clone(),))?;
        let result = streams.accept_uni().await;
        Ok(Some(result?))
    }

    pub fn unreliable_reader(&self) -> io::Result<UnreliableReader> {
        self.map(|core_conn| core_conn.spaces.data.datagrams.reader())?
    }

    pub async fn unreliable_writer(&self) -> io::Result<UnreliableWriter> {
        let (params, datagrams) = self.map(|core_conn| {
            (
                core_conn.components.parameters.clone(),
                core_conn.spaces.data.datagrams.clone(),
            )
        })?;
        let param::Pair { remote, .. } = params.await?;
        datagrams.writer(remote.max_datagram_frame_size().into())
    }

    pub fn add_path(&self, pathway: Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.add_path(pathway))
    }

    pub fn del_path(&self, pathway: Pathway) -> io::Result<()> {
        self.map(|core_conn| core_conn.del_path(pathway))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let state = self.0.read().unwrap();
        assert!(state.is_err(), "Connection must be closed before drop");
    }
}
