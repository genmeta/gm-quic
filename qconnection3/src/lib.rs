use std::{
    io,
    sync::{Arc, RwLock},
};

use events::EmitEvent;
use path::{entry::PacketEntry, ArcPaths};
use qbase::{
    cid, error::Error, flow, frame::ConnectionCloseFrame, param::ArcParameters,
    token::ArcTokenRegistry,
};
use qrecovery::{
    recv,
    reliable::{self, ArcReliableFrameDeque},
    send,
    streams::{self, Ext},
};
use router::ConnInterface;
use space::Spaces;
use tls::ArcTlsSession;

pub mod events;
pub mod interface;
pub mod path;
pub mod router;
pub mod space;
pub mod termination;
pub mod tls;
pub mod tx;
pub mod util;

pub mod prelude {}

pub mod builder;

pub type ArcLocalCids = cid::ArcLocalCids<router::RouterRegistry<reliable::ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<reliable::ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<reliable::ArcReliableFrameDeque>;

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
    spaces: Spaces,
    paths: ArcPaths,
    conn_iface: Arc<ConnInterface>,
    packet_entry: Arc<PacketEntry>,
}

#[derive(Clone)]
pub struct Termination {
    error: Error,
    cid_registry: CidRegistry,
    conn_iface: Arc<ConnInterface>,
    packet_entry: Arc<PacketEntry>,
    is_draining: bool,
}

pub struct Connection(RwLock<Result<CoreConnection, Termination>>);

impl Connection {
    pub fn enter_closing<EE>(&self, error: Error, event_broker: EE)
    where
        EE: EmitEvent + Send + Clone + 'static,
    {
        let mut conn = self.0.write().unwrap();
        if let Ok(core_conn) = conn.as_mut() {
            *conn = Err(core_conn.clone().enter_closing(error, event_broker));
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

    pub fn stateless(&self) {
        let conn = self.0.read().unwrap();
        let (cid_registry, conn_iface) = match conn.as_ref() {
            Ok(conn) => (&conn.components.cid_registry, &conn.conn_iface),
            Err(conn) => (&conn.cid_registry, &conn.conn_iface),
        };

        // TODO: store stateless token in QuicProto
        cid_registry.local.freeze();
        for cid in cid_registry.local.active_cids() {
            conn_iface.router_if().unregister(&cid.into());
        }
    }

    fn map<T>(&self, map: impl Fn(&CoreConnection) -> T) -> io::Result<T> {
        let guard = self.0.read().unwrap();
        guard.as_ref().map(map).map_err(|e| e.error.clone().into())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.stateless();
    }
}
