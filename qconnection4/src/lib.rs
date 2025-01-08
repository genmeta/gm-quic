pub mod events;
pub mod path;
pub mod space;
pub mod termination;
pub mod tls;
pub mod tx;

pub mod builder;

use std::sync::{Arc, RwLock};

use path::{entry::PacketEntry, ArcPaths};
use qbase::{cid, error::Error, flow, param::ArcParameters, token::ArcTokenRegistry};
use qinterface::{conn::ConnInterface, router::RouterRegistry};
use qrecovery::{
    recv,
    reliable::ArcReliableFrameDeque,
    send,
    streams::{self, Ext},
};
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
    _cid_registry: CidRegistry,
    // for closing space to enter draining state
    packet_entry: Arc<PacketEntry>,
    is_draining: bool,
}

pub struct Connection(RwLock<Result<CoreConnection, Termination>>);
