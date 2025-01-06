use std::sync::{Arc, RwLock};

use path::{entry::PacketEntry, ArcPaths};
use qbase::{cid, flow, param::ArcParameters, token::ArcTokenRegistry};
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

pub struct CoreConnection {
    components: Components,
    spaces: Spaces,
    paths: ArcPaths,
    conn_iface: Arc<ConnInterface>,
    packet_entry: Arc<PacketEntry>,
}

pub struct Connection(RwLock<Result<CoreConnection, ()>>);
