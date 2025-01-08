pub mod events;
pub mod path;
pub mod space;
pub mod tls;
pub mod tx;

use std::sync::Arc;

use path::ArcPaths;
use qbase::{cid, flow, param::ArcParameters, token::ArcTokenRegistry};
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
