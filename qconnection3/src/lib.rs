use qbase::{cid, flow, param, token};
use qrecovery::{
    recv,
    reliable::{self, ArcReliableFrameDeque},
    send,
    streams::{self, Ext},
};

pub mod events;
pub mod interface;
pub mod path;
pub mod router;
pub mod space;
pub mod tls;
pub mod tx;
pub mod util;

pub type ArcLocalCids = cid::ArcLocalCids<router::RouterRegistry<reliable::ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<reliable::ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<reliable::ArcReliableFrameDeque>;

pub struct Components {
    parameters: param::ArcParameters,
    tls_session: tls::ArcTlsSession,
    handshake: Handshake,
    token_registry: token::ArcTokenRegistry,
    cid_registry: CidRegistry,
    flow_ctrl: FlowController,
}
