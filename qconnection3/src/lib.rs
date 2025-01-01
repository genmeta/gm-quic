use futures::channel::mpsc;
use path::Pathway;
use qbase::{flow, packet::DataPacket};
use qrecovery::{
    recv,
    reliable::{self, ArcReliableFrameDeque},
    send,
    streams::{self, Ext},
};

pub mod events;
pub mod interface;
pub mod path;
pub mod space;
pub mod tls;
pub mod tx;

pub type RcvdPackets = mpsc::UnboundedReceiver<(DataPacket, Pathway)>;

pub type FlowController = flow::FlowController<ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<Ext<ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<Ext<ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<reliable::ArcReliableFrameDeque>;
