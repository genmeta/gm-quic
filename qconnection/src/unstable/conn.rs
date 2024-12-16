use futures::channel::mpsc;
use qbase::{cid, flow, packet::DataPacket};
use qrecovery::{
    recv,
    reliable::ArcReliableFrameDeque,
    send,
    streams::{self, Ext},
};

use super::{path::Pathway, router::RouterRegistry, usc::ArcUsc};

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
