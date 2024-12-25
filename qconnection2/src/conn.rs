use std::sync::Mutex;

use deref_derive::*;
use qbase::{cid, flow};
use qrecovery::{recv, reliable, send, streams};

use super::router::RouterRegistry;
use crate::{builder, dying};

pub type ArcLocalCids = cid::ArcLocalCids<RouterRegistry<reliable::ArcReliableFrameDeque>>;
pub type ArcRemoteCids = cid::ArcRemoteCids<reliable::ArcReliableFrameDeque>;
pub type CidRegistry = cid::Registry<ArcLocalCids, ArcRemoteCids>;

pub type FlowController = flow::FlowController<reliable::ArcReliableFrameDeque>;
pub type Credit<'a> = flow::Credit<'a, reliable::ArcReliableFrameDeque>;

pub type DataStreams = streams::DataStreams<reliable::ArcReliableFrameDeque>;
pub type StreamWriter = send::Writer<streams::Ext<reliable::ArcReliableFrameDeque>>;
pub type StreamReader = recv::Reader<streams::Ext<reliable::ArcReliableFrameDeque>>;

pub type Handshake = qbase::handshake::Handshake<reliable::ArcReliableFrameDeque>;

#[derive(Deref, DerefMut)]
pub struct Connection(Mutex<Result<builder::CoreConnection, dying::DyingConnection>>);
