use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::Arc,
};

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::cid::{ArcCidCell, ConnectionId};
use qcongestion::congestion::MSS;
use qrecovery::reliable::ArcReliableFrameDeque;
use qudp::{ArcUsc, Sender};

mod anti_amplifier;
mod raw;
mod state;
mod util;

pub mod read;

pub use anti_amplifier::ArcAntiAmplifier;
pub use raw::RawPath;
pub use util::{RecvBuffer, SendBuffer};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Pathway {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

pub trait ViaPathway {
    fn send_via_pathway<'a>(
        &mut self,
        iovecs: &'a [IoSlice<'a>],
        pathway: Pathway,
    ) -> qudp::Sender<'a>;

    fn sync_send_via_pathway(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()>;
}

impl ViaPathway for ArcUsc {
    fn send_via_pathway<'a>(
        &mut self,
        iovecs: &'a [IoSlice<'a>],
        pathway: Pathway,
    ) -> qudp::Sender<'a> {
        let (src, dst) = match &pathway {
            Pathway::Direct { local, remote } => (*local, *remote),
            // todo: append relay hdr
            Pathway::Relay { local, remote } => (local.addr, remote.agent),
        };

        Sender {
            usc: self.clone(),
            iovecs,
            hdr: qudp::PacketHeader {
                src,
                dst,
                ttl: 64,
                ecn: None,
                seg_size: MSS as u16,
                gso: true,
            },
        }
    }

    fn sync_send_via_pathway(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()> {
        let (src, dst) = match &pathway {
            Pathway::Direct { local, remote } => (*local, *remote),
            // todo: append relay hdr
            Pathway::Relay { local, remote } => (local.addr, remote.agent),
        };
        let hdr = qudp::PacketHeader {
            src,
            dst,
            ttl: 64,
            ecn: None,
            seg_size: MSS as u16,
            gso: true,
        };
        self.sync_send(iovec, hdr)
    }
}

#[derive(Clone, Deref)]
pub struct ArcPath(Arc<RawPath>);

impl ArcPath {
    pub fn new(usc: ArcUsc, scid: ConnectionId, dcid: ArcCidCell<ArcReliableFrameDeque>) -> Self {
        Self(Arc::new(RawPath::new(usc, scid, dcid)))
    }
}

#[derive(Deref, DerefMut)]
pub struct Pathes {
    #[deref]
    map: DashMap<Pathway, ArcPath>,
    creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
}

impl Pathes {
    fn new(creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>) -> Self {
        Self {
            map: DashMap::new(),
            creator,
        }
    }

    pub fn get(&self, pathway: Pathway, usc: ArcUsc) -> ArcPath {
        self.map
            .entry(pathway)
            .or_insert_with(|| {
                let path = (self.creator)(pathway, usc);
                let state = path.state.clone();
                let map = self.map.clone();
                tokio::spawn(async move {
                    state.has_been_inactivated().await;
                    map.remove(&pathway);
                });
                path
            })
            .value()
            .clone()
    }
}

#[derive(Clone, Deref, DerefMut)]
pub struct ArcPathes(Arc<Pathes>);

impl ArcPathes {
    pub fn new(creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>) -> Self {
        Self(Arc::new(Pathes::new(creator)))
    }
}
