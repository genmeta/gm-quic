use std::sync::Arc;

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::cid::{ArcCidCell, ConnectionId};
use qcongestion::{CongestionControl, MayLoss, RetirePktRecord};
use qrecovery::reliable::ArcReliableFrameDeque;

mod anti_amplifier;
mod raw;
mod state;
mod util;

pub mod pathway;
pub mod read;

pub use anti_amplifier::ArcAntiAmplifier;
pub use pathway::Pathway;
pub use raw::RawPath;
pub use util::{RecvBuffer, SendBuffer};

use crate::usc::ArcUsc;

#[derive(Clone, Deref)]
pub struct ArcPath(Arc<RawPath>);

impl ArcPath {
    pub fn new(
        usc: ArcUsc,
        scid: ConnectionId,
        dcid: ArcCidCell<ArcReliableFrameDeque>,
        loss: [Box<dyn MayLoss>; 3],
        retire: [Box<dyn RetirePktRecord>; 3],
    ) -> Self {
        Self(Arc::new(RawPath::new(usc, scid, dcid, loss, retire)))
    }
}

#[derive(Deref, DerefMut)]
pub struct Pathes {
    #[deref]
    map: DashMap<Pathway, ArcPath>,
    creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
    on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
}

impl Pathes {
    fn new(
        creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
        on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        Self {
            map: DashMap::new(),
            on_no_path,
            creator,
        }
    }

    pub fn get_or_create(&self, pathway: Pathway, usc: ArcUsc) -> ArcPath {
        let pathes = self.map.clone();
        let on_no_path = self.on_no_path.clone();

        self.map
            .entry(pathway)
            .or_insert_with(|| {
                let path = (self.creator)(pathway, usc);
                let state = path.state.clone();
                tokio::spawn({
                    let state = state.clone();
                    let cc = path.cc.clone();
                    async move {
                        loop {
                            tokio::select! {
                                _ = state.has_been_inactivated() => break,
                                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => cc.do_tick(),
                            }
                        }
                        pathes.remove(&pathway);
                        if pathes.is_empty() {
                            (on_no_path)();
                        }
                    }
                });
                path
            })
            .value()
            .clone()
    }
}

#[derive(Clone, Deref)]
pub struct ArcPathes(Arc<Pathes>);

impl ArcPathes {
    pub fn new(
        creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
        on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        Self(Arc::new(Pathes::new(creator, on_no_path)))
    }
}
