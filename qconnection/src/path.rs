use std::sync::Arc;

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::cid::{ArcCidCell, ConnectionId};
use qcongestion::{CongestionControl, MayLoss, RetirePktRecord};
use qrecovery::reliable::ArcReliableFrameDeque;

mod anti_amplifier;
mod pathway;
mod raw;
mod read;
mod state;
mod util;

pub use anti_amplifier::ArcAntiAmplifier;
pub use pathway::{Pathway, RelayAddr};
pub use raw::Path;
pub use read::ReadIntoDatagrams;
pub use util::{RecvBuffer, SendBuffer};

use crate::usc::ArcUsc;

/// The shared version of [`Path`].
#[derive(Clone, Deref)]
pub struct ArcPath(Arc<Path>);

impl ArcPath {
    /// Create a new [`ArcPath`].
    ///
    /// Read [`Path::new`] for more information.
    pub fn new(
        usc: ArcUsc,
        scid: ConnectionId,
        dcid: ArcCidCell<ArcReliableFrameDeque>,
        loss: [Box<dyn MayLoss>; 3],
        retire: [Box<dyn RetirePktRecord>; 3],
    ) -> Self {
        Self(Arc::new(Path::new(usc, scid, dcid, loss, retire)))
    }
}

/// The set of all paths of a connection.
///
/// GM-QUIC supports multiple paths for a connection, each path corresponds to a [`Pathway`].
///
/// The main purpose of this structure is to manage all paths of connections. When other components
/// need to obtain a path, they can call [`Paths::get_or_create`] to get a existing path or create a
/// new path.
///
/// This structure is also responsible for automatically removing a path from the set when it becomes
/// inactive and terminating a connection when no path is available.
#[derive(Deref, DerefMut)]
pub struct Paths {
    #[deref]
    map: DashMap<Pathway, ArcPath>,
    creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
    on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
}

impl Paths {
    /// Create a new [`Paths`].
    ///
    /// There are two parameters:
    /// - `creator`:  When a path is obtained, but it does not exist, this function will be used to
    ///    create the path. The created paths will be automatically added to the collection and managed.
    ///
    /// - `on_no_path`: A function that will be called when there is no path in the set, this usually
    ///    means that the connection is no longer available. This function can set a connection error
    ///    and directly terminate the connection.
    pub fn new(
        creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
        on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        Self {
            map: DashMap::new(),
            on_no_path,
            creator,
        }
    }

    /// Get a path from the set, if the path does not exist, create a new path.
    ///
    /// The method used to create [`ArcPath`] is specified when creating [`Paths`], you can read
    /// [`Paths::new`] for more information.
    ///
    /// When a path is created, a task will be started to monitor the path. When the path is inactive,
    /// the path will be removed from the set. If there are no paths in the set, the function specified
    /// by `on_no_path`(read [`Paths::new`]) will be called.
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

/// The shared version of [`Paths`].
#[derive(Clone, Deref)]
pub struct ArcPathes(Arc<Paths>);

impl ArcPathes {
    /// Create a new [`ArcPathes`].
    ///
    /// Read [`Paths::new`] for more information.
    pub fn new(
        creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
        on_no_path: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Self {
        Self(Arc::new(Paths::new(creator, on_no_path)))
    }
}
