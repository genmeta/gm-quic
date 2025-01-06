use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use qbase::Epoch;
use qcongestion::CongestionControl;

use super::{Path, Pathway};

#[derive(Clone)]
pub struct ArcPaths(Arc<DashMap<Pathway, Arc<Path>>>);

impl Default for ArcPaths {
    fn default() -> Self {
        Self::new()
    }
}

impl ArcPaths {
    pub fn new() -> Self {
        let arc_paths = Self(Arc::new(DashMap::new()));
        tokio::spawn({
            let arc_paths = arc_paths.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_micros(10)).await;
                    for path in arc_paths.0.iter() {
                        path.cc.do_tick();
                    }
                }
            }
        });
        arc_paths
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.0.get(pathway).map(|arc| arc.value().clone())
    }

    pub fn entry(&self, pathway: Pathway) -> dashmap::Entry<'_, Pathway, Arc<Path>> {
        self.0.entry(pathway)
    }

    pub fn del(&self, pathway: &Pathway) {
        self.0.remove(pathway);
    }

    pub fn exist_paths(&self) -> usize {
        self.0.len()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.0.iter().map(|p| p.cc.pto_time(Epoch::Data)).max()
    }

    pub fn launch_ticker(self: &Arc<Self>) {}
}
