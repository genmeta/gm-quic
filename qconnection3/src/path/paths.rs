use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use qbase::Epoch;
use qcongestion::CongestionControl;
use tokio::task::AbortHandle;

use super::{Path, Pathway};

#[derive(Clone)]
pub struct ArcPaths {
    paths: Arc<DashMap<Pathway, Arc<Path>>>,
    ticker: AbortHandle,
}

impl Default for ArcPaths {
    fn default() -> Self {
        Self::new()
    }
}

impl ArcPaths {
    pub fn new() -> Self {
        let paths: Arc<DashMap<Pathway, Arc<Path>>> = Arc::new(DashMap::new());
        let ticker = tokio::spawn({
            let arc_paths = paths.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_micros(10)).await;
                    for path in arc_paths.iter() {
                        path.value().cc.do_tick();
                    }
                }
            }
        })
        .abort_handle();
        Self { paths, ticker }
    }

    pub fn get(&self, pathway: &Pathway) -> Option<Arc<Path>> {
        self.paths.get(pathway).map(|arc| arc.value().clone())
    }

    pub fn entry(&self, pathway: Pathway) -> dashmap::Entry<'_, Pathway, Arc<Path>> {
        self.paths.entry(pathway)
    }

    pub fn del(&self, pathway: &Pathway) {
        self.paths.remove(pathway);
    }

    pub fn exist_paths(&self) -> usize {
        self.paths.len()
    }

    pub fn max_pto_duration(&self) -> Option<Duration> {
        self.paths.iter().map(|p| p.cc.pto_time(Epoch::Data)).max()
    }

    pub fn clear(&self) {
        self.ticker.abort();
        self.paths.clear();
    }
}
