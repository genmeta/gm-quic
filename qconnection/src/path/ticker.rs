use std::{sync::Arc, time::Duration};

use qcongestion::CongestionControl;

use super::Path;

pub struct Ticker {
    path: Arc<Path>,
}

impl super::Path {
    pub fn new_ticker(self: &Arc<Self>) -> Ticker {
        Ticker { path: self.clone() }
    }
}

impl Ticker {
    pub async fn launch(self) {
        loop {
            tokio::time::sleep(Duration::from_micros(10)).await;
            self.path.cc.do_tick();
        }
    }
}
