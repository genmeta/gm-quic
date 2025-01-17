use std::time::Duration;

use qcongestion::CongestionControl;

impl super::Path {
    pub async fn do_ticks(&self) {
        loop {
            tokio::time::sleep(Duration::from_micros(10)).await;
            self.cc.do_tick();
        }
    }
}
