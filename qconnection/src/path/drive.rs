use qbase::{Epoch, time::IdleTimedOut};
use qcongestion::Transport;
use tokio::time::{self, Duration};

use crate::tls::ArcTlsHandshake;

impl super::Path {
    pub async fn drive(&self, tls_handshake: ArcTlsHandshake) -> Result<(), IdleTimedOut> {
        let mut interval = time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            if matches!(tls_handshake.is_finished(), Ok(true)) {
                self.max_idle_timer.check(self.cc.get_pto(Epoch::Data))?;
            }
            self.cc.do_tick();
        }
    }
}
