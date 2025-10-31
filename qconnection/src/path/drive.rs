use qbase::{Epoch, net::tx::Signals};
use qcongestion::Transport;
use tokio::time::Duration;

use crate::{path::PathDeactivated, tls::ArcTlsHandshake};

impl super::Path {
    pub async fn drive(&self, tls_handshake: ArcTlsHandshake) -> Result<(), PathDeactivated> {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if matches!(tls_handshake.is_finished(), Ok(true)) {
                self.max_idle_timer.run_out(self.cc.get_pto(Epoch::Data))?;
            }
            if self.heartbeat.need_trigger() {
                self.tx_waker.wake_by(Signals::TRANSPORT);
            }
            self.cc.do_tick()?;
        }
    }
}
