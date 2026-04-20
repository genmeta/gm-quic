use qcongestion::Transport;
use tokio::time::Duration;

use crate::{path::PathDeactivated, tls::ArcTlsHandshake};

impl super::Path {
    pub async fn drive(&self, _tls_handshake: ArcTlsHandshake) -> Result<(), PathDeactivated> {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Some(frame) = self.idle_timer.health()? {
                self.heartbeat_sndbuf.write(frame);
            }
            self.cc.do_tick()?;
        }
    }
}
