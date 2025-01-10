use crate::Termination;

impl Termination {
    pub fn enter_draining(&mut self) {
        if core::mem::replace(&mut self.is_draining, true) {
            return;
        }
        self.rvd_pkt_buf.initial.close();
        self.rvd_pkt_buf.handshake.close();
        // zero_rtt has already closed
        self.rvd_pkt_buf.one_rtt.close();
    }
}
