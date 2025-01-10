use crate::Termination;

impl Termination {
    pub fn enter_draining(&mut self) {
        if core::mem::replace(&mut self.is_draining, true) {
            return;
        }
        self.rvd_pkt_buf.close();
    }
}
