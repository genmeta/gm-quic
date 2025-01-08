use crate::Termination;

impl Termination {
    pub fn enter_draining(&mut self) {
        if core::mem::replace(&mut self.is_draining, true) {
            return;
        }
        self.packet_entry.initial.close();
        self.packet_entry.handshake.close();
        // zero_rtt has already closed
        self.packet_entry.one_rtt.close();
    }
}
