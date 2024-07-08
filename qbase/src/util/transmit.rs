#[derive(Debug, Clone, Copy)]
pub struct TransportLimit {
    /// *`anti-amplification`*
    anti_amplification: Option<usize>,
    /// *`congestion control`*
    congestion_control: usize,
    /// flow control
    /// [`InitialSpace`] and [`HandshakeSpace`] ignore this
    flow_control: usize,
}

impl TransportLimit {
    pub fn new(
        anti_amplification: Option<usize>,
        congestion_control: usize,
        flow_control: usize,
    ) -> Self {
        Self {
            anti_amplification,
            congestion_control,
            flow_control,
        }
    }

    pub fn remaining(&self) -> usize {
        self.anti_amplification
            .map(|aa| aa.min(self.congestion_control))
            .unwrap_or(self.congestion_control)
    }

    pub fn flow_control_limit(&self) -> usize {
        self.flow_control
    }

    pub fn record_write(&mut self, written: usize) {
        if let Some(ref mut aa) = self.anti_amplification {
            *aa -= written
        };
        self.congestion_control -= written;
    }

    pub fn record_write_new_stream_data(&mut self, written: usize) {
        self.flow_control -= written;
    }
}
