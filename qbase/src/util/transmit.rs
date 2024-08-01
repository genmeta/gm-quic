#[derive(Debug, Clone, Copy)]
pub struct Burst {
    /// *`anti-amplification`*
    anti_amplification: Option<usize>,
    /// *`congestion control`*
    congestion_control: usize,
    /// flow control
    /// [`InitialSpace`] and [`HandshakeSpace`] ignore this
    flow_control: usize,
}

impl Burst {
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

    pub fn available(&self) -> usize {
        if let Some(aa) = self.anti_amplification {
            aa.min(self.congestion_control)
        } else {
            self.congestion_control
        }
    }

    pub fn flow_control_limit(&self) -> usize {
        self.flow_control
    }

    pub fn post_write(&mut self, written: usize) {
        if let Some(ref mut aa) = self.anti_amplification {
            *aa -= written
        };
        self.congestion_control -= written;
    }

    pub fn post_write_new_stream_data(&mut self, fresh: usize) {
        self.flow_control -= fresh;
    }
}
