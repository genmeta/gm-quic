#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    /// *`anti-amplification`*
    anti_amplification: Option<usize>,
    /// *`congestion control`*
    congestion_control: usize,
    /// flow control
    /// [`InitialSpace`] and [`HandshakeSpace`] ignore this
    flow_control: usize,
}

impl Constraints {
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

    /// 根据自身信息，以及hdr_len和buf_len，计算出可以写入的量，包括拥塞量、抗放大余量、新数据量
    pub fn measure(&self, data_len: usize, buf_len: usize) -> Option<Constraints> {
        None
    }
}
