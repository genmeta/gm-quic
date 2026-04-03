use std::fmt;

use qbase::frame::{AddAddressFrame, PunchDoneFrame, PunchKnockFrame, PunchMeNowFrame};

pub(super) mod predictor;
pub mod puncher;
pub(super) mod scheduler;
pub(super) mod tx;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqPair {
    pub local_seq: u32,
    pub remote_seq: u32,
}

impl SeqPair {
    pub fn new(local_seq: u32, remote_seq: u32) -> Self {
        Self {
            local_seq,
            remote_seq,
        }
    }

    pub fn flip(self) -> Self {
        Self {
            local_seq: self.remote_seq,
            remote_seq: self.local_seq,
        }
    }
}

impl fmt::Display for SeqPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.local_seq, self.remote_seq)
    }
}

pub trait AsSeqPair {
    fn seq_pair(&self) -> SeqPair;
}

impl AsSeqPair for PunchKnockFrame {
    fn seq_pair(&self) -> SeqPair {
        SeqPair::new(self.local_seq(), self.remote_seq())
    }
}

impl AsSeqPair for PunchDoneFrame {
    fn seq_pair(&self) -> SeqPair {
        SeqPair::new(self.local_seq(), self.remote_seq())
    }
}

impl AsSeqPair for PunchMeNowFrame {
    fn seq_pair(&self) -> SeqPair {
        SeqPair::new(self.local_seq(), self.remote_seq())
    }
}

impl AsSeqPair for (&AddAddressFrame, &AddAddressFrame) {
    fn seq_pair(&self) -> SeqPair {
        SeqPair::new(self.0.seq_num(), self.1.seq_num())
    }
}
