use std::collections::VecDeque;

use crate::packets::{AckedPackets, SentPacket};

// pub(crate) mod bbr;
pub(crate) mod new_reno;

/// The [`CongestionAlgorithm`] enum represents different congestion control algorithms that can be used.
pub enum Algorithm {
    Bbr,
    NewReno,
}

pub trait Control: Send {
    fn on_sent(&mut self, sent: &mut SentPacket, sent_bytes: usize);

    fn on_ack(&mut self, packet: VecDeque<AckedPackets>);

    fn on_congestion_event(&mut self, lost: &SentPacket);

    fn cwnd(&self) -> u64;

    fn pacing_rate(&self) -> Option<u64>;
}
