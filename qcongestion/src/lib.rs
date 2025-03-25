use std::time::{Duration, Instant};

use qbase::{
    Epoch,
    frame::AckFrame,
    net::tx::{ArcSendWaker, Signals},
};
use qlog::quic::recovery::PacketLostTrigger;
use tokio::task::AbortHandle;

mod algorithm;
pub use algorithm::Algorithm;
mod congestion;
pub use congestion::ArcCC;
mod pacing;
mod packets;
mod rtt;
mod status;
pub use status::{HandshakeStatus, PathStatus};

///  default datagram size in bytes.
pub const MSS: usize = 1200;

/// The [`Transport`] trait defines the interface for congestion control algorithms.
pub trait Transport {
    /// Performs a periodic tick to drive the congestion control algorithm.
    fn launch_with_waker(&self, tx_waker: ArcSendWaker) -> AbortHandle;

    fn send_quota(&self, expect_quota: usize) -> Result<usize, Signals>;

    fn retransmit_and_expire_time(&self, epoch: Epoch) -> (Duration, Duration);

    /// Records the sending of a packet, which may affect congestion control state.
    /// # Parameters
    /// - `pn`: The packet number of the sent packet.
    /// - `is_ack_eliciting`: A boolean indicating whether the packet is ack-eliciting.
    /// - `sent_bytes`: The number of bytes sent in this packet.
    /// - `in_flight`: A boolean indicating whether the packet is considered in-flight.
    /// - `ack`: An optional `u64` representing the largest acknowledged packet number if an AckFrame was included.
    fn on_pkt_sent(
        &self,
        epoch: Epoch,
        pn: u64,
        is_ack_eliciting: bool,
        sent_bytes: usize,
        in_flight: bool,
        ack: Option<u64>,
    );

    /// Records the receipt of a packet, which may influence future packet transmissions.
    /// # Parameters
    /// - `pn`: The packet number of the received packet.
    /// - `is_ack_elicition`: A boolean indicating whether the received packet is ack-eliciting.
    fn on_pkt_rcvd(&self, space: Epoch, pn: u64, is_ack_elicition: bool);

    /// Checks if an AckFrame should be sent in the next packet for the given epoch.
    /// # Returns
    /// An [`Option`] containing the largest packet ID and the time it was received if an AckFrame is needed.
    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)>;

    fn need_send_ack_eliciting(&self, space: Epoch) -> usize;

    /// Updates the congestion control state upon receiving an AckFrame.
    fn on_ack_rcvd(&self, space: Epoch, ack_frame: &AckFrame);

    /// Retrieves the current path's PTO duration.
    /// # Returns
    /// The current PTO duration for the given epoch.
    fn get_pto(&self, epoch: Epoch) -> Duration;

    fn discard_epoch(&self, epoch: Epoch);

    fn grant_anti_amplifier(&self);
}

/// The [`Feedback`] trait defines the interface for packet tracking
pub trait Feedback: Send + Sync {
    /// Indicates that a packet with the specified packet number may have been lost.
    /// # Parameters
    /// - `pn`: The packet number of the potentially lost packet.
    fn may_loss(&self, trigger: PacketLostTrigger, pns: &mut dyn Iterator<Item = u64>);
}
