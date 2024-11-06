use std::{
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub use congestion::{ArcCC, CongestionAlgorithm, MSS};
use qbase::frame::AckFrame;
use qrecovery::journal::Epoch;

mod bbr;
mod congestion;
mod delivery_rate;
mod min_max;
mod new_reno;
mod pacing;
mod rtt;

/// The [`CongestionControl`] trait defines the interface for congestion control algorithms.
pub trait CongestionControl {
    /// Performs a periodic tick to drive the congestion control algorithm.
    fn do_tick(&self);

    /// Polls whether packets can be sent and returns the amount of data that can be sent.
    /// # Returns
    /// A [`Poll`] indicating readiness to send and the amount of data that can be sent.
    fn poll_send(&self, cx: &mut Context<'_>) -> Poll<usize>;

    /// Checks if an AckFrame should be sent in the next packet for the given epoch.
    /// # Returns
    /// An [`Option`] containing the largest packet ID and the time it was received if an AckFrame is needed.
    fn need_ack(&self, space: Epoch) -> Option<(u64, Instant)>;

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

    /// Updates the congestion control state upon receiving an AckFrame.
    fn on_ack(&self, space: Epoch, ack_frame: &AckFrame);

    /// Records the receipt of a packet, which may influence future packet transmissions.
    /// # Parameters
    /// - `pn`: The packet number of the received packet.
    /// - `is_ack_elicition`: A boolean indicating whether the received packet is ack-eliciting.
    fn on_pkt_rcvd(&self, space: Epoch, pn: u64, is_ack_elicition: bool);

    /// Retrieves the current path's PTO duration.
    /// # Returns
    /// The current PTO duration for the given epoch.
    fn pto_time(&self, epoch: Epoch) -> Duration;

    /// Handles the update of the handshake key state.
    fn on_get_handshake_keys(&self);

    /// Indicates that the handshake process has been completed.
    fn on_handshake_done(&self);
}

/// The [`MayLoss`] trait is used to handle potential packet losses.
pub trait MayLoss: Send + Sync {
    /// Indicates that a packet with the specified packet number may have been lost.
    /// # Parameters
    /// - `pn`: The packet number of the potentially lost packet.
    fn may_loss(&self, pn: u64);
}

/// The [`RetirePktRecord`] trait is used to retire packet records that are no longer needed.
pub trait RetirePktRecord: Send + Sync {
    /// Retires a packet record with the specified packet number in recv buffer.
    /// # Parameters
    /// - `pn`: The packet number of the packet record to retire.
    fn retire(&self, pn: u64);
}
