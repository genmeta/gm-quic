use std::time::Instant;

use qbase::{Epoch, frame::AckFrame};
use qlog::quic::recovery::RecoveryMetricsUpdated;

use crate::{
    MSS,
    algorithm::Control,
    packets::{SentPacket, State},
};

// The upper bound for the initial window will be
// min (10*MSS, max (2*MSS, 14600))
// See https://datatracker.ietf.org/doc/html/rfc6928#autoid-3
const INIT_CWND: usize = 10 * MSS;
// The RECOMMENDED value is 2 * max_datagram_size.
// See https://datatracker.ietf.org/doc/html/rfc9002#name-initial-and-minimum-congest
const MININUM_WINDOW: usize = 2 * MSS;
const INFINITRE_SSTHRESH: usize = usize::MAX;

pub(crate) struct NewReno {
    max_datagram_size: usize,
    ecn_ce_counters: [u64; Epoch::count()],
    bytes_in_flight: usize,
    congestion_window: usize,
    congestion_recovery_start_time: Option<Instant>,
    ssthresh: usize,
}

impl From<&NewReno> for RecoveryMetricsUpdated {
    fn from(reno: &NewReno) -> Self {
        qlog::build!(RecoveryMetricsUpdated {
            congestion_window: reno.congestion_window as u64,
            ssthresh: reno.ssthresh as u64,
        })
    }
}

impl NewReno {
    /// B.3. Initialization
    pub(crate) fn new() -> Self {
        NewReno {
            max_datagram_size: MSS,
            ecn_ce_counters: [0, 0, 0],
            congestion_window: INIT_CWND,
            bytes_in_flight: 0,
            congestion_recovery_start_time: None,
            ssthresh: INFINITRE_SSTHRESH,
        }
    }

    /// B.4. On Packet Sent
    /// OnPacketSentCC(sent_bytes):
    /// . bytes_in_flight += sent_bytes
    fn on_packet_sent_cc(&mut self, sent_bytes: usize) {
        self.bytes_in_flight += sent_bytes;
    }

    /// B.5. On Packet Acknowledgment
    /// InCongestionRecovery(sent_time):
    ///   return sent_time <= congestion_recovery_start_time
    fn in_congestion_recovery(&self, sent_time: &Instant) -> bool {
        self.congestion_recovery_start_time
            .map(|recovery_start_time| *sent_time <= recovery_start_time)
            .unwrap_or(false)
    }

    /// OnPacketAcked(acked_packet):
    ///   if (!acked_packet.in_flight):
    ///     return;
    ///   // Remove from bytes_in_flight.
    ///   bytes_in_flight -= acked_packet.sent_bytes
    ///   // Do not increase congestion_window if application
    ///   // limited or flow control limited.
    ///   if (IsAppOrFlowControlLimited())
    ///     return
    ///   // Do not increase congestion window in recovery period.
    ///   if (InCongestionRecovery(acked_packet.time_sent)):
    ///     return
    ///   if (congestion_window < ssthresh):
    ///     // Slow start.
    ///     congestion_window += acked_packet.sent_bytes
    ///   else:
    ///     // Congestion avoidance.
    ///     congestion_window +=
    ///       max_datagram_size * acked_packet.sent_bytes
    ///       / congestion_window
    fn on_packet_acked(&mut self, acked_packet: &SentPacket) {
        if !acked_packet.count_for_cc {
            return;
        }
        // 如果不是 inflight 状态，说明已经丢包重传了
        if acked_packet.state == State::Inflight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_packet.sent_bytes);
        }
        // 如果是 Retranmit 状态，又被 ack， 把拥塞窗口加回来
        if self.in_congestion_recovery(&acked_packet.time_sent) {
            return;
        }
        if self.congestion_window < self.ssthresh {
            self.congestion_window += acked_packet.sent_bytes;
        } else {
            self.congestion_window +=
                self.max_datagram_size * acked_packet.sent_bytes / self.congestion_window;
        }
    }

    /// B.6. On New Congestion Event
    /// OnCongestionEvent(sent_time):
    ///   // No reaction if already in a recovery period.
    ///   if (InCongestionRecovery(sent_time)):
    ///     return
    ///   // Enter recovery period.
    ///   congestion_recovery_start_time = now()
    ///   ssthresh = congestion_window * kLossReductionFactor
    ///   congestion_window = max(ssthresh, kMinimumWindow)
    ///   // A packet can be sent to speed up loss recovery.
    ///   MaybeSendOnePacket()
    fn on_congestion_event(&mut self, sent_time: &Instant) {
        if self.in_congestion_recovery(sent_time) {
            return;
        }

        let now = tokio::time::Instant::now().into_std();
        self.congestion_recovery_start_time = Some(now);
        // WARN: will be zero
        self.ssthresh = self.congestion_window - MSS;
        self.congestion_window = self.ssthresh.max(MININUM_WINDOW);
        // A packet can be sent to speed up loss recovery.
        // self.maybe_send_packet(1);
    }

    /// B.7. Process ECN Information
    /// ProcessECN(ack, pn_space):
    ///   // If the ECN-CE counter reported by the peer has increased,
    ///   // this could be a new congestion event.
    ///   if (ack.ce_counter > ecn_ce_counters[pn_space]):
    ///     ecn_ce_counters[pn_space] = ack.ce_counter
    ///     sent_time = sent_packets[ack.largest_acked].time_sent
    ///     OnCongestionEvent(sent_time)
    fn process_ecn(&mut self, ack: &AckFrame, sent_time: &Instant, epoch: Epoch) {
        if let Some(ecn) = ack.ecn() {
            if ecn.ce() > self.ecn_ce_counters[epoch] {
                self.ecn_ce_counters[epoch] = ecn.ce();
                self.on_congestion_event(sent_time);
            }
        }
    }

    /// B.8. On Packets Lost
    /// OnPacketsLost(lost_packets):
    ///   sent_time_of_last_loss = 0
    ///   // Remove lost packets from bytes_in_flight.
    ///   for lost_packet in lost_packets:
    ///     if lost_packet.in_flight:
    ///       bytes_in_flight -= lost_packet.sent_bytes
    ///       sent_time_of_last_loss =
    ///         max(sent_time_of_last_loss, lost_packet.time_sent)
    ///   // Congestion event if in-flight packets were lost
    ///   if (sent_time_of_last_loss != 0):
    ///     OnCongestionEvent(sent_time_of_last_loss)
    ///   // Reset the congestion window if the loss of these
    ///   // packets indicates persistent congestion.
    ///   // Only consider packets sent after getting an RTT sample.
    ///   if (first_rtt_sample == 0):
    ///     return
    ///   pc_lost = []
    ///   for lost in lost_packets:
    ///     if lost.time_sent > first_rtt_sample:
    ///       pc_lost.insert(lost)
    ///   if (InPersistentCongestion(pc_lost)):
    ///     congestion_window = kMinimumWindow
    ///     congestion_recovery_start_time = 0
    fn on_packets_lost(
        &mut self,
        lost_packets: &mut dyn Iterator<Item = &SentPacket>,
        persistent_lost: bool,
    ) {
        // 1. may loss
        // 2. pc_lost
        let mut sent_time_last_loss: Option<Instant> = None;
        for lost_packet in lost_packets {
            if lost_packet.count_for_cc {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_packet.sent_bytes);
                sent_time_last_loss = sent_time_last_loss
                    .map(|t| t.max(lost_packet.time_sent))
                    .or(Some(lost_packet.time_sent));
            }
        }
        if let Some(time) = sent_time_last_loss {
            self.on_congestion_event(&time);
        }
        if persistent_lost {
            // WARN: will be zero
            self.ssthresh = self.congestion_window >> 1;
            self.congestion_window = self.ssthresh.max(MININUM_WINDOW);
            self.congestion_recovery_start_time = None;
        }
    }

    /// RemoveFromBytesInFlight(discarded_packets):
    ///  // Remove any unacknowledged packets from flight.
    ///  foreach packet in discarded_packets:
    ///    if packet.in_flight
    ///      bytes_in_flight -= size
    fn remove_from_bytes_in_flight(
        &mut self,
        discard_packets: &mut dyn Iterator<Item = &SentPacket>,
    ) {
        for packet in discard_packets {
            if packet.count_for_cc && packet.state != State::Retransmitted {
                self.bytes_in_flight -= packet.sent_bytes;
            }
        }
    }
}

impl Control for NewReno {
    fn on_packet_sent_cc(&mut self, packet: &SentPacket) {
        self.on_packet_sent_cc(packet.sent_bytes);
    }

    fn on_packet_acked(&mut self, acked_packet: &SentPacket) {
        self.on_packet_acked(acked_packet);
    }

    fn on_packets_lost(
        &mut self,
        lost_packets: &mut dyn Iterator<Item = &SentPacket>,
        persistent_lost: bool,
    ) {
        self.on_packets_lost(lost_packets, persistent_lost);
    }

    fn congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn pacing_rate(&self) -> Option<usize> {
        None
    }

    fn remove_from_bytes_in_flight(&mut self, packets: &mut dyn Iterator<Item = &SentPacket>) {
        self.remove_from_bytes_in_flight(packets);
    }

    fn process_ecn(&mut self, ack: &AckFrame, sent_time: &Instant, epoch: Epoch) {
        self.process_ecn(ack, sent_time, epoch);
    }
}
/*
#[cfg(test)]
mod tests {

    use super::*;
    use crate::packets::SentPacket;

    #[test]
    fn test_reno_init() {
        let reno = NewReno::new();
        assert_eq!(reno.cwnd, INIT_CWND);
        assert_eq!(reno.ssthresh, super::INFINITRE_SSTHRESH);
        assert_eq!(reno.recovery_start_time, None);
    }

    #[test]
    fn test_reno_slow_start() {
        let mut reno = NewReno::new();
        let acks = generate_acks(0, 10);

        // first roud trip
        reno.on_ack(acks);
        assert_eq!(reno.cwnd, 20 * MSS as u64);

        // second roud trip
        let acks = generate_acks(10, 30);
        reno.on_ack(acks);
        assert_eq!(reno.cwnd, 40 * MSS as u64);
    }

    #[test]
    fn test_reno_congestion_avoidance() {
        let mut reno = NewReno::new();
        reno.ssthresh = 30 * MSS as u64;
        let acks = generate_acks(0, 20);
        let pre_cwnd = reno.cwnd();
        // slow start
        reno.on_ack(acks);
        assert_eq!(reno.cwnd, pre_cwnd + 20 * MSS as u64);

        let pre_cwnd = reno.cwnd();
        let acks = generate_acks(20, 60);
        // congestion avoidance
        // increase a MSS when bytes_acked is greater than cwnd
        reno.on_ack(acks);
        assert_eq!(reno.cwnd, pre_cwnd + MSS as u64);
    }

    #[test]
    fn test_reno_congestion_event() {
        let mut reno = NewReno::new();
        let now = Instant::now();
        reno.ssthresh = 20 * MSS as u64;
        let acks = generate_acks(0, 10);

        reno.on_ack(acks);

        assert_eq!(reno.cwnd, 20 * MSS as u64);
        assert_eq!(reno.recovery_start_time, None);

        let time_lost = now + std::time::Duration::from_millis(100);
        let lost = SentPacket {
            packet_number: 11,
            sent_bytes: MSS,
            time_sent: now,
            ..Default::default()
        };

        reno.on_congestion_event(&lost);

        assert_eq!(reno.cwnd, 10 * MSS as u64);
        assert_eq!(reno.ssthresh, 10 * MSS as u64);
        assert_eq!(reno.recovery_start_time, Some(time_lost));
    }

    fn generate_acks(start: usize, end: usize) -> VecDeque<AckedPackets> {
        let mut acks = VecDeque::with_capacity(end - start);
        for i in start..end {
            let sent = SentPacket {
                packet_number: i as u64,
                sent_bytes: MSS,
                time_sent: Instant::now(),
                ..Default::default()
            };
            let ack: AckedPackets = sent.into();
            acks.push_back(ack);
        }
        acks
    }
}
*/
