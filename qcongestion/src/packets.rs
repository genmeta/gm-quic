use std::{
    cmp::Ordering,
    collections::VecDeque,
    time::{Duration, Instant},
};

use qbase::{Epoch, frame::AckFrame};

use crate::algorithm::Control;

#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub(crate) enum State {
    #[default]
    Inflight,
    Acked,
    Retransmitted,
}

#[derive(Eq, Clone, Debug)]
pub struct SentPacket {
    pub(crate) packet_number: u64,
    pub(crate) time_sent: Instant,
    pub(crate) ack_eliciting: bool,
    pub(crate) sent_bytes: usize,
    pub(crate) state: State,
    pub(crate) count_for_cc: bool,
}

impl Default for SentPacket {
    fn default() -> Self {
        SentPacket {
            packet_number: 0,
            time_sent: Instant::now(),
            ack_eliciting: true,
            sent_bytes: 0,
            state: State::Inflight,
            count_for_cc: false,
        }
    }
}

impl SentPacket {
    pub(crate) fn new(
        packet_number: u64,
        time_sent: Instant,
        ack_eliciting: bool,
        count_for_cc: bool,
        sent_bytes: usize,
    ) -> Self {
        SentPacket {
            packet_number,
            time_sent,
            ack_eliciting,
            count_for_cc,
            sent_bytes,
            ..Default::default()
        }
    }
}

impl PartialOrd for SentPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SentPacket {
    fn eq(&self, other: &Self) -> bool {
        self.packet_number == other.packet_number
    }
}

impl Ord for SentPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.packet_number.cmp(&other.packet_number)
    }
}

/// The [`RcvdRecords`] struct is used to maintain records of received packets for each epoch.
/// It tracks acknowledged packets and determines when an ACK frame should be sent.
/// It also retires packets that have been acknowledged by an ACK frame that has already sent and which has been confirmed by the peer.
#[derive(Debug)]
pub(crate) struct RcvdRecords {
    epoch: Epoch,
    ack_immedietly: bool,
    latest_rcvd_time: Option<Instant>,
    largest_rcvd_packet: Option<(u64, Instant)>,
    max_ack_delay: Duration,
}

impl RcvdRecords {
    pub(crate) fn new(epoch: Epoch, max_ack_delay: Duration) -> Self {
        Self {
            epoch,
            ack_immedietly: false,
            latest_rcvd_time: None,
            largest_rcvd_packet: None,
            max_ack_delay,
        }
    }

    pub(crate) fn on_pkt_rcvd(&mut self, pn: u64) {
        // An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately
        if self.epoch == Epoch::Initial || self.epoch == Epoch::Handshake {
            self.ack_immedietly = true;
        }
        // See [Section 13.2.1](https://www.rfc-editor.org/rfc/rfc9000.html#name-sending-ack-frames)
        // An endpoint SHOULD generate and send an ACK frame without delay when it receives an ack-eliciting packet either:
        // 1. When the received packet has a packet number less than another ack-eliciting packet that has been received
        // 2. when the packet has a packet number larger than the highest-numbered ack-eliciting packet that has been
        // received and there are missing packets between that packet and this packet.
        let now = tokio::time::Instant::now().into_std();
        if self.latest_rcvd_time.is_none() {
            self.latest_rcvd_time = Some(now);
        }
        self.ack_immedietly |= self
            .largest_rcvd_packet
            .is_some_and(|(largest_pn, _)| pn < largest_pn);

        self.largest_rcvd_packet =
            self.largest_rcvd_packet
                .map_or(Some((pn, now)), |(largest_pn, time)| {
                    if pn > largest_pn {
                        Some((pn, now))
                    } else {
                        Some((largest_pn, time))
                    }
                });
    }

    /// Checks whether an ACK frame needs to be sent.
    /// Returns [`Some`] if it's time to send an ACK based on the maximum delay.
    pub(crate) fn need_ack(&self) -> Option<(u64, Instant)> {
        let now = tokio::time::Instant::now().into_std();
        if self.ack_immedietly {
            return self.largest_rcvd_packet;
        }

        if self
            .latest_rcvd_time
            .is_some_and(|t| t + self.max_ack_delay < now)
        {
            return self.largest_rcvd_packet;
        }
        None
    }

    /// Called when an ACK is sent.
    /// Updates the last ACK sent information and resets the `need_ack` flag.
    pub(crate) fn on_ack_sent(&mut self, _pn: u64, _largest_acked: u64) {
        self.largest_rcvd_packet = None;
        self.latest_rcvd_time = None;
        self.ack_immedietly = false;
    }
}

// bbr_packet: VecDeque<BbrPackets>
pub(crate) struct PacketSpace {
    pub(crate) largest_acked_packet: Option<u64>,
    pub(crate) time_of_last_ack_eliciting_packet: Option<Instant>,
    pub(crate) loss_time: Option<Instant>,
    pub(crate) sent_packets: VecDeque<SentPacket>,
    pub(crate) rcvd_packets: RcvdRecords,
}

pub(crate) struct NewlyAckedPackets {
    pub(crate) include_ack_eliciting: bool,
    pub(crate) largest: (u64, Instant),
}

impl PacketSpace {
    pub(crate) fn with_epoch(epoch: Epoch, max_ack_delay: Duration) -> Self {
        Self {
            largest_acked_packet: None,
            time_of_last_ack_eliciting_packet: None,
            loss_time: None,
            sent_packets: VecDeque::with_capacity(4),
            rcvd_packets: RcvdRecords::new(epoch, max_ack_delay),
        }
    }

    pub(crate) fn update_largest_acked_packet(&mut self, pn: u64) {
        self.largest_acked_packet = self.largest_acked_packet.map(|n| n.max(pn)).or(Some(pn));
    }

    pub(crate) fn on_ack_rcvd(
        &mut self,
        ack_frame: &AckFrame,
        algorithm: &mut Box<dyn Control>,
    ) -> Option<NewlyAckedPackets> {
        if self.sent_packets.is_empty() {
            return None;
        }
        let mut include_ack_eliciting = false;
        let mut largest_acked = None;
        let mut index = self
            .sent_packets
            .binary_search_by(|p| p.packet_number.cmp(&ack_frame.largest()))
            .unwrap_or_else(|i| i.saturating_sub(1));

        for range in ack_frame.iter() {
            for pn in range.rev() {
                while index > 0 && self.sent_packets[index].packet_number > pn {
                    index = index.saturating_sub(1);
                }
                if self.sent_packets[index].packet_number == pn
                    && self.sent_packets[index].state != State::Acked
                {
                    algorithm.on_packet_acked(&self.sent_packets[index]);
                    self.sent_packets[index].state = State::Acked;
                    include_ack_eliciting |= self.sent_packets[index].ack_eliciting;
                    largest_acked = largest_acked
                        .map(|(n, t)| {
                            if n < pn {
                                (pn, self.sent_packets[index].time_sent)
                            } else {
                                (n, t)
                            }
                        })
                        .or(Some((pn, self.sent_packets[index].time_sent)));
                }
            }
        }

        while self
            .sent_packets
            .front()
            .is_some_and(|sent| sent.state == State::Acked || sent.state == State::Retransmitted)
        {
            self.sent_packets.pop_front();
        }

        Some(NewlyAckedPackets {
            include_ack_eliciting,
            largest: largest_acked?,
        })
    }

    pub(crate) fn no_ack_eliciting_in_flight(&self) -> bool {
        self.sent_packets
            .iter()
            .all(|sent| !sent.ack_eliciting || sent.state != State::Inflight)
    }

    pub(crate) fn detect_lost_packets(
        &mut self,
        loss_delay: Duration,
        packet_threshold: usize,
        algorithm: &mut Box<dyn Control>,
    ) -> impl Iterator<Item = u64> {
        assert!(self.largest_acked_packet.is_some());
        self.loss_time = None;

        let now = tokio::time::Instant::now().into_std();
        let lost_sent_time = now - loss_delay;
        let largest_acked = self.largest_acked_packet.unwrap_or(0);
        let largest_index = self
            .sent_packets
            .binary_search_by(|p| p.packet_number.cmp(&largest_acked))
            .unwrap_or_else(|i| i.saturating_sub(1));

        let loss: Vec<_> = self
            .sent_packets
            .iter_mut()
            .enumerate()
            .take_while(move |(_, pkt)| pkt.packet_number <= largest_acked)
            .filter(|(_, pkt)| pkt.state == State::Inflight)
            .map(move |(idx, unacked)| {
                if unacked.time_sent < lost_sent_time || largest_index >= idx + packet_threshold {
                    unacked.state = State::Retransmitted;
                    Ok((idx, &*unacked))
                } else {
                    Err(unacked.time_sent + loss_delay)
                }
            })
            .filter(|result| match result {
                Ok(_) => true,
                Err(time) => {
                    self.loss_time = self.loss_time.map_or(Some(*time), |t| Some(t.min(*time)));
                    false
                }
            })
            .map(|result| result.unwrap())
            .collect();

        const PERSISTENT_LOSS_THRESHOLD: usize = 3;
        let persistent_lost = loss
            .iter()
            .map(|(idx, _)| idx)
            .try_fold((None, 0), |(prev, count), &idx| {
                let lost_count = prev.map_or(0, |p| (idx - p == 1) as usize * (count + 1));
                if lost_count + 1 >= PERSISTENT_LOSS_THRESHOLD {
                    Err(())
                } else {
                    Ok((Some(idx), lost_count))
                }
            })
            .is_err();

        let (packet_numbers, loss_packet): (Vec<_>, Vec<_>) = loss
            .into_iter()
            .map(|(_, pkt)| (pkt.packet_number, pkt))
            .unzip();
        if !loss_packet.is_empty() {
            algorithm.on_packets_lost(&mut loss_packet.into_iter(), persistent_lost);
        }
        packet_numbers.into_iter()
    }

    pub(crate) fn discard(&mut self, algorithm: &mut Box<dyn Control>) {
        let mut remove_from_inflight = self
            .sent_packets
            .iter()
            .filter(|sent| sent.state == State::Inflight);
        algorithm.remove_from_bytes_in_flight(&mut remove_from_inflight);
        self.sent_packets.clear();
        self.time_of_last_ack_eliciting_packet = None;
        self.loss_time = None;
    }
}

#[cfg(test)]
mod tests {

    use std::vec;

    use super::*;
    use crate::{MSS, algorithm::new_reno::NewReno};

    #[test]
    fn test_packet_space() {
        let mut packet_space = PacketSpace::with_epoch(Epoch::Initial, Duration::from_millis(100));

        for i in 0..10 {
            packet_space.sent_packets.push_back(SentPacket::new(
                i,
                Instant::now(),
                true,
                true,
                MSS,
            ));
        }

        // ack 9 ~ 4, 1 ~ 0 loss 2,3
        let ack_frame = AckFrame::new(
            9_u32.into(),
            100_u32.into(),
            5_u32.into(),
            vec![(1_u32.into(), 1_u32.into())],
            None,
        );

        let mut reno: Box<dyn Control> = Box::new(NewReno::new());
        packet_space.on_ack_rcvd(&ack_frame, &mut reno);
        // init 12000, ack 8 packet 12000 + 8 * MSS = 21600
        assert_eq!(reno.congestion_window(), 21600);
        packet_space.largest_acked_packet = Some(ack_frame.largest());
        let loss = packet_space.detect_lost_packets(Duration::from_millis(100), 3, &mut reno);
        assert_eq!(loss.collect::<Vec<_>>(), vec![2, 3]);
        // loss 2, 3 cwnd = 21600 - MSS
        assert_eq!(reno.congestion_window(), 20400);

        for i in 10..15 {
            packet_space.sent_packets.push_back(SentPacket::new(
                i,
                Instant::now(),
                true,
                true,
                MSS,
            ));
        }
        for i in 20..25 {
            packet_space.sent_packets.push_back(SentPacket::new(
                i,
                Instant::now(),
                false,
                true,
                MSS,
            ));
        }

        // ack 24 ~ 20 13
        // loss 10, 11,12,14
        let ack_frame = AckFrame::new(
            24_u32.into(),
            100_u32.into(),
            5_u32.into(),
            vec![(4_u32.into(), 0_u32.into())],
            None,
        );

        packet_space.on_ack_rcvd(&ack_frame, &mut reno);
        packet_space.largest_acked_packet = Some(ack_frame.largest());
        assert_eq!(reno.congestion_window(), 20817);
        packet_space.largest_acked_packet = Some(ack_frame.largest());
        let loss = packet_space.detect_lost_packets(Duration::from_millis(100), 3, &mut reno);
        assert_eq!(loss.collect::<Vec<_>>(), vec![10, 11, 12, 14]);
        assert_eq!(reno.congestion_window(), (20817 - 1200) / 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_rcvd_records() {
        let mut rcvd_records = RcvdRecords::new(Epoch::Data, Duration::from_millis(100));
        for i in 0..10 {
            rcvd_records.on_pkt_rcvd(i);
        }

        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(rcvd_records.need_ack().unwrap().0, 9);
        rcvd_records.on_ack_sent(9, 9);
        assert_eq!(rcvd_records.need_ack(), None);

        tokio::time::resume();
        rcvd_records.on_pkt_rcvd(10);
        assert_eq!(rcvd_records.need_ack(), None);
        rcvd_records.on_pkt_rcvd(15);
        assert_eq!(rcvd_records.need_ack(), None);
        rcvd_records.on_pkt_rcvd(11);
        assert_eq!(rcvd_records.need_ack().unwrap().0, 15);
    }
}
