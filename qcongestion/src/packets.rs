use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use qbase::{Epoch, frame::AckFrame};

use crate::algorithm::Control;

#[derive(Clone, Debug)]
pub struct AckedPackets {
    pub(crate) pn: u64,
    pub(crate) time_sent: Instant,
    pub(crate) size: usize,
    pub(crate) rtt: Duration,
    pub(crate) delivered: usize,
    pub(crate) delivered_time: Instant,
    pub(crate) first_sent_time: Instant,
    pub(crate) is_app_limited: bool,
}

impl From<SentPacket> for AckedPackets {
    fn from(sent: SentPacket) -> Self {
        let now = Instant::now();
        AckedPackets {
            pn: sent.packet_number,
            time_sent: sent.time_sent,
            size: sent.sent_bytes,
            rtt: now - sent.time_sent,
            delivered: sent.delivered,
            delivered_time: sent.delivered_time,
            first_sent_time: sent.first_sent_time,
            is_app_limited: sent.is_app_limited,
        }
    }
}

#[derive(Eq, Clone, Debug)]
pub struct SentPacket {
    pub(crate) packet_number: u64,
    pub(crate) time_sent: Instant,
    pub(crate) ack_eliciting: bool,
    pub(crate) in_flight: bool,
    pub(crate) sent_bytes: usize,
    pub(crate) delivered: usize,
    pub(crate) delivered_time: Instant,
    pub(crate) first_sent_time: Instant,
    pub(crate) is_app_limited: bool,
    pub(crate) tx_in_flight: usize,
    pub(crate) lost: u64,
    pub(crate) is_acked: bool,
    pub(crate) may_loss: bool,
}

impl Default for SentPacket {
    fn default() -> Self {
        SentPacket {
            packet_number: 0,
            time_sent: Instant::now(),
            ack_eliciting: true,
            in_flight: true,
            sent_bytes: 0,
            delivered: 0,
            delivered_time: Instant::now(),
            first_sent_time: Instant::now(),
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            is_acked: false,
            may_loss: false,
        }
    }
}

impl SentPacket {
    pub(crate) fn new(
        packet_number: u64,
        time_sent: Instant,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
    ) -> Self {
        SentPacket {
            packet_number,
            time_sent,
            ack_eliciting,
            in_flight,
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
    ack_sent: HashMap<u64, u64>,
    last_ack_sent: Option<(u64, u64)>,
    rcvd_queue: VecDeque<(u64, Instant)>,
}

impl RcvdRecords {
    pub(crate) fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            ack_immedietly: false,
            ack_sent: HashMap::new(),
            last_ack_sent: None,
            rcvd_queue: VecDeque::new(),
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
        if let Some(&(largest_pn, _)) = self.rcvd_queue.back() {
            self.ack_immedietly = pn < largest_pn || pn.saturating_sub(largest_pn) > 1;

            let idx = self.rcvd_queue.partition_point(|&(x, _)| x < pn);
            match self.rcvd_queue.get(idx) {
                Some(&(n, _)) if n != pn => self.rcvd_queue.insert(idx, (pn, Instant::now())),
                None => {
                    self.rcvd_queue.push_back((pn, Instant::now()));
                }
                _ => (),
            }
        } else {
            self.rcvd_queue.push_back((pn, Instant::now()));
        }
    }

    /// Checks whether an ACK frame needs to be sent.
    /// Returns [`Some`] if it's time to send an ACK based on the maximum delay.
    pub(crate) fn requires_ack(&self, max_delay: Duration, now: Instant) -> Option<(u64, Instant)> {
        let largest_pn = self.rcvd_queue.back().map(|&(pn, time)| (pn, time));
        if self.ack_immedietly {
            return largest_pn;
        }

        let largest_ack_sent = self.last_ack_sent.map(|x| x.1).unwrap_or(0);
        let pos = self
            .rcvd_queue
            .partition_point(|&(x, _)| x <= largest_ack_sent);
        for (_pn, rec_time) in self.rcvd_queue.iter().skip(pos) {
            if now - *rec_time >= max_delay {
                return largest_pn;
            }
        }
        None
    }

    /// Called when an ACK is sent.
    /// Updates the last ACK sent information and resets the `need_ack` flag.
    pub(crate) fn on_ack_sent(&mut self, pn: u64, largest_acked: u64) {
        self.ack_sent.insert(pn, largest_acked);
        self.last_ack_sent = Some((pn, largest_acked));
        self.ack_immedietly = false;
    }

    /// Processes an acknowledged (ACK) packet.
    /// If the ACKed packet number matches the last sent ACK number, retires all acknowledged packets.
    pub(crate) fn should_drain(&mut self, ack_pn: u64) -> Option<u64> {
        let largest = self.ack_sent.get(&ack_pn)?;
        const THRESHOLD: u64 = 3;
        let drain = largest.saturating_sub(THRESHOLD);
        self.rcvd_queue.retain(|&(pn, _)| pn > drain);
        self.ack_sent.remove(&ack_pn);
        Some(drain)
    }
}

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
    pub(crate) fn with_epoch(epoch: Epoch) -> Self {
        Self {
            largest_acked_packet: None,
            time_of_last_ack_eliciting_packet: None,
            loss_time: None,
            sent_packets: VecDeque::with_capacity(4),
            rcvd_packets: RcvdRecords::new(epoch),
        }
    }

    pub(crate) fn update_largest_acked_packet(&mut self, pn: u64) {
        self.largest_acked_packet = self.largest_acked_packet.map(|n| n.max(pn)).or(Some(pn));
    }

    pub(crate) fn on_ack_rcvd(
        &mut self,
        ack_frame: &AckFrame,
        algorithm: &Box<dyn Control + Send>,
    ) -> Option<NewlyAckedPackets> {
        let mut include_ack_eliciting = false;
        let mut largest_acked = None;
        for range in ack_frame.iter() {
            for pn in range {
                if let Some(sent) = self
                    .sent_packets
                    .iter_mut()
                    .find(|sent| sent.packet_number == pn && !sent.is_acked)
                {
                    sent.is_acked = true;
                    // TODO: 这里让算法处理 acked packet
                    algorithm.on_packet_acked(sent);
                    include_ack_eliciting |= sent.ack_eliciting;
                    largest_acked = largest_acked
                        .map(|(n, t)| if n < pn { (pn, sent.time_sent) } else { (n, t) })
                        .or(Some((pn, sent.time_sent)));
                }
            }
        }

        while self
            .sent_packets
            .front()
            .map_or(false, |sent| sent.is_acked || sent.may_loss)
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
            .all(|sent| !sent.ack_eliciting || sent.is_acked || sent.may_loss)
    }

    pub(crate) fn detect_lost_packets(
        &mut self,
        loss_delay: Duration,
        packet_threshold: usize,
    ) -> impl Iterator<Item = u64> {
        assert!(self.largest_acked_packet.is_some());
        self.loss_time = None;

        let now = tokio::time::Instant::now().into_std();
        let lost_sent_time = now - loss_delay;
        let largest_acked = self.largest_acked_packet.unwrap_or(0);
        let largest_index = self
            .sent_packets
            .iter()
            .position(|sent| sent.packet_number >= largest_acked)
            .unwrap_or(0);
        self.sent_packets
            .iter_mut()
            .enumerate()
            .take_while(move |(_, pkt)| pkt.packet_number <= largest_acked)
            .filter(|(_, pkt)| !pkt.is_acked && !pkt.may_loss)
            .map(move |(idx, unacked)| {
                if unacked.time_sent < lost_sent_time || largest_index >= idx + packet_threshold {
                    unacked.may_loss = true;
                    Ok(unacked.packet_number)
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
    }

    pub(crate) fn discard(&mut self) {
        self.sent_packets.clear();
        self.time_of_last_ack_eliciting_packet = None;
        self.loss_time = None;
    }
}
