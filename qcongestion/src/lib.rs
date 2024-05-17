use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub mod bbr;

pub mod delivery_rate;

pub enum CongestionAlgorithm {
    Bbr,
}

pub struct CongestionState {
    cc: Box<dyn CongestionControl>,
    sent_packets: [HashMap<u64, Sent>; 3],
    time_of_last_sent_ack_eliciting_pkt: [Option<Instant>; 3],
}

impl CongestionState {
    fn new(algorithm: CongestionAlgorithm) -> Self {
        let cc = match algorithm {
            CongestionAlgorithm::Bbr => Box::new(bbr::BBRState::new()),
        };
        CongestionState {
            cc,
            sent_packets: [HashMap::new(), HashMap::new(), HashMap::new()],
            time_of_last_sent_ack_eliciting_pkt: [None, None, None],
        }
    }

    fn on_packet_sent(
        &mut self,
        packet_number: u64,
        pn_space: u8,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
    ) {
        let now = Instant::now();

        let sent = Sent {
            pkt_num: packet_number,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            size: sent_bytes,
            ack_eliciting,
            in_flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
        };
        self.sent_packets[pn_space as usize].insert(packet_number, sent);
        if in_flight {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt[pn_space as usize] = Some(now);
            }
            self.cc.on_packet_sent(sent_bytes, now);
        }
    }

    fn on_packet_acked(&mut self, packet_number: u64, pn_space: u8, ack_delay: Duration) {
        let now = Instant::now();
        let sent = self.sent_packets[pn_space as usize]
            .remove(&packet_number)
            .unwrap();

        let ack = Acked {
            pkt_num: packet_number,
            time_sent: sent.time_sent,
            size: sent.size,
            rtt: now - sent.time_sent,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
        };
        self.cc.on_packet_acked(&ack, now);
        todo!("on_packet_acked")
    }

    fn on_packet_lost(packet_number: u64, pn_space: u8) {
        todo!("on_packet_lost")
    }

    fn get_congestion_window(&self) -> u64 {
        self.cc.cwnd()
    }
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: u64,

    pub time_sent: Instant,

    pub size: usize,

    pub rtt: Duration,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,
}

#[derive(Eq, Hash, PartialEq)]
pub struct Sent {
    pub pkt_num: u64,

    pub time_sent: Instant,

    pub time_acked: Option<Instant>,

    pub time_lost: Option<Instant>,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,

    pub delivered: usize,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,

    pub has_data: bool,
}

pub trait CongestionControl {
    fn init(&mut self);

    fn on_packet_sent(&mut self, sent_bytes: usize, now: Instant);

    fn on_packet_acked(&mut self, packets: &Acked, now: Instant);

    fn on_congestion_event(&mut self);

    fn cwnd(&self) -> u64;
}
