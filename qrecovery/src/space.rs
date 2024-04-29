use crate::rtt::Rtt;

use super::index_deque::IndexDeque;
use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{self, ext::*, *},
    varint::VARINT_MAX,
};
use std::{
    collections::VecDeque,
    fmt::Debug,
    time::{Duration, Instant},
};

pub trait TrySend<T: BufMut> {
    fn try_send(&mut self, buf: T) -> Result<(u64, usize), Error>;
}

/// 网络socket收到一个数据包，解析出属于该空间时，将数据包内容传递给该空间
pub trait Receive {
    /// receive的数据，尚未解析，解析过程中可能会出错，
    /// 发生解析失败，或者解析出不该在该空间存在的帧
    fn receive(&mut self, pktid: u64, payload: Bytes, rtt: &mut Rtt) -> Result<(), Error>;
}

/// 以下的泛型定义，F表示信令帧集合，D表示数据帧即可
pub trait Transmit<F, D> {
    fn confirm(&mut self, frame: F);
    fn confirm_data(&mut self, data_frame: D);
    fn may_loss(&mut self, data_frame: D);

    fn recv_frame(&mut self, frame: F);
    fn recv_data(&mut self, data_frame: D, data: Bytes);
    fn recv_close(&mut self, frame: ConnectionCloseFrame);
}

#[derive(Debug, Clone)]
pub(crate) enum Records<F, D> {
    Frame(F),
    Data(D),
    Ack(AckRecord),
}

type Payload<F, D> = Vec<Records<F, D>>;

#[derive(Debug, Clone, Default)]
enum State<T> {
    Ignored(T),
    Important(T),
    #[default]
    Acked,
}

impl<T> State<T> {
    fn new(t: T, is_ack_eliciting: bool) -> Self {
        if is_ack_eliciting {
            Self::Important(t)
        } else {
            Self::Ignored(t)
        }
    }

    fn ack(&mut self) {
        *self = Self::Acked;
    }
}

#[derive(Debug, Clone)]
struct Packet<F, D> {
    send_time: Instant,
    payload: Payload<F, D>,
    sent_bytes: usize,
    is_ack_eliciting: bool,
}

const PACKET_THRESHOLD: u64 = 3;

/// 可靠空间的抽象实现，需要实现上述所有trait
/// 可靠空间中的重传、确认，由可靠空间内部实现，无需外露
#[derive(Debug, Default)]
pub struct Space<F, D, T: Transmit<F, D> + Default + Debug, const R: bool = true> {
    // 将要发出的数据帧，包括重传的数据帧；可以是外部的功能帧，也可以是具体传输空间内部的
    // 起到“信号”作用的信令帧，比如数据空间内部的各类通信帧。
    // 需要注意的是，数据帧以及Ack帧(记录)，并不在此中保存，因为数据帧占数据空间，ack帧
    // 则是内部可靠性的产物，他们在发包记录中会作记录保存。
    frames: VecDeque<F>,
    // 记录着发包时间、发包内容，供收到ack frame时，确认那些内容被接收了，哪些丢失了，需要
    // 重传。如果是一般帧，直接进入帧队列就可以了，但有2种需要特殊处理：
    // - 数据帧记录：无论被确认还是判定丢失了，都要通知发送缓冲区
    // - ack帧记录：被确认了，要滑动ack记录队列到合适位置
    // 另外，因为发送信令帧，是自动重传的，因此无需其他实现干扰
    inflight_packets: IndexDeque<Option<Packet<F, D>>, VARINT_MAX>,
    disorder_tolerance: u64,
    time_of_last_sent_ack_eliciting_packet: Option<Instant>,
    largest_acked_packet: u64,
    // 设计丢包重传定时器，在收到AckFrame的探测丢包时，可能会设置该定时器，实际上是过期时间
    loss_time: Option<Instant>,

    // 接收到数据包，帧可以是任意帧，需要调用具体空间的处理函数来具体处理，但需注意
    // - Ack帧，涉及可用空间基本功能，必须在可用空间处理
    // - 其他帧，交给具体空间处理。需判定是否是该空间的帧。由具体空间，唤醒相关读取子来处理
    //   - 要末能转化成F
    //   - 要末能转化成D，主要针对带数据的，或者直接就是D更合适

    // 用于产生ack frame，Instant用于计算ack_delay，bool表明是否ack eliciting
    rcvd_packets: IndexDeque<Option<State<Instant>>, VARINT_MAX>,

    // 应该计算rtt的时候，传进来；或者收到ack frame的时候，将(last_rtt, ack_delay)传出去
    max_ack_delay: Duration,

    transmission: T,
}

impl<F, D, T, const R: bool> Space<F, D, T, R>
where
    T: Transmit<F, D> + Default + Debug,
{
    pub fn write_frame(&mut self, frame: F) {
        self.frames.push_back(frame);
    }

    fn recv_ack_frame(&mut self, mut ack: AckFrame, rtt: &mut Rtt) -> Option<usize> {
        let largest_acked = ack.largest.into_inner();
        if largest_acked < self.largest_acked_packet {
            return None;
        }
        // largest_acked == self.largest_acked_packet，也是可以接受的，也许有新包被确认
        self.largest_acked_packet = largest_acked;

        let mut no_newly_acked = true;
        let mut includes_ack_eliciting = false;
        let mut acked_bytes = 0;
        let ecn_in_ack = ack.take_ecn();
        let ack_delay = Duration::from_micros(ack.delay.into_inner());
        for range in ack.into_iter() {
            for pktid in range {
                if let Some(packet) = self
                    .inflight_packets
                    .get_mut(pktid)
                    .and_then(|record| record.take())
                {
                    no_newly_acked = false;
                    if packet.is_ack_eliciting {
                        includes_ack_eliciting = true;
                    }
                    self.confirm(packet.payload);
                    acked_bytes += packet.sent_bytes;
                }
            }
        }

        if no_newly_acked {
            return None;
        }

        if let Some(_ecn) = ecn_in_ack {
            todo!("处理ECN信息");
        }

        if let Some(packet) = self
            .inflight_packets
            .get_mut(largest_acked)
            .and_then(|record| record.take())
        {
            if packet.is_ack_eliciting {
                includes_ack_eliciting = true;
            }
            if includes_ack_eliciting {
                // TODO: is_handshake_confirmed is known from connection logic
                rtt.update(packet.send_time.elapsed(), ack_delay, true);
            }
            self.confirm(packet.payload);
            acked_bytes += packet.sent_bytes;
        }

        // 没被确认的，要重传；对于大部分Frame直接重入frames_buf即可，但对于StreamFrame，得判定丢失
        for packet in self
            .inflight_packets
            .drain_to(largest_acked.saturating_sub(PACKET_THRESHOLD))
            .flatten()
        {
            acked_bytes += packet.sent_bytes;
            for record in packet.payload {
                match record {
                    Records::Ack(_) => { /* needn't resend */ }
                    Records::Frame(frame) => self.frames.push_back(frame),
                    Records::Data(data) => self.transmission.may_loss(data),
                }
            }
        }

        let loss_delay = rtt.loss_delay();
        // Packets sent before this time are deemed lost.
        let lost_send_time = Instant::now() - loss_delay;
        self.loss_time = None;
        for packet in self
            .inflight_packets
            .iter_mut()
            .take(PACKET_THRESHOLD as usize)
            .filter(|p| p.is_some())
        {
            let send_time = packet.as_ref().unwrap().send_time;
            if send_time <= lost_send_time {
                for record in packet.take().unwrap().payload {
                    match record {
                        Records::Ack(_) => { /* needn't resend */ }
                        Records::Frame(frame) => self.frames.push_back(frame),
                        Records::Data(data) => self.transmission.may_loss(data),
                    }
                }
            } else {
                self.loss_time = self
                    .loss_time
                    .map(|t| std::cmp::min(t, send_time + loss_delay))
                    .or(Some(send_time + loss_delay));
            }
        }
        // 一个小优化，如果inflight_packets队首存在连续的None，则向前滑动
        let n = self
            .inflight_packets
            .iter()
            .take_while(|p| p.is_none())
            .count();
        let _ = self.inflight_packets.drain(..n);
        Some(acked_bytes)
    }

    fn confirm(&mut self, payload: Payload<F, D>) {
        for record in payload {
            match record {
                Records::Ack(ack) => {
                    let _ = self
                        .rcvd_packets
                        .drain_to(ack.0.saturating_sub(self.disorder_tolerance));
                }
                Records::Frame(frame) => self.transmission.confirm(frame),
                Records::Data(data) => self.transmission.confirm_data(data),
            }
        }
    }

    fn need_send_ack(&self) -> bool {
        // self.rcvd_packets.
        false
    }
}

impl<F, D, T, B> TrySend<B> for Space<F, D, T>
where
    T: Transmit<F, D> + Default + Debug,
    B: BufMut + WriteFrame<F> + WriteDataFrame<D>,
{
    fn try_send(&mut self, mut buf: B) -> Result<(u64, usize), Error> {
        let mut is_ack_eliciting = false;
        let mut remaning = buf.remaining_mut();
        let mut sent_bytes = 0;
        let mut payload = Payload::<F, D>::new();
        // TODO: 是否要收集ack frame，得看时间到了没有，有没有达到ack delay、丢包产生、或者有足够量的包需要确认了
        // 但是Ack frame不计入sent_bytes，不占用抗放大攻击和流控限制
        for frame in self.frames.drain(..) {
            // TODO: 确保不会超限，buf能容下
            is_ack_eliciting = true;
            buf.put_frame(&frame);
            payload.push(Records::Frame(frame));
            sent_bytes += remaning - buf.remaining_mut();
            remaning = buf.remaining_mut();
        }
        // TODO: 还要再去收集数据帧
        if is_ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = Some(Instant::now());
        }
        // 记录
        let pktid = self.inflight_packets.push(Some(Packet {
            send_time: Instant::now(),
            payload,
            sent_bytes,
            is_ack_eliciting,
        }));
        // 返回; TODO: 有可能超过最大pktid，此时要返回错误
        Ok((pktid.unwrap(), sent_bytes))
    }
}

impl<F, D, T, const R: bool> Receive for Space<F, D, T, R>
where
    F: TryFrom<InfoFrame, Error = frame::Error>,
    D: TryFrom<DataFrame, Error = frame::Error>,
    T: Transmit<F, D> + Default + Debug,
{
    // 返回流控字节数，以及可能的rtt新采样
    // 可能会遇到解析错误，可能遇到不合适的帧
    // 收到重复的包，不作为错误，可能会增加NDU，乱序容忍度
    fn receive(&mut self, pktid: u64, payload: Bytes, rtt: &mut Rtt) -> Result<(), Error> {
        if pktid < self.rcvd_packets.offset() {
            return Ok(());
        }
        if let Some(Some(_)) = self.rcvd_packets.get(pktid) {
            // TODO: 收到重复的包，对乱序容忍度进行处理
            return Ok(());
        }

        let mut is_ack_eliciting = false;
        let frames = parse_frames_from_bytes(payload)?;
        for frame in frames {
            match frame {
                Frame::Padding => continue,
                Frame::Ack(ack) => {
                    if R {
                        self.recv_ack_frame(ack, rtt);
                    } else {
                        // Note that it is not possible to send the following frames in 0-RTT packets for various reasons:
                        // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and RETIRE_CONNECTION_ID. A server MAY
                        // treat receipt of these frames in 0-RTT packets as a connection error of type PROTOCOL_VIOLATION.
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            ack.frame_type(),
                            "No ACK frame can be received in 0-RTT packets",
                        ));
                    }
                }
                Frame::Close(frame) => {
                    self.transmission.recv_close(frame);
                }
                Frame::Data(frame, data) => {
                    is_ack_eliciting = true;
                    self.transmission.recv_data(frame.try_into()?, data);
                }
                Frame::Info(frame) => {
                    is_ack_eliciting = true;
                    self.transmission.recv_frame(frame.try_into()?);
                }
            }
        }
        self.rcvd_packets
            .insert(pktid, Some(State::new(Instant::now(), is_ack_eliciting)));
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
