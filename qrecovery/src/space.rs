use super::{index_deque::IndexDeque, rtt::Rtt};
use bytes::{BufMut, Bytes};
use qbase::{
    error::{Error, ErrorKind},
    frame::{self, ext::*, *},
    varint::{VarInt, VARINT_MAX},
};
use std::{
    collections::VecDeque,
    fmt::Debug,
    time::{Duration, Instant},
};

pub trait TrySend<B: BufMut> {
    fn try_send(&mut self, buf: &mut B) -> Result<Option<(u64, usize)>, Error>;
}

/// When a network socket receives a data packet and determines that it belongs
/// to a specific space, the content of the packet is passed on to that space.
pub trait Receive {
    fn receive(&mut self, pktid: u64, payload: Bytes, rtt: &mut Rtt) -> Result<(), Error>;
}

/// The following generic definition:
/// - F represents a collection of signaling frames, and
/// - D represents data frames.
pub trait Transmit<F, D> {
    type Buffer: BufMut + WriteFrame<F> + WriteDataFrame<D>;

    // Attempt to collect data for transmission. If data is available, return the
    // header of the data frame and the number of additional bytes added. If there
    // is no data to send, return None.
    // Note: Crypto data is not subject to flow control, congestion control,
    // or amplification attack limitations. Therefore, the amount of Crypto data
    // written should be ignored.
    fn try_send(&mut self, buf: &mut Self::Buffer) -> Option<(D, usize)>;
    fn confirm(&mut self, frame: F);
    fn confirm_data(&mut self, data_frame: D);
    fn may_loss(&mut self, data_frame: D);

    fn recv_frame(&mut self, frame: F);
    fn recv_data(&mut self, data_frame: D, data: Bytes);
    fn recv_close(&mut self, frame: ConnectionCloseFrame);
}

#[derive(Debug, Clone)]
enum Records<F, D> {
    Frame(F),
    Data(D),
    Ack(AckRecord),
}

type Payload<F, D> = Vec<Records<F, D>>;

#[derive(Debug, Clone, Default)]
enum State {
    #[default]
    NotReceived,
    // aka NACK: negative acknowledgment or not acknowledged,
    //     indicate that data transmitted over a network was received
    //     with errors or was otherwise unreadable.
    Unreached,
    Ignored(Instant),
    Important(Instant),
    Synced(Instant),
}

impl State {
    fn rcvd(t: Instant, is_ack_eliciting: bool) -> Self {
        if is_ack_eliciting {
            Self::Important(t)
        } else {
            Self::Ignored(t)
        }
    }

    fn delay(&self) -> Option<Duration> {
        match self {
            Self::Ignored(t) | Self::Important(t) | Self::Synced(t) => Some(t.elapsed()),
            _ => None,
        }
    }

    fn into_synced(&mut self) {
        match self {
            Self::Ignored(t) | Self::Important(t) => {
                *self = Self::Synced(*t);
            }
            Self::NotReceived => *self = Self::Unreached,
            _ => (),
        }
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
pub struct Space<F, D, T, const R: bool = true>
where
    T: Transmit<F, D> + Default + Debug,
{
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
    largest_acked_pktid: u64,
    // 设计丢包重传定时器，在收到AckFrame的探测丢包时，可能会设置该定时器，实际上是过期时间
    loss_time: Option<Instant>,

    // 接收到数据包，帧可以是任意帧，需要调用具体空间的处理函数来具体处理，但需注意
    // - Ack帧，涉及可用空间基本功能，必须在可用空间处理
    // - 其他帧，交给具体空间处理。需判定是否是该空间的帧。由具体空间，唤醒相关读取子来处理
    //   * 要末能转化成F
    //   * 要末能转化成D，主要针对带数据的

    // 用于产生ack frame，Instant用于计算ack_delay，bool表明是否ack eliciting
    rcvd_packets: IndexDeque<State, VARINT_MAX>,
    // 收到的最大的ack-eliciting packet的pktid
    largest_rcvd_ack_eliciting_pktid: u64,
    last_synced_ack_largest: u64,
    new_lost_event: bool,
    rcvd_unreached_packet: bool,
    // 下一次需要同步ack frame的时间：
    // - 每次发送ack frame后，会重置该时间为None
    // - 每次收到新的ack-eliciting frame后，会更新该时间
    time_to_sync: Option<Instant>,
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

    fn gen_ack_frame(&mut self) -> AckFrame {
        // must be a reliable space; otherwise, if it is an unreliable space,
        // such as the 0-RTT space, never send an ACK frame.
        assert!(R);
        // There must be an ACK-eliciting packet; otherwise, it will not
        // trigger the sending of an ACK frame.
        debug_assert!(self
            .rcvd_packets
            .iter()
            .any(|p| matches!(p, State::Important(_))));

        let largest = self.rcvd_packets.offset() + self.rcvd_packets.len() as u64 - 1;
        let delay = self.rcvd_packets.get_mut(largest).unwrap().delay().unwrap();
        let mut rcvd_iter = self.rcvd_packets.iter_mut().rev();
        let first_range = rcvd_iter
            .by_ref()
            .take_while(|s| !matches!(s, State::NotReceived))
            .map(|s| s.into_synced())
            .count()
            - 1;
        let mut ranges = Vec::with_capacity(16);
        loop {
            if rcvd_iter.next().is_none() {
                break;
            }
            let gap = rcvd_iter
                .by_ref()
                .take_while(|s| matches!(s, State::NotReceived))
                .count();

            if rcvd_iter.next().is_none() {
                break;
            }
            let acked = rcvd_iter
                .by_ref()
                .take_while(|s| !matches!(s, State::NotReceived))
                .count();

            ranges.push(unsafe {
                (
                    VarInt::from_u64_unchecked(gap as u64),
                    VarInt::from_u64_unchecked(acked as u64),
                )
            });
        }

        AckFrame {
            largest: unsafe { VarInt::from_u64_unchecked(largest) },
            delay: unsafe { VarInt::from_u64_unchecked(delay.as_micros() as u64) },
            first_range: unsafe { VarInt::from_u64_unchecked(first_range as u64) },
            ranges,
            // TODO: support ECN
            ecn: None,
        }
    }

    fn recv_ack_frame(&mut self, mut ack: AckFrame, rtt: &mut Rtt) -> Option<usize> {
        let largest_acked = ack.largest.into_inner();
        if largest_acked < self.largest_acked_pktid {
            return None;
        }
        // largest_acked == self.largest_acked_packet is also acceptable,
        // perhaps indicating that new packets have been acknowledged.
        self.largest_acked_pktid = largest_acked;

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

        // retranmission
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
        // Packets sent before this time are deemed lost too.
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
        // A small optimization would be to slide forward if the first consecutive
        // packets in the inflight_packets queue have been acknowledged.
        let n = self
            .inflight_packets
            .iter()
            .take_while(|p| p.is_none())
            .count();
        let _ = self.inflight_packets.drain(..n);
        Some(acked_bytes)
    }

    fn need_send_ack_frame(&self) -> bool {
        // non-reliable space such as 0-RTT space, never send ack frame
        if !R {
            return false;
        }

        // In order to assist loss detection at the sender, an endpoint SHOULD generate
        // and send an ACK frame without delay when it receives an ack-eliciting packet either:
        //   (下述第一条，莫非是只要ack-eliciting包乱序就要发送ack frame？不至于吧)
        //   (应该是过往ack过的包，里面没被确认的，突然被收到的话，就立刻发ack帧，为避免发送端不必要的重传，这样比较合适)
        // - when the received packet has a packet number less than another
        //   ack-eliciting packet that has been received, or
        //   (下述这一条比较科学，收包收到感知到丢包，立即发送ack帧）
        // - when the packet has a packet number larger than the highest-numbered
        //   ack-eliciting packet that has been received and there are missing
        //   packets between that packet and this packet.
        if self.new_lost_event || self.rcvd_unreached_packet {
            return true;
        }

        // ack-eliciting packets MUST be acknowledged at least once within the maximum delay
        match self.time_to_sync {
            Some(t) => t > Instant::now(),
            None => false,
        }
    }
}

impl<F, D, T, B, const R: bool> TrySend<B> for Space<F, D, T, R>
where
    F: BeFrame,
    T: Transmit<F, D, Buffer = B> + Default + Debug,
    B: BufMut + WriteFrame<F> + WriteDataFrame<D>,
{
    fn try_send(&mut self, buf: &mut B) -> Result<Option<(u64, usize)>, Error> {
        let mut is_ack_eliciting = false;
        let mut remaning = buf.remaining_mut();
        let mut payload = Payload::<F, D>::new();
        if self.need_send_ack_frame() {
            let ack = self.gen_ack_frame();
            if remaning >= ack.max_encoding_size() || remaning >= ack.encoding_size() {
                self.time_to_sync = None;
                self.new_lost_event = false;
                self.rcvd_unreached_packet = false;
                self.last_synced_ack_largest = ack.largest.into_inner();
                buf.put_ack_frame(&ack);
                payload.push(Records::Ack(ack.into()));
                // The ACK frame is not counted towards sent_bytes, is not subject to
                // amplification attacks, and is not subject to flow control limitations.
                remaning = buf.remaining_mut();
                // All known packet information needs to be marked as synchronized.
                self.rcvd_packets.iter_mut().for_each(|s| s.into_synced());
            }
        }

        // Prioritize retransmitting lost or info frames.
        loop {
            if let Some(frame) = self.frames.front() {
                if remaning >= frame.max_encoding_size() || remaning >= frame.encoding_size() {
                    buf.put_frame(frame);
                    remaning = buf.remaining_mut();
                    is_ack_eliciting = true;

                    let frame = self.frames.pop_front().unwrap();
                    payload.push(Records::Frame(frame));
                    continue;
                }
            }
            break;
        }

        // Consider transmitting data frames.
        if let Some((data_frame, ignore)) = self.transmission.try_send(buf) {
            payload.push(Records::Data(data_frame));
            remaning += ignore;
        }

        // Record
        let sent_bytes = remaning - buf.remaining_mut();
        if sent_bytes == 0 {
            // no data to send
            return Ok(None);
        }
        if is_ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = Some(Instant::now());
        }
        let pktid = self.inflight_packets.push(Some(Packet {
            send_time: Instant::now(),
            payload,
            sent_bytes,
            is_ack_eliciting,
        }))?;
        Ok(Some((pktid, sent_bytes)))
    }
}

impl<F, D, T, const R: bool> Receive for Space<F, D, T, R>
where
    F: TryFrom<InfoFrame, Error = frame::Error>,
    D: TryFrom<DataFrame, Error = frame::Error>,
    T: Transmit<F, D> + Default + Debug,
{
    // TODO: 返回流控字节数，以及可能的rtt新采样，还有需要上层立即处理的帧
    fn receive(&mut self, pktid: u64, payload: Bytes, rtt: &mut Rtt) -> Result<(), Error> {
        if pktid < self.rcvd_packets.offset() {
            return Ok(());
        }
        if !matches!(
            self.rcvd_packets.get(pktid),
            Some(State::NotReceived) | Some(State::Unreached)
        ) {
            return Ok(());
        }
        // TODO: 超过最新包号一定范围，仍然是不允许的，可能是某种错误

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
            .insert(pktid, State::rcvd(Instant::now(), is_ack_eliciting))
            .unwrap();
        if is_ack_eliciting {
            if self.largest_rcvd_ack_eliciting_pktid < pktid {
                self.largest_rcvd_ack_eliciting_pktid = pktid;
                self.new_lost_event |= self
                    .rcvd_packets
                    .iter_with_idx()
                    .rev()
                    .skip_while(|(pn, _)| pn >= &pktid)
                    .skip(PACKET_THRESHOLD as usize)
                    .take_while(|(pn, _)| pn > &self.last_synced_ack_largest)
                    .any(|(_, s)| matches!(s, State::NotReceived));
            }
            if pktid < self.last_synced_ack_largest {
                self.rcvd_unreached_packet = true;
            }
            self.time_to_sync = self
                .time_to_sync
                .or(Some(Instant::now() + self.max_ack_delay));
        }
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
