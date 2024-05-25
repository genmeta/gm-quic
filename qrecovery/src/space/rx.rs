use crate::{
    crypto::{CryptoStream, TransmitCrypto},
    frame_queue::ArcFrameQueue,
    index_deque::IndexDeque,
    space::SpaceFrame,
    streams::{Streams, TransmitStream},
};
use futures::StreamExt;
use qbase::{
    error::Error,
    frame::{io::WriteAckFrame, AckFrame, AckRecord, BeFrame, DataFrame},
    packet::PacketNumber,
    varint::{VarInt, VARINT_MAX},
    SpaceId,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Debug, Clone, Default)]
pub(crate) enum State {
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
    pub fn new_rcvd(t: Instant, is_ack_eliciting: bool) -> Self {
        if is_ack_eliciting {
            Self::Important(t)
        } else {
            Self::Ignored(t)
        }
    }

    pub fn has_rcvd(&self) -> bool {
        matches!(
            self,
            Self::Ignored(_) | Self::Important(_) | Self::Synced(_)
        )
    }

    pub fn delay(&self) -> Option<Duration> {
        match self {
            Self::Ignored(t) | Self::Important(t) | Self::Synced(t) => Some(t.elapsed()),
            _ => None,
        }
    }

    pub fn change_into_synced(&mut self) {
        match self {
            Self::Ignored(t) | Self::Important(t) => {
                *self = Self::Synced(*t);
            }
            Self::NotReceived => *self = Self::Unreached,
            _ => (),
        }
    }
}

// 负责接收帧，将数据或者控制信息交给数据流的接收部
// 生成ack frame，随发送端在合适的时机发送
// 收ack的ack，推动接收记录窗口的滑动
#[derive(Debug)]
pub struct Receiver<ST: TransmitStream> {
    space_id: SpaceId,
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
    // 这里只需要Incoming的部分
    crypto_stream: CryptoStream,
    data_stream: ST,
}

impl<ST: TransmitStream> Receiver<ST> {
    fn new(space_id: SpaceId, crypto_stream: CryptoStream, data_stream: ST) -> Self {
        Self {
            space_id,
            rcvd_packets: IndexDeque::new(),
            largest_rcvd_ack_eliciting_pktid: 0,
            last_synced_ack_largest: 0,
            new_lost_event: false,
            rcvd_unreached_packet: false,
            time_to_sync: None,
            max_ack_delay: Duration::from_millis(100),
            crypto_stream,
            data_stream,
        }
    }

    fn expected_pn(&self) -> u64 {
        self.rcvd_packets.largest()
    }

    fn has_rcvd(&self, pktid: u64) -> bool {
        self.rcvd_packets
            .get(pktid)
            .map(|s| s.has_rcvd())
            .unwrap_or(false)
            || pktid < self.rcvd_packets.offset()
    }

    fn recv_frame(&mut self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Ack(_ack, _rtt) => {
                // let _ = self.recv_ack_frame(ack, rtt);
            }
            SpaceFrame::Stream(f) => self.data_stream.recv_frame(f)?,
            SpaceFrame::Data(f, data) => match f {
                DataFrame::Crypto(f) => self.crypto_stream.recv_data(f, data)?,
                DataFrame::Stream(f) => self.data_stream.recv_data(f, data)?,
            },
        };
        Ok(())
    }

    fn record(&mut self, pkt_id: u64, is_ack_eliciting: bool) {
        self.rcvd_packets
            .insert(pkt_id, State::new_rcvd(Instant::now(), is_ack_eliciting))
            .unwrap();
        if is_ack_eliciting {
            if self.largest_rcvd_ack_eliciting_pktid < pkt_id {
                self.largest_rcvd_ack_eliciting_pktid = pkt_id;
                self.new_lost_event |= self
                    .rcvd_packets
                    .iter_with_idx()
                    .rev()
                    .skip_while(|(pn, _)| *pn >= pkt_id)
                    .skip(3_usize)
                    .take_while(|(pn, _)| pn > &self.last_synced_ack_largest)
                    .any(|(_, s)| matches!(s, State::NotReceived));
            }
            if pkt_id < self.last_synced_ack_largest {
                self.rcvd_unreached_packet = true;
            }
            self.time_to_sync = self
                .time_to_sync
                .or(Some(Instant::now() + self.max_ack_delay));
        }
    }

    fn gen_ack_frame(&mut self) -> AckFrame {
        // must be a reliable space; otherwise, if it is an unreliable space,
        // such as the 0-RTT space, never send an ACK frame.
        assert!(self.space_id != SpaceId::ZeroRtt);
        // There must be an ACK-eliciting packet; otherwise, it will not
        // trigger the sending of an ACK frame.
        debug_assert!(self
            .rcvd_packets
            .iter()
            .any(|p| matches!(p, State::Important(_))));

        let largest = self.rcvd_packets.offset() + self.rcvd_packets.len() as u64 - 1;
        let delay = self.rcvd_packets.get_mut(largest).unwrap().delay().unwrap();
        let mut rcvd_iter = self.rcvd_packets.iter_mut().rev();
        let first_range = rcvd_iter.by_ref().take_while(|s| s.has_rcvd()).count() - 1;
        let mut ranges = Vec::with_capacity(16);
        loop {
            if rcvd_iter.next().is_none() {
                break;
            }
            let gap = rcvd_iter.by_ref().take_while(|s| !s.has_rcvd()).count();

            if rcvd_iter.next().is_none() {
                break;
            }
            let acked = rcvd_iter.by_ref().take_while(|s| s.has_rcvd()).count();

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

    fn need_send_ack_frame(&self) -> bool {
        // non-reliable space such as 0-RTT space, never send ack frame
        if self.space_id == SpaceId::ZeroRtt {
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

impl Receiver<Streams> {
    fn upgrade(&mut self) {
        self.space_id = SpaceId::OneRtt;
    }
}

#[derive(Debug, Clone)]
pub struct ArcReceiver<ST: TransmitStream> {
    inner: Arc<Mutex<Receiver<ST>>>,
}

impl<ST: TransmitStream + Send + 'static> ArcReceiver<ST> {
    pub fn new(
        space_id: SpaceId,
        crypto_stream: CryptoStream,
        data_stream: ST,
        recv_frame_queue: ArcFrameQueue<SpaceFrame>,
        ack_record_rx: UnboundedReceiver<u64>,
    ) -> Self {
        let receiver = Arc::new(Mutex::new(Receiver::new(
            space_id,
            crypto_stream,
            data_stream,
        )));
        // 创建Receiver时，自带一个不停地读取Frame的异步任务
        tokio::spawn({
            let receiver = receiver.clone();
            async move {
                let mut frame_queue = recv_frame_queue;
                while let Some(frame) = frame_queue.next().await {
                    let mut receiver = receiver.lock().unwrap();
                    // TODO: 可能某些帧引起违反协议的错误，需要处理错误
                    let _ = receiver.recv_frame(frame);
                }
            }
        });
        tokio::spawn({
            let receiver = receiver.clone();
            async move {
                let mut ack_record_rx = ack_record_rx;
                while let Some(pkt_id) = ack_record_rx.recv().await {
                    let _ = receiver.lock().unwrap().rcvd_packets.drain_to(pkt_id);
                }
            }
        });
        Self { inner: receiver }
    }
}

impl ArcReceiver<Streams> {
    pub fn upgrade(&self) {
        self.inner.lock().unwrap().upgrade();
    }
}

impl<ST: TransmitStream> ArcReceiver<ST> {
    /// 收到数据包，要根据已收数据包的最大包号，计算真正的包号
    /// 收到数据包并解析出包号后，要询问数据包是否曾收到过，重复数据包不重复处理
    pub fn receive_pkt_no(&self, pn: PacketNumber) -> Result<u64, u64> {
        let mut guard = self.inner.lock().unwrap();
        let pkt_id = pn.decode(guard.expected_pn());
        if !guard.has_rcvd(pkt_id) {
            Ok(pkt_id)
        } else {
            Err(pkt_id)
        }
    }

    /// 如果真发出了AckFrame，那发包记录要记下AckRecord
    pub fn read_ack_frame(&self, mut buf: &mut [u8]) -> Option<(AckRecord, usize)> {
        let mut guard = self.inner.lock().unwrap();
        if guard.need_send_ack_frame() {
            let remaning = buf.len();
            let ack = guard.gen_ack_frame();
            let ack_size = ack.encoding_size();
            if remaning >= ack_size {
                // 到这里，Ack帧肯定会被发送了
                guard.time_to_sync = None;
                guard.new_lost_event = false;
                guard.rcvd_unreached_packet = false;
                guard.last_synced_ack_largest = ack.largest.into_inner();
                buf.put_ack_frame(&ack);
                // All known packet information needs to be marked as synchronized.
                guard
                    .rcvd_packets
                    .iter_mut()
                    .for_each(|s| s.change_into_synced());
                return Some((ack.into(), ack_size));
            }
        }
        None
    }

    /// 当收到一个数据包，该数据包正常，且能被正常解析出帧，需要登记该数据包的收取状态
    pub fn record(&self, pkt_id: u64, is_ack_eliciting: bool) {
        self.inner.lock().unwrap().record(pkt_id, is_ack_eliciting);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
