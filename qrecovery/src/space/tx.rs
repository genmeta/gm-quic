use crate::{
    crypto::{CryptoStream, TransmitCrypto},
    index_deque::IndexDeque,
    rtt::Rtt,
    streams::{Streams, TransmitStream},
};
use bytes::BufMut;
use qbase::{
    frame::{
        io::WriteFrame, AckFrame, AckRecord, BeFrame, ConnFrame, DataFrame, ReliableFrame,
        StreamCtlFrame,
    },
    packet::PacketNumber,
    varint::VARINT_MAX,
    SpaceId,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Debug, Clone)]
pub enum Record {
    Reliable(ReliableFrame),
    Data(DataFrame),
    Ack(AckRecord),
}

pub type Payload = Vec<Record>;

#[derive(Debug, Clone)]
pub struct Packet {
    pub send_time: Instant,
    pub payload: Payload,
    pub sent_bytes: usize,
    pub is_ack_eliciting: bool,
}

#[derive(Debug)]
struct Transmiter<ST: TransmitStream> {
    space_id: SpaceId,
    // 以下三个字段，是为了重传需要，也为了发送数据需要
    frames: Arc<Mutex<VecDeque<ReliableFrame>>>,
    // 其实只需要CryptoString的Outgoing部分
    crypto_stream: CryptoStream,
    // 其实只需要TransmitStream的Outgoing部分
    data_stream: ST,

    // 正在飞行中的数据包记录，如果某个包为None，说明已经确认到达了
    inflight_packets: IndexDeque<Option<Packet>, VARINT_MAX>,
    ack_record_tx: UnboundedSender<u64>,
    // 上一次发送ack-eliciting包的时间
    time_of_last_sent_ack_eliciting_packet: Option<Instant>,
    // 对方确认的最大包id，可认为对方收到的最大包id，尽管可能有半rtt以上时间的信息过时
    largest_acked_pktid: Option<u64>,
}

impl<ST: TransmitStream> Transmiter<ST> {
    pub fn new(
        space_id: SpaceId,
        crypto_stream: CryptoStream,
        data_stream: ST,
        ack_record_tx: UnboundedSender<u64>,
    ) -> Self {
        Self {
            space_id,
            frames: Arc::new(Mutex::new(VecDeque::new())),
            crypto_stream,
            data_stream,
            inflight_packets: IndexDeque::new(),
            ack_record_tx,
            time_of_last_sent_ack_eliciting_packet: None,
            largest_acked_pktid: None,
        }
    }

    fn next_pkt_no(&self) -> (u64, PacketNumber) {
        let pkt_id = self.inflight_packets.largest();
        let pn = PacketNumber::encode(pkt_id, self.largest_acked_pktid.unwrap_or(0));
        (pkt_id, pn)
    }

    fn read(&mut self, mut buf: &mut [u8]) -> usize {
        let mut is_ack_eliciting = false;
        let remaning = buf.remaining_mut();

        let mut records = Payload::new();
        {
            // Prioritize retransmitting lost or info frames.
            let mut frames = self.frames.lock().unwrap();
            while let Some(frame) = frames.front() {
                if buf.remaining_mut() >= frame.max_encoding_size()
                    || buf.remaining_mut() >= frame.encoding_size()
                {
                    buf.put_frame(frame);
                    is_ack_eliciting = true;

                    let frame = frames.pop_front().unwrap();
                    records.push(Record::Reliable(frame));
                } else {
                    break;
                }
            }
        }

        // Consider transmit stream info frames if has
        if let Some((stream_info_frame, len)) = self.data_stream.try_read_frame(buf) {
            records.push(Record::Reliable(ReliableFrame::Stream(stream_info_frame)));
            unsafe {
                buf.advance_mut(len);
            }
        }

        // Consider transmitting data frames.
        if self.space_id != SpaceId::ZeroRtt {
            while let Some((data_frame, len)) = self.crypto_stream.try_read_data(buf) {
                records.push(Record::Data(DataFrame::Crypto(data_frame)));
                unsafe {
                    buf.advance_mut(len);
                }
            }
        }
        while let Some((data_frame, len)) = self.data_stream.try_read_data(buf) {
            records.push(Record::Data(DataFrame::Stream(data_frame)));
            unsafe {
                buf.advance_mut(len);
            }
        }

        // Record
        let sent_bytes = remaning - buf.remaining_mut();
        if sent_bytes == 0 {
            // no data to send
            return 0;
        }
        if is_ack_eliciting {
            self.time_of_last_sent_ack_eliciting_packet = Some(Instant::now());
        }
        self.record_sent_packet(Packet {
            send_time: Instant::now(),
            payload: records,
            sent_bytes,
            is_ack_eliciting,
        });
        sent_bytes
    }

    /// 单单发送一个AckFrame，也要记录
    fn record_sent_packet(&mut self, packet: Packet) {
        let _pkt_id = self.inflight_packets.push(Some(packet)).expect(
            r#"The packet number cannot exceed 2^62. Even if 100 million packets are sent 
                per second, it would take more than a million years to exceed this limit."#,
        );
    }

    fn recv_ack_frame(&mut self, mut ack: AckFrame, rtt: Arc<Mutex<Rtt>>) {
        let largest_acked = ack.largest.into_inner();
        if self
            .largest_acked_pktid
            .map(|v| v > largest_acked)
            .unwrap_or(false)
        {
            return;
        }
        // largest_acked == self.largest_acked_packet is also acceptable,
        // perhaps indicating that old 'lost' packets have been acknowledged.
        self.largest_acked_pktid = Some(largest_acked);

        let mut no_newly_acked = true;
        let mut includes_ack_eliciting = false;
        let mut rtt_sample = None;
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
                    if pktid == largest_acked {
                        rtt_sample = Some(packet.send_time.elapsed());
                    }
                    self.confirm_packet_rcvd(pktid, packet);
                }
            }
        }

        if no_newly_acked {
            return;
        }

        if includes_ack_eliciting {
            let is_handshake_confirmed = self.space_id == SpaceId::OneRtt;
            if let Some(latest_rtt) = rtt_sample {
                rtt.lock()
                    .unwrap()
                    .update(latest_rtt, ack_delay, is_handshake_confirmed);
            }
        }

        if let Some(_ecn) = ecn_in_ack {
            todo!("处理ECN信息");
        }
    }

    /// A small optimization would be to slide forward if the first consecutive
    /// packets in the inflight_packets queue have been acknowledged.
    fn slide_inflight_pkt_window(&mut self) {
        let n = self
            .inflight_packets
            .iter()
            .take_while(|p| p.is_none())
            .count();
        let _ = self.inflight_packets.drain(..n);
    }

    fn confirm_packet_rcvd(&mut self, _pkt_id: u64, packet: Packet) {
        // TODO: 此处应通知发送该包的路径，让该路径计算速度，并最终用于判定那些包丢了

        // 告知有关模块该包负载的内容已被接收
        for record in packet.payload {
            match record {
                Record::Ack(ack) => {
                    // THINK: 这里需不需要减去3这个乱序容忍度
                    let _ = self.ack_record_tx.send(ack.0.saturating_sub(3));
                }
                Record::Reliable(_frame) => {
                    todo!("哪些帧需要确认呢？")
                }
                Record::Data(data) => match data {
                    DataFrame::Crypto(f) => self.crypto_stream.confirm_data(f),
                    DataFrame::Stream(f) => self.data_stream.confirm_data(f),
                },
            }
        }
    }

    fn may_loss_packet(&mut self, pkt_id: u64) {
        // retranmit the frames, tell stream that the data is lost and need to retranmit in future
        if let Some(packet) = self
            .inflight_packets
            .get_mut(pkt_id)
            .and_then(|record| record.take())
        {
            for record in packet.payload {
                match record {
                    Record::Ack(_) => { /* needn't resend */ }
                    Record::Reliable(frame) => {
                        let mut frames = self.frames.lock().unwrap();
                        frames.push_back(frame);
                    }
                    Record::Data(data) => match data {
                        DataFrame::Crypto(f) => self.crypto_stream.may_loss_data(f),
                        DataFrame::Stream(f) => self.data_stream.may_loss_data(f),
                    },
                }
            }
        }
    }
}

impl Transmiter<Streams> {
    fn write_conn_frame(&mut self, frame: ConnFrame) {
        assert!(frame.belongs_to(self.space_id));
        let mut frames = self.frames.lock().unwrap();
        frames.push_back(ReliableFrame::Conn(frame));
    }

    fn write_stream_frame(&mut self, frame: StreamCtlFrame) {
        assert!(frame.belongs_to(self.space_id));
        let mut frames = self.frames.lock().unwrap();
        frames.push_back(ReliableFrame::Stream(frame));
    }
}

pub struct ArcTransmiter<ST: TransmitStream> {
    inner: Arc<Mutex<Transmiter<ST>>>,
}

impl<ST: TransmitStream + Send + 'static> ArcTransmiter<ST> {
    /// 一个Transmitter，不仅仅要发送数据，还要接收AckFrame，以及丢包序号去重传。
    /// 然后，接收端提供的AckFrame如果被确认了，也需要通知到接收端
    pub fn new(
        space_id: SpaceId,
        crypto_stream: CryptoStream,
        data_stream: ST,
        ack_record_tx: UnboundedSender<u64>,
        mut ack_frame_rx: UnboundedReceiver<(AckFrame, Arc<Mutex<Rtt>>)>,
        mut loss_pkt_rx: UnboundedReceiver<u64>,
    ) -> Self {
        let transmitter = Arc::new(Mutex::new(Transmiter::new(
            space_id,
            crypto_stream,
            data_stream,
            ack_record_tx,
        )));

        tokio::spawn({
            let transmitter = transmitter.clone();
            async move {
                // 通过rx接收并处理AckFrame，AckFrame是Path收包解包得到
                while let Some((ack, rtt)) = ack_frame_rx.recv().await {
                    transmitter.lock().unwrap().recv_ack_frame(ack, rtt);
                }
            }
        });

        tokio::spawn({
            let transmitter = transmitter.clone();
            async move {
                // 不停地接收丢包序号，这些丢包序号由path记录反馈，更新Transmiter的状态
                while let Some(pkt_id) = loss_pkt_rx.recv().await {
                    let mut guard = transmitter.lock().unwrap();
                    guard.may_loss_packet(pkt_id);
                    guard.slide_inflight_pkt_window();
                }
            }
        });
        Self { inner: transmitter }
    }
}

impl<ST: TransmitStream> ArcTransmiter<ST> {
    pub fn next_pkt_no(&self) -> (u64, PacketNumber) {
        self.inner.lock().unwrap().next_pkt_no()
    }

    pub fn read(&self, buf: &mut [u8]) -> usize {
        self.inner.lock().unwrap().read(buf)
    }

    pub fn record_sent_ack(&self, packet: Packet) {
        self.inner.lock().unwrap().record_sent_packet(packet);
    }
}

impl ArcTransmiter<Streams> {
    pub fn write_conn_frame(&self, frame: ConnFrame) {
        self.inner.lock().unwrap().write_conn_frame(frame);
    }

    pub fn write_stream_frame(&self, frame: StreamCtlFrame) {
        self.inner.lock().unwrap().write_stream_frame(frame);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
