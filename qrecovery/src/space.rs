use std::{fmt::Debug, sync::Arc, time::Instant};

use bytes::{BufMut, Bytes};
use deref_derive::Deref;
use qbase::{
    error::Error,
    frame::{
        io::{WriteAckFrame, WriteFrame},
        AckFrame, BeFrame, DataFrame, StreamCtlFrame,
    },
    packet::{PacketNumber, WritePacketNumber},
    streamid::Role,
};

use super::{
    crypto::{CryptoStream, TransmitCrypto},
    rcvdpkt::{ArcRcvdPktRecords, Error as RcvPnError},
    reliable::{ArcReliableFrameQueue, ArcSentPktRecords, SentRecord},
    streams::{none::NoDataStreams, ArcDataStreams, ReceiveStream, TransmitStream},
    unreliable::DatagramStream,
};

#[derive(Debug, Clone)]
pub enum SpaceFrame {
    Stream(StreamCtlFrame),
    Data(DataFrame, Bytes),
}

#[derive(Debug)]
pub struct RawSpace<T> {
    reliable_frame_queue: ArcReliableFrameQueue,
    sent_pkt_records: ArcSentPktRecords,
    rcvd_pkt_records: ArcRcvdPktRecords,
    data_streams: T,
    crypto_stream: CryptoStream,
}

impl<T> RawSpace<T>
where
    T: TransmitStream + ReceiveStream,
{
    /// 可用于收包解码包号，判定包号是否重复或者过期，记录收包状态，淘汰并滑动收包记录窗口
    pub fn rcvd_pkt_records(&self) -> &ArcRcvdPktRecords {
        &self.rcvd_pkt_records
    }

    pub fn decode_pn(&self, encoded_pn: PacketNumber) -> Result<u64, RcvPnError> {
        self.rcvd_pkt_records.decode_pn(encoded_pn)
    }

    /// 解码出pn还无法判定这个包的内容是否正常，只有等所有包内容都正确解析了，才可以登记该pn被正式接收
    pub fn register_pn(&self, pn: u64) {
        self.rcvd_pkt_records.register_pn(pn)
    }

    /// 要发送一个该空间的数据包，读出下一个包号，然后检查是否要发送AckFrame，
    /// 然后发送帧，最后发送数据流中的数据帧。
    /// 返回该数据包的包号，以及大小
    /// 给出包缓冲区，读取该space下可以写入的数据，包括包号，AckFrame，可靠帧，数据帧
    /// 返回包号、包号编码大小、写入的数据大小
    pub fn read(&self, mut buf: &mut [u8], ack_pkt: Option<(u64, Instant)>) -> (u64, usize, usize) {
        let origin = buf.remaining_mut();

        let mut send_guard = self.sent_pkt_records.send();
        let (pn, encoded_pn) = send_guard.next_pn();
        if buf.remaining_mut() > encoded_pn.size() {
            buf.put_packet_number(encoded_pn);
        } else {
            return (pn, encoded_pn.size(), 0);
        }

        if let Some(largest) = ack_pkt {
            let ack_frame = self
                .rcvd_pkt_records
                .gen_ack_frame_util(largest, buf.remaining_mut());
            buf.put_ack_frame(&ack_frame);
            send_guard.record_ack_frame(ack_frame);
        }

        {
            let mut read_frame_guard = self.reliable_frame_queue.read();
            while let Some(frame) = read_frame_guard.front() {
                let remaining = buf.remaining_mut();
                if remaining > frame.max_encoding_size() || remaining > frame.encoding_size() {
                    buf.put_frame(frame);
                    let frame = read_frame_guard.pop_front().unwrap();
                    send_guard.record_reliable_frame(frame);
                } else {
                    break;
                }
            }
        }

        let mut len = 0;
        // 尝试写入流数据，优先写入加密流数据，然后再努力写入数据流数据
        if let Some((crypto_frame, n)) = self.crypto_stream.try_read_data(&mut buf[len..]) {
            send_guard.record_data_frame(DataFrame::Crypto(crypto_frame));
            len += n;
        }

        // while循环，可能发送stream1，stream2流
        while let Some((stream_frame, n)) = self.data_streams.try_read_stream(&mut buf[len..]) {
            send_guard.record_data_frame(DataFrame::Stream(stream_frame));
            len += n;
        }

        while let Some((datagram_frame, n)) = self.data_streams.try_read_datagram(&mut buf[len..]) {
            send_guard.record_data_frame(DataFrame::Datagram(datagram_frame));
            len += n;
        }

        (pn, encoded_pn.size(), origin - buf.remaining_mut() + len)
    }

    /// 接收Space相关的帧，包括数据帧
    pub fn receive(&self, frame: SpaceFrame) -> Result<(), Error> {
        match frame {
            SpaceFrame::Stream(frame) => {
                self.data_streams.recv_stream_control(frame)?;
            }
            SpaceFrame::Data(DataFrame::Crypto(frame), data) => {
                self.crypto_stream.recv_data(frame, data)?;
            }
            SpaceFrame::Data(DataFrame::Stream(frame), data) => {
                self.data_streams.recv_stream(frame, data)?;
            }
            SpaceFrame::Data(DataFrame::Datagram(frame), data) => {
                self.data_streams.recv_datagram(frame, data)?;
            }
        }
        Ok(())
    }

    /// 此处接收AckFrame，只负责内容，涉及RTT和传输速度控制的，path已经处理过
    pub fn on_ack(&self, ack: AckFrame) {
        let mut recv_guard = self.sent_pkt_records.receive();
        recv_guard.update_largest(ack.largest.into_inner());

        for pn in ack.iter().flat_map(|r| r.rev()) {
            for record in recv_guard.on_pkt_acked(pn) {
                match record {
                    SentRecord::Data(DataFrame::Crypto(frame)) => {
                        self.crypto_stream.on_data_acked(frame);
                    }
                    SentRecord::Data(DataFrame::Stream(frame)) => {
                        self.data_streams.on_data_acked(frame);
                    }
                    // Ack Reliable Datagram
                    // do nothing
                    _ => {}
                }
            }
        }
    }

    /// 发现丢包，就要重传
    pub fn may_loss_pkt(&self, pn: u64) {
        let mut sent_pkt_guard = self.sent_pkt_records.receive();
        let mut write_frame_guard = self.reliable_frame_queue.write();
        for record in sent_pkt_guard.may_loss_pkt(pn) {
            match record {
                SentRecord::Reliable(frame) => {
                    write_frame_guard.push_reliable_frame(frame);
                }
                SentRecord::Data(DataFrame::Crypto(frame)) => {
                    self.crypto_stream.may_loss_data(frame);
                }
                SentRecord::Data(DataFrame::Stream(frame)) => {
                    self.data_streams.may_loss_data(frame);
                }
                // Ack Datagram
                // do nothing
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, Deref)]
pub struct ArcSpace<T>(#[deref] Arc<RawSpace<T>>);

impl ArcSpace<NoDataStreams> {
    /// Initial空间和Handshake空间皆通过此函数创建
    pub fn with_crypto_stream(crypto_stream: CryptoStream) -> Self {
        ArcSpace(Arc::new(RawSpace {
            reliable_frame_queue: Default::default(),
            sent_pkt_records: Default::default(),
            rcvd_pkt_records: Default::default(),
            data_streams: NoDataStreams,
            crypto_stream,
        }))
    }
}

impl ArcSpace<ArcDataStreams> {
    /// 数据空间通过此函数创建
    pub fn new(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        max_datagram_frame_size: u64,
        crypto_stream: CryptoStream,
    ) -> Self {
        let reliable_frame_queue = ArcReliableFrameQueue::default();
        let datagram_stream = DatagramStream::new(max_datagram_frame_size);

        ArcSpace(Arc::new(RawSpace {
            reliable_frame_queue: reliable_frame_queue.clone(),
            sent_pkt_records: Default::default(),
            rcvd_pkt_records: Default::default(),
            data_streams: ArcDataStreams::with_role_and_limit(
                role,
                max_bi_streams,
                max_uni_streams,
                reliable_frame_queue,
                datagram_stream,
            ),
            crypto_stream,
        }))
    }

    pub fn data_streams(&self) -> ArcDataStreams {
        self.0.data_streams.clone()
    }
}

#[cfg(test)]
mod tests {}
