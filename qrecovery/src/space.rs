use bytes::{Bytes, BytesMut};
use qbase::{
    frame::{ext::parse_frames_from_bytes, *},
    varint::VARINT_MAX,
};
use std::{
    collections::VecDeque,
    fmt::Debug,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use super::index_deque::IndexDeque;

/// 网络socket缓过来时，会轮询调用此发送函数，询问该空间下是否有数据需要发送
pub trait AsyncSend {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<(u64, BytesMut)>;
}

/// 传输控制模块按其传输速度、时间间隔算出的到调用时该发送至多max_len字节的数据
pub trait TrySend<D> {
    fn try_send(&mut self, max_len: usize) -> D;
}

/// 网络socket收到一个数据包，解析出属于该空间时，将数据包内容传递给该空间
pub trait Receive {
    /// receive的数据，尚未解析，解析过程中可能会出错，
    /// 发生解析失败，或者解析出不该在该空间存在的帧
    /// TODO: 错误类型待定
    fn receive(&mut self, pktid: u64, payload: Bytes) -> Result<(), ()>;
}

/// 以下的泛型定义，F表示信令帧集合，D表示数据帧即可
pub trait Transmit<F, D> {
    fn confirm(&mut self, frame: F);
    fn confirm_data(&mut self, data_frame: D);
    fn may_loss(&mut self, data_frame: D);

    fn recv_frame(&mut self, frame: F);
    fn recv_data(&mut self, data_frame: D, data: Bytes);
    fn recv_close(&mut self, frame: ConnectionCloseFrame);
    fn gen_ack(&self) -> Option<AckFrame> {
        None
    }
}

#[derive(Debug)]
enum Records<F, D> {
    Frame(F),
    Data(D),
    Ack(AckRecord),
}

type Payload<F, D> = Vec<Records<F, D>>;

/// 可靠空间的抽象实现，需要实现上述所有trait
/// 可靠空间中的重传、确认，由可靠空间内部实现，无需外露
#[derive(Debug, Default)]
pub struct Space<F, D, T: Transmit<F, D> + Default + Debug> {
    // 将要发出的数据帧，包括重传的数据帧；可以是外部的功能帧，也可以是具体传输空间内部的
    // 起到“信号”作用的信令帧，比如数据空间内部的各类通信帧。
    // 需要注意的是，数据帧以及Ack帧(记录)，并不在此中保存，因为数据帧占数据空间，ack帧
    // 则是内部可靠性的产物，他们在发包记录中会作记录保存。
    frames: VecDeque<F>,
    // 一方面将out frames中的帧打包成二进制，并记录；另一方面，再合适的时机生成Ack帧塞进
    // 二进制数据包里面，并记录ack帧位置；最后，寻求发送数据帧，并记录数据帧头部。
    // 此队列中的数据包是暂存发送，还要通知底层的网络socket来真正发送，那时提供包序号，并
    // 记录发送时间
    pending_packets: IndexDeque<(BytesMut, Payload<F, D>), VARINT_MAX>,
    // 唤醒底层的网络socket来真正发送
    send_packet_waker: Option<Waker>,
    // 记录着发包时间、发包内容，供收到ack frame时，确认那些内容被接收了，哪些丢失了，需要
    // 重传。如果是一般帧，直接进入帧队列就可以了，但有2种需要特殊处理：
    // - 数据帧记录：无论被确认还是判定丢失了，都要通知发送缓冲区
    // - ack帧记录：被确认了，要滑动ack记录队列到合适位置
    // 另外，因为发送信令帧，是自动重传的，因此无需其他实现干扰
    inflight_packets: IndexDeque<Option<(Instant, Payload<F, D>)>, VARINT_MAX>,

    // 接收到数据包，帧可以是任意帧，需要调用具体空间的处理函数来具体处理，但需注意
    // - Ack帧，涉及可用空间基本功能，必须在可用空间处理
    // - 其他帧，交给具体空间处理。需判定是否是该空间的帧。由具体空间，唤醒相关读取子来处理
    //   - 要末能转化成F
    //   - 要末能转化成D，主要针对带数据的，或者直接就是D更合适

    // 用于产生ack frame，Instant用于计算ack_delay，bool表明是否ack eliciting
    rcvd_packets: IndexDeque<Option<(Instant, bool)>, VARINT_MAX>,

    transmission: T,
}

impl<F, D, T> Space<F, D, T>
where
    T: Transmit<F, D> + Default + Debug,
{
    pub fn write_frame(&mut self, frame: F) {
        self.frames.push_back(frame);
    }

    pub fn try_send(&mut self, _max_len: usize) -> usize {
        todo!("create BytesMut，collect frames, try generate ack frame，then collect Data frames util max_len bytes be filled or no data can be sent")
    }

    fn recv_ack_frame(&mut self, mut ack: AckFrame) {
        if let Some(_ecn) = ack.take_ecn() {
            todo!("处理ECN信息");
        }

        let largest_acked = ack.largest.into_inner();
        if largest_acked < self.inflight_packets.offset() {
            return;
        }

        if let Some((send_time, payload)) = self
            .inflight_packets
            .get_mut(largest_acked)
            .and_then(|record| record.take())
        {
            // TODO: 生成rtt，有更严格的要求，且rtt要反馈到路径上的拥塞控制中
            let _rtt_sample = send_time.elapsed() - Duration::from_micros(ack.delay.into_inner());
            self.confirm(payload);
        }

        for range in ack.into_iter() {
            for pktid in range {
                if let Some((_, payload)) = self
                    .inflight_packets
                    .get_mut(pktid)
                    .and_then(|record| record.take())
                {
                    self.confirm(payload);
                }
            }
        }

        // 没被确认的，要重传；对于大部分Frame直接重入frames_buf即可，但对于StreamFrame，得判定丢失
        for (_, records) in self.inflight_packets.drain_to(largest_acked - 3).flatten() {
            for record in records {
                match record {
                    Records::Ack(_) => { /* needn't resend */ }
                    Records::Frame(frame) => self.frames.push_back(frame),
                    Records::Data(data) => self.transmission.may_loss(data),
                }
            }
        }
    }

    fn confirm(&mut self, payload: Payload<F, D>) {
        for record in payload {
            match record {
                Records::Ack(ack) => {
                    const NDUP: u64 = 3;
                    let _ = self.rcvd_packets.drain_to(ack.0 - NDUP);
                }
                Records::Frame(frame) => self.transmission.confirm(frame),
                Records::Data(data) => self.transmission.confirm_data(data),
            }
        }
    }
}

impl<F, D, T> AsyncSend for Space<F, D, T>
where
    T: Transmit<F, D> + Default + Debug,
{
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<(u64, BytesMut)> {
        if let Some((pktid, (payload, record))) = self.pending_packets.pop() {
            self.inflight_packets.push(Some((Instant::now(), record)));
            Poll::Ready((pktid, payload))
        } else {
            self.send_packet_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<F, D, T> Receive for Space<F, D, T>
where
    F: TryFrom<InfoFrame, Error = FrameDecodingError>,
    D: TryFrom<DataFrame, Error = FrameDecodingError>,
    T: Transmit<F, D> + Default + Debug,
{
    // 返回流控字节数，以及可能的rtt新采样
    // 可能会遇到解析错误，可能遇到不合适的帧
    // 收到重复的包，不作为错误，可能会增加NDU，乱序容忍度
    fn receive(&mut self, pktid: u64, payload: Bytes) -> Result<(), ()> {
        if self.rcvd_packets.contain(pktid) {
            // TODO: 收到重复的包，对乱序容忍度进行处理
        } else {
            let mut is_ack_eliciting = false;
            // TODO: 后面要用?代替unwrap，实现自动的错误转换
            let frames = parse_frames_from_bytes(payload).unwrap();
            for frame in frames {
                match frame {
                    Frame::Padding => continue,
                    Frame::Ack(ack) => {
                        self.recv_ack_frame(ack);
                    }
                    Frame::Close(frame) => {
                        self.transmission.recv_close(frame);
                    }
                    Frame::Data(frame, data) => {
                        is_ack_eliciting = true;
                        // TODO: 后面要用?代替unwrap，实现自动的错误转换
                        let frame = D::try_from(frame).unwrap();
                        self.transmission.recv_data(frame, data);
                    }
                    Frame::Info(frame) => {
                        is_ack_eliciting = true;
                        // TODO: 后面要用?代替unwrap，实现自动的错误转换
                        let frame = F::try_from(frame).unwrap();
                        self.transmission.recv_frame(frame);
                    }
                }
            }
            self.rcvd_packets
                .insert(pktid, Some((Instant::now(), is_ack_eliciting)));
            return Ok(());
        }

        todo!("parse frames, handle ack frame if exist, ")
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
