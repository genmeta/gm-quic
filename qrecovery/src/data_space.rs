use super::index_deque::IndexDeque;
use crate::recv::{self, Incoming, Reader};
use crate::send::{self, Outgoing, Writer};
use bytes::Bytes;
use qbase::frame::*;
use qbase::frame::{ReadFrame, WriteFrame};
use qbase::streamid::{AcceptSid, Dir, NeedCreate, StreamId, StreamIds};
use qbase::varint::VarInt;
use qbase::varint::VARINT_MAX;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

type Payload = Vec<WriteFrame>;
type Packets = IndexDeque<(Bytes, Payload), VARINT_MAX>;
type PacketRecords = IndexDeque<Option<(Instant, Payload)>, VARINT_MAX>;

/// DataSpace对外主要有2个接口：
/// - `poll_collect_to_send`
/// - `poll_send`: 向DataSpace收集要发送的数据，如果有数据要发送，就返回`Poll::Ready`；否则返回`Poll::Pending`。
///                实际上，何时该发送数据，主要由DataSpace中的传输控制算法来决定，受传输算法内部各类定时器、rtt、传输速率驱动。
/// - `recv`: 代表着收到一个包，不用poll，无论是ack还是数据包，`DataSpace`都会立即处理。
#[derive(Debug)]
pub struct DataSpace {
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: HashMap<StreamId, Outgoing>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: HashMap<StreamId, Incoming>,

    // 当前的各种流类型的最大能用流ID：
    // - 我方创建型最大流ID受制于对方的MAX_STREAMS_FRAME反馈
    // - 对方创建型最大流ID受制于我方决定
    stream_ids: StreamIds,

    // 主要是各种命令型frame，如RESET/STOP_SENDING/MAX_XXX/XXX_BLOCKED等，
    // 不包括PADDING/STREAM/CRYPTO/ACK/PING?等。
    // 命令式的frame，直接写入到此队列。
    // 这些frame天生要可靠的，如若发生丢包，也直接进入到该队列进行重传。
    // 该队列的frame拥有更高的优先级发送。
    frames_buf: Arc<Mutex<VecDeque<WriteFrame>>>,

    // 由传输控制引擎激发的发包，通常发包需要持有底层网络socket才能发，但DataSpace
    // 并不该依赖底层网络socket，因为发包先进入发送缓冲区，并唤醒底层来读包进行实际发送，
    // 这样便可解藕。
    // pending_packet，已是真实的二进制字节包了，只是还没发出去，在发送缓冲区里。
    // 帧记录则是包的记录，在真正发送时，要进入到flighting队列
    pending_packets: Packets,
    send_waker: Option<Waker>,
    // 经过正式发送的包，就会被记录下来，等待ACK_FRAME确认，或者判丢。
    // 确认的包自不必说，判丢的包里面的命令帧则进入frames队列重传
    // inflight packets多了发送时间以计算RTT，还有包id即索引，配合ACK_FRAME进行ack和判丢，
    // 如果被确认，就会变成None。变成None之后的数据包不用被重复确认。
    inflight_packets: PacketRecords,

    // 如果是tlp，那尾丢包超时器就会启动，判定丢包

    // 接收包记录，用于进行反馈ACK_FRAME；
    // Duration: 接收包的时间用于计算delay
    // bool: 接收包的内容决定是否需要产生ack信息
    recved_packets: VecDeque<Option<(Instant, bool)>>,
    // 加入有携带ack帧的包被对方确认了，那recved_pktid就要据此向前滑动
    recved_pktid: u64,
    // congestion控制器，可以是BBR，也可以是传统的Cubic、Reno
    // 靠着6个定时器、RTT维护、传输速度等来驱动
}

impl DataSpace {
    pub fn create_sender(&mut self, sid: StreamId) -> Writer {
        let (outgoing, writer) = send::new(1000_1000);
        // 创建异步轮询子，监听来自应用层的cancel
        // 一旦cancel，直接向对方发送reset_stream
        // 但要等ResetRecved才能真正释放该流
        tokio::spawn({
            let outgoing = outgoing.clone();
            let frames = self.frames_buf.clone();
            async move {
                let _ = outgoing.is_cancelled_by_app().await;
                let mut frames = frames.lock().unwrap();
                frames.push_back(WriteFrame::ResetStream(ResetStreamFrame {
                    stream_id: sid,
                    app_error_code: VarInt::from_u32(0),
                    final_size: VarInt::from_u32(0),
                }));
            }
        });
        self.output.insert(sid, outgoing);
        writer
    }

    pub fn create_recver(&mut self, sid: StreamId) -> Reader {
        let (incoming, reader) = recv::new(1000_1000);
        // 不停地检查，是否需要及时更新MaxStreamData
        tokio::spawn({
            let incoming = incoming.clone();
            let frames = self.frames_buf.clone();
            async move {
                loop {
                    let max_data = incoming.need_window_update().await;
                    frames.lock().unwrap().push_back(WriteFrame::MaxStreamData(
                        MaxStreamDataFrame {
                            stream_id: sid,
                            max_stream_data: unsafe { VarInt::from_u64_unchecked(max_data) },
                        },
                    ));
                }
            }
        });
        // 监听是否被应用stop了。如果是，则要发送一个StopSendingFrame
        tokio::spawn({
            let incoming = incoming.clone();
            let frames = self.frames_buf.clone();
            async move {
                let _ = incoming.is_stopped_by_app().await;
                frames
                    .lock()
                    .unwrap()
                    .push_back(WriteFrame::StopSending(StopSendingFrame {
                        stream_id: sid,
                        app_err_code: VarInt::from_u32(0),
                    }));
            }
        });
        self.input.insert(sid, incoming);
        reader
    }
}

impl DataSpace {
    pub fn recv(&mut self, pktid: u64, payload: Vec<ReadFrame>) {
        if pktid < self.recved_pktid {
            // 重复收到了，不用处理
            return;
        }
        let idx = (pktid - self.recved_pktid) as usize;
        if self.recved_packets.get(idx).is_some() {
            // 重复收到了，不用处理
            return;
        }

        let mut is_ack_elicited = false;
        if idx >= self.recved_packets.len() {
            self.recved_packets.resize(idx + 1, None);
        }

        for frame in payload {
            match frame {
                ReadFrame::Padding => {}
                ReadFrame::Ping => {}
                ReadFrame::Ack(ack) => self.recv_ack(ack),
                ReadFrame::Stream(stream, body) => {
                    is_ack_elicited = true;
                    let sid = stream.id;
                    let result = self.stream_ids.try_accept_sid(sid);
                    match result {
                        Ok(accept) => match accept {
                            AcceptSid::Old => break,
                            AcceptSid::New(need_create, _extend_max_streams) => {
                                for sid in need_create {
                                    let reader = self.create_recver(sid);
                                    if sid.dir() == Dir::Bi {
                                        let writer = self.create_sender(sid);
                                    }
                                }
                            }
                        },
                        Err(_e) => {}
                    }
                    // TODO: 处理下这个sid，可能要新建流
                    self.input.get_mut(&sid).map(|incoming| {
                        incoming.recv(stream.offset.into_inner(), body);
                    });
                }
                ReadFrame::Crypto(_crypto, _body) => {
                    is_ack_elicited = true;
                    // TODO: 处理加密帧
                }
                ReadFrame::ResetStream(reset) => {
                    is_ack_elicited = true;
                    let sid = reset.stream_id;
                    // TODO: 处理下这个sid
                    // TODO: ResetStream中还携带着error code、final size，需要处理下
                    self.input.get_mut(&sid).map(|incoming| {
                        incoming.recv_reset();
                    });
                }
                ReadFrame::StopSending(stop) => {
                    is_ack_elicited = true;
                    let sid = stop.stream_id;
                    // TODO: 处理下这个sid
                    self.output.get_mut(&sid).map(|outgoing| {
                        outgoing.stop();
                    });
                    // 回写一个ResetStreamFrame
                    self.frames_buf
                        .lock()
                        .unwrap()
                        .push_back(WriteFrame::ResetStream(ResetStreamFrame {
                            stream_id: sid,
                            app_error_code: VarInt::from_u32(0),
                            final_size: VarInt::from_u32(0),
                        }));
                }
                ReadFrame::MaxData(_max_data) => {
                    is_ack_elicited = true;
                    // do nothing
                }
                ReadFrame::MaxStreamData(max_stream_data) => {
                    is_ack_elicited = true;
                    let sid = max_stream_data.stream_id;
                    // TODO: 处理下这个sid
                    self.output.get_mut(&sid).map(|outgoing| {
                        outgoing.update_window(max_stream_data.max_stream_data.into_inner());
                    });
                }
                ReadFrame::MaxStreams(max_streams) => {
                    is_ack_elicited = true;
                    match max_streams {
                        MaxStreamsFrame::Bi(val) => {
                            self.stream_ids.set_max_sid(Dir::Bi, val.into_inner());
                        }
                        MaxStreamsFrame::Uni(val) => {
                            self.stream_ids.set_max_sid(Dir::Uni, val.into_inner());
                        }
                    };
                }
                ReadFrame::DataBlocked(_data_blocked) => {
                    is_ack_elicited = true;
                    // 仅仅起到通知作用?
                }
                ReadFrame::StreamDataBlocked(_stream_data_blocked) => {
                    is_ack_elicited = true;
                    // 仅仅起到通知作用?
                }
                ReadFrame::StreamsBlocked(_streams_blocked) => {
                    is_ack_elicited = true;
                    // 仅仅起到通知作用?
                }
            }
        }

        self.recved_packets[idx] = Some((Instant::now(), is_ack_elicited));
    }

    pub fn gen_ack(&self) -> AckFrame {
        todo!("DataSpace::gen_ack")
    }

    fn recv_ack(&mut self, mut ack: AckFrame) {
        if let Some(_ecn) = ack.take_ecn() {
            // TODO: 处理ECN信息
        }

        let largest_acked = ack.largest.into_inner();
        if largest_acked < self.inflight_packets.offset() {
            return;
        }

        self.inflight_packets
            .get_mut(largest_acked)
            .and_then(|record| record.take())
            .map(|(send_time, payload)| {
                let _rtt_sample =
                    send_time.elapsed() - Duration::from_micros(ack.delay.into_inner());
                self.ack_recved(payload);
            });

        for range in ack.into_iter() {
            for pktid in range {
                self.inflight_packets
                    .get_mut(pktid)
                    .and_then(|record| record.take())
                    .map(|(_, payload)| self.ack_recved(payload));
            }
        }
    }

    fn ack_recved(&mut self, payload: Payload) {
        for frame in payload {
            match frame {
                WriteFrame::Stream(stream) => {
                    let sid = stream.id;
                    let start = stream.offset.into_inner();
                    let end = start + stream.length as u64;
                    let range = start..end;
                    self.output
                        .get_mut(&sid)
                        .map(|outgoing| outgoing.ack_recv(&range))
                        .map(|all_data_recved| {
                            if all_data_recved {
                                self.input.remove(&sid);
                            }
                        });
                }
                WriteFrame::Ack(range) => {
                    // 我方发送的ACK包，已经被对方确认，确认窗口要前移，使早期的确认不必再重发
                }
                WriteFrame::ResetStream(reset) => {
                    self.input.remove(&reset.stream_id);
                }
                // 其他的帧被对方收到，有通知发送者的权利，但没必要通知
                _ => println!("ignored"),
            }
        }
    }

    pub fn try_send(&mut self, max_size: usize) {
        todo!("DataSpace::try_send")
    }

    /// 其实，是去拿pending_packets缓冲的包
    pub fn poll_send(&mut self, cx: &mut Context) -> Poll<(u64, Bytes)> {
        assert!(self.send_waker.is_none(), "poll_send already called");
        match self.pending_packets.pop() {
            None => {
                self.send_waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Some((pktid, (payload, frames))) => {
                let now = Instant::now();
                self.inflight_packets.push(Some((now, frames)));
                Poll::Ready((pktid, payload))
            }
        }
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
