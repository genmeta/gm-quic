/// Application data space, 1-RTT data space
use crate::{
    recv::{self, Incoming, Reader},
    send::{self, Outgoing, Writer},
    AppStream,
};
use qbase::{
    frame::{OneRttFrame, *},
    streamid::*,
    varint::VarInt,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
};
use tokio::sync::mpsc::UnboundedSender;

type OneRttDataFrame = DataFrame;

pub struct OneRttDataSpace(Arc<Mutex<super::Space<OneRttFrame, OneRttDataFrame, Transmission>>>);

#[derive(Debug)]
pub struct Transmission {
    stream_ids: StreamIds,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: HashMap<StreamId, Outgoing>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: HashMap<StreamId, Incoming>,
    // 对方主动创建的流
    accepted_streams: VecDeque<AppStream>,
    accpet_waker: Option<Waker>,

    frame_tx: UnboundedSender<OneRttFrame>,
}

impl super::Transmit<OneRttFrame, OneRttDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(OneRttDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream) => {
                let sid = stream.id;
                let start = stream.offset.into_inner();
                let end = start + stream.length as u64;
                let range = start..end;
                if let Some(all_data_recved) = self
                    .output
                    .get_mut(&sid)
                    .map(|outgoing| outgoing.ack_rcvd(&range))
                {
                    if all_data_recved {
                        self.input.remove(&sid);
                    }
                }
            }
            OneRttDataFrame::Crypto(_crypto) => {
                // TODO: 处理加密数据流
            }
        }
    }

    fn may_loss(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream) => {
                if let Some(outgoing) = self.output.get_mut(&stream.id) {
                    outgoing.may_loss(&stream.range());
                }
            }
            OneRttDataFrame::Crypto(_crypto) => {
                // 处理加密数据流的丢包
            }
        }
    }

    fn recv_data(&mut self, data_frame: OneRttDataFrame, body: bytes::Bytes) {
        match data_frame {
            OneRttDataFrame::Stream(stream) => {
                let sid = stream.id;
                self.try_accept_sid(sid);
                if let Some(incoming) = self.input.get_mut(&sid) {
                    incoming.recv(stream.offset.into_inner(), body);
                }
                // 否则，该流已经结束，再收到任何该流的frame，都将被忽略
            }
            OneRttDataFrame::Crypto(_crypto) => {
                // TODO: 处理加密数据
            }
        }
    }

    fn recv_frame(&mut self, frame: OneRttFrame) {
        match frame {
            OneRttFrame::Ping(_) => (),
            OneRttFrame::ResetStream(reset) => {
                let sid = reset.stream_id;
                // TODO: 处理下这个sid
                // TODO: ResetStream中还携带着error code、final size，需要处理下
                if let Some(incoming) = self.input.get_mut(&sid) {
                    incoming.recv_reset();
                }
            }
            OneRttFrame::StopSending(stop) => {
                let sid = stop.stream_id;
                // TODO: 处理下这个sid
                if let Some(outgoing) = self.output.get_mut(&sid) {
                    outgoing.stop();
                }
                // 回写一个ResetStreamFrame
                let _ = self
                    .frame_tx
                    .send(OneRttFrame::ResetStream(ResetStreamFrame {
                        stream_id: sid,
                        app_error_code: VarInt::from_u32(0),
                        final_size: VarInt::from_u32(0),
                    }));
            }
            OneRttFrame::MaxStreamData(max_stream_data) => {
                let sid = max_stream_data.stream_id;
                // TODO: 处理下这个sid
                if let Some(outgoing) = self.output.get_mut(&sid) {
                    outgoing.update_window(max_stream_data.max_stream_data.into_inner());
                }
            }
            OneRttFrame::MaxStreams(max_streams) => {
                match max_streams {
                    MaxStreamsFrame::Bi(val) => {
                        self.stream_ids.set_max_sid(Dir::Bi, val.into_inner());
                    }
                    MaxStreamsFrame::Uni(val) => {
                        self.stream_ids.set_max_sid(Dir::Uni, val.into_inner());
                    }
                };
            }
            OneRttFrame::StreamDataBlocked(_stream_data_blocked) => {
                // 仅仅起到通知作用?
            }
            OneRttFrame::StreamsBlocked(_streams_blocked) => {
                // 仅仅起到通知作用?
            }
            _ => unreachable!("these are handled in connection layer"),
        }
    }
}

impl Transmission {
    pub fn poll_create(&mut self, cx: &mut Context<'_>, dir: Dir) -> Poll<Option<AppStream>> {
        if let Some(sid) = ready!(self.stream_ids.poll_alloc_sid(cx, dir)) {
            let writer = self.create_sender(sid);
            if dir == Dir::Bi {
                let reader = self.create_recver(sid);
                Poll::Ready(Some(AppStream::ReadWrite(reader, writer)))
            } else {
                Poll::Ready(Some(AppStream::WriteOnly(writer)))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn try_accept_sid(&mut self, sid: StreamId) {
        let result = self.stream_ids.try_accept_sid(sid);
        match result {
            Ok(accept) => match accept {
                AcceptSid::Old => (),
                AcceptSid::New(need_create, _extend_max_streams) => {
                    for sid in need_create {
                        let reader = self.create_recver(sid);
                        if sid.dir() == Dir::Bi {
                            let writer = self.create_sender(sid);
                            let stream = AppStream::ReadWrite(reader, writer);
                            self.accepted_streams.push_back(stream);
                        } else {
                            let stream = AppStream::ReadOnly(reader);
                            self.accepted_streams.push_back(stream);
                        }
                    }

                    // accpet新连接
                    if let Some(waker) = self.accpet_waker.take() {
                        waker.wake();
                    }
                }
            },
            Err(_e) => {
                // TODO: 错误处理，错误的角色，或创建了超过最大限值的流
            }
        }
    }

    fn create_sender(&mut self, sid: StreamId) -> Writer {
        let (outgoing, writer) = send::new(1000_1000);
        // 创建异步轮询子，监听来自应用层的cancel
        // 一旦cancel，直接向对方发送reset_stream
        // 但要等ResetRecved才能真正释放该流
        tokio::spawn({
            let outgoing = outgoing.clone();
            let frame_tx = self.frame_tx.clone();
            async move {
                let final_size = outgoing.is_cancelled_by_app().await;
                let _ = frame_tx.send(OneRttFrame::ResetStream(ResetStreamFrame {
                    stream_id: sid,
                    app_error_code: VarInt::from_u32(0),
                    final_size: unsafe { VarInt::from_u64_unchecked(final_size.unwrap()) },
                }));
            }
        });
        self.output.insert(sid, outgoing);
        writer
    }

    fn create_recver(&mut self, sid: StreamId) -> Reader {
        let (incoming, reader) = recv::new(1000_1000);
        // 不停地检查，是否需要及时更新MaxStreamData
        tokio::spawn({
            let incoming = incoming.clone();
            let frame_tx = self.frame_tx.clone();
            async move {
                loop {
                    let max_data = incoming.need_window_update().await;
                    let _ = frame_tx.send(OneRttFrame::MaxStreamData(MaxStreamDataFrame {
                        stream_id: sid,
                        max_stream_data: unsafe { VarInt::from_u64_unchecked(max_data) },
                    }));
                }
            }
        });
        // 监听是否被应用stop了。如果是，则要发送一个StopSendingFrame
        tokio::spawn({
            let incoming = incoming.clone();
            let frame_tx = self.frame_tx.clone();
            async move {
                let _ = incoming.is_stopped_by_app().await;
                let _ = frame_tx.send(OneRttFrame::StopSending(StopSendingFrame {
                    stream_id: sid,
                    app_err_code: VarInt::from_u32(0),
                }));
            }
        });
        self.input.insert(sid, incoming);
        reader
    }
}

impl OneRttDataSpace {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
