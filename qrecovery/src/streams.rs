use crate::{
    recv::{self, Incoming, Reader},
    send::{self, Outgoing, Writer},
    space::Transmit,
    AppStream,
};
use qbase::{
    error::{Error, ErrorKind},
    frame::*,
    streamid::*,
    varint::VarInt,
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll, Waker},
};
use tokio::sync::mpsc::UnboundedSender;

/// 专门根据Stream相关帧处理streams相关逻辑
#[derive(Debug)]
pub struct Streams {
    stream_ids: StreamIds,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: HashMap<StreamId, Outgoing>,
    // 所有流的待读端，收到了数据，交付给这些流
    input: HashMap<StreamId, Incoming>,
    // 对方主动创建的流
    listener: Listener,

    frame_tx: UnboundedSender<StreamInfoFrame>,
}

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> Error {
    move |e| Error::new(ErrorKind::StreamLimit, fty, e.to_string())
}

impl Transmit<StreamInfoFrame, StreamFrame> for Streams {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(StreamFrame, usize)> {
        // 遍历所有的Outgoing，看是否有数据要发送，一定要公平
        todo!()
    }

    fn confirm_data(&mut self, stream_frame: StreamFrame) {
        let sid = stream_frame.id;
        let start = stream_frame.offset.into_inner();
        let end = start + stream_frame.length as u64;
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

    fn may_loss(&mut self, stream_frame: StreamFrame) {
        if let Some(outgoing) = self.output.get_mut(&stream_frame.id) {
            outgoing.may_loss(&stream_frame.range());
        }
    }

    fn recv_data(&mut self, stream_frame: StreamFrame, body: bytes::Bytes) -> Result<(), Error> {
        let sid = stream_frame.id;
        // 对方必须是发送端，才能发送此帧
        if sid.role() != self.stream_ids.role() {
            // 对方的sid，看是否跳跃，把跳跃的流给创建好
            self.try_accept_sid(sid)
                .map_err(wrapper_error(stream_frame.frame_type()))?;
        } else {
            // 我方的sid，那必须是双向流才能收到对方的数据，否则就是错误
            if sid.dir() == Dir::Uni {
                return Err(Error::new(
                    ErrorKind::StreamState,
                    stream_frame.frame_type(),
                    format!("local {sid} cannot receive STREAM_FRAME"),
                ));
            }
        }
        if let Some(incoming) = self.input.get_mut(&sid) {
            incoming.recv(stream_frame, body)?;
        }
        // 否则，该流已经结束，再收到任何该流的frame，都将被忽略
        Ok(())
    }

    fn recv_frame(&mut self, stream_info_frame: StreamInfoFrame) -> Result<(), Error> {
        match stream_info_frame {
            StreamInfoFrame::ResetStream(reset_frame) => {
                let sid = reset_frame.stream_id;
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.stream_ids.role() {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(reset_frame.frame_type()))?;
                } else {
                    // 我方创建的流必须是双向流，对方才能发送ResetStream,否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(Error::new(
                            ErrorKind::StreamState,
                            stream_info_frame.frame_type(),
                            format!("local {sid} cannot receive RESET_FRAME"),
                        ));
                    }
                }
                if let Some(incoming) = self.input.get_mut(&sid) {
                    incoming.recv_reset(reset_frame)?;
                }
            }
            StreamInfoFrame::StopSending(stop) => {
                let sid = stop.stream_id;
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.stream_ids.role() {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的StopSendingFrame
                    if sid.dir() == Dir::Uni {
                        return Err(Error::new(
                            ErrorKind::StreamState,
                            stream_info_frame.frame_type(),
                            format!("remote {sid} must not send STOP_SENDING_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stop.frame_type()))?;
                }
                if let Some(outgoing) = self.output.get_mut(&sid) {
                    outgoing.stop();
                }

                let _ = self
                    .frame_tx
                    .send(StreamInfoFrame::ResetStream(ResetStreamFrame {
                        stream_id: sid,
                        app_error_code: VarInt::from_u32(0),
                        final_size: VarInt::from_u32(0),
                    }));
            }
            StreamInfoFrame::MaxStreamData(max_stream_data) => {
                let sid = max_stream_data.stream_id;
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.stream_ids.role() {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的MaxStreamData
                    if sid.dir() == Dir::Uni {
                        return Err(Error::new(
                            ErrorKind::StreamState,
                            stream_info_frame.frame_type(),
                            format!("remote {sid} must not send MAX_STREAM_DATA_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(max_stream_data.frame_type()))?;
                }
                if let Some(outgoing) = self.output.get_mut(&sid) {
                    outgoing.update_window(max_stream_data.max_stream_data.into_inner());
                }
            }
            StreamInfoFrame::StreamDataBlocked(stream_data_blocked) => {
                let sid = stream_data_blocked.stream_id;
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.stream_ids.role() {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stream_data_blocked.frame_type()))?;
                } else {
                    // 我方创建的，必须是双向流，对方才是发送端，才能发出StreamDataBlocked；否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(Error::new(
                            ErrorKind::StreamState,
                            stream_info_frame.frame_type(),
                            format!("local {sid} cannot receive STREAM_DATA_BLOCKED_FRAME"),
                        ));
                    }
                }
                // 仅仅起到通知作用?主动更新窗口的，此帧没多大用，或许要进一步放大缓冲区大小；被动更新窗口的，此帧有用
            }
            StreamInfoFrame::MaxStreams(max_streams) => {
                // 主要更新我方能创建的单双向流
                match max_streams {
                    MaxStreamsFrame::Bi(val) => {
                        self.stream_ids.set_max_sid(Dir::Bi, val.into_inner());
                    }
                    MaxStreamsFrame::Uni(val) => {
                        self.stream_ids.set_max_sid(Dir::Uni, val.into_inner());
                    }
                };
            }
            StreamInfoFrame::StreamsBlocked(_streams_blocked) => {
                // 仅仅起到通知作用?也分主动和被动
            }
        }
        Ok(())
    }
}

impl Streams {
    pub fn new(stream_ids: StreamIds, frame_tx: UnboundedSender<StreamInfoFrame>) -> Self {
        Self {
            stream_ids,
            output: HashMap::new(),
            input: HashMap::new(),
            listener: Listener::default(),
            frame_tx,
        }
    }

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

    pub fn listener(&self) -> Listener {
        self.listener.clone()
    }

    fn try_accept_sid(&mut self, sid: StreamId) -> Result<(), ExceedLimitError> {
        let result = self.stream_ids.try_accept_sid(sid)?;
        match result {
            AcceptSid::Old => Ok(()),
            AcceptSid::New(need_create, _extend_max_streams) => {
                for sid in need_create {
                    let reader = self.create_recver(sid);
                    let stream = if sid.dir() == Dir::Bi {
                        let writer = self.create_sender(sid);
                        AppStream::ReadWrite(reader, writer)
                    } else {
                        AppStream::ReadOnly(reader)
                    };
                    self.listener.push(stream);
                }
                Ok(())
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
                let _ = frame_tx.send(StreamInfoFrame::ResetStream(ResetStreamFrame {
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
                    let _ = frame_tx.send(StreamInfoFrame::MaxStreamData(MaxStreamDataFrame {
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
                incoming.is_stopped_by_app().await;
                let _ = frame_tx.send(StreamInfoFrame::StopSending(StopSendingFrame {
                    stream_id: sid,
                    app_err_code: VarInt::from_u32(0),
                }));
            }
        });
        self.input.insert(sid, incoming);
        reader
    }
}

#[derive(Debug, Default)]
struct RawListener {
    // 对方主动创建的流
    streams: VecDeque<AppStream>,
    waker: Option<Waker>,
}

impl RawListener {
    fn push(&mut self, stream: AppStream) {
        self.streams.push_back(stream);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<AppStream, Error>> {
        if let Some(stream) = self.streams.pop_front() {
            Poll::Ready(Ok(stream))
        } else {
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Listener(Arc<Mutex<RawListener>>);

impl Listener {
    fn push(&self, stream: AppStream) {
        self.0.lock().unwrap().push(stream);
    }

    pub fn accept(&self) -> Accept {
        Accept {
            inner: self.clone(),
        }
    }

    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Result<AppStream, Error>> {
        self.0.lock().unwrap().poll_accept(cx)
    }
}

#[derive(Debug, Clone)]
pub struct Accept {
    inner: Listener,
}

impl Future for Accept {
    type Output = Result<AppStream, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_accept(cx)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
