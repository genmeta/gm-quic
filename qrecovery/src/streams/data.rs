use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    task::{ready, Context, Poll},
};

use bytes::BufMut;
use qbase::{
    error::{Error as QuicError, ErrorKind},
    frame::*,
    streamid::{AcceptSid, Dir, ExceedLimitError, Role, StreamId, StreamIds},
    varint::VarInt,
};

use super::listener::ArcListener;
use crate::{
    recv::{self, Incoming, Reader},
    reliable::ArcReliableFrameQueue,
    send::{self, Outgoing, Writer},
};

/// ArcOutput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[derive(Debug, Clone)]
pub struct ArcOutput(Arc<Mutex<Result<HashMap<StreamId, Outgoing>, QuicError>>>);

impl Default for ArcOutput {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Ok(HashMap::new()))))
    }
}

impl ArcOutput {
    fn guard(&self) -> Result<ArcOutputGuard, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ArcOutputGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }
}

struct ArcOutputGuard<'a> {
    inner: MutexGuard<'a, Result<HashMap<StreamId, Outgoing>, QuicError>>,
}

impl ArcOutputGuard<'_> {
    fn insert(&mut self, sid: StreamId, outgoing: Outgoing) {
        match self.inner.as_mut() {
            Ok(set) => set.insert(sid, outgoing),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
    }

    fn on_conn_error(&mut self, err: &QuicError) {
        match self.inner.as_ref() {
            Ok(set) => set.values().for_each(|o| o.on_conn_error(err)),
            // 已经遇到过conn error了，不需要再次处理。然而guard()时就已经返回了Err，不会再走到这里来
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.inner = Err(err.clone());
    }
}

/// ArcInput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[derive(Debug, Clone)]
struct ArcInput(Arc<Mutex<Result<HashMap<StreamId, Incoming>, QuicError>>>);

impl Default for ArcInput {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Ok(HashMap::new()))))
    }
}

impl ArcInput {
    fn guard(&self) -> Result<ArcInputGuard, QuicError> {
        let guard = self.0.lock().unwrap();
        match guard.as_ref() {
            Ok(_) => Ok(ArcInputGuard { inner: guard }),
            Err(e) => Err(e.clone()),
        }
    }
}

struct ArcInputGuard<'a> {
    inner: MutexGuard<'a, Result<HashMap<StreamId, Incoming>, QuicError>>,
}

impl ArcInputGuard<'_> {
    fn insert(&mut self, sid: StreamId, incoming: Incoming) {
        match self.inner.as_mut() {
            Ok(set) => set.insert(sid, incoming),
            Err(e) => unreachable!("input is invalid: {e}"),
        };
    }

    fn on_conn_error(&mut self, err: &QuicError) {
        match self.inner.as_ref() {
            Ok(set) => set.values().for_each(|o| o.on_conn_error(err)),
            Err(e) => unreachable!("output is invalid: {e}"),
        };
        *self.inner = Err(err.clone());
    }
}

/// 专门根据Stream相关帧处理streams相关逻辑
#[derive(Debug, Clone)]
pub(super) struct RawDataStreams {
    role: Role,
    stream_ids: StreamIds,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: ArcOutput,
    // 所有流的待读端，收到了数据，交付给这些流
    input: ArcInput,
    // 对方主动创建的流
    listener: ArcListener,

    // 该queue与space中的transmitter中的frame_queue共享，为了方便向transmitter中写入帧
    reliable_frame_queue: ArcReliableFrameQueue,
}

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> QuicError {
    move |e| QuicError::new(ErrorKind::StreamLimit, fty, e.to_string())
}

impl RawDataStreams {
    pub fn try_read_data(&self, mut buf: &mut [u8]) -> Option<(StreamFrame, usize)> {
        let guard = &mut self.output.0.lock().unwrap();
        let output = &guard.as_mut().ok()?;
        output
            .iter()
            .filter_map(|(&sid, outgoing)| {
                let remain = buf.remaining_mut();
                let frame = outgoing.try_read(sid, &mut buf)?;
                let len = remain - buf.remaining_mut();
                Some((frame, len))
            })
            .next()
    }

    pub fn on_data_acked(&self, stream_frame: StreamFrame) {
        if let Ok(set) = self.output.0.lock().unwrap().as_mut() {
            if let Some(all_data_rcvd) = set
                .get(&stream_frame.id)
                .map(|o| o.on_data_acked(&stream_frame.range()))
            {
                if all_data_rcvd {
                    set.remove(&stream_frame.id);
                }
            }
        }
    }

    pub fn may_loss_data(&self, stream_frame: StreamFrame) {
        if let Some(o) = self
            .output
            .0
            .lock()
            .unwrap()
            .as_mut()
            .ok()
            .and_then(|set| set.get(&stream_frame.id))
        {
            o.may_loss_data(&stream_frame.range());
        }
    }

    pub fn on_reset_acked(&self, reset_frame: ResetStreamFrame) {
        if let Ok(set) = self.output.0.lock().unwrap().as_mut() {
            if let Some(o) = set.remove(&reset_frame.stream_id) {
                o.on_reset_acked();
            }
            // 如果流是双向的，接收部分的流独立地管理结束。其实是上层应用决定接收的部分是否同时结束
        }
    }

    pub fn recv_data(
        &self,
        stream_frame: StreamFrame,
        body: bytes::Bytes,
    ) -> Result<(), QuicError> {
        let sid = stream_frame.id;
        // 对方必须是发送端，才能发送此帧
        if sid.role() != self.role {
            // 对方的sid，看是否跳跃，把跳跃的流给创建好
            self.try_accept_sid(sid)
                .map_err(wrapper_error(stream_frame.frame_type()))?;
        } else {
            // 我方的sid，那必须是双向流才能收到对方的数据，否则就是错误
            if sid.dir() == Dir::Uni {
                return Err(QuicError::new(
                    ErrorKind::StreamState,
                    stream_frame.frame_type(),
                    format!("local {sid} cannot receive STREAM_FRAME"),
                ));
            }
        }
        self.input
            .0
            .lock()
            .unwrap()
            .as_mut()
            .ok()
            .and_then(|set| set.get(&sid))
            .map(|incoming| incoming.recv_data(stream_frame, body));
        // 否则，该流已经结束，再收到任何该流的frame，都将被忽略
        Ok(())
    }

    pub fn recv_stream_control(&self, stream_ctl_frame: StreamCtlFrame) -> Result<(), QuicError> {
        match stream_ctl_frame {
            StreamCtlFrame::ResetStream(reset_frame) => {
                let sid = reset_frame.stream_id;
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.role {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(reset_frame.frame_type()))?;
                } else {
                    // 我方创建的流必须是双向流，对方才能发送ResetStream,否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_ctl_frame.frame_type(),
                            format!("local {sid} cannot receive RESET_FRAME"),
                        ));
                    }
                }
                if let Ok(set) = self.input.0.lock().unwrap().as_mut() {
                    if let Some(incoming) = set.remove(&sid) {
                        incoming.recv_reset(reset_frame)?;
                    }
                }
            }
            StreamCtlFrame::StopSending(stop) => {
                let sid = stop.stream_id;
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.role {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的StopSendingFrame
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_ctl_frame.frame_type(),
                            format!("remote {sid} must not send STOP_SENDING_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stop.frame_type()))?;
                }
                if self
                    .output
                    .0
                    .lock()
                    .unwrap()
                    .as_mut()
                    .ok()
                    .and_then(|set| set.get(&sid))
                    .map(|outgoing| outgoing.stop())
                    .unwrap_or(false)
                {
                    self.reliable_frame_queue.write().push_stream_control_frame(
                        StreamCtlFrame::ResetStream(ResetStreamFrame {
                            stream_id: sid,
                            app_error_code: VarInt::from_u32(0),
                            final_size: VarInt::from_u32(0),
                        }),
                    );
                }
            }
            StreamCtlFrame::MaxStreamData(max_stream_data) => {
                let sid = max_stream_data.stream_id;
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.role {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的MaxStreamData
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_ctl_frame.frame_type(),
                            format!("remote {sid} must not send MAX_STREAM_DATA_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(max_stream_data.frame_type()))?;
                }
                if let Some(outgoing) = self
                    .output
                    .0
                    .lock()
                    .unwrap()
                    .as_ref()
                    .ok()
                    .and_then(|set| set.get(&sid))
                {
                    outgoing.update_window(max_stream_data.max_stream_data.into_inner());
                }
            }
            StreamCtlFrame::StreamDataBlocked(stream_data_blocked) => {
                let sid = stream_data_blocked.stream_id;
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.role {
                    self.try_accept_sid(sid)
                        .map_err(wrapper_error(stream_data_blocked.frame_type()))?;
                } else {
                    // 我方创建的，必须是双向流，对方才是发送端，才能发出StreamDataBlocked；否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_ctl_frame.frame_type(),
                            format!("local {sid} cannot receive STREAM_DATA_BLOCKED_FRAME"),
                        ));
                    }
                }
                // 仅仅起到通知作用?主动更新窗口的，此帧没多大用，或许要进一步放大缓冲区大小；被动更新窗口的，此帧有用
            }
            StreamCtlFrame::MaxStreams(max_streams) => {
                // 主要更新我方能创建的单双向流
                match max_streams {
                    MaxStreamsFrame::Bi(val) => {
                        self.stream_ids
                            .local
                            .permit_max_sid(Dir::Bi, val.into_inner());
                    }
                    MaxStreamsFrame::Uni(val) => {
                        self.stream_ids
                            .local
                            .permit_max_sid(Dir::Uni, val.into_inner());
                    }
                };
            }
            StreamCtlFrame::StreamsBlocked(_streams_blocked) => {
                // 仅仅起到通知作用?也分主动和被动
            }
        }
        Ok(())
    }

    pub fn on_conn_error(&self, err: &QuicError) {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(_) => return,
        };
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(_) => return,
        };
        let mut listener = match self.listener.guard() {
            Ok(listener) => listener,
            Err(_) => return,
        };

        output.on_conn_error(err);
        input.on_conn_error(err);
        listener.on_conn_error(err);
    }
}

impl RawDataStreams {
    pub(super) fn with_role_and_limit(
        role: Role,
        max_bi_streams: u64,
        max_uni_streams: u64,
        reliable_frame_queue: ArcReliableFrameQueue,
    ) -> Self {
        Self {
            role,
            stream_ids: StreamIds::with_role_and_limit(role, max_bi_streams, max_uni_streams),
            output: ArcOutput::default(),
            input: ArcInput::default(),
            listener: ArcListener::default(),
            reliable_frame_queue,
        }
    }

    pub(super) fn poll_open_bi_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<(Reader, Writer)>, QuicError>> {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Bi)) {
            let (outgoing, writer) = self.create_sender(sid);
            let (incoming, reader) = self.create_recver(sid);
            output.insert(sid, outgoing);
            input.insert(sid, incoming);
            Poll::Ready(Ok(Some((reader, writer))))
        } else {
            Poll::Ready(Ok(None))
        }
    }

    pub(super) fn poll_open_uni_stream(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Writer>, QuicError>> {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Uni)) {
            let (outgoing, writer) = self.create_sender(sid);
            output.insert(sid, outgoing);
            Poll::Ready(Ok(Some(writer)))
        } else {
            Poll::Ready(Ok(None))
        }
    }

    pub(super) fn listener(&self) -> ArcListener {
        self.listener.clone()
    }

    fn try_accept_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        match sid.dir() {
            Dir::Bi => self.try_accept_bi_sid(sid),
            Dir::Uni => self.try_accept_uni_sid(sid),
        }
    }

    fn try_accept_bi_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(_) => return Ok(()),
        };
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(_) => return Ok(()),
        };
        let mut listener = match self.listener.guard() {
            Ok(listener) => listener,
            Err(_) => return Ok(()),
        };
        let result = self.stream_ids.remote.try_accept_sid(sid)?;
        match result {
            AcceptSid::Old => Ok(()),
            AcceptSid::New(need_create) => {
                for sid in need_create {
                    let (incoming, reader) = self.create_recver(sid);
                    let (outgoing, writer) = self.create_sender(sid);
                    input.insert(sid, incoming);
                    output.insert(sid, outgoing);
                    listener.push_bi_stream((reader, writer));
                }
                Ok(())
            }
        }
    }

    fn try_accept_uni_sid(&self, sid: StreamId) -> Result<(), ExceedLimitError> {
        let mut input = match self.input.guard() {
            Ok(input) => input,
            Err(_) => return Ok(()),
        };
        let mut listener = match self.listener.guard() {
            Ok(listener) => listener,
            Err(_) => return Ok(()),
        };
        let result = self.stream_ids.remote.try_accept_sid(sid)?;
        match result {
            AcceptSid::Old => Ok(()),
            AcceptSid::New(need_create) => {
                for sid in need_create {
                    let (incoming, reader) = self.create_recver(sid);
                    input.insert(sid, incoming);
                    listener.push_uni_stream(reader);
                }
                Ok(())
            }
        }
    }

    fn create_sender(&self, sid: StreamId) -> (Outgoing, Writer) {
        let (outgoing, writer) = send::new(1000_1000);
        // 创建异步轮询子，监听来自应用层的cancel
        // 一旦cancel，直接向对方发送reset_stream
        // 但要等ResetRecved才能真正释放该流
        tokio::spawn({
            let outgoing = outgoing.clone();
            let frames = self.reliable_frame_queue.clone();
            async move {
                if let Some((final_size, err_code)) = outgoing.is_cancelled_by_app().await {
                    frames
                        .write()
                        .push_stream_control_frame(StreamCtlFrame::ResetStream(ResetStreamFrame {
                            stream_id: sid,
                            app_error_code: VarInt::from_u64(err_code)
                                .expect("app error code must not exceed VARINT_MAX"),
                            final_size: unsafe { VarInt::from_u64_unchecked(final_size) },
                        }));
                }
            }
        });
        (outgoing, writer)
    }

    fn create_recver(&self, sid: StreamId) -> (Incoming, Reader) {
        let (incoming, reader) = recv::new(1000_1000);
        // Continuously check whether the MaxStreamData window needs to be updated.
        tokio::spawn({
            let incoming = incoming.clone();
            let frames = self.reliable_frame_queue.clone();
            async move {
                while let Some(max_data) = incoming.need_update_window().await {
                    frames
                        .write()
                        .push_stream_control_frame(StreamCtlFrame::MaxStreamData(
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
            let frames = self.reliable_frame_queue.clone();
            async move {
                if let Some(err_code) = incoming.is_stopped_by_app().await {
                    frames
                        .write()
                        .push_stream_control_frame(StreamCtlFrame::StopSending(StopSendingFrame {
                            stream_id: sid,
                            app_err_code: VarInt::from_u64(err_code)
                                .expect("app error code must not exceed VARINT_MAX"),
                        }));
                }
            }
        });
        (incoming, reader)
    }
}
