use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard},
    task::{ready, Context, Poll},
};

use deref_derive::{Deref, DerefMut};
use qbase::{
    config::Parameters,
    error::{Error as QuicError, ErrorKind},
    frame::{
        BeFrame, FrameType, MaxStreamDataFrame, MaxStreamsFrame, ReliableFrame, ResetStreamFrame,
        StopSendingFrame, StreamCtlFrame, StreamFrame,
    },
    streamid::{AcceptSid, Dir, ExceedLimitError, Role, StreamId, StreamIds},
    varint::VarInt,
};

use super::listener::{AcceptBiStream, AcceptUniStream, ArcListener};
use crate::{
    recv::{self, Incoming, Reader},
    reliable::ArcReliableFrameDeque,
    send::{self, Outgoing, Writer},
};

#[derive(Default, Debug, Clone, Deref, DerefMut)]
struct RawOutput {
    #[deref]
    outgoings: BTreeMap<StreamId, Outgoing>,
    cur_sending_stream: Option<(StreamId, usize)>,
}

/// ArcOutput里面包含一个Result类型，一旦发生quic error，就会被替换为Err
/// 发生quic error后，其操作将被忽略，不会再抛出QuicError或者panic，因为
/// 有些异步任务可能还未完成，在置为Err后才会完成。
#[derive(Debug, Clone)]
pub struct ArcOutput(Arc<Mutex<Result<RawOutput, QuicError>>>);

impl Default for ArcOutput {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Ok(Default::default()))))
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
    inner: MutexGuard<'a, Result<RawOutput, QuicError>>,
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
pub struct RawDataStreams {
    // 该queue与space中的transmitter中的frame_queue共享，为了方便向transmitter中写入帧
    pub reliable_frame_deque: ArcReliableFrameDeque,

    role: Role,
    stream_ids: StreamIds,
    // 所有流的待写端，要发送数据，就得向这些流索取
    output: ArcOutput,
    // 所有流的待读端，收到了数据，交付给这些流
    input: ArcInput,
    // 对方主动创建的流
    listener: ArcListener,
}

fn wrapper_error(fty: FrameType) -> impl FnOnce(ExceedLimitError) -> QuicError {
    move |e| QuicError::new(ErrorKind::StreamLimit, fty, e.to_string())
}

impl RawDataStreams {
    pub fn try_read_data(
        &self,
        buf: &mut [u8],
        flow_limit: usize,
    ) -> Option<(StreamFrame, usize, usize)> {
        let guard = &mut self.output.0.lock().unwrap();
        let output = guard.as_mut().ok()?;

        const DEFAULT_TOKENS: usize = 4096;

        // 该tokens是令牌桶算法的token，为了多条Stream的公平性，给每个流定期地发放tokens，不累积
        // 各流轮流按令牌桶算法发放的tokens来整理数据去发送
        let (sid, outgoing, tokens) = output
            .cur_sending_stream
            .and_then(|(sid, tokens): (StreamId, usize)| {
                if tokens == 0 {
                    // 没有额度：下一个
                    output
                        .outgoings
                        .range(sid..)
                        .nth(1)
                        .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
                } else {
                    // 有额度：继续
                    Some((sid, output.outgoings.get(&sid)?, tokens))
                }
            })
            .or_else(|| {
                // 还没开始/没有下一个/该sid已经被移除：从头开始
                output
                    .outgoings
                    .first_key_value()
                    .map(|(sid, outgoing)| (*sid, outgoing, DEFAULT_TOKENS))
            })?;

        let (frame, dat_len, is_fresh, written) =
            outgoing.try_read(sid, buf, tokens, flow_limit)?;
        output.cur_sending_stream = Some((sid, tokens - dat_len));

        Some((frame, written, if is_fresh { dat_len } else { 0 }))
    }

    pub fn on_data_acked(&self, frame: StreamFrame) {
        if let Ok(set) = self.output.0.lock().unwrap().as_mut() {
            if set
                .get(&frame.id)
                .map(|o| o.on_data_acked(&frame.range(), frame.is_fin()))
                .is_some_and(|all_data_rcvd| all_data_rcvd)
            {
                set.remove(&frame.id);
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
        local_params: &Parameters,
        remote_params: &Parameters,
        stream_frame: &StreamFrame,
        body: bytes::Bytes,
    ) -> Result<usize, QuicError> {
        let sid = stream_frame.id;
        // 对方必须是发送端，才能发送此帧
        if sid.role() != self.role {
            // 对方的sid，看是否跳跃，把跳跃的流给创建好
            self.try_accept_sid(sid, local_params, remote_params)
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
        let ret = self
            .input
            .0
            .lock()
            .unwrap()
            .as_mut()
            .ok()
            .and_then(|set| set.get(&sid))
            .map(|incoming| incoming.recv_data(stream_frame, body));

        match ret {
            Some(recv_ret) => recv_ret,
            // 该流已结束，收到的数据将被忽略
            None => Ok(0),
        }
    }

    pub fn recv_stream_control(
        &self,
        local_params: &Parameters,
        remote_params: &Parameters,
        stream_ctl_frame: &StreamCtlFrame,
    ) -> Result<(), QuicError> {
        match stream_ctl_frame {
            StreamCtlFrame::ResetStream(reset) => {
                let sid = reset.stream_id;
                // 对方必须是发送端，才能发送此帧
                if sid.role() != self.role {
                    self.try_accept_sid(sid, local_params, remote_params)
                        .map_err(wrapper_error(reset.frame_type()))?;
                } else {
                    // 我方创建的流必须是双向流，对方才能发送ResetStream,否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            reset.frame_type(),
                            format!("local {sid} cannot receive RESET_FRAME"),
                        ));
                    }
                }
                if let Ok(set) = self.input.0.lock().unwrap().as_mut() {
                    if let Some(incoming) = set.remove(&sid) {
                        incoming.recv_reset(reset)?;
                    }
                }
            }
            StreamCtlFrame::StopSending(stop_sending) => {
                let sid = stop_sending.stream_id;
                // 对方必须是接收端，才能发送此帧
                if sid.role() != self.role {
                    // 对方创建的单向流，接收端是我方，不可能收到对方的StopSendingFrame
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stop_sending.frame_type(),
                            format!("remote {sid} must not send STOP_SENDING_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid, local_params, remote_params)
                        .map_err(wrapper_error(stop_sending.frame_type()))?;
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
                    self.reliable_frame_deque
                        .lock_guard()
                        .push_back(ReliableFrame::Stream(StreamCtlFrame::ResetStream(
                            ResetStreamFrame {
                                stream_id: sid,
                                app_error_code: VarInt::from_u32(0),
                                final_size: VarInt::from_u32(0),
                            },
                        )));
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
                            max_stream_data.frame_type(),
                            format!("remote {sid} must not send MAX_STREAM_DATA_FRAME"),
                        ));
                    }
                    self.try_accept_sid(sid, local_params, remote_params)
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
                    self.try_accept_sid(sid, local_params, remote_params)
                        .map_err(wrapper_error(stream_data_blocked.frame_type()))?;
                } else {
                    // 我方创建的，必须是双向流，对方才是发送端，才能发出StreamDataBlocked；否则就是错误
                    if sid.dir() == Dir::Uni {
                        return Err(QuicError::new(
                            ErrorKind::StreamState,
                            stream_data_blocked.frame_type(),
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

    pub fn premit_max_sid(&self, dir: Dir, val: u64) {
        self.stream_ids.local.permit_max_sid(dir, val);
    }
}

impl RawDataStreams {
    pub(super) fn new(
        role: Role,
        local_params: &Parameters,
        reliable_frame_deque: ArcReliableFrameDeque,
    ) -> Self {
        Self {
            role,
            stream_ids: StreamIds::new(role, local_params),
            output: ArcOutput::default(),
            input: ArcInput::default(),
            listener: ArcListener::default(),
            reliable_frame_deque,
        }
    }

    pub(super) fn poll_open_bi_stream(
        &self,
        cx: &mut Context<'_>,
        local_params: &Parameters,
        remote_params: &Parameters,
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
            let writer_max_stream_data = remote_params.initial_max_stream_data_bidi_remote().into();
            let (outgoing, writer) = self.create_sender(sid, writer_max_stream_data);
            let reader_max_stream_data = local_params.initial_max_stream_data_bidi_local().into();
            let (incoming, reader) = self.create_recver(sid, reader_max_stream_data);
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
        remote_params: &Parameters,
    ) -> Poll<Result<Option<Writer>, QuicError>> {
        let mut output = match self.output.guard() {
            Ok(out) => out,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Some(sid) = ready!(self.stream_ids.local.poll_alloc_sid(cx, Dir::Uni)) {
            let max_stream_data = remote_params.initial_max_stream_data_uni().into();
            let (outgoing, writer) = self.create_sender(sid, max_stream_data);
            output.insert(sid, outgoing);
            Poll::Ready(Ok(Some(writer)))
        } else {
            Poll::Ready(Ok(None))
        }
    }

    #[inline]
    pub(super) fn accept_bi(&self) -> AcceptBiStream {
        self.listener.accept_bi_stream()
    }

    #[inline]
    pub(super) fn accept_uni(&self) -> AcceptUniStream {
        self.listener.accept_uni_stream()
    }

    pub(super) fn listener(&self) -> ArcListener {
        self.listener.clone()
    }

    fn try_accept_sid(
        &self,
        sid: StreamId,
        local_params: &Parameters,
        remote_params: &Parameters,
    ) -> Result<(), ExceedLimitError> {
        match sid.dir() {
            Dir::Bi => self.try_accept_bi_sid(sid, local_params, remote_params),
            Dir::Uni => self.try_accept_uni_sid(sid, local_params),
        }
    }

    fn try_accept_bi_sid(
        &self,
        sid: StreamId,
        local_params: &Parameters,
        remote_params: &Parameters,
    ) -> Result<(), ExceedLimitError> {
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
                let reader_max_stream_data =
                    local_params.initial_max_stream_data_bidi_remote().into();
                let writer_max_stream_data =
                    remote_params.initial_max_stream_data_bidi_local().into();

                for sid in need_create {
                    let (incoming, reader) = self.create_recver(sid, reader_max_stream_data);
                    let (outgoing, writer) = self.create_sender(sid, writer_max_stream_data);
                    input.insert(sid, incoming);
                    output.insert(sid, outgoing);
                    listener.push_bi_stream((reader, writer));
                }
                Ok(())
            }
        }
    }

    fn try_accept_uni_sid(
        &self,
        sid: StreamId,
        local_params: &Parameters,
    ) -> Result<(), ExceedLimitError> {
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
                let reader_max_stream_data = local_params.initial_max_stream_data_uni().into();

                for sid in need_create {
                    let (incoming, reader) = self.create_recver(sid, reader_max_stream_data);
                    input.insert(sid, incoming);
                    listener.push_uni_stream(reader);
                }
                Ok(())
            }
        }
    }

    fn create_sender(&self, sid: StreamId, max_stream_data: u64) -> (Outgoing, Writer) {
        let (outgoing, writer) = send::new(max_stream_data);
        // 创建异步轮询子，监听来自应用层的cancel
        // 一旦cancel，直接向对方发送reset_stream
        // 但要等ResetRecved才能真正释放该流
        tokio::spawn({
            let outgoing = outgoing.clone();
            let frames = self.reliable_frame_deque.clone();
            async move {
                if let Some((final_size, err_code)) = outgoing.is_cancelled_by_app().await {
                    frames.lock_guard().push_back(ReliableFrame::Stream(
                        StreamCtlFrame::ResetStream(ResetStreamFrame {
                            stream_id: sid,
                            app_error_code: VarInt::from_u64(err_code)
                                .expect("app error code must not exceed VARINT_MAX"),
                            final_size: unsafe { VarInt::from_u64_unchecked(final_size) },
                        }),
                    ));
                }
            }
        });
        (outgoing, writer)
    }

    fn create_recver(&self, sid: StreamId, max_stream_data: u64) -> (Incoming, Reader) {
        let (incoming, reader) = recv::new(max_stream_data);
        // Continuously check whether the MaxStreamData window needs to be updated.
        tokio::spawn({
            let incoming = incoming.clone();
            let frames = self.reliable_frame_deque.clone();
            async move {
                while let Some(max_data) = incoming.need_update_window().await {
                    frames.lock_guard().push_back(ReliableFrame::Stream(
                        StreamCtlFrame::MaxStreamData(MaxStreamDataFrame {
                            stream_id: sid,
                            max_stream_data: unsafe { VarInt::from_u64_unchecked(max_data) },
                        }),
                    ));
                }
            }
        });
        // 监听是否被应用stop了。如果是，则要发送一个StopSendingFrame
        tokio::spawn({
            let incoming = incoming.clone();
            let frames = self.reliable_frame_deque.clone();
            async move {
                if let Some(err_code) = incoming.is_stopped_by_app().await {
                    frames.lock_guard().push_back(ReliableFrame::Stream(
                        StreamCtlFrame::StopSending(StopSendingFrame {
                            stream_id: sid,
                            app_err_code: VarInt::from_u64(err_code)
                                .expect("app error code must not exceed VARINT_MAX"),
                        }),
                    ));
                }
            }
        });
        (incoming, reader)
    }
}
