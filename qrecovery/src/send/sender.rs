use std::{
    io,
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use qbase::{
    error::Error,
    frame::{ResetStreamError, ResetStreamFrame, SendFrame},
    net::tx::{ArcSendWakers, Signals},
    sid::StreamId,
    util::DescribeData,
    varint::VarInt,
};
use qevent::{
    RawInfo,
    quic::transport::{
        DataMovedAdditionalInfo, GranularStreamStates, StreamDataLocation, StreamDataMoved,
        StreamSide, StreamStateUpdated,
    },
};

use super::sndbuf::SendBuf;

fn log_reset_event(sid: StreamId, from_state: GranularStreamStates) {
    qevent::event!(StreamStateUpdated {
        stream_id: sid,
        stream_type: sid.dir(),
        old: from_state,
        new: GranularStreamStates::ResetSent,
        stream_side: StreamSide::Sending
    });
}

/// The "Ready" state represents a newly created stream that is able to accept data from the application.
/// Stream data might be buffered in this state in preparation for sending.
/// An implementation might choose to defer allocating a stream ID to a stream until it sends the first
/// STREAM frame and enters this state, which can allow for better stream prioritization.
#[derive(Debug)]
pub struct ReadySender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    tx_wakers: ArcSendWakers,
    max_stream_data: u64,
    writable_waker: Option<Waker>,
}

impl<TX> ReadySender<TX> {
    pub(super) fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        tx_wakers: ArcSendWakers,
    ) -> ReadySender<TX> {
        ReadySender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size as usize),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers,
            writable_waker: None,
            max_stream_data: buf_size,
        }
    }

    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// 非阻塞写，如果没有多余的发送缓冲区，将返回WouldBlock错误。
    /// 但什么时候可写，是没通知的，只能不断去尝试写，直到写入成功。
    /// 仅供展示学习
    #[allow(dead_code)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.sndbuf.written();
        if written < self.max_stream_data {
            let n = std::cmp::min((self.max_stream_data - written) as usize, buf.len());
            self.tx_wakers.wake_all_by(Signals::WRITTEN);
            Ok(self.sndbuf.write(&buf[..n]))
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_waker.is_some() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The stream has been shutdown",
            )))
        } else {
            let stream_data = self.sndbuf.written();
            if stream_data < self.max_stream_data {
                let n = std::cmp::min((self.max_stream_data - stream_data) as usize, buf.len());
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset: self.sndbuf.written(),
                    length: n as u64,
                    from: StreamDataLocation::Application,
                    to: StreamDataLocation::Transport,
                });
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.max_stream_data {
            self.max_stream_data = max_stream_data;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 就算当前没有流量窗口，也可以单独发送一个空StreamFrame，携带fin bit
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }
}

/// 状态升级，ReaderSender => SendingSender
impl<TX: Clone> ReadySender<TX> {
    pub(super) fn upgrade(&mut self) -> SendingSender<TX> {
        qevent::event!(StreamStateUpdated {
            stream_id: self.stream_id,
            stream_type: self.stream_id.dir(),
            old: GranularStreamStates::Ready,
            new: GranularStreamStates::Send,
            stream_side: StreamSide::Sending
        });
        SendingSender {
            stream_id: self.stream_id,
            sndbuf: std::mem::take(&mut self.sndbuf),
            flush_waker: self.flush_waker.take(),
            shutdown_waker: self.shutdown_waker.take(),
            broker: self.broker.clone(),
            tx_wakers: self.tx_wakers.clone(),
            writable_waker: self.writable_waker.take(),
            max_stream_data: self.max_stream_data,
        }
    }
}

impl<TX> ReadySender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    /// 应用层使用，取消发送流
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::error!(
            "Error: {} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::Ready);
        reset_stream_err
    }
}

#[derive(Debug)]
pub struct SendingSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    tx_wakers: ArcSendWakers,
    writable_waker: Option<Waker>,
    max_stream_data: u64,
}

type StreamData<'s> = (u64, bool, (&'s [u8], &'s [u8]), bool);

impl<TX> SendingSender<TX> {
    pub(super) fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_waker.is_some() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The stream has been shutdown",
            )))
        } else {
            let stream_data = self.sndbuf.written();
            if stream_data < self.max_stream_data {
                let n = std::cmp::min((self.max_stream_data - stream_data) as usize, buf.len());
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset: self.sndbuf.written(),
                    length: n as u64,
                    from: StreamDataLocation::Application,
                    to: StreamDataLocation::Transport,
                });
                self.tx_wakers.wake_all_by(Signals::WRITTEN);
                Poll::Ready(Ok(self.sndbuf.write(&buf[..n])))
            } else {
                self.writable_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// 传输层使用
    pub(super) fn update_window(&mut self, max_stream_data: u64) {
        if max_stream_data > self.max_stream_data {
            self.max_stream_data = max_stream_data;
            if let Some(waker) = self.writable_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn pick_up<P>(
        &mut self,
        predicate: P,
        flow_limit: usize,
    ) -> Result<StreamData, Signals>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let fin_pos = self.fin_pos();
        let sent = self.sndbuf.sent();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(offset, is_fresh, data)| {
                let is_eos = fin_pos == Some(offset + data.len() as u64);
                (offset, is_fresh, data, is_eos)
            })
            .or_else(|signals| {
                if fin_pos.is_some_and(|fin_pos| fin_pos == sent) {
                    predicate(sent).ok_or(signals | Signals::CONGESTION)?;
                    Ok((sent, false, (&[], &[]), true))
                } else {
                    Err(signals)
                }
            })
            .map(|(offset, is_fresh, data, is_eos)| {
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset,
                    length: data.len() as u64,
                    from: StreamDataLocation::Transport,
                    to: StreamDataLocation::Network,
                    ?additional_info: is_eos.then_some(DataMovedAdditionalInfo::FinSet),
                    raw: RawInfo { data }
                });
                (offset, is_fresh, data, is_eos)
            })
    }

    pub(super) fn on_data_acked(&mut self, range: &Range<u64>) {
        self.sndbuf.on_data_acked(range);
        if self.sndbuf.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn may_loss_data(&mut self, range: &Range<u64>) {
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.sndbuf.may_loss_data(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.sndbuf.is_all_rcvd() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn fin_pos(&self) -> Option<u64> {
        if self.shutdown_waker.is_some() {
            Some(self.sndbuf.written())
        } else {
            None
        }
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.writable_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    /// 传输层使用
    pub(super) fn be_stopped(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.sent()
    }
}

impl<TX: Clone> SendingSender<TX> {
    pub(super) fn upgrade(&mut self) -> DataSentSender<TX> {
        qevent::event!(StreamStateUpdated {
            stream_id: self.stream_id,
            stream_type: self.stream_id.dir(),
            old: GranularStreamStates::Send,
            new: GranularStreamStates::DataSent,
            stream_side: StreamSide::Sending
        });
        DataSentSender {
            stream_id: self.stream_id,
            sndbuf: std::mem::take(&mut self.sndbuf),
            flush_waker: self.flush_waker.take(),
            shutdown_waker: self.shutdown_waker.take(),
            broker: self.broker.clone(),
            tx_wakers: self.tx_wakers.clone(),
            fin_state: FinState::Sent,
        }
    }
}

impl<TX> SendingSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::error!(
            "Error: {} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::Send);
        reset_stream_err
    }
}

#[derive(Debug, PartialEq)]
enum FinState {
    Sent,
    Lost,
    Rcvd,
}

#[derive(Debug)]
pub struct DataSentSender<TX> {
    stream_id: StreamId,
    sndbuf: SendBuf,
    flush_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    broker: TX,
    // retran/fin
    tx_wakers: ArcSendWakers,
    fin_state: FinState,
}

impl<TX> DataSentSender<TX> {
    pub(super) fn pick_up<P>(
        &mut self,
        predicate: P,
        flow_limit: usize,
    ) -> Result<StreamData, Signals>
    where
        P: Fn(u64) -> Option<usize>,
    {
        let total_size = self.sndbuf.written();
        self.sndbuf
            .pick_up(&predicate, flow_limit)
            .map(|(offset, is_fresh, data)| {
                let is_eos = offset + data.len() as u64 == total_size;
                (offset, is_fresh, data, is_eos)
            })
            .or_else(|signals| {
                if self.fin_state == FinState::Lost {
                    self.fin_state = FinState::Sent;
                    Ok((total_size, false, (&[], &[]), true))
                } else {
                    Err(signals)
                }
            })
            .map(|(offset, is_fresh, data, is_eos)| {
                qevent::event!(StreamDataMoved {
                    stream_id: self.stream_id,
                    offset,
                    length: data.len() as u64,
                    from: StreamDataLocation::Transport,
                    to: StreamDataLocation::Network,
                    ?additional_info: is_eos.then_some(DataMovedAdditionalInfo::FinSet),
                    raw: RawInfo { data }
                },);
                (offset, is_fresh, data, is_eos)
            })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub(super) fn on_data_acked(&mut self, range: &Range<u64>, is_fin: bool) {
        self.sndbuf.on_data_acked(range);
        if is_fin {
            self.fin_state = FinState::Rcvd;
        }
        if self.is_all_rcvd() {
            if let Some(waker) = self.flush_waker.take() {
                waker.wake();
            }
            if let Some(waker) = self.shutdown_waker.take() {
                waker.wake();
            }
        }
    }

    pub(super) fn is_all_rcvd(&self) -> bool {
        self.sndbuf.is_all_rcvd() && self.fin_state == FinState::Rcvd
    }

    pub(super) fn may_loss_data(&mut self, range: &Range<u64>) {
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        if range.end == self.sndbuf.written() && self.fin_state != FinState::Rcvd {
            self.fin_state = FinState::Lost;
        }
        self.sndbuf.may_loss_data(range)
    }

    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        debug_assert!(!self.is_all_rcvd());
        self.flush_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        debug_assert!(!self.is_all_rcvd());
        self.tx_wakers.wake_all_by(Signals::TRANSPORT);
        self.shutdown_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) fn wake_all(&mut self) {
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.shutdown_waker.take() {
            waker.wake();
        }
    }

    pub(super) fn be_stopped(&mut self) -> u64 {
        self.wake_all();
        // Actually, these remaining data is not acked and will not be acked
        self.sndbuf.written()
    }
}

impl<TX> DataSentSender<TX>
where
    TX: SendFrame<ResetStreamFrame>,
{
    pub(super) fn cancel(&mut self, err_code: u64) -> ResetStreamError {
        let final_size = self.sndbuf.sent();
        let reset_stream_err = ResetStreamError::new(
            VarInt::from_u64(err_code).expect("app error code must not exceed 2^62"),
            VarInt::from_u64(final_size).expect("final size must not exceed 2^62"),
        );
        tracing::error!(
            "Error: {} is canceled by app layer, with error code {err_code}",
            self.stream_id
        );
        self.broker
            .send_frame([reset_stream_err.combine(self.stream_id)]);
        log_reset_event(self.stream_id, GranularStreamStates::DataSent);
        reset_stream_err
    }
}

#[derive(Debug)]
pub(super) enum Sender<TX> {
    Ready(ReadySender<TX>),
    Sending(SendingSender<TX>),
    DataSent(DataSentSender<TX>),
    DataRcvd,
    ResetSent(ResetStreamError),
    ResetRcvd(ResetStreamError),
}

impl<TX> Sender<TX> {
    pub fn new(stream_id: StreamId, buf_size: u64, broker: TX, tx_wakers: ArcSendWakers) -> Self {
        Sender::Ready(ReadySender::new(stream_id, buf_size, broker, tx_wakers))
    }
}

/// The internal state representations of [`Outgoing`] and [`Writer`].
///
/// For the application layer, this struct is represented as [`Writer`]. The application can use it to
/// write data to the stream, or reset the stream.
///
/// For the protocol layer, this struct is represented as [`Outgoing`]. The protocol layer uses it to
/// manage the status of the `Sender`, sends data(stream frame),reset frames and other frames to peer.
///
/// [`Outgoing`]: super::Outgoing
/// [`Writer`]: super::Writer
#[derive(Debug, Clone)]
pub struct ArcSender<TX>(Arc<Mutex<Result<Sender<TX>, Error>>>);

impl<TX> ArcSender<TX> {
    #[doc(hidden)]
    pub(crate) fn new(
        stream_id: StreamId,
        buf_size: u64,
        broker: TX,
        tx_wakers: ArcSendWakers,
    ) -> Self {
        ArcSender(Arc::new(Mutex::new(Ok(Sender::new(
            stream_id, buf_size, broker, tx_wakers,
        )))))
    }
}

impl<TX> ArcSender<TX> {
    // for accept transport parameter(if 0rtt parameter is used to create the stream)
    pub(crate) fn revise_buffer_size(&self, snd_buf_size: u64) {
        match self.sender().as_mut() {
            Ok(Sender::Ready(s)) => s.update_window(snd_buf_size),
            Ok(Sender::Sending(s)) => s.update_window(snd_buf_size),
            _ => {}
        }
    }

    pub(super) fn sender(&self) -> MutexGuard<Result<Sender<TX>, Error>> {
        self.0.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use qbase::sid::{Dir, Role};

    use super::*;

    #[derive(Debug, Default, Clone)]
    struct MockBroker(Arc<Mutex<Vec<ResetStreamFrame>>>);

    impl SendFrame<ResetStreamFrame> for MockBroker {
        fn send_frame<I: IntoIterator<Item = ResetStreamFrame>>(&self, iter: I) {
            self.0.lock().unwrap().extend(iter);
        }
    }

    fn create_test_sender() -> ArcSender<MockBroker> {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        ArcSender::new(stream_id, buf_size, broker, Default::default())
    }

    #[test]
    fn test_ready_sender_new() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let sender = ReadySender::new(stream_id, buf_size, broker, Default::default());

        assert_eq!(sender.stream_id, stream_id);
        assert_eq!(sender.max_stream_data, buf_size);
        assert!(sender.flush_waker.is_none());
        assert!(sender.shutdown_waker.is_none());
        assert!(sender.writable_waker.is_none());
    }

    #[test]
    fn test_ready_sender_write() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 10;
        let broker = MockBroker::default();
        let mut sender = ReadySender::new(stream_id, buf_size, broker, Default::default());

        let data = b"hello";
        let result = sender.write(data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        // Test write when buffer is full
        let large_data = b"too much data";
        let result = sender.write(large_data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    #[tokio::test]
    async fn test_ready_sender_poll_write() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 10;
        let broker = MockBroker::default();
        let mut sender = ReadySender::new(stream_id, buf_size, broker, Default::default());

        let data = b"test";
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        if let Poll::Ready(result) = sender.poll_write(&mut cx, data) {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 4);
        }

        // Test poll_write when buffer is full
        sender.max_stream_data = 0;
        let result = sender.poll_write(&mut cx, data);
        assert!(result.is_pending());
    }

    #[test]
    fn test_sender_state_transitions() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut ready = ReadySender::new(stream_id, buf_size, broker, Default::default());

        // Test transition to SendingSender
        let mut sending = ready.upgrade();
        assert_eq!(sending.stream_id, stream_id);
        assert_eq!(sending.max_stream_data, buf_size);

        // Test transition to DataSentSender
        let data_sent = sending.upgrade();
        assert_eq!(data_sent.stream_id, stream_id);
        assert!(data_sent.fin_state == FinState::Sent);
    }

    #[test]
    fn test_arc_sender() {
        let sender = create_test_sender();

        // Test buffer size revision
        sender.revise_buffer_size(2000);

        // Test sender lock access
        let guard = sender.sender();
        assert!(guard.is_ok());
    }

    #[test]
    fn test_data_sent_sender() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut sender = DataSentSender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size as usize),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers: Default::default(),
            fin_state: FinState::Sent,
        };

        // Test pick_up with empty buffer
        let predicate = |_| Some(100);
        let result = sender.pick_up(predicate, 1000);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_data_sent_sender_polling() {
        let stream_id = StreamId::new(Role::Client, Dir::Bi, 0);
        let buf_size = 1000;
        let broker = MockBroker::default();
        let mut sender = DataSentSender {
            stream_id,
            sndbuf: SendBuf::with_capacity(buf_size as usize),
            flush_waker: None,
            shutdown_waker: None,
            broker,
            tx_wakers: Default::default(),
            fin_state: FinState::Sent,
        };

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        // Test poll_flush when all data received
        let result = sender.poll_flush(&mut cx);
        assert!(result.is_pending());

        // Test poll_shutdown when all data received
        let _ = sender.poll_shutdown(&mut cx);
        assert!(sender.shutdown_waker.is_some());
    }
}
