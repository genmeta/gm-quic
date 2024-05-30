use super::sender::{ArcSender, Sender};
use bytes::BufMut;
use qbase::{
    error::Error as QuicError,
    frame::{
        io::{WritePaddingFrame, WriteStreamFrame},
        ShouldCarryLength, StreamFrame,
    },
    streamid::StreamId,
    varint::VARINT_MAX,
};
use std::{
    future::Future,
    io::Error,
    ops::{DerefMut, Range},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub struct Outgoing(pub(super) ArcSender);

impl Outgoing {
    pub fn update_window(&self, max_data_size: u64) {
        assert!(max_data_size <= VARINT_MAX);
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::Sending(mut s) => {
                    s.update_window(max_data_size);
                    sending_state.replace(Sender::Sending(s));
                }
                other => sending_state.replace(other),
            },
            Err(_) => (),
        }
    }

    pub fn try_read<B>(&self, sid: StreamId, mut buffer: B) -> Option<StreamFrame>
    where
        B: BufMut,
    {
        let mut result = None;
        let capacity = buffer.remaining_mut();
        let estimate_capacity = |offset| StreamFrame::estimate_max_capacity(capacity, sid, offset);
        let write = |(offset, data, is_eos): (u64, &[u8], bool)| {
            let mut frame = StreamFrame::new(sid, offset, data.len());
            frame.set_eos_flag(is_eos);
            match frame.should_carry_length(buffer.remaining_mut()) {
                ShouldCarryLength::NoProblem => {
                    buffer.put_stream_frame(&frame, data);
                }
                ShouldCarryLength::PaddingFirst(n) => {
                    for _ in 0..n {
                        buffer.put_padding_frame();
                    }
                    buffer.put_stream_frame(&frame, data);
                }
                ShouldCarryLength::ShouldAfter(_not_carry_len, _carry_len) => {
                    frame.carry_length();
                    buffer.put_stream_frame(&frame, data);
                }
            }
            frame
        };

        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::Ready(s) => {
                    if s.is_shutdown() {
                        let mut s = s.end();
                        result = s.pick_up(estimate_capacity).map(write);
                        sending_state.replace(Sender::DataSent(s));
                    } else {
                        let mut s = s.begin_sending();
                        result = s.pick_up(estimate_capacity).map(write);
                        sending_state.replace(Sender::Sending(s));
                    }
                }
                Sender::Sending(mut s) => {
                    result = s.pick_up(estimate_capacity).map(write);
                    sending_state.replace(Sender::Sending(s));
                }
                Sender::DataSent(mut s) => {
                    result = s.pick_up(estimate_capacity).map(write);
                    sending_state.replace(Sender::DataSent(s));
                }
                other => sending_state.replace(other),
            },
            Err(_) => (),
        };
        result
    }

    pub fn on_data_acked(&self, range: &Range<u64>) -> bool {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(mut s) => {
                    s.on_acked(range);
                    sending_state.replace(Sender::Sending(s));
                }
                Sender::DataSent(mut s) => {
                    s.on_acked(range);
                    if s.is_all_rcvd() {
                        sending_state.replace(Sender::DataRecvd);
                        return true;
                    } else {
                        sending_state.replace(Sender::DataSent(s));
                    }
                }
                // ignore recv
                other => sending_state.replace(other),
            },
            Err(_) => (),
        };
        false
    }

    pub fn may_loss_data(&self, range: &Range<u64>) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    s.may_loss(range);
                }
                Sender::DataSent(s) => {
                    s.may_loss(range);
                }
                // ignore loss
                _ => (),
            },
            Err(_) => (),
        };
    }

    /// 被动stop，返回true说明成功stop了；返回false则表明流没有必要stop，要么已经完成，要么已经reset
    pub fn stop(&self) -> bool {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::Ready(_) => {
                    unreachable!("never send data before recv data");
                }
                Sender::Sending(s) => {
                    sending_state.replace(Sender::ResetSent(s.stop()));
                    true
                }
                Sender::DataSent(s) => {
                    sending_state.replace(Sender::ResetSent(s.stop()));
                    true
                }
                other => {
                    sending_state.replace(other);
                    false
                }
            },
            Err(_) => false,
        }
    }

    pub fn on_reset_acked(&self) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::ResetSent(_) | Sender::ResetRecvd => {
                    sending_state.replace(Sender::ResetRecvd);
                }
                _ => {
                    unreachable!(
                        "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                    );
                }
            },
            Err(_) => (),
        }
    }

    /// When a connection-level error occurs, all data streams must be notified.
    /// Their reading and writing should be terminated, accompanied the error of the connection.
    pub fn conn_error(&self, err: &QuicError) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state {
                Sender::Ready(s) => s.wake_all(),
                Sender::Sending(s) => s.wake_all(),
                Sender::DataSent(s) => s.wake_all(),
                _ => return,
            },
            Err(_) => return,
        };
        *inner = Err(Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()));
    }

    pub fn is_cancelled_by_app(&self) -> IsCancelled {
        IsCancelled(self.0.clone())
    }
}

pub struct IsCancelled(ArcSender);

impl Future for IsCancelled {
    type Output = Option<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner {
            Ok(sending_state) => match sending_state.take() {
                Sender::Ready(mut s) => match s.poll_cancel(cx) {
                    Poll::Ready(final_size) => {
                        sending_state.replace(Sender::ResetSent(final_size));
                        Poll::Ready(Some(final_size))
                    }
                    Poll::Pending => {
                        sending_state.replace(Sender::Ready(s));
                        Poll::Pending
                    }
                },
                Sender::Sending(mut s) => match s.poll_cancel(cx) {
                    Poll::Ready(final_size) => {
                        sending_state.replace(Sender::ResetSent(final_size));
                        Poll::Ready(Some(final_size))
                    }
                    Poll::Pending => {
                        sending_state.replace(Sender::Sending(s));
                        Poll::Pending
                    }
                },
                Sender::DataSent(mut s) => match s.poll_cancel(cx) {
                    Poll::Ready(final_size) => {
                        sending_state.replace(Sender::ResetSent(final_size));
                        Poll::Ready(Some(final_size))
                    }
                    Poll::Pending => {
                        sending_state.replace(Sender::DataSent(s));
                        Poll::Pending
                    }
                },
                other => {
                    sending_state.replace(other);
                    Poll::Ready(None)
                }
            },
            // 既然发生连接错误了，那也没必要监听应用层的取消了
            Err(_) => Poll::Ready(None),
        }
    }
}
