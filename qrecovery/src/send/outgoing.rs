use super::sender::{ArcSender, Sender};
use bytes::BufMut;
use qbase::{
    frame::{
        ext::{WritePaddingFrame, WriteStreamFrame},
        ShouldCarryLength, StreamFrame,
    },
    streamid::StreamId,
    varint::VARINT_MAX,
};
use std::{
    future::Future,
    ops::{DerefMut, Range},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub struct Outgoing(pub(super) ArcSender);

impl Outgoing {
    pub fn update_window(&mut self, max_data_size: u64) {
        assert!(max_data_size <= VARINT_MAX);
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Sending(mut s) => {
                s.update_window(max_data_size);
                inner.replace(Sender::Sending(s));
            }
            other => inner.replace(other),
        }
    }

    pub fn try_send<B>(&mut self, sid: StreamId, mut buffer: B) -> Option<StreamFrame>
    where
        B: BufMut,
    {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        let mut result = None;
        let capacity = buffer.remaining_mut();
        let estimate_capacity = |offset| StreamFrame::estimate_max_capacity(capacity, sid, offset);
        let write = |content: (u64, &[u8], bool)| {
            let (offset, data, is_eos) = content;
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
        match inner.take() {
            Sender::Ready(s) => {
                if s.is_shutdown() {
                    let mut s = s.end();
                    result = s.pick_up(estimate_capacity).map(write);
                    inner.replace(Sender::DataSent(s));
                } else {
                    let mut s = s.begin_sending();
                    result = s.pick_up(estimate_capacity).map(write);
                    inner.replace(Sender::Sending(s));
                }
            }
            Sender::Sending(mut s) => {
                result = s.pick_up(estimate_capacity).map(write);
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(mut s) => {
                result = s.pick_up(estimate_capacity).map(write);
                inner.replace(Sender::DataSent(s));
            }
            other => inner.replace(other),
        };
        result
    }

    pub fn confirm_rcvd(&mut self, range: &Range<u64>) -> bool {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::Sending(mut s) => {
                s.confirm_rcvd(range);
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(mut s) => {
                s.confirm_rcvd(range);
                if s.is_all_rcvd() {
                    inner.replace(Sender::DataRecvd);
                    return true;
                } else {
                    inner.replace(Sender::DataSent(s));
                }
            }
            // ignore recv
            other => inner.replace(other),
        };
        false
    }

    pub fn may_loss(&mut self, range: &Range<u64>) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::Sending(mut s) => {
                s.may_loss(range);
                inner.replace(Sender::Sending(s));
            }
            Sender::DataSent(mut s) => {
                s.may_loss(range);
                inner.replace(Sender::DataSent(s));
            }
            // ignore loss
            other => inner.replace(other),
        };
    }

    /// 被动stop，返回true说明成功stop了；返回false则表明流没有必要stop，要么已经完成，要么已经reset
    pub fn stop(&mut self) -> bool {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::Ready(_) => {
                unreachable!("never send data before recv data");
            }
            Sender::Sending(s) => {
                inner.replace(Sender::ResetSent(s.stop()));
                true
            }
            Sender::DataSent(s) => {
                inner.replace(Sender::ResetSent(s.stop()));
                true
            }
            other => {
                inner.replace(other);
                false
            }
        }
    }

    pub fn confirm_reset(&mut self) {
        let mut sender = self.0.lock().unwrap();
        let inner = sender.deref_mut();
        match inner.take() {
            Sender::ResetSent(_) | Sender::ResetRecvd => {
                inner.replace(Sender::ResetRecvd);
            }
            _ => {
                unreachable!(
                    "If no RESET_STREAM has been sent, how can there be a received acknowledgment?"
                );
            }
        };
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
        match inner.take() {
            Sender::Ready(mut s) => match s.poll_cancel(cx) {
                Poll::Ready(final_size) => {
                    inner.replace(Sender::ResetSent(final_size));
                    Poll::Ready(Some(final_size))
                }
                Poll::Pending => {
                    inner.replace(Sender::Ready(s));
                    Poll::Pending
                }
            },
            Sender::Sending(mut s) => match s.poll_cancel(cx) {
                Poll::Ready(final_size) => {
                    inner.replace(Sender::ResetSent(final_size));
                    Poll::Ready(Some(final_size))
                }
                Poll::Pending => {
                    inner.replace(Sender::Sending(s));
                    Poll::Pending
                }
            },
            Sender::DataSent(mut s) => match s.poll_cancel(cx) {
                Poll::Ready(final_size) => {
                    inner.replace(Sender::ResetSent(final_size));
                    Poll::Ready(Some(final_size))
                }
                Poll::Pending => {
                    inner.replace(Sender::DataSent(s));
                    Poll::Pending
                }
            },
            other => {
                inner.replace(other);
                Poll::Ready(None)
            }
        }
    }
}
