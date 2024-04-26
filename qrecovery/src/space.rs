use bytes::{Bytes, BytesMut};
use qbase::{frame::AckRecord, varint::VARINT_MAX};
use std::{
    collections::VecDeque,
    task::{Context, Poll, Waker},
    time::Instant,
};

use super::index_deque::IndexDeque;

/// 网络socket缓过来时，会轮询调用此发送函数，询问该空间下是否有数据需要发送
pub trait AsyncSend {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<(u64, BytesMut)>;
}

/// 传输控制模块按其传输速度、时间间隔算出的到调用时该发送至多max_len字节的数据
pub trait TrySend {
    fn try_send(&mut self, max_len: usize) -> usize;
}

/// 网络socket收到一个数据包，解析出属于该空间时，将数据包内容传递给该空间
pub trait Receive {
    /// receive的数据，尚未解析，解析过程中可能会出错，
    /// 发生解析失败，或者解析出不该在该空间存在的帧
    /// TODO: 错误类型待定
    fn receive(&mut self, pktid: u64, payload: Bytes) -> Result<(), ()>;
}

/// 逻辑层向该空间写帧数据。需要注意的是，各空间允许发送的帧类型并不一样，因此使用泛型严格约束
/// Ref: https://www.rfc-editor.org/rfc/rfc9000.html#frame-types
pub trait Write<F> {
    fn write_frame(&mut self, frame: F);
}

pub trait AsyncRead<F> {
    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<F>;
}

#[derive(Debug)]
enum FrameRecords<O, I> {
    Outer(O),
    Inner(I),
    Ack(AckRecord),
}

type Payload<O, I> = Vec<FrameRecords<O, I>>;

/// 可靠空间的抽象实现，需要实现上述所有trait
/// 可靠空间中的重传、确认，由可靠空间内部实现，无需外露
#[derive(Debug)]
pub struct Space<O, I> {
    out_frames: VecDeque<FrameRecords<O, I>>,
    pending_packets: IndexDeque<(Bytes, Payload<O, I>), VARINT_MAX>,
    send_waker: Option<Waker>,
    inflight: IndexDeque<Option<(Instant, Payload<O, I>)>, VARINT_MAX>,

    // 用于产生ack frame，Instant用于计算ack_delay，bool表明是否ack eliciting
    rcvd_packets: IndexDeque<Option<(Instant, bool)>, VARINT_MAX>,
    in_frames: VecDeque<O>,
    read_waker: Option<Waker>,
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
