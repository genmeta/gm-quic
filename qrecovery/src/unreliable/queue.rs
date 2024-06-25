use std::collections::VecDeque;

use bytes::Bytes;

/// 是否应该对其大小有所限制？还是不断发，无限存。。。
#[derive(Default, Debug)]
pub(super) struct DatagramQueue {
    queue: VecDeque<Bytes>,
}

impl DatagramQueue {
    pub fn write(&mut self, data: Bytes) {
        self.queue.push_back(data);
    }

    pub fn try_read(&mut self) -> Option<Bytes> {
        self.queue.pop_front()
    }

    pub fn peek(&mut self) -> Option<&Bytes> {
        self.queue.front()
    }
}
