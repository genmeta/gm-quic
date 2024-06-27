use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use qbase::frame::*;

pub mod rcvdpkt;
pub mod sentpkt;

#[derive(Debug, Default)]
pub struct RawReliableFrameQueue {
    queue: VecDeque<ReliableFrame>,
}

impl RawReliableFrameQueue {
    fn push_conn_frame(&mut self, frame: ConnFrame) {
        self.queue.push_back(ReliableFrame::Conn(frame));
    }

    fn push_stream_control_frame(&mut self, frame: StreamCtlFrame) {
        self.queue.push_back(ReliableFrame::Stream(frame));
    }

    fn push_reliable_frame(&mut self, frame: ReliableFrame) {
        self.queue.push_back(frame);
    }

    fn front(&self) -> Option<&ReliableFrame> {
        self.queue.front()
    }

    fn pop_front(&mut self) -> Option<ReliableFrame> {
        self.queue.pop_front()
    }
}

/// Frames that need to be sent reliably, there are 3 operations:
/// - write: write a frame to the sending queue, include Conn and StreamCtl frames
/// - retran: retransmit the lost frames, is equal to write operation
/// - read: read the frames to send
#[derive(Debug, Default, Clone)]
pub struct ArcReliableFrameQueue(Arc<Mutex<RawReliableFrameQueue>>);

impl ArcReliableFrameQueue {
    pub fn read(&self) -> ReliableFrameQueueReader<'_> {
        ReliableFrameQueueReader(self.0.lock().unwrap())
    }

    pub fn write(&self) -> ReliableFrameQueueWriter<'_> {
        ReliableFrameQueueWriter(self.0.lock().unwrap())
    }
}

pub struct ReliableFrameQueueReader<'a>(MutexGuard<'a, RawReliableFrameQueue>);

impl ReliableFrameQueueReader<'_> {
    pub fn front(&self) -> Option<&ReliableFrame> {
        self.0.front()
    }

    pub fn pop_front(&mut self) -> Option<ReliableFrame> {
        self.0.pop_front()
    }
}

pub struct ReliableFrameQueueWriter<'a>(MutexGuard<'a, RawReliableFrameQueue>);

impl ReliableFrameQueueWriter<'_> {
    pub fn push_conn_frame(&mut self, frame: ConnFrame) {
        self.0.push_conn_frame(frame);
    }

    pub fn push_stream_control_frame(&mut self, frame: StreamCtlFrame) {
        self.0.push_stream_control_frame(frame);
    }

    pub fn push_reliable_frame(&mut self, frame: ReliableFrame) {
        self.0.push_reliable_frame(frame);
    }
}

#[cfg(test)]
mod tests {}
