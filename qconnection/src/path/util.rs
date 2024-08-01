use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use bytes::BufMut;
use qbase::{
    frame::{io::WriteFrame, BeFrame},
    util::TransportLimit,
};

#[derive(Default, Clone)]
pub(super) struct PathFrameBuffer<T>(Arc<Mutex<Option<T>>>);

impl<T> PathFrameBuffer<T> {
    pub fn write(&self, frame: T) {
        *self.0.lock().unwrap() = Some(frame);
    }
}

impl<T> PathFrameBuffer<T>
where
    T: BeFrame,
    for<'a> &'a mut [u8]: WriteFrame<T>,
{
    pub fn read(&self, mut buf: &mut [u8], limit: &mut TransportLimit) -> usize {
        let mut guard = self.0.lock().unwrap();
        if let Some(frame) = guard.deref() {
            let size = frame.encoding_size();
            if limit.available() >= size && buf.remaining_mut() >= size {
                buf.put_frame(&frame);
                limit.record_write(size);
                *guard = None;
                return size;
            }
        }
        0
    }
}
