//！ An implementation of the receiving buffer for stream data.

use std::collections::VecDeque;

use bytes::{Buf, BufMut, Bytes};

/// 一段连续的数据片段，每个片段都是Bytes
#[derive(Debug, Default)]
struct Segment {
    offset: u64,
    data: Bytes,
}

impl Segment {
    fn new_with_data(offset: u64, data: Bytes) -> Self {
        Segment { offset, data }
    }

    fn end(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

/// Received data of a stream is stored in [`RecvBuf`].
///
/// The receiving buffer is relatively simple, as it receives segmented data
/// that may not be continuous. It sequentially stores the received data
/// fragments and then reassembles them into a continuous data stream for
/// future reading by the application layer.
///
/// It implements the [`Buf`] triat and can operate on the **received continuous
/// data** through the [`Buf`] trait. [`Buf::has_remaining`] return `flase` not
/// only when the buffer is empty, but also when no readable continuous data in
/// the buffer.
#[derive(Default, Debug)]
pub struct RecvBuf {
    nread: u64,
    largest_offset: u64,
    // segments[0].offset >= nread
    segments: VecDeque<Segment>,
}

impl RecvBuf {
    /// Returns whether the receiving buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns how many continuous data have been read.
    ///
    /// # Example
    ///
    /// ``` rust
    /// # use bytes::{Bytes, BytesMut};
    /// # use qrecovery::recv::RecvBuf;
    /// let mut recvbuf = RecvBuf::default();
    /// assert_eq!(recvbuf.nread(), 0);
    ///
    /// recvbuf.recv(0, Bytes::from("hello"));
    /// assert_eq!(recvbuf.nread(), 0);
    /// // recvbuf:  hello
    /// // offset=0  ^
    ///
    /// let mut dst = BytesMut::new();
    /// recvbuf.try_read(&mut dst);
    /// assert_eq!(recvbuf.nread(), 5);
    /// // recvbuf:  hello
    /// // offset=5       ^
    pub fn nread(&self) -> u64 {
        self.nread
    }

    /// Returns the largest offset received.
    ///
    /// For receiver in SizeKnown state, this must smaller than the `final_size`
    pub fn largest_offset(&self) -> u64 {
        self.largest_offset
    }

    /// Receive a fragment of data, return the new data's size.
    ///
    /// # Example
    ///
    /// The following example demonstrates how [`RecvBuf`] works.
    ///
    /// The data "hello, world!" is splitted into four fragments.
    /// ``` rust
    /// # use bytes::{Bytes, BytesMut};
    /// # use qrecovery::recv::RecvBuf;
    /// let mut recvbuf = RecvBuf::default();
    /// // data:    "hello, world!"
    /// assert_eq!(recvbuf.recv(0, Bytes::from("hell")), 4);
    /// // recvbuf: "hell"
    /// // new:     "hell"
    /// assert_eq!(recvbuf.recv(7, Bytes::from("world")), 5);
    /// // recvbuf: "hell" "world"
    /// // new:            "world"
    /// assert_eq!(recvbuf.recv(3, Bytes::from("lo, ")), 3);
    /// // recvbuf: "hello, world"
    /// // new:         "o, "
    /// assert_eq!(recvbuf.recv(7, Bytes::from("world!")), 1);
    /// // recvbuf: "hello, world!"
    /// // new:                 "!"
    /// let mut received = BytesMut::new();
    /// recvbuf.try_read(&mut received);
    /// assert_eq!(received.as_ref(), b"hello, world!");
    /// ```
    pub fn recv(&mut self, offset: u64, mut data: Bytes) -> u64 {
        let mut written = 0;

        // advance data that already read
        let mut start = offset.max(self.nread);
        data.advance(data.remaining().min((start - offset) as usize));

        loop {
            if data.is_empty() {
                break;
            }

            // 从前往后放：
            match self.segments.binary_search_by(|seg| seg.offset.cmp(&start)) {
                // 恰好和现有的一个数据段在同一位置开始现有的数据段上，如：
                // | exist_seg | ... |
                // | new_seg....................|
                // 裁剪掉new_seg的前面部分，然后继续循环
                // | exist_seg | ... |
                //             | new_seg........|
                // 绝大多数情况下都会先进入这一个分支
                Ok(exist_seg_index) => {
                    let length_covered = self.segments[exist_seg_index].data.len();
                    data.advance(data.len().min(length_covered));
                    start += length_covered as u64;
                }
                // 没有恰好和一个现有的数据段重合：瞻前顾后
                //      | exist_seg1 |    | exist_seg2 |
                // 1.                  | new_seg|
                // 2. | new_seg |
                // seg_index可能是上一个seg的index，也可能是下一个seg的index
                // 1. 如果是上一个seg的index，需要有逻辑：需要检查下一个seg是否存在，如果存在就裁剪自身
                // 2. 如果是下一个seg的index（只可能是index=0)，也会执行上述逻辑，故index 0 可以做特别处理
                Err(0) => {
                    let uncovered = match self.segments.front() {
                        // 如果和下一段数据有重合的话，裁下data中前一部分（不重合的部分）
                        Some(next_seg) if start + data.len() as u64 > next_seg.offset => {
                            // 裁下后，start必定和next_seg.offset相等，下次loop就会进入上一个分支
                            // next_seg.offset < start + data.len()
                            // next_seg.offset - start < data.len() ，不会越界
                            data.split_to((next_seg.offset - start) as usize)
                        }
                        // 如果没有重合，或者这是第一段数据，直接取出整个data
                        // 然后下次循环时data.is_empty() == true => break
                        Some(..) | None => core::mem::take(&mut data),
                    };
                    let segment = Segment::new_with_data(start, uncovered);
                    written += segment.data.len() as u64;
                    start += segment.data.len() as u64;
                    self.largest_offset = self.largest_offset.max(segment.end());
                    self.segments.push_front(segment);
                }
                // seg_index != 0 => seg_index > 0
                Err(seg_index) => {
                    // 首先需要检测是否和上一个seg重合
                    data = match self.segments.get(seg_index - 1) {
                        // start > prev_seg.offset && end < prev_seg.offset + prev_seg.len
                        // 有可能这一段完全被上一段囊括，直接break
                        Some(prev_seg)
                            if (start + data.len() as u64)
                                < prev_seg.offset + prev_seg.data.len() as u64 =>
                        {
                            break;
                        }
                        Some(prev_seg) if start < prev_seg.offset + prev_seg.data.len() as u64 => {
                            // 裁下后，start必定和prev_seg.offset + prev_seg.data.len()相等
                            // 下次loop就会进入上一个分支
                            // start < prev_seg.offset + prev_seg.data.len()
                            // 0 < start - prev_seg.offset + prev_seg.data.len() - start ，不会越界
                            //
                            // 还有可能，start + data.len() < prev_seg.offset + prev_seg.data.len() 也就是被上一个段完全覆盖
                            // 所以需要data.len(length_covered)
                            let length_covered = (data.len() as u64)
                                .min(prev_seg.offset + prev_seg.data.len() as u64 - start);
                            start += length_covered;
                            data.split_off(length_covered as usize)
                        }
                        // 如果没有重合，直接取出data
                        // 然后下次循环时data.is_empty() == true => break
                        Some(..) | None => data,
                    };

                    let uncovered = match self.segments.get(seg_index) {
                        // 如果和下一段数据有重合的话，裁下data中不重合的部分
                        Some(next_seg) if start + data.len() as u64 > next_seg.offset => {
                            // 裁下后，start必定和next_seg.offset相等，下次loop就会进入上一个分支
                            // next_seg.offset < start + data.len()
                            // next_seg.offset - start < data.len() ，不会越界
                            data.split_to((next_seg.offset - start) as usize)
                        }
                        // 如果没有重合，或者这是第一段数据，直接取出data
                        // 然后下次循环时data.is_empty() == true => break
                        Some(..) | None => core::mem::take(&mut data),
                    };

                    let segment = Segment::new_with_data(start, uncovered);
                    written += segment.data.len() as u64;
                    start += segment.data.len() as u64;
                    self.largest_offset = self.largest_offset.max(segment.end());
                    self.segments.insert(seg_index, segment);
                }
            }
            // 进入新的循环（也可递归）
        }

        written
    }

    /// Returns the length of continuous unread data.
    #[tracing::instrument(level = "trace", skip(self), ret)]
    pub fn available(&self) -> u64 {
        use core::ops::ControlFlow;
        let (ControlFlow::Continue(continuous_end) | ControlFlow::Break(continuous_end)) =
            self.segments.iter().try_fold(self.nread, |offset, seg| {
                if seg.offset == offset {
                    ControlFlow::Continue(offset + seg.data.len() as u64)
                } else {
                    ControlFlow::Break(offset)
                }
            });
        continuous_end - self.nread
    }

    /// Once the received data becomes continuous, it becomes readable. If necessary (if the application
    /// layer is blocked on reading), it is necessary to notify the application layer to read.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_readable(&self) -> bool {
        !self.segments.is_empty() && self.segments[0].offset == self.nread
    }

    /// Try to read continuous data from [`RecvBuf`] into the buffer passed in.
    ///
    /// If the following data is not continuous or there is no data, this method returns [`None`]
    ///
    /// Otherwise, returns how much data was written to the buffer passed in.
    ///
    /// # Example
    ///
    /// ``` rust
    /// # use bytes::{BytesMut, Bytes};
    /// # use qrecovery::recv::RecvBuf;
    /// let mut recvbuf = RecvBuf::default();
    /// recvbuf.recv(0, Bytes::from("012"));
    /// recvbuf.recv(3, Bytes::from("345"));
    /// recvbuf.recv(7, Bytes::from("789"));
    /// // recvbuf:  012345 789
    /// // readable: ^^^^^^
    ///
    /// let mut dst1 = BytesMut::new();
    /// recvbuf.try_read(&mut dst1);
    /// assert_eq!(dst1.as_ref(), b"012345");
    ///
    /// let mut dst2 = BytesMut::new();
    /// recvbuf.recv(6, Bytes::from("6"));
    /// // recvbuf:  0123456789
    /// // readable:       ^^^^
    ///
    /// recvbuf.try_read(&mut dst2);
    /// assert_eq!(dst2.as_ref(), b"6789");
    ///
    #[tracing::instrument(level = "trace", skip(self, dst), ret)]
    pub fn try_read(&mut self, dst: &mut impl BufMut) -> usize {
        let origin = dst.remaining_mut();
        while let Some(seg) = self.segments.front_mut() {
            if seg.offset != self.nread || !dst.has_remaining_mut() {
                break;
            }

            let read = dst.remaining_mut().min(seg.data.len());
            dst.put(seg.data.split_to(read));
            self.nread += read as u64;
            if seg.data.has_remaining() {
                seg.offset += read as u64;
            } else {
                self.segments.pop_front();
            }
        }
        origin - dst.remaining_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recvbuf_recv() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world")), 5);

        assert_eq!(buf.segments.len(), 2);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 6);

        assert_eq!(buf.recv(5, Bytes::from(" ")), 1);
        assert_eq!(buf.segments.len(), 3);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 5);
        assert_eq!(buf.segments[2].offset, 6);

        assert_eq!(buf.recv(12, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world.hell")), 1);
    }

    #[test]
    fn test_rcvbuf_recv_extend() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world!")), 6);
        assert_eq!(buf.recv(5, Bytes::from(" wor")), 1);

        assert_eq!(buf.segments.len(), 3);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 5);
        assert_eq!(buf.segments[2].offset, 6);
        assert_eq!(buf.available(), 12);
    }

    #[test]
    fn test_rcvbuf_recv_extend_more() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world")), 5);
        assert_eq!(buf.recv(5, Bytes::from(" world!")), 2);

        assert_eq!(buf.segments.len(), 4);
        assert_eq!(buf.available(), 12);
    }

    #[test]
    fn test_overlap() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(2, Bytes::from("4514")), 4);
        assert_eq!(buf.recv(0, Bytes::from("1199")), 2);

        assert_eq!(buf.segments.len(), 2);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 2);
        assert_eq!(buf.available(), 6);
    }

    #[test]
    fn test_covered() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("114514")), 6);
        assert_eq!(buf.recv(2, Bytes::from("45")), 0);
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.available(), 6);
    }

    #[test]
    fn test_covered2() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(2, Bytes::from("45")), 2);
        assert_eq!(buf.recv(0, Bytes::from("114514")), 4);
        assert_eq!(buf.segments.len(), 3);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 2);
        assert_eq!(buf.segments[2].offset, 4);
        assert_eq!(buf.available(), 6);
    }

    #[test]
    fn test_rcvbuf_recv_extend_and_replace() {
        // "hello  world!"
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(7, Bytes::from("world")), 5);
        assert_eq!(buf.recv(6, Bytes::from(" world!")), 2);

        assert_eq!(buf.segments.len(), 4);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 6);
        assert_eq!(buf.segments[2].offset, 7);
        assert_eq!(buf.segments[3].offset, 12);
        assert_eq!(buf.available(), 5);

        assert_eq!(buf.recv(0, Bytes::from("hello  world!")), 1);
        assert_eq!(buf.segments.len(), 5);
        assert_eq!(buf.available(), 13);
    }

    #[test]
    fn test_recvbuf_recv_and_insert() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("how")), 3);
        assert_eq!(buf.recv(9, Bytes::from("you")), 3);
        assert_eq!(buf.recv(5, Bytes::from("are")), 3);

        assert_eq!(buf.segments.len(), 3);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[1].offset, 5);
        assert_eq!(buf.segments[2].offset, 9);

        assert_eq!(buf.recv(3, Bytes::from("w are you")), 3);

        assert_eq!(buf.segments.len(), 5);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.available(), 12);
    }

    #[test]
    fn test_recvbuf_read() {
        let mut rcvbuf = RecvBuf::default();
        assert_eq!(rcvbuf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(rcvbuf.recv(6, Bytes::from("world")), 5);

        let mut dst = [0u8; 20];
        let mut buf = &mut dst[..];
        rcvbuf.try_read(&mut buf);
        assert_eq!(buf.remaining_mut(), 15);

        assert_eq!(rcvbuf.recv(5, Bytes::from(" ")), 1);
        rcvbuf.try_read(&mut buf);

        assert_eq!(buf.remaining_mut(), 9);
        assert_eq!(dst[..11], b"hello world"[..]);
    }

    #[test]
    fn test_rcvbuf_recv_overlap_seg() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("he")), 2);
        assert_eq!(buf.recv(6, Bytes::from("world")), 5);
        assert_eq!(buf.recv(0, Bytes::from("hello")), 3);

        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("he")), 2);
        assert_eq!(buf.recv(6, Bytes::from("wo")), 2);
        assert_eq!(buf.recv(12, Bytes::from("00")), 2);
        assert_eq!(buf.recv(0, Bytes::from("hello world")), 7);
    }
}
