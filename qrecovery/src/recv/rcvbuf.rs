use bytes::{BufMut, Bytes};
use std::{collections::VecDeque, fmt, ops::Range};

/// 一段连续的数据片段，每个片段都是Bytes
#[derive(Debug, Default)]
pub struct Segment {
    offset: u64,
    length: u64,
    fragments: VecDeque<Bytes>,
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}..{}]", self.offset, self.offset + self.length)
    }
}

impl Segment {
    fn from(offset: u64) -> Self {
        Segment {
            offset,
            length: 0,
            fragments: VecDeque::new(),
        }
    }

    fn try_prepend(&self, range: &Range<u64>) -> Option<Range<u64>> {
        if range.start < self.offset && range.end >= self.offset {
            Some(range.start..self.offset)
        } else {
            None
        }
    }

    fn try_append(&self, range: &Range<u64>) -> Option<Range<u64>> {
        if range.start <= self.offset + self.length && range.end > self.offset + self.length {
            Some(self.offset + self.length..range.end)
        } else {
            None
        }
    }

    fn prepend(&mut self, data: Bytes) {
        self.offset -= data.len() as u64;
        self.length += data.len() as u64;
        self.fragments.push_front(data);
    }

    fn append(&mut self, data: Bytes) {
        self.length += data.len() as u64;
        self.fragments.push_back(data);
    }

    fn replace(&mut self, offset: u64, data: Bytes) {
        self.offset = offset;
        self.length = data.len() as u64;
        self.fragments.clear();
        self.fragments.push_back(data);
    }

    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// The receiving buffer is relatively simple, as it receives segmented data
/// that may not be continuous. It sequentially stores the received data
/// fragments and then reassembles them into a continuous data stream for
/// future reading by the application layer.
/// ## Example
/// ```
/// use qrecovery::recv::rcvbuf::RecvBuf;
/// use bytes::{Bytes, BufMut};
///
/// let mut rcvbuf = RecvBuf::default();
/// rcvbuf.recv(0, Bytes::from("hello"));
/// rcvbuf.recv(6, Bytes::from("world"));
/// rcvbuf.recv(5, Bytes::from(" "));
///
/// let mut dst = [0u8; 20];
/// let mut buf = &mut dst[..];
/// rcvbuf.read(&mut buf);
/// let n = 20 - buf.remaining_mut();
/// assert_eq!(&dst[..n], b"hello world");
/// ```
#[derive(Default, Debug)]
pub struct RecvBuf {
    offset: u64,
    segments: VecDeque<Segment>,
}

impl fmt::Display for RecvBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecvBuf(offset={}, segments=[", self.offset)?;
        for segment in &self.segments {
            write!(f, "{}", segment)?;
        }
        write!(f, "])")
    }
}

impl RecvBuf {
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn recv(&mut self, mut offset: u64, mut data: Bytes) {
        if offset < self.offset {
            data = data.slice((self.offset - offset) as usize..);
            offset = self.offset;
        }
        if data.is_empty() {
            return;
        }

        let range = offset..offset + data.len() as u64;
        let index = self
            .segments
            .binary_search_by(|s| s.offset.cmp(&offset))
            .unwrap_or_else(|i| {
                if i == 0 {
                    self.segments.push_front(Segment::from(offset));
                    0
                } else {
                    i - 1
                }
            });

        let pre_segment = self.segments.get_mut(index).unwrap();
        let append = pre_segment.try_append(&range);
        if let Some(range) = append {
            pre_segment.append(data.slice((range.start - offset) as usize..));
            self.try_merge(index);
        } else {
            // 已经与上一个segment中断，不用考虑向前合并的事情了
            // 不过要注意，后续的不能仅考虑前向插入，很可能收到一个大块，直接把后面几个segment都覆盖掉了
            match self.segments.get_mut(index + 1) {
                Some(next) => match (next.try_prepend(&range), next.try_append(&range)) {
                    (Some(range), None) => {
                        next.prepend(data.slice(..(range.end - offset) as usize));
                    }
                    (None, Some(range)) => {
                        next.append(data.slice((range.start - offset) as usize..));
                        self.try_merge(index + 1);
                    }
                    (Some(_), Some(_)) => {
                        next.replace(offset, data);
                        self.try_merge(index + 1);
                    }
                    (None, None) => {
                        let mut new_segment = Segment::from(offset);
                        new_segment.append(data);
                        self.segments.insert(index + 1, new_segment);
                    }
                },
                None => {
                    let mut new_segment = Segment::from(offset);
                    new_segment.append(data);
                    self.segments.push_back(new_segment);
                }
            };
        }
    }

    fn try_merge(&mut self, index: usize) {
        let mut seg = self.segments.get_mut(index).unwrap().take();
        let mut cursor = index + 1;
        while cursor < self.segments.len() {
            let next = self.segments.get_mut(cursor).unwrap();
            let seg_end = seg.offset + seg.length;
            if seg_end >= next.offset {
                while let Some(frag) = next.fragments.pop_front() {
                    if next.offset + frag.len() as u64 <= seg_end {
                        next.length -= frag.len() as u64;
                        next.offset += frag.len() as u64;
                        continue;
                    } else if next.offset < seg_end {
                        let repeat_len = seg_end - next.offset;
                        seg.length += frag.len() as u64 - repeat_len;
                        next.length -= frag.len() as u64;
                        next.offset += frag.len() as u64;
                        seg.fragments.push_back(frag.slice(repeat_len as usize..));
                        break;
                    } else if next.offset == seg_end {
                        next.length -= frag.len() as u64;
                        next.offset += frag.len() as u64;
                        seg.length += frag.len() as u64;
                        seg.fragments.push_back(frag);
                        break;
                    }
                }
                seg.fragments.append(&mut next.fragments);
                seg.length += next.length;
                cursor += 1;
            } else {
                break;
            }
        }
        self.segments[index] = seg;
        if index + 1 < cursor {
            self.segments.drain(index + 1..cursor);
        }
    }
}

impl RecvBuf {
    /// To read continuously starting from self.offset, it means that the offset of
    /// first segments should also start from self.offset or be smaller than self.offset.
    /// Otherwise, the data will be discontinuous and cannot be read. At most, buf.len()
    /// bytes will be read, and if it cannot read that many, it will return the number
    /// of bytes read.
    pub fn read<T: BufMut>(&mut self, buf: &mut T) {
        if let Some(mut seg) = self.segments.pop_front() {
            if seg.offset > self.offset {
                self.segments.push_front(seg);
                return;
            }

            while let Some(frag) = seg.fragments.pop_front() {
                let n = std::cmp::min(buf.remaining_mut(), frag.len());
                buf.put_slice(&frag[..n]);
                self.offset += n as u64;
                seg.offset += n as u64;
                if n < frag.len() {
                    seg.fragments.push_front(frag.slice(n..));
                    self.segments.push_front(seg);
                    break;
                }
            }
        }
    }

    /// The maximum length of continuous readable data, which can be compared with the final size
    /// known as "SizeKnown." If they match, it indicates that all the data has been received.
    pub fn available(&self) -> u64 {
        if !self.segments.is_empty() && self.segments[0].offset == self.offset {
            self.offset + self.segments[0].length
        } else {
            self.offset
        }
    }

    /// Once the received data becomes continuous, it becomes readable. If necessary (if the application
    /// layer is blocked on reading), it is necessary to notify the application layer to read.
    pub fn is_readable(&self) -> bool {
        !self.segments.is_empty()
            && self.segments[0].offset == self.offset
            && self.segments[0].length > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recvbuf_recv() {
        let mut buf = RecvBuf::default();
        buf.recv(0, Bytes::from("hello"));
        buf.recv(6, Bytes::from("world"));
        assert_eq!(buf.segments.len(), 2);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 5);
        assert_eq!(buf.segments[0].fragments.len(), 1);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[1].offset, 6);
        assert_eq!(buf.segments[1].length, 5);
        assert_eq!(buf.segments[1].fragments.len(), 1);
        assert_eq!(buf.segments[1].fragments[0], Bytes::from("world"));

        buf.recv(5, Bytes::from(" "));
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 11);
        assert_eq!(buf.segments[0].fragments.len(), 3);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" "));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("world"));
    }

    #[test]
    fn test_rcvbuf_recv_extend() {
        let mut buf = RecvBuf::default();
        buf.recv(0, Bytes::from("hello"));
        buf.recv(6, Bytes::from("world"));
        buf.recv(5, Bytes::from(" wor"));
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 11);
        assert_eq!(buf.segments[0].fragments.len(), 3);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" wor"));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("ld"));
    }

    #[test]
    fn test_rcvbuf_recv_extend_more() {
        let mut buf = RecvBuf::default();
        buf.recv(0, Bytes::from("hello"));
        buf.recv(6, Bytes::from("world"));
        buf.recv(5, Bytes::from(" world!"));
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 12);
        assert_eq!(buf.segments[0].fragments.len(), 2);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" world!"));
    }

    #[test]
    fn test_rcvbuf_recv_extend_and_replace() {
        let mut buf = RecvBuf::default();
        buf.recv(0, Bytes::from("hello"));
        buf.recv(7, Bytes::from("world"));
        buf.recv(6, Bytes::from(" world!"));
        assert_eq!(buf.segments.len(), 2);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 5);
        assert_eq!(buf.segments[0].fragments.len(), 1);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[1].offset, 6);
        assert_eq!(buf.segments[1].length, 7);
        assert_eq!(buf.segments[1].fragments.len(), 1);
        assert_eq!(buf.segments[1].fragments[0], Bytes::from(" world!"));
    }

    #[test]
    fn test_recvbuf_recv_and_insert() {
        let mut buf = RecvBuf::default();
        buf.recv(0, Bytes::from("how"));
        buf.recv(9, Bytes::from("you"));
        buf.recv(5, Bytes::from("are"));
        assert_eq!(buf.segments.len(), 3);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 3);
        assert_eq!(buf.segments[0].fragments.len(), 1);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("how"));
        assert_eq!(buf.segments[1].offset, 5);
        assert_eq!(buf.segments[1].length, 3);
        assert_eq!(buf.segments[1].fragments.len(), 1);
        assert_eq!(buf.segments[1].fragments[0], Bytes::from("are"));
        assert_eq!(buf.segments[2].offset, 9);
        assert_eq!(buf.segments[2].length, 3);
        assert_eq!(buf.segments[2].fragments.len(), 1);
        assert_eq!(buf.segments[2].fragments[0], Bytes::from("you"));

        buf.recv(3, Bytes::from("w are you"));
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 12);
        assert_eq!(buf.segments[0].fragments.len(), 2);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("how"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from("w are you"));
    }

    #[test]
    fn test_recvbuf_read() {
        let mut rcvbuf = RecvBuf::default();
        rcvbuf.recv(0, Bytes::from("hello"));
        rcvbuf.recv(6, Bytes::from("world"));

        let mut dst = [0u8; 20];
        let mut buf = &mut dst[..];
        rcvbuf.read(&mut buf);
        assert_eq!(buf.remaining_mut(), 15);

        rcvbuf.recv(5, Bytes::from(" "));
        rcvbuf.read(&mut buf);
        assert_eq!(buf.remaining_mut(), 9);
        assert_eq!(dst[..11], b"hello world"[..]);
    }
}
