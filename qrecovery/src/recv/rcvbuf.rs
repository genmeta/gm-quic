use std::{collections::VecDeque, fmt};

use bytes::{BufMut, Bytes};

/// 一段连续的数据片段，每个片段都是Bytes
#[derive(Debug, Default)]
pub(super) struct Segment {
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
    fn new_with_data(offset: u64, data: Bytes) -> Self {
        Segment {
            offset,
            length: data.len() as u64,
            fragments: vec![data].into(),
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

    fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// The receiving buffer is relatively simple, as it receives segmented data
/// that may not be continuous. It sequentially stores the received data
/// fragments and then reassembles them into a continuous data stream for
/// future reading by the application layer.
#[derive(Default, Debug)]
pub struct RecvBuf {
    nread: u64,
    segments: VecDeque<Segment>,
}

impl fmt::Display for RecvBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecvBuf(offset={}, segments=[", self.nread)?;
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
        self.nread
    }

    // Returns the number of newly read bytes
    pub fn recv(&mut self, mut offset: u64, mut data: Bytes) -> usize {
        if data.is_empty() {
            return 0;
        }

        if offset < self.nread {
            data = data.slice((self.nread - offset) as usize..);
            offset = self.nread;
        }

        match self.segments.binary_search_by(|s| s.offset.cmp(&offset)) {
            // 恰好落在一个片段上
            Ok(seg_idx) => {
                let new_data_size = self.overlap_seg(seg_idx, data);
                self.try_merge(seg_idx);
                new_data_size
            }
            // 并没有落在一个片段上，offset比任何一个片段都小
            Err(0) => {
                // 优先尝试添加到后一个片段之前
                if let Some(new_data_size) = self.try_prepend(0, offset, &data) {
                    return new_data_size;
                }
                self.insert(0, Segment::new_with_data(offset, data))
            }
            // segments[recommend].offset < offset
            Err(recommend) => {
                // 优先尝试添加到前一个片段之后
                if let Some(new_data_size) = self.try_append(recommend - 1, offset, &data) {
                    return new_data_size;
                }
                // 再尝试添加到后一个片段之前
                if let Some(new_data_size) = self.try_prepend(recommend, offset, &data) {
                    return new_data_size;
                }
                self.insert(recommend, Segment::new_with_data(offset, data))
            }
        }
    }

    // 返回片段之间是否有连接
    // 如果有连接，返回 Some(new_data_size)，否则返回 None
    fn try_prepend(&mut self, seg_idx: usize, offset: u64, data: &Bytes) -> Option<usize> {
        let data_end = offset + data.len() as u64;
        let mut new_data_size = 0;
        match self.segments.get(seg_idx) {
            Some(next_seg) if data_end >= next_seg.offset => {
                let end = (next_seg.offset - offset) as usize;
                let next_end = next_seg.offset + next_seg.length;
                self.segments[seg_idx].prepend(data.slice(..end));
                new_data_size += end;
                // 有可能被追加在前的片段覆盖了整个段
                if data_end > next_end {
                    let remain = data.slice((next_end - offset) as usize..);
                    if let Some(new_data) = self.try_append(seg_idx, next_end, &remain) {
                        new_data_size += new_data;
                    }
                }
                Some(new_data_size)
            }
            _ => None,
        }
    }

    // 需要 offset >= segs[seg_idx].offset
    // 返回片段之间是否有连接
    // 如果有连接，返回 Some(new_data_size)，否则返回 None
    fn try_append(&mut self, seg_idx: usize, offset: u64, data: &Bytes) -> Option<usize> {
        let pre_seg = &self.segments[seg_idx];
        let data_end = offset + data.len() as u64;
        let pre_seg_end = pre_seg.offset + pre_seg.length;

        // 已经完全被前一个片段包含，不需要处理
        if data_end <= pre_seg_end {
            return Some(0);
        }

        // 完全和前一个片段没有连接
        if offset > pre_seg_end {
            return None;
        }

        let start = if offset < pre_seg_end {
            (pre_seg_end - offset) as usize
        } else {
            0
        };
        // 可能这段数据已经覆盖了下一段数据
        let next_offset = self.segments.get(seg_idx + 1).map(|seg| seg.offset);
        let end = match next_offset {
            Some(next_offset) => (next_offset - offset) as usize,
            None => data.len(),
        }
        .min(data.len());

        let mut new_data_size = 0;
        new_data_size += end - start;
        self.segments[seg_idx].append(data.slice(start..end));

        // 有可能片段和下一个段有连接
        if data.len() > end {
            new_data_size += self.overlap_seg(seg_idx + 1, data.slice(end..));
        }
        self.try_merge(seg_idx);
        Some(new_data_size)
    }

    fn insert(&mut self, at: usize, seg: Segment) -> usize {
        let new_data_size = seg.length as usize;
        self.segments.insert(at, seg);
        new_data_size
    }

    // 不同于 append 和 prepend，这是对于和段从头开始重合的情况
    // 是append的特化情况
    // 返回新增的数据字节数
    fn overlap_seg(&mut self, mut seg_idx: usize, mut data: Bytes) -> usize {
        let mut new_data_size = 0;
        loop {
            let cur_seg = &self.segments[seg_idx];
            let offset = cur_seg.offset;

            if data.len() as u64 <= cur_seg.length {
                break new_data_size;
            }

            let start = cur_seg.length as usize;

            let end = match self.segments.get(seg_idx + 1).map(|next| next.offset) {
                Some(next_offset) => (next_offset - offset) as usize,
                None => data.len(),
            }
            .min(data.len());

            self.segments[seg_idx].append(data.slice(start..end));

            new_data_size += end - start;
            if data.len() > end {
                data = data.slice(end..);
                seg_idx += 1;
            } else {
                break new_data_size;
            }

            // 不在这里merge，而是在外部，是因为append可能多创造一个连接段
        }
    }

    fn try_merge(&mut self, mut idx: usize) {
        let start_idx = idx;
        let mut cur_seg = self.segments[idx].take();
        while idx + 1 < self.segments.len() {
            let next_seg = &mut self.segments[idx + 1];
            if next_seg.offset != cur_seg.offset + cur_seg.length {
                break;
            }

            cur_seg.fragments.append(&mut next_seg.fragments);
            cur_seg.length += next_seg.length;
            idx += 1;
        }

        self.segments[idx] = cur_seg;
        self.segments.drain(start_idx..idx);
    }

    /// To read continuously starting from self.offset, it means that the offset of
    /// first segments should also start from self.offset or be smaller than self.offset.
    /// Otherwise, the data will be discontinuous and cannot be read. At most, buf.len()
    /// bytes will be read, and if it cannot read that many, it will return the number
    /// of bytes read.
    pub fn read<T: BufMut>(&mut self, buf: &mut T) {
        if let Some(mut seg) = self.segments.pop_front() {
            if seg.offset != self.nread {
                self.segments.push_front(seg);
                return;
            }

            while let Some(frag) = seg.fragments.pop_front() {
                let n = buf.remaining_mut().min(frag.len());
                buf.put_slice(&frag[..n]);
                seg.offset += n as u64;
                self.nread = seg.offset;
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
        if self
            .segments
            .front()
            .is_some_and(|seg| seg.offset == self.nread)
        {
            self.nread + self.segments[0].length
        } else {
            self.nread
        }
    }

    /// Once the received data becomes continuous, it becomes readable. If necessary (if the application
    /// layer is blocked on reading), it is necessary to notify the application layer to read.
    pub fn is_readable(&self) -> bool {
        !self.segments.is_empty()
            && self.segments[0].offset == self.nread
            && self.segments[0].length > 0
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
        assert_eq!(buf.segments[0].length, 5);
        assert_eq!(buf.segments[0].fragments.len(), 1);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[1].offset, 6);
        assert_eq!(buf.segments[1].length, 5);
        assert_eq!(buf.segments[1].fragments.len(), 1);
        assert_eq!(buf.segments[1].fragments[0], Bytes::from("world"));

        assert_eq!(buf.recv(5, Bytes::from(" ")), 1);
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 11);
        assert_eq!(buf.segments[0].fragments.len(), 3);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" "));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("world"));

        assert_eq!(buf.recv(12, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world.hell")), 1);
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("world"));
        assert_eq!(buf.segments[0].fragments[3], Bytes::from("."));
        assert_eq!(buf.segments[0].fragments[4], Bytes::from("hello"));
    }

    #[test]
    fn test_rcvbuf_recv_extend() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world")), 5);
        assert_eq!(buf.recv(5, Bytes::from(" wor")), 1);

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 11);
        assert_eq!(buf.segments[0].fragments.len(), 3);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" "));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("world"));
    }

    #[test]
    fn test_rcvbuf_recv_extend_more() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(6, Bytes::from("world")), 5);
        assert_eq!(buf.recv(5, Bytes::from(" world!")), 2);

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 12);
        assert_eq!(buf.segments[0].fragments.len(), 4);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from(" "));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("world"));
        assert_eq!(buf.segments[0].fragments[3], Bytes::from("!"));
    }

    #[test]
    fn test_overlap() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(2, Bytes::from("4514")), 4);
        assert_eq!(buf.recv(0, Bytes::from("1199")), 2);

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 6);
        assert_eq!(buf.segments[0].fragments.len(), 2);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("11"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from("4514"));
    }

    #[test]
    fn test_rcvbuf_recv_extend_and_replace() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(buf.recv(7, Bytes::from("world")), 5);
        assert_eq!(buf.recv(6, Bytes::from(" world!")), 2);

        assert_eq!(buf.segments.len(), 2);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 5);
        assert_eq!(buf.segments[0].fragments.len(), 1);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("hello"));
        assert_eq!(buf.segments[1].offset, 6);
        assert_eq!(buf.segments[1].length, 7);
        assert_eq!(buf.segments[1].fragments.len(), 3);
        assert_eq!(buf.segments[1].fragments[0], Bytes::from(" "));
        assert_eq!(buf.segments[1].fragments[1], Bytes::from("world"));
        assert_eq!(buf.segments[1].fragments[2], Bytes::from("!"));
    }

    #[test]
    fn test_recvbuf_recv_and_insert() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.recv(0, Bytes::from("how")), 3);
        assert_eq!(buf.recv(9, Bytes::from("you")), 3);
        assert_eq!(buf.recv(5, Bytes::from("are")), 3);

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

        assert_eq!(buf.recv(3, Bytes::from("w are you")), 3);

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].offset, 0);
        assert_eq!(buf.segments[0].length, 12);
        assert_eq!(buf.segments[0].fragments.len(), 5);
        assert_eq!(buf.segments[0].fragments[0], Bytes::from("how"));
        assert_eq!(buf.segments[0].fragments[1], Bytes::from("w "));
        assert_eq!(buf.segments[0].fragments[2], Bytes::from("are"));
        assert_eq!(buf.segments[0].fragments[3], Bytes::from(" "));
        assert_eq!(buf.segments[0].fragments[4], Bytes::from("you"));
    }

    #[test]
    fn test_recvbuf_read() {
        let mut rcvbuf = RecvBuf::default();
        assert_eq!(rcvbuf.recv(0, Bytes::from("hello")), 5);
        assert_eq!(rcvbuf.recv(6, Bytes::from("world")), 5);

        let mut dst = [0u8; 20];
        let mut buf = &mut dst[..];
        rcvbuf.read(&mut buf);
        assert_eq!(buf.remaining_mut(), 15);

        assert_eq!(rcvbuf.recv(5, Bytes::from(" ")), 1);
        rcvbuf.read(&mut buf);

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
