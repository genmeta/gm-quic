use std::{
    collections::VecDeque,
    ops::{Index, IndexMut},
};

use thiserror::Error;

use crate::error::{Error, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the packet number exceed the limit {0}")]
pub struct ExceedLimit(u64);

/// This structure will be used for the packets to be sent and
/// the records of the packets that have been sent and are awaiting confirmation.
#[derive(Debug)]
pub struct IndexDeque<T, const LIMIT: u64> {
    deque: VecDeque<T>,
    offset: u64,
}

impl<T, const LIMIT: u64> Default for IndexDeque<T, LIMIT> {
    fn default() -> Self {
        Self {
            deque: VecDeque::default(),
            offset: 0,
        }
    }
}

impl From<ExceedLimit> for Error {
    fn from(err: ExceedLimit) -> Self {
        Error::new(
            ErrorKind::None,
            crate::frame::FrameType::Padding,
            err.to_string(),
        )
    }
}

impl<T, const LIMIT: u64> IndexDeque<T, LIMIT> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            deque: VecDeque::with_capacity(capacity),
            offset: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn largest(&self) -> u64 {
        self.offset + self.deque.len() as u64
    }

    pub fn contain(&self, idx: u64) -> bool {
        idx >= self.offset && idx < self.largest()
    }

    pub fn get(&self, idx: u64) -> Option<&T> {
        if self.contain(idx) {
            Some(&self.deque[(idx - self.offset) as usize])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, idx: u64) -> Option<&mut T> {
        if self.contain(idx) {
            Some(&mut self.deque[(idx - self.offset) as usize])
        } else {
            None
        }
    }

    /// Append an element to the end of the queue and return the enqueue index of the element.
    /// If it exceeds the maximum limit of the enqueue index, return None
    pub fn push_back(&mut self, value: T) -> Result<u64, ExceedLimit> {
        let next_idx = self.offset.overflowing_add(self.deque.len() as u64);
        if next_idx.1 || next_idx.0 > LIMIT {
            Err(ExceedLimit(LIMIT))
        } else {
            self.deque.push_back(value);
            Ok(self.deque.len() as u64 - 1 + self.offset)
        }
    }

    /// When the queue is empty, it returns None; otherwise, it returns
    /// the first element in the queue along with its enqueue index.
    /// This API will be used by the queue for the packets to be sent.
    pub fn pop_front(&mut self) -> Option<(u64, T)> {
        self.deque.pop_front().map(|v| {
            let offset = self.offset;
            self.offset += 1;
            (offset, v)
        })
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> {
        self.deque.iter()
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> {
        self.deque.iter_mut()
    }

    pub fn iter_with_idx(&self) -> impl DoubleEndedIterator<Item = (u64, &T)> {
        self.deque
            .iter()
            .enumerate()
            .map(|(idx, item)| (self.offset + idx as u64, item))
    }

    pub fn iter_mut_with_idx(&mut self) -> impl DoubleEndedIterator<Item = (u64, &mut T)> {
        self.deque
            .iter_mut()
            .enumerate()
            .map(|(idx, item)| (self.offset + idx as u64, item))
    }

    pub fn advance(&mut self, n: usize) {
        self.offset += n as u64;
        let _ = self.deque.drain(..n);
    }

    /// This API will be used for the records of the packets that have been
    /// sent and are awaiting confirmation.
    /// The records of the sent packets can only be removed from the queue
    /// when the acknowledgment (ack) is received. Additionally, any unacknowledged
    /// elements in the records are considered lost and require retransmission.
    pub fn drain_to(&mut self, end: u64) -> impl DoubleEndedIterator<Item = T> + '_ {
        #[cfg(not(test))]
        debug_assert!(end >= self.offset && end <= self.offset + self.deque.len() as u64);
        // avoid end < self.offset
        let end = std::cmp::max(end, self.offset);
        let offset = self.offset;
        // avoid end > self.offset + self.deque.len()
        self.offset = std::cmp::min(end, offset + self.deque.len() as u64);
        let end = (self.offset - offset) as usize;
        self.deque.drain(..end)
    }
}

impl<T: Default + Clone, const LIMIT: u64> IndexDeque<T, LIMIT> {
    pub fn insert(&mut self, idx: u64, value: T) -> Result<Option<T>, ExceedLimit> {
        if idx > LIMIT || idx < self.offset {
            Err(ExceedLimit(LIMIT))
        } else {
            let pos = (idx - self.offset) as usize;
            if pos < self.deque.len() {
                return Ok(Some(std::mem::replace(&mut self.deque[pos], value)));
            }

            if pos > self.deque.len() {
                self.deque.resize(pos, T::default());
            }
            self.deque.push_back(value);
            Ok(None)
        }
    }
}

impl<T, const LIMIT: u64> Index<u64> for IndexDeque<T, LIMIT> {
    type Output = T;

    fn index(&self, index: u64) -> &Self::Output {
        &self.deque[(index - self.offset) as usize]
    }
}

impl<T, const LIMIT: u64> IndexMut<u64> for IndexDeque<T, LIMIT> {
    fn index_mut(&mut self, index: u64) -> &mut Self::Output {
        &mut self.deque[(index - self.offset) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_queue() {
        let mut deque = IndexDeque::<u64, 19>::default();
        for i in 0..10 {
            assert_eq!(deque.push_back(i + 1), Ok(i));
        }
        assert_eq!(deque.offset, 0);

        for i in 0..10 {
            assert_eq!(deque.pop_front(), Some((i, i + 1)));
            assert_eq!(deque.offset, i + 1);
        }
        assert_eq!(deque.pop_front(), None);
        assert_eq!(deque.offset, 10);

        for i in 10..20 {
            assert_eq!(deque.push_back(i + 1), Ok(i));
        }
        assert_eq!(deque.push_back(21), Err(ExceedLimit(19)));
        assert_eq!(deque.offset, 10);

        assert!(!deque.contain(0));
        assert!(!deque.contain(9));
        assert!(deque.contain(10));
        assert!(deque.contain(19));
        assert!(!deque.contain(21));

        assert_eq!(deque[10], 11);
        assert_eq!(deque[19], 20);

        assert_eq!(deque.drain_to(10).count(), 0);
        let mut i = 10;
        for item in deque.drain_to(15) {
            i += 1;
            assert_eq!(item, i);
        }
        assert_eq!(i, 15);
        assert!(deque.contain(15));
        assert_eq!(deque.offset, 15);

        assert_eq!(deque.drain_to(30).count(), 5);
        assert_eq!(deque.offset, 20);
        assert!(deque.is_empty());
    }

    #[test]
    fn test_insert() {
        let mut deque = IndexDeque::<u64, 19>::default();
        deque.insert(10, 11).unwrap();
        assert_eq!(deque.offset, 0);
        assert_eq!(deque.len(), 11);

        for i in 0..10 {
            assert_eq!(deque[i], u64::default());
        }
        assert_eq!(deque[10], 11);
    }

    #[test]
    fn test_skip() {
        let mut deque = IndexDeque::<u64, 19>::default();
        for i in 0..10 {
            assert_eq!(deque.push_back(i), Ok(i));
        }
        assert_eq!(deque.offset, 0);

        deque.advance(5);
        assert_eq!(deque.offset, 5);

        deque.iter_with_idx().for_each(|(idx, item)| {
            assert_eq!(idx, *item);
        });
    }
}
