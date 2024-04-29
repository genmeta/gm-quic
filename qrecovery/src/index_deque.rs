use std::{
    collections::VecDeque,
    ops::{Index, IndexMut},
};

/// This structure will be used for the packets to be sent and
/// the records of the packets that have been sent and are awaiting confirmation.
#[derive(Default, Debug)]
pub struct IndexDeque<T, const LIMIT: u64> {
    deque: VecDeque<T>,
    offset: u64,
}

impl<T, const LIMIT: u64> IndexDeque<T, LIMIT> {
    pub fn new() -> Self {
        IndexDeque {
            deque: VecDeque::new(),
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

    pub fn contain(&self, idx: u64) -> bool {
        idx >= self.offset && idx < self.offset + self.deque.len() as u64
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
    pub fn push(&mut self, value: T) -> Option<u64> {
        let next_idx = self.offset.overflowing_add(self.deque.len() as u64);
        if next_idx.1 || next_idx.0 > LIMIT {
            None
        } else {
            self.deque.push_back(value);
            Some(self.deque.len() as u64 - 1 + self.offset)
        }
    }

    /// When the queue is empty, it returns None; otherwise, it returns
    /// the first element in the queue along with its enqueue index.
    /// This API will be used by the queue for the packets to be sent.
    pub fn pop(&mut self) -> Option<(u64, T)> {
        self.deque.pop_front().map(|v| {
            let offset = self.offset;
            self.offset += 1;
            (offset, v)
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut T)> {
        self.deque
            .iter_mut()
            .enumerate()
            .map(|(idx, item)| (self.offset + idx as u64, item))
    }

    /// This API will be used for the records of the packets that have been
    /// sent and are awaiting confirmation.
    /// The records of the sent packets can only be removed from the queue
    /// when the acknowledgment (ack) is received. Additionally, any unacknowledged
    /// elements in the records are considered lost and require retransmission.
    pub fn drain_to(&mut self, end: u64) -> impl Iterator<Item = T> + '_ {
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
    pub fn insert(&mut self, idx: u64, value: T) -> Option<u64> {
        if idx > LIMIT || idx < self.offset {
            None
        } else {
            let pos = (idx - self.offset) as usize;
            if pos >= self.deque.len() {
                if pos > self.deque.len() {
                    self.deque.resize(pos, T::default());
                }
                self.deque.push_back(value);
            } else {
                self.deque[pos] = value;
            }
            Some(idx)
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
        let mut deque = IndexDeque::<u64, 19>::new();
        for i in 0..10 {
            assert_eq!(deque.push(i + 1), Some(i));
        }
        assert_eq!(deque.offset, 0);

        for i in 0..10 {
            assert_eq!(deque.pop(), Some((i, i + 1)));
            assert_eq!(deque.offset, i + 1);
        }
        assert_eq!(deque.pop(), None);
        assert_eq!(deque.offset, 10);

        for i in 10..20 {
            assert_eq!(deque.push(i + 1), Some(i));
        }
        assert_eq!(deque.push(21), None);
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
            i = i + 1;
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
        let mut deque = IndexDeque::<u64, 19>::new();
        deque.insert(10, 11);
        assert_eq!(deque.offset, 0);
        assert_eq!(deque.len(), 11);

        for i in 0..10 {
            assert_eq!(deque[i], u64::default());
        }
        assert_eq!(deque[10], 11);
    }
}
