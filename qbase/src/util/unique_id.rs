use std::{
    hash::Hash,
    sync::atomic::{AtomicUsize, Ordering},
};

use derive_more::Into;

/// Opque, hashable, unique ID type.
#[derive(Debug, Clone, Copy, Into, PartialEq, Eq, Hash)]
pub struct UniqueId(usize);

/// Thread safe, lock free unique ID generator.
#[derive(Debug)]
pub struct UniqueIdGenerator(AtomicUsize);

impl Default for UniqueIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl UniqueIdGenerator {
    /// Create a new `UniqueIdGenerator`
    ///
    /// # Example
    ///
    /// ```
    /// use qbase::util::UniqueIdGenerator;
    ///
    /// let generator = UniqueIdGenerator::new();
    /// let id1 = generator.generate();
    /// let id2 = generator.generate();
    /// assert_ne!(id1, id2);
    /// ```
    pub const fn new() -> Self {
        UniqueIdGenerator(AtomicUsize::new(1))
    }

    /// Generated a new `UniqueId` starting from a specific value
    ///
    /// # Example
    ///
    /// ```
    /// use qbase::util::UniqueIdGenerator;
    ///
    /// let generator = UniqueIdGenerator::new();
    /// let id1 = generator.generate();
    /// let id2 = generator.generate();
    /// assert_ne!(id1, id2);
    /// ```
    pub fn generate(&self) -> UniqueId {
        let id = self.0.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, 0, "UniqueId overflow");
        UniqueId(id)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, thread};

    use super::*;

    #[test]
    fn test_unique_id_basic() {
        let generator = UniqueIdGenerator::new();
        let id1 = generator.generate();
        let id2 = generator.generate();

        assert_ne!(id1, id2);
        assert_eq!(id1.0, 1);
        assert_eq!(id2.0, 2);
    }

    #[test]
    fn test_unique_id_hash() {
        let generator = UniqueIdGenerator::new();
        let id1 = generator.generate();
        let id2 = generator.generate();

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_unique_id_clone_copy() {
        let generator = UniqueIdGenerator::new();
        let id1 = generator.generate();
        let id2 = id1; // Copy

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_thread_safety() {
        let generator = Arc::new(UniqueIdGenerator::new());
        let mut handles = vec![];

        // 启动多个线程同时生成ID
        for _ in 0..10 {
            let generator = Arc::clone(&generator);
            let handle = thread::spawn(move || {
                let mut ids = Vec::new();
                for _ in 0..100 {
                    ids.push(generator.generate());
                }
                ids
            });
            handles.push(handle);
        }

        // 收集所有生成的ID
        let mut all_ids = HashSet::new();
        for handle in handles {
            let ids = handle.join().unwrap();
            for id in ids {
                assert!(all_ids.insert(id), "Duplicate ID found: {id:?}");
            }
        }

        // 应该有1000个唯一的ID
        assert_eq!(all_ids.len(), 1000);
    }

    #[test]
    fn test_default_generator() {
        let gen1 = UniqueIdGenerator::new();
        let gen2 = UniqueIdGenerator::new();

        assert_eq!(gen1.generate(), gen2.generate())
    }
}
