use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
};

/// MinAware is a wrapper around HashMap that tracks the minimum value
/// among all values while ensuring values can only be updated to larger ones
#[derive(Debug, Default, Clone)]
pub struct MinAware<K, V>
where
    K: Eq + Hash,
    V: Ord + Copy,
{
    inner: HashMap<K, V>,
}

impl<K, V> MinAware<K, V>
where
    K: Eq + Hash,
    V: Ord + Copy,
{
    /// Creates a new MinAware instance.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Inserts or updates a value.
    /// If the key doesn't exist, directly inserts.
    /// If the key exists, only updates when the new value is greater than the old value.
    /// Returns whether the insert/update operation occurred.
    pub fn insert(&mut self, key: K, value: V) -> V {
        self.inner
            .entry(key)
            .and_modify(|v| {
                assert!(*v <= value);
                *v = value;
            })
            .or_insert(value);

        self.min_value().unwrap_or(value)
    }

    /// Gets the minimum value among all values.
    /// Returns None if the map is empty.
    pub fn min_value(&self) -> Option<V> {
        self.inner.values().min().copied()
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key);
        self.min_value()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArcMinAware<K, V>(Arc<Mutex<MinAware<K, V>>>)
where
    K: Eq + Hash,
    V: Ord + Copy;

impl<K, V> ArcMinAware<K, V>
where
    K: Eq + Hash,
    V: Ord + Copy,
{
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(MinAware::new())))
    }

    pub fn insert(&self, key: K, value: V) -> V {
        self.0.lock().unwrap().insert(key, value)
    }

    pub fn min_value(&self) -> Option<V> {
        self.0.lock().unwrap().min_value()
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.0.lock().unwrap().remove(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_aware() {
        let mut min_aware = MinAware::new();

        assert_eq!(min_aware.insert("a", 1), 1);
        assert_eq!(min_aware.insert("c", 3), 1);
        assert_eq!(min_aware.insert("b", 2), 1);

        assert_eq!(min_aware.min_value(), Some(1));

        assert_eq!(min_aware.insert("a", 4), 2);

        assert_eq!(min_aware.min_value(), Some(2));

        assert_eq!(min_aware.inner.get(&"a"), Some(&4));
        assert_eq!(min_aware.inner.get(&"d"), None);

        assert_eq!(min_aware.inner.len(), 3);
        assert!(!min_aware.inner.is_empty());

        min_aware.inner.clear();
        assert_eq!(min_aware.min_value(), None);
    }

    #[test]
    #[should_panic]
    fn test_insert_samller() {
        let mut min_aware = MinAware::new();

        assert_eq!(min_aware.insert("a", 4), 4);
        min_aware.insert("a", 1);
    }
}
