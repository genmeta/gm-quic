use std::{
    hash::Hash,
    sync::{Arc, OnceLock},
};

use dashmap::{DashMap, DashSet};
use derive_more::{Deref, DerefMut};
use qbase::{
    net::{addr::BindUri, route::EndpointAddr},
    util::{UniqueId, UniqueIdGenerator},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Manages a collection of local addresses and notifies subscribers of changes.
/// T is a generic type for the address, which must be comparable, hashable, and cloneable.
pub struct Locations<T: PartialEq + Eq + Hash + Clone> {
    /// A set of unique local addresses.
    addresses: DashSet<T>,
    /// A map of subscribers, mapping a unique ID to a sender.
    subscribers: Arc<DashMap<UniqueId, UnboundedSender<T>>>,
    /// The next available ID for a new subscriber.
    id_generator: UniqueIdGenerator,
}

/// A handle to a subscription.
/// It allows receiving messages and automatically unsubscribes when dropped.
#[derive(Deref, DerefMut)]
pub struct Observer<T> {
    id: UniqueId,
    #[deref]
    #[deref_mut]
    receiver: UnboundedReceiver<T>,
    subscribers: Arc<DashMap<UniqueId, UnboundedSender<T>>>,
}

impl<T> Drop for Observer<T> {
    fn drop(&mut self) {
        // When the Topic is dropped, try to upgrade the weak reference to an Arc
        // and remove the corresponding subscriber from the HashMap.
        self.subscribers.remove(&self.id);
    }
}

impl<T> Default for Locations<T>
where
    T: PartialEq + Eq + Hash + Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Locations<T>
where
    T: PartialEq + Eq + Hash + Clone + Send + 'static,
{
    /// Creates a new, empty `Locations` instance.
    pub fn new() -> Self {
        Self {
            addresses: DashSet::new(),
            subscribers: Arc::new(DashMap::new()),
            id_generator: UniqueIdGenerator::new(),
        }
    }

    /// Inserts an address into the local set.
    /// If the address is new, it notifies all subscribers.
    /// Returns `true` if the address was newly inserted, `false` otherwise.
    pub fn insert(&self, address: T) -> bool {
        let is_new_item = self.addresses.insert(address.clone());
        if is_new_item {
            self.notify_all(address);
        }
        is_new_item
    }

    /// Removes an address from the local set.
    pub fn remove(&self, address: &T) -> bool {
        self.addresses.remove(address).is_some()
    }

    /// Subscribes to address changes.
    /// Returns a `Topic` handle which contains a receiver.
    /// The new subscriber will immediately receive all currently known addresses.
    pub fn subscribe(&self) -> Observer<T> {
        let (tx, rx) = mpsc::unbounded_channel(); // Channel capacity can be configured.

        // Send all existing addresses to the new subscriber.
        for address in self.addresses.iter() {
            _ = tx.send(address.clone());
        }

        let id = self.id_generator.generate();
        self.subscribers.insert(id, tx);

        Observer {
            id,
            receiver: rx,
            subscribers: self.subscribers.clone(),
        }
    }

    /// Notifies all subscribers of a new address.
    fn notify_all(&self, address: T) {
        // Retain only the subscribers that are still active.
        self.subscribers
            .retain(|_, subscriber| subscriber.send(address.clone()).is_ok());
    }
}

/// Represents a network endpoint with a bind URI and an endpoint address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// The URI to bind to.
    pub bind: BindUri,
    /// The address of the endpoint.
    pub addr: EndpointAddr,
}

impl Locations<Endpoint> {
    /// Returns a global, singleton instance of `Locations<Endpoint>`.
    /// This is useful for sharing local endpoint information across the application.
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL_LOCAL_ENDPOINTS: OnceLock<Arc<Locations<Endpoint>>> = OnceLock::new();
        GLOBAL_LOCAL_ENDPOINTS.get_or_init(|| Arc::new(Self::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[tokio::test]
    async fn test_locations_with_topic() {
        let locations = Locations::<String>::new();

        // 1. Insert an address.
        locations.insert("addr1".to_string());

        // 2. Subscribe and get a topic.
        let mut observer1 = locations.subscribe();
        // It should immediately receive the existing address.
        assert_eq!(observer1.recv().await.unwrap(), "addr1");

        // 3. Insert another address.
        locations.insert("addr2".to_string());
        // The first subscriber should receive it.
        assert_eq!(observer1.recv().await.unwrap(), "addr2");

        // 4. Create a second subscriber.
        let mut observer2 = locations.subscribe();
        // It should receive all current addresses.
        let mut received_addrs = HashSet::new();
        received_addrs.insert(observer2.recv().await.unwrap());
        received_addrs.insert(observer2.recv().await.unwrap());
        assert_eq!(
            received_addrs,
            ["addr1".to_string(), "addr2".to_string()]
                .into_iter()
                .collect()
        );

        // 5. Insert a third address, both subscribers should get it.
        locations.insert("addr3".to_string());
        assert_eq!(observer1.recv().await.unwrap(), "addr3");
        assert_eq!(observer2.recv().await.unwrap(), "addr3");

        // 6. Test auto-cleanup via Drop.
        {
            let num_subscribers = locations.subscribers.len();
            assert_eq!(num_subscribers, 2);
        }
        drop(observer1); // Drop the first topic.
        {
            // The subscriber should be removed.
            let num_subscribers = locations.subscribers.len();
            assert_eq!(num_subscribers, 1);
        }

        // 7. The remaining subscriber should still work.
        locations.insert("addr4".to_string());
        assert_eq!(observer2.recv().await.unwrap(), "addr4");

        // 8. Remove an address.
        assert!(locations.remove(&"addr1".to_string()));
        let mut observer3 = locations.subscribe();
        let mut received_addrs = HashSet::new();
        received_addrs.insert(observer3.recv().await.unwrap());
        received_addrs.insert(observer3.recv().await.unwrap());
        received_addrs.insert(observer3.recv().await.unwrap());
        assert_eq!(
            received_addrs,
            [
                "addr2".to_string(),
                "addr3".to_string(),
                "addr4".to_string()
            ]
            .into_iter()
            .collect()
        );
    }
}
