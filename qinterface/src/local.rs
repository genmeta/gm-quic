use std::{
    any::{Any, TypeId},
    sync::{Arc, OnceLock},
};

use dashmap::DashMap;
use derive_more::{Deref, DerefMut};
use qbase::{
    net::addr::BindUri,
    util::{UniqueId, UniqueIdGenerator},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

type Address = Arc<dyn Any + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddressEvent<A = Address> {
    Upsert(BindUri, A),
    Removed(BindUri, TypeId),
}

impl AddressEvent<Address> {
    pub fn downcast<A: Send + Sync + 'static>(self) -> Result<AddressEvent<Arc<A>>, Self> {
        match self {
            AddressEvent::Upsert(bind_uri, address) => match address.downcast::<A>() {
                Ok(address) => Ok(AddressEvent::Upsert(bind_uri, address)),
                Err(address) => Err(AddressEvent::Upsert(bind_uri, address)),
            },
            AddressEvent::Removed(bind_uri, type_id) => match TypeId::of::<A>() == type_id {
                true => Ok(AddressEvent::Removed(bind_uri, type_id)),
                false => Err(AddressEvent::Removed(bind_uri, type_id)),
            },
        }
    }
}

type Addresses = DashMap<BindUri, Arc<DashMap<TypeId, Address>>>;
type Subscribers = Arc<DashMap<UniqueId, UnboundedSender<AddressEvent>>>;

/// Manages a collection of local addresses and notifies subscribers of changes.
/// T is a generic type for the address, which must be comparable and cloneable.
pub struct Locations {
    /// A set of unique local addresses.
    addresses: Addresses,
    /// A map of subscribers, mapping a unique ID to a sender.
    subscribers: Subscribers,
    /// The next available ID for a new subscriber.
    id_generator: UniqueIdGenerator,
}

/// A handle to a subscription.
/// It allows receiving messages and automatically unsubscribes when dropped.
#[derive(Deref, DerefMut)]
pub struct Observer {
    id: UniqueId,
    #[deref]
    #[deref_mut]
    receiver: UnboundedReceiver<AddressEvent>,
    subscribers: Subscribers,
}

impl Drop for Observer {
    fn drop(&mut self) {
        // When the Topic is dropped, try to upgrade the weak reference to an Arc
        // and remove the corresponding subscriber from the HashMap.
        self.subscribers.remove(&self.id);
    }
}

impl Default for Locations {
    fn default() -> Self {
        Self::new()
    }
}

impl Locations {
    /// Creates a new, empty `Locations` instance.
    pub fn new() -> Self {
        Self {
            addresses: DashMap::new(),
            subscribers: Arc::new(DashMap::new()),
            id_generator: UniqueIdGenerator::new(),
        }
    }

    /// Inserts an address into the local set.
    /// If the address is new, it notifies all subscribers.
    /// Returns `true` if the address was newly inserted or changed, `false` otherwise.
    pub fn upsert<A: PartialEq<A> + Any + Send + Sync>(
        &self,
        bind_uri: &BindUri,
        address: A,
    ) -> bool {
        let map = self.addresses.entry(bind_uri.clone()).or_default();
        let entry = map.entry(TypeId::of::<A>());
        let is_new_item = match &entry {
            dashmap::Entry::Occupied(occupied_entry) => {
                let old_value = occupied_entry.get().downcast_ref::<A>().unwrap();
                old_value != &address
            }
            dashmap::Entry::Vacant(..) => true,
        };

        if is_new_item {
            let address = Arc::new(address) as Address;
            entry.insert(address.clone());
            self.notify_all(AddressEvent::Upsert(bind_uri.clone(), address));
        }
        is_new_item
    }

    /// Removes an address from the local set.
    pub fn remove<A: PartialEq<A> + 'static>(&self, bind_uri: &BindUri) -> bool {
        let dashmap::Entry::Occupied(map) = self.addresses.entry(bind_uri.clone()) else {
            return false;
        };

        let removed = map.get().remove(&TypeId::of::<A>()).is_some();
        if map.get().is_empty() {
            map.remove_entry();
        }

        if removed {
            self.notify_all(AddressEvent::Removed(bind_uri.clone(), TypeId::of::<A>()));
        }

        removed
    }

    pub fn remove_all(&self, bind_uri: &BindUri) -> bool {
        match self.addresses.remove(bind_uri) {
            Some((_bind_uri, map)) => {
                for type_id in map.iter().map(|entry| *entry.key()) {
                    self.notify_all(AddressEvent::Removed(bind_uri.clone(), type_id));
                }
                true
            }
            None => false,
        }
    }

    /// Subscribes to address changes.
    /// Returns a `Topic` handle which contains a receiver.
    /// The new subscriber will immediately receive all currently known addresses.
    pub fn subscribe(&self) -> Observer {
        let (tx, rx) = mpsc::unbounded_channel(); // Channel capacity can be configured.

        // Send all existing addresses to the new subscriber.
        for map in self.addresses.iter() {
            for address in map.value().iter() {
                _ = tx.send(AddressEvent::Upsert(
                    map.key().clone(),
                    address.value().clone(),
                ));
            }
        }

        let id = self.id_generator.generate();
        self.subscribers.insert(id, tx);

        Observer {
            id,
            receiver: rx,
            subscribers: self.subscribers.clone(),
        }
    }

    /// Notifies all subscribers of a new address event.
    fn notify_all(&self, event: AddressEvent) {
        // Retain only the subscribers that are still active.
        self.subscribers
            .retain(|_, subscriber| subscriber.send(event.clone()).is_ok());
    }

    /// Returns a global, singleton instance of `Locations<Endpoint>`.
    /// This is useful for sharing local endpoint information across the application.
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL_LOCAL_ENDPOINTS: OnceLock<Arc<Locations>> = OnceLock::new();
        GLOBAL_LOCAL_ENDPOINTS.get_or_init(|| Arc::new(Self::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use super::*;

    #[tokio::test]
    async fn test_locations_with_topic() {
        let locations = Locations::new();

        let ifaces = [
            "iface://v6.netdev1:0",
            "iface://v6.netdev2:0",
            "iface://v6.netdev3:0",
            "iface://v6.netdev4:0",
        ];

        // 1. Insert an address.
        locations.upsert(&ifaces[0].into(), "addr0");

        // 2. Subscribe and get a topic.
        let mut observer1 = locations.subscribe();
        // It should immediately receive the existing address.
        assert_eq!(
            observer1.recv().await.unwrap().downcast().unwrap(),
            AddressEvent::Upsert(ifaces[0].into(), Arc::new("addr0"))
        );

        // 3. Insert another address.
        locations.upsert(&ifaces[1].into(), "addr1");
        // The first subscriber should receive it.
        assert_eq!(
            observer1.recv().await.unwrap().downcast().unwrap(),
            AddressEvent::Upsert(ifaces[1].into(), Arc::new("addr1"))
        );

        // 4. Create a second subscriber.
        let mut observer2 = locations.subscribe();
        // It should receive all current addresses.
        let mut received_addrs = HashSet::new();
        received_addrs.insert(observer2.recv().await.unwrap().downcast().unwrap());
        received_addrs.insert(observer2.recv().await.unwrap().downcast().unwrap());
        assert_eq!(
            received_addrs,
            [
                AddressEvent::Upsert(ifaces[0].into(), Arc::new("addr0")),
                AddressEvent::Upsert(ifaces[1].into(), Arc::new("addr1"))
            ]
            .into_iter()
            .collect()
        );

        // 5. Insert a third address, both subscribers should get it.
        locations.upsert(&ifaces[2].into(), "addr2");
        assert_eq!(
            observer1.recv().await.unwrap().downcast().unwrap(),
            AddressEvent::Upsert(ifaces[2].into(), Arc::new("addr2"))
        );
        assert_eq!(
            observer2.recv().await.unwrap().downcast().unwrap(),
            AddressEvent::Upsert(ifaces[2].into(), Arc::new("addr2"))
        );

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
        locations.upsert(&ifaces[3].into(), "addr3");
        assert_eq!(
            observer2.recv().await.unwrap().downcast().unwrap(),
            AddressEvent::Upsert(ifaces[3].into(), Arc::new("addr3"))
        );

        // 8. Remove an address.
        assert!(locations.remove_all(&ifaces[0].into()));
        let mut observer3 = locations.subscribe();
        let mut received_addrs = HashSet::new();
        received_addrs.insert(observer3.recv().await.unwrap().downcast().unwrap());
        received_addrs.insert(observer3.recv().await.unwrap().downcast().unwrap());
        received_addrs.insert(observer3.recv().await.unwrap().downcast().unwrap());
        assert_eq!(
            received_addrs,
            [
                AddressEvent::Upsert(ifaces[1].into(), Arc::new("addr1")),
                AddressEvent::Upsert(ifaces[2].into(), Arc::new("addr2")),
                AddressEvent::Upsert(ifaces[3].into(), Arc::new("addr3"))
            ]
            .into_iter()
            .collect()
        );
    }
}
