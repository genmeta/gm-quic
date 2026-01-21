use std::{
    any::{Any, TypeId},
    collections::{HashMap, hash_map},
    fmt::Debug,
    hash::{BuildHasherDefault, Hasher},
    task::{Context, Poll, ready},
};

mod rebind_on_network_changed;
pub use rebind_on_network_changed::RebindOnNetworkChangedComponent;
// TODO: rewrite to component
mod receive_and_deliver_quic;
pub use receive_and_deliver_quic::{QuicRouterComponent, Task};

use crate::logical::Interface;

pub trait Component: Any + Debug + Send + Sync {
    /// Gracefully shutdown the component when QuicIO is closing.
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()>;

    /// Re-initialize the component after the QuicIO has been rebound
    ///
    /// Normally, this method first shuts down the component,
    /// then re-initializes it with the new QuicIO.
    ///
    /// Implementation may override this method for optimization.
    fn reinit(&self, iface: &Interface);
}

// With TypeIds as keys, there's no need to hash them. They are already hashes
// themselves, coming from the compiler. The IdHasher just holds the u64 of
// the TypeId, and then returns it, instead of doing any bit fiddling.
#[derive(Default)]
pub(super) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Default)]
pub struct Components {
    pub(super) map: HashMap<TypeId, Box<dyn Component>, BuildHasherDefault<IdHasher>>,
}

impl Components {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<C: Component>(&self) -> Option<&C> {
        self.map
            .get(&TypeId::of::<C>())
            .and_then(|c| (c.as_ref() as &dyn Any).downcast_ref())
    }

    pub fn with<C: Component, T>(&self, f: impl FnOnce(&C) -> T) -> Option<T> {
        self.get::<C>().map(f)
    }

    pub fn init_with<C: Component>(&mut self, init: impl FnOnce() -> C) -> &mut C {
        let ref_mut = self
            .map
            .entry(TypeId::of::<C>())
            .or_insert_with(|| Box::new(init()));
        (ref_mut.as_mut() as &mut dyn Any).downcast_mut().unwrap()
    }

    pub fn poll_remove<C>(&mut self, cx: &mut Context<'_>) -> Poll<()>
    where
        C: Component,
    {
        let hash_map::Entry::Occupied(entry) = self.map.entry(TypeId::of::<C>()) else {
            return Poll::Ready(());
        };

        ready!(entry.get().poll_shutdown(cx));
        entry.remove();

        Poll::Ready(())
    }
}
