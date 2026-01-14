use std::{
    any::{Any, TypeId},
    collections::HashMap,
    fmt::Debug,
    hash::{BuildHasherDefault, Hasher},
    task::{Context, Poll},
};

use futures::ready;

mod rebind_on_network_changed;
pub use rebind_on_network_changed::RebindOnNetworkChanged;
// TODO: rewrite to component
mod receive_and_deliver_quic;
pub use receive_and_deliver_quic::Task;

use crate::logical::QuicInterface;

pub trait Component: Any + Debug + Send + Sync {
    /// Initialize the component when the QuicIO is bound.
    fn init(&mut self, quic_iface: &QuicInterface);

    /// Gracefully shutdown the component when QuicIO is closing.
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<()>;

    /// Re-initialize the component after the QuicIO has been rebound
    ///
    /// Normally, this method first shuts down the component,
    /// then re-initializes it with the new QuicIO.
    ///
    /// Implementation may override this method for optimization.
    fn poll_reinit(&mut self, cx: &mut Context<'_>, quic_iface: &QuicInterface) -> Poll<()> {
        ready!(self.poll_shutdown(cx));
        self.init(quic_iface);
        Poll::Ready(())
    }
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

pub(super) type ComponentsMap = HashMap<TypeId, Box<dyn Component>, BuildHasherDefault<IdHasher>>;
