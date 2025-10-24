use std::{
    io,
    sync::{Arc, OnceLock},
};

use dashmap::{DashMap, Entry};
use qbase::{net::addr::BindUri, util::UniqueIdGenerator};

use super::RwInterface;
use crate::{
    factory::ProductQuicIO,
    iface::{
        BindInterface, Interface, QuicInterface, context::InterfaceContext,
        physical::PhysicalInterfaces,
    },
    local::Locations,
};

/// Global [`QuicIO`] manager that manages the lifecycle of all interfaces and automatically rebinds [`QuicIO`] when network changes occur.
///
/// Calling the [`QuicInterfaces::bind`] method with a [`BindUri`] returns a [`BindInterface`], primarily used for listening on addresses.
/// As long as [`BindInterface`] instances exist, the corresponding [`QuicIO`] for that [`BindUri`] won't be automatically released.
///
/// For actual data transmission, you need [`QuicInterface`], which can be obtained via [`QuicInterfaces::get`] or [`BindInterface::borrow`].
/// Like [`BindInterface`], it keeps the [`QuicIO`] alive, but with one key difference: once a rebind occurs,
/// any previous [`QuicInterface`] for that [`BindUri`] becomes invalid, and attempting to send or receive packets
/// will result in [`io::ErrorKind::NotConnected`] errors.
///
/// [`QuicIO`]: crate::QuicIO
/// [`io::ErrorKind::NotConnected`]: std::io::ErrorKind::NotConnected
#[derive(Default, Debug)]
pub struct QuicInterfaces {
    interfaces: DashMap<BindUri, InterfaceContext>,
    pub(super) bind_id_generator: UniqueIdGenerator,
}

impl QuicInterfaces {
    #[inline]
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: OnceLock<Arc<QuicInterfaces>> = OnceLock::new();
        GLOBAL.get_or_init(QuicInterfaces::new)
    }

    #[inline]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn bind(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> BindInterface {
        let entry = self.interfaces.entry(bind_uri.clone());
        if let Entry::Occupied(entry) = &entry {
            if let Some(iface) = entry.get().iface().upgrade() {
                return iface.binding();
            }
        }

        let iface = Arc::new(RwInterface::new(bind_uri, factory, self.clone()));
        let context =
            InterfaceContext::new(iface.clone(), PhysicalInterfaces::global().event_receiver());
        entry.insert(context);
        iface.publish_address();

        iface.binding()
    }

    #[inline]
    pub fn borrow(&self, bind_uri: &BindUri) -> Option<QuicInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|ctx| ctx.iface().upgrade()?.borrow().ok())
    }

    #[inline]
    pub fn get(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|ctx| Some(ctx.iface().upgrade()?.binding()))
    }

    #[inline]
    pub fn remove(&self, bind_uri: &BindUri) {
        self.interfaces.remove(bind_uri);
    }

    #[inline]
    pub fn clear(&self) {
        // clear map & close interfaces
        self.interfaces.retain(|_bind_uri, iface| {
            if let Some(iface) = iface.iface().upgrade() {
                iface.write().io = Err(io::ErrorKind::NotConnected.into());
            }
            false
        });
    }
}

impl Interface {
    pub(super) fn close(&mut self) {
        self.io = Err(io::ErrorKind::NotConnected.into());
        if let Entry::Occupied(entry) = self.ifaces.interfaces.entry(self.bind_uri.clone()) {
            if entry.get().iface().upgrade().is_none() {
                // NOTE: QuicInterfaces and Locations must be kept in sync.
                Locations::global().remove_all(&self.bind_uri);
                entry.remove();
            }
        }
    }
}
