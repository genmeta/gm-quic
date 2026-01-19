use std::{
    any::Any,
    fmt::Debug,
    future::Future,
    io, mem,
    ops::{Deref, DerefMut},
    sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use dashmap::{DashMap, Entry};
use futures::FutureExt;
use qbase::{
    net::{addr::RealAddr, route},
    util::{UniqueId, UniqueIdGenerator},
};
use tokio::sync::SetOnce;

use crate::{
    Interface, InterfaceExt,
    factory::ProductInterface,
    logical::{
        BindInterface, BindUri, QuicInterface, RebindedError, WeakInterface,
        component::{Component, Components},
    },
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
    interfaces: DashMap<BindUri, InterfaceEntry>,
    bind_id_generator: UniqueIdGenerator,
}

#[derive(Debug)]
struct InterfaceEntry {
    weak_iface: WeakInterface,
    dropped: Arc<SetOnce<()>>,
}

impl InterfaceEntry {
    fn is_dropped(&self) -> bool {
        self.dropped.get().is_some()
    }

    fn dropped(&self) -> impl Future<Output = ()> + use<> {
        let dropped = self.dropped.clone();
        async move {
            dropped.wait().await;
        }
    }
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

    fn new_binding(
        self: &Arc<Self>,
        entry: Entry<BindUri, InterfaceEntry>,
        factory: Arc<dyn ProductInterface>,
    ) -> BindInterface {
        let context = InterfaceContext {
            factory: factory.clone(),
            binding: RwLock::new(Binding {
                io: factory.bind(entry.key().clone()),
                id: self.bind_id_generator.generate(),
            }),
            dropped: Arc::new(SetOnce::new()),
            ifaces: self.clone(),
            components: RwLock::new(Components::default()),
        };
        let dropped = context.dropped.clone();
        let iface = BindInterface::new(context);
        let weak_iface = iface.downgrade();

        entry.insert(InterfaceEntry {
            weak_iface,
            dropped,
        });

        iface
    }

    pub async fn bind(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductInterface>,
    ) -> BindInterface {
        loop {
            match self.interfaces.entry(bind_uri.clone()) {
                // (1) new binding: context closed but not yet removed
                Entry::Occupied(entry) if entry.get().is_dropped() => {
                    return self.new_binding(Entry::Occupied(entry), factory);
                }
                // (2) new binding: no existing context
                Entry::Vacant(entry) => {
                    return self.new_binding(Entry::Vacant(entry), factory);
                }
                // try reuse existing binding
                Entry::Occupied(entry) => match entry.get().weak_iface.upgrade() {
                    // (3) reuse existing binding
                    Ok(iface) => return iface.clone(),
                    // (4) no existing binding: close context and retry
                    Err(..) => {
                        let dropped_future = entry.get().dropped();
                        drop(entry);
                        dropped_future.await;
                    }
                },
            }
        }
    }

    #[inline]
    pub fn borrow(&self, bind_uri: &BindUri) -> Option<QuicInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|entry| Some(entry.weak_iface.upgrade().ok()?.borrow()))
    }

    #[inline]
    pub fn get(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|entry| entry.weak_iface.upgrade().ok())
    }

    #[inline]
    pub fn unbind(self: &Arc<Self>, bind_uri: BindUri) -> impl Future<Output = ()> + Send + use<> {
        let Entry::Occupied(entry) = self.interfaces.entry(bind_uri) else {
            return std::future::ready(()).right_future();
        };

        match entry.get().weak_iface.upgrade() {
            Ok(bind_iface) => {
                let drop_future = bind_iface.context.as_ref().drop();
                spawn_on_drop::SpawnOnDrop::new(Box::pin(drop_future)).left_future()
            }
            // Dropping by InterfaceContext::Drop
            Err(..) => entry.get().dropped().right_future(),
        }
        .left_future()
    }
}

mod spawn_on_drop {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, ready},
    };

    pub(crate) struct SpawnOnDrop<F: Future<Output: Send + 'static> + Unpin + Send + 'static> {
        pub(crate) future: Option<F>,
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> SpawnOnDrop<F> {
        pub(crate) fn new(future: F) -> Self {
            Self {
                future: Some(future),
            }
        }
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> Future for SpawnOnDrop<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.as_mut().get_mut().future.as_mut() {
                Some(future) => {
                    let output = ready!(Pin::new(future).poll(cx));
                    self.future = None;
                    Poll::Ready(output)
                }
                None => panic!("future polled after completion"),
            }
        }
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> Drop for SpawnOnDrop<F> {
        fn drop(&mut self) {
            if let Some(future) = self.future.take() {
                tokio::spawn(future);
            }
        }
    }
}

struct Binding {
    io: Box<dyn Interface>,
    id: UniqueId,
}

pub struct InterfaceContext {
    factory: Arc<dyn ProductInterface>,
    binding: RwLock<Binding>,
    // shared with [InterfaceEntry]
    dropped: Arc<SetOnce<()>>,
    ifaces: Arc<QuicInterfaces>,
    components: RwLock<Components>,
}

impl InterfaceContext {
    fn binding(&self) -> RwLockReadGuard<'_, Binding> {
        self.binding.read().expect("QuicIO binding poisoned")
    }

    fn binding_mut(&self) -> RwLockWriteGuard<'_, Binding> {
        self.binding.write().expect("QuicIO binding poisoned")
    }

    pub fn bind_id(&self) -> UniqueId {
        self.binding().id
    }

    fn components(&self) -> RwLockReadGuard<'_, Components> {
        self.components.read().expect("Components poisoned")
    }

    fn components_mut(&self) -> RwLockWriteGuard<'_, Components> {
        self.components.write().expect("Components poisoned")
    }

    pub fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        let (mut binding, components) = (self.binding_mut(), self.components());
        for (.., component) in &components.map {
            ready!(component.poll_shutdown(cx));
        }
        binding.io.poll_close(cx)
    }
}

impl Debug for InterfaceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("bind_uri", &self.binding().io.bind_uri())
            .finish()
    }
}

impl BindInterface {
    pub fn poll_rebind(&self, cx: &mut Context<'_>) -> Poll<()> {
        let context = self.context.as_ref();

        // 降级binding锁
        // A: rebind, reinit
        // B:                rebind, reinit

        // 释放binding锁
        // A: lock(B), lock(C), rebind, release(B), reinit, release(C)
        // B:                                      lock(B),             lock(C), rebind, reinit

        // hold read lock to prevent subsequent rebind, avoid compoents seeing inconsistent state
        let (new_bind_id, components) = {
            let mut binding = context.binding_mut();
            let components = context.components();

            ready!(context.factory.poll_rebind(cx, &mut binding.io));
            binding.id = context.ifaces.bind_id_generator.generate();
            (binding.id, components)
        };

        let quic_iface = QuicInterface {
            bind_id: new_bind_id,
            bind_iface: self.clone(),
        };
        for (.., component) in &components.map {
            component.reinit(&quic_iface);
        }
        Poll::Ready(())
    }

    pub async fn rebind2(&self) {}

    pub fn insert_component_with<C: Component>(&self, init: impl FnOnce(&QuicInterface) -> C) {
        self.with_components_mut(|components, quic_iface| {
            components.init_with(|| init(quic_iface));
        });
    }

    pub fn with_components<T>(&self, f: impl FnOnce(&Components, &QuicInterface) -> T) -> T {
        let context = self.context.as_ref();
        let (binding, components) = (context.binding(), context.components());

        let quic_iface = QuicInterface {
            bind_id: binding.id,
            bind_iface: self.clone(),
        };
        f(components.deref(), &quic_iface)
    }

    pub fn with_components_mut<T>(
        &self,
        f: impl FnOnce(&mut Components, &QuicInterface) -> T,
    ) -> T {
        let context = self.context.as_ref();
        let (binding, mut components) = (context.binding(), context.components_mut());

        let quic_iface = QuicInterface {
            bind_id: binding.id,
            bind_iface: self.clone(),
        };
        f(components.deref_mut(), &quic_iface)
    }
}

impl QuicInterface {
    pub fn with_component<C: Component, T>(
        &self,
        f: impl FnOnce(&C) -> T,
    ) -> Result<Option<T>, RebindedError> {
        let context = self.bind_iface.context.as_ref();
        let (binding, components) = (context.binding(), context.components());

        if self.bind_id != binding.id {
            return Err(RebindedError);
        }

        Ok(components.with(f))
    }

    pub fn get_component<C: Component + Clone>(&self) -> Result<Option<C>, RebindedError> {
        self.with_component(C::clone)
    }
}

impl Interface for InterfaceContext {
    fn bind_uri(&self) -> BindUri {
        self.binding().io.bind_uri()
    }

    fn real_addr(&self) -> io::Result<RealAddr> {
        self.binding().io.real_addr()
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        self.binding().io.max_segment_size()
    }

    fn max_segments(&self) -> io::Result<usize> {
        self.binding().io.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: route::PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.binding().io.poll_send(cx, pkts, hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [route::PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.binding().io.poll_recv(cx, pkts, hdrs)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        InterfaceContext::poll_close(self, cx)
    }
}

mod dropping_io {
    use thiserror::Error;

    use super::*;

    #[derive(Debug, Clone, Error)]
    #[error("QuicIO is dropping and cannot be used anymore, you should never see this error")]
    pub(crate) struct DroppingIO {
        pub(crate) bind_uri: BindUri,
    }

    impl DroppingIO {
        pub(crate) fn to_io_error(&self) -> io::Error {
            io::Error::new(io::ErrorKind::NotConnected, self.clone())
        }
    }

    impl From<DroppingIO> for io::Error {
        fn from(error: DroppingIO) -> Self {
            error.to_io_error()
        }
    }

    impl Interface for DroppingIO {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            Err(self.to_io_error())
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Err(self.to_io_error())
        }

        fn max_segments(&self) -> io::Result<usize> {
            Err(self.to_io_error())
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: route::PacketHeader,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.to_io_error()))
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [route::PacketHeader],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.to_io_error()))
        }

        fn poll_close(&mut self, _: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

impl Binding {
    pub fn is_dropping(&self) -> bool {
        (self.io.as_ref() as &dyn Any).is::<dropping_io::DroppingIO>()
    }

    pub fn take_io(&mut self) -> Option<Box<dyn Interface>> {
        if self.is_dropping() {
            return None;
        }
        let bind_uri = self.io.bind_uri();
        let dropping_io = Box::new(dropping_io::DroppingIO { bind_uri });
        Some(mem::replace(&mut self.io, dropping_io))
    }
}

impl InterfaceContext {
    fn drop(&self) -> impl Future<Output = ()> + Send + use<> {
        let dropped = self.dropped.clone();
        let Some(mut io) = self.binding_mut().take_io() else {
            return std::future::ready(()).right_future();
        };

        let ifaces = self.ifaces.clone();
        let bind_uri = io.bind_uri();
        let components = mem::take(self.components_mut().deref_mut());

        async move {
            for (_, component) in components.map {
                _ = core::future::poll_fn(|cx| component.poll_shutdown(cx)).await;
            }
            _ = io.close().await;

            dropped.set(()).expect("duplicated drop, this is a bug");
            tokio::task::spawn_blocking(move || {
                ifaces
                    .interfaces
                    .remove_if(&bind_uri, |_, entry| entry.is_dropped());
            });
        }
        .left_future()
    }
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        if !{ self.binding().is_dropping() } {
            tokio::spawn(InterfaceContext::drop(self));
        }
    }
}
