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
        monitor::InterfacesMonitor,
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
        let context = InterfaceContext::new(iface.clone(), InterfacesMonitor::global().subscribe());
        entry.insert(context);
        iface.publish_endpoint_addr();

        iface.binding()
    }

    #[inline]
    pub fn get(&self, bind_uri: &BindUri) -> Option<QuicInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|ctx| ctx.iface().upgrade()?.borrow().ok())
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
                Locations::global().remove(&self.bind_uri);
                entry.remove();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io,
        ops::DerefMut,
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{addr::RealAddr, route::PacketHeader};
    use tokio::task::JoinHandle;

    use super::*;
    use crate::QuicIO;

    struct TestQuicIO {
        bind_uri: BindUri,
        some_task: Mutex<JoinHandle<()>>,
    }

    static BIND_TIMES: AtomicUsize = AtomicUsize::new(0);
    static SOME_RESOURCES: OnceLock<Arc<()>> = OnceLock::new();

    impl TestQuicIO {
        fn bind(bind_uri: BindUri) -> io::Result<Self> {
            let global_state = SOME_RESOURCES.get_or_init(Arc::default);
            if Arc::strong_count(global_state) > 1 {
                panic!("Last TestQuicIO instance must release resources before binding again");
            }

            let state = global_state.clone();
            let task = tokio::spawn(async move {
                // Simulate some async work
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                drop(state);
            });

            BIND_TIMES.fetch_add(1, Ordering::SeqCst);

            Ok(Self {
                bind_uri,
                some_task: Mutex::new(task),
            })
        }
    }

    impl QuicIO for TestQuicIO {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn max_segments(&self) -> io::Result<usize> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [PacketHeader],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
            ready!(Pin::new(&mut self.some_task.lock().unwrap().deref_mut()).poll(cx)).unwrap();
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn async_close() {
        let _quic_interface =
            QuicInterfaces::global().bind(BindUri::from("127.0.0.1:0"), Arc::new(TestQuicIO::bind));
        InterfacesMonitor::global().on_interface_changed();

        InterfacesMonitor::global()
            .subscribe()
            .changed()
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(BIND_TIMES.load(Ordering::SeqCst), 2);
    }
}
