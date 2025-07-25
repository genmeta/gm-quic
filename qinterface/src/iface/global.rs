use std::{
    io,
    sync::{Arc, OnceLock, Weak},
};

use dashmap::{DashMap, Entry};
use qbase::net::addr::BindUri;

use crate::{
    factory::ProductQuicIO,
    iface::{QuicInterface, context::InterfaceContext, monitor::InterfacesMonitor},
};

#[derive(Default, Debug)]
pub struct QuicInterfaces {
    interfaces: DashMap<BindUri, (InterfaceContext, Weak<QuicInterface>)>,
}

impl QuicInterfaces {
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: OnceLock<Arc<QuicInterfaces>> = OnceLock::new();
        GLOBAL.get_or_init(QuicInterfaces::new)
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> io::Result<Arc<QuicInterface>> {
        match self.interfaces.entry(bind_uri.clone()) {
            dashmap::Entry::Occupied(..) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Interface already exists for {bind_uri}"),
            )),
            dashmap::Entry::Vacant(entry) => {
                let interfaces = InterfacesMonitor::global().subscribe();
                let iface_ctx = InterfaceContext::new(bind_uri.clone(), factory, interfaces);
                let iface = Arc::new(QuicInterface::new(
                    bind_uri.clone(),
                    Arc::downgrade(iface_ctx.iface()),
                    self.clone(),
                ));

                entry.insert((iface_ctx, Arc::downgrade(&iface)));
                Ok(iface)
            }
        }
    }

    pub fn get(&self, bind_uri: BindUri) -> Option<Arc<QuicInterface>> {
        match self.interfaces.entry(bind_uri) {
            Entry::Occupied(entry) => match entry.get().1.upgrade() {
                Some(iface) => Some(iface),
                None => {
                    entry.remove();
                    None
                }
            },
            Entry::Vacant(..) => None,
        }
    }

    pub fn get_or_insert(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> Arc<QuicInterface> {
        let entry = self.interfaces.entry(bind_uri.clone());

        if let Entry::Occupied(entry) = &entry {
            if let Some(iface) = entry.get().1.upgrade() {
                return iface;
            }
        }

        let interfaces = InterfacesMonitor::global().subscribe();
        let iface_ctx = InterfaceContext::new(bind_uri.clone(), factory, interfaces);
        let iface = Arc::new(QuicInterface::new(
            bind_uri.clone(),
            Arc::downgrade(iface_ctx.iface()),
            self.clone(),
        ));

        entry.insert((iface_ctx, Arc::downgrade(&iface)));
        iface
    }

    pub fn remove(&self, bind_uri: BindUri) {
        self.interfaces.remove(&bind_uri);
    }
}

impl Drop for QuicInterface {
    fn drop(&mut self) {
        self.ifaces
            .interfaces
            .remove_if(&self.bind_uri, |_, (iface_ctx, _)| {
                Weak::ptr_eq(&Arc::downgrade(iface_ctx.iface()), &self.iface)
            });
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
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
        let _quic_interface = QuicInterfaces::global()
            .insert(BindUri::from("127.0.0.1:0"), Arc::new(TestQuicIO::bind))
            .unwrap();
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
