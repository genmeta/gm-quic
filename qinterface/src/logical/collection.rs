use std::{
    fmt::Debug,
    future::Future,
    io, mem,
    pin::pin,
    sync::{Arc, OnceLock, Weak},
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
use tokio_util::task::AbortOnDropHandle;

use crate::{
    QuicIO, QuicIoExt,
    factory::ProductQuicIO,
    local::Locations,
    logical::{BindInterface, BindUri, QuicInterface, rw_iface::RwInterface},
    physical::{InterfaceEventReceiver, PhysicalInterfaces},
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
    // mdns_queue
    bind_id_generator: UniqueIdGenerator,
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
        entry: Entry<BindUri, InterfaceContext>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> BindInterface {
        let iface = Interface::new(bind_uri.clone(), factory, self.clone());
        let iface = Arc::new(RwInterface::from(iface));

        let events = PhysicalInterfaces::global().event_receiver();
        entry.insert(InterfaceContext::new(iface.clone(), events));

        iface.binding()
    }

    pub async fn bind(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
    ) -> BindInterface {
        loop {
            match self.interfaces.entry(bind_uri.clone()) {
                // (1) new binding: context closed but not yet removed
                Entry::Occupied(entry) if entry.get().is_closed() => {
                    return self.new_binding(Entry::Occupied(entry), bind_uri, factory);
                }
                // (2) new binding: no existing context
                Entry::Vacant(entry) => {
                    return self.new_binding(Entry::Vacant(entry), bind_uri, factory);
                }
                // try reuse existing binding
                Entry::Occupied(mut entry) => match entry.get().reuse() {
                    // (3) reuse existing binding
                    Some(iface) => return iface.binding(),
                    // (4) no existing binding: close context and retry
                    None => {
                        let close_future = entry.get_mut().close();
                        drop(entry);
                        close_future.await;
                    }
                },
            }
        }
    }

    #[inline]
    pub fn borrow(&self, bind_uri: &BindUri) -> Option<QuicInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|ctx| Some(ctx.reuse()?.borrow()))
    }

    #[inline]
    pub fn get(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|ctx| Some(ctx.reuse()?.binding()))
    }

    #[inline]
    pub fn unbind(self: &Arc<Self>, bind_uri: BindUri) -> impl Future<Output = ()> + Send + use<> {
        let Some(mut context) = self.interfaces.get_mut(&bind_uri) else {
            return std::future::ready(()).right_future();
        };

        let this = self.clone();
        let close_future = context.close();

        spawn_on_drop::SpawnOnDrop::new(Box::pin(async move {
            close_future.await;
            this.interfaces
                .remove_if(&bind_uri, |_, ctx| ctx.is_closed());
        }))
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

mod wakers {
    use std::{
        mem,
        sync::{Arc, Mutex, MutexGuard},
        task::{Wake, Waker},
    };

    use smallvec::SmallVec;

    #[derive(Debug)]
    pub struct Wakers {
        wakers: Mutex<SmallVec<[Waker; 4]>>,
    }

    impl Wake for Wakers {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            for waker in { mem::replace(&mut *self.lock(), SmallVec::new_const()) }.drain(..) {
                waker.wake();
            }
        }
    }

    impl Wakers {
        pub const fn new() -> Self {
            Self {
                wakers: Mutex::new(SmallVec::new_const()),
            }
        }

        fn lock(&self) -> MutexGuard<'_, SmallVec<[Waker; 4]>> {
            self.wakers.lock().expect("Wakers mutex poisoned")
        }

        pub fn register(&self, waker: &Waker) {
            let mut wakers = self.lock();
            if !wakers.iter().any(|w| w.will_wake(waker)) {
                wakers.push(waker.clone());
            }
        }

        pub fn to_waker(self: &Arc<Self>) -> Waker {
            Waker::from(self.clone())
        }

        pub fn combine(self: &Arc<Self>, other: &Waker) -> Waker {
            self.register(other);
            self.to_waker()
        }
    }
}

pub struct Interface {
    factory: Arc<dyn ProductQuicIO>,
    io: Box<dyn QuicIO>,
    send_wakers: Arc<wakers::Wakers>,
    recv_wakers: Arc<wakers::Wakers>,
    close_wakers: Arc<wakers::Wakers>,
    rebind_wakers: Arc<wakers::Wakers>,
    /// Unique ID generator from [`QuicInterfaces`]
    ifaces: Arc<QuicInterfaces>,
    locations: Arc<Locations>,
    /// Unique identifier for this binding
    bind_id: UniqueId,
}

impl Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("bind_uri", &self.io.bind_uri())
            .finish()
    }
}

impl Interface {
    fn new(
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
        ifaces: Arc<QuicInterfaces>,
    ) -> Self {
        let iface = Self {
            io: factory.bind(bind_uri.clone()),
            send_wakers: Arc::new(wakers::Wakers::new()),
            recv_wakers: Arc::new(wakers::Wakers::new()),
            close_wakers: Arc::new(wakers::Wakers::new()),
            rebind_wakers: Arc::new(wakers::Wakers::new()),
            bind_id: ifaces.bind_id_generator.generate(),
            factory,
            ifaces,
            locations: Locations::global().clone(),
        };
        iface.publish_address();
        iface
    }

    fn publish_address(&self) {
        let bind_uri = self.io.bind_uri();
        if bind_uri.is_temporary() {
            return;
        }
        let Ok(real_addr) = self.io.real_addr() else {
            return;
        };
        self.locations.upsert(bind_uri, Arc::new(real_addr));
    }

    pub fn poll_rebind(&mut self, cx: &mut Context) -> Poll<()> {
        let waker = self.rebind_wakers.combine(cx.waker());
        let cx = &mut Context::from_waker(&waker);
        ready!(self.factory.poll_rebind(cx, &mut self.io));
        self.bind_id = self.ifaces.bind_id_generator.generate();
        self.locations.close(self.io.bind_uri());
        self.publish_address();
        Poll::Ready(())
    }

    pub fn bind_id(&self) -> UniqueId {
        self.bind_id
    }
}

impl QuicIO for Interface {
    fn bind_uri(&self) -> BindUri {
        self.io.bind_uri()
    }

    fn real_addr(&self) -> io::Result<RealAddr> {
        self.io.real_addr()
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        self.io.max_segment_size()
    }

    fn max_segments(&self) -> io::Result<usize> {
        self.io.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: route::PacketHeader,
    ) -> Poll<io::Result<usize>> {
        let waker = self.send_wakers.combine(cx.waker());
        self.io
            .poll_send(&mut Context::from_waker(&waker), pkts, hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [route::PacketHeader],
    ) -> Poll<io::Result<usize>> {
        let waker = self.recv_wakers.combine(cx.waker());
        self.io
            .poll_recv(&mut Context::from_waker(&waker), pkts, hdrs)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let waker = self.close_wakers.combine(cx.waker());
        let result = ready!(self.io.poll_close(&mut Context::from_waker(&waker)));
        self.locations.close(self.io.bind_uri());
        Poll::Ready(result)
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

    impl QuicIO for DroppingIO {
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

impl Drop for Interface {
    fn drop(&mut self) {
        // drop order: Arc<RwInterface>::drop -> RwInterface::drop -> Interface::drop
        // when Interface is dropped: original Arc<RwInterface> strong count is 0

        let mut io = {
            let bind_uri = self.io.bind_uri();
            mem::replace(&mut self.io, Box::new(dropping_io::DroppingIO { bind_uri }))
        };

        if let Some(mut context) = self.ifaces.interfaces.get_mut(&self.io.bind_uri())
            && context.iface.upgrade().is_none()
            // when iface.upgrade().is_none(), rebind will not happen anymore
            && let Some(mut task) = context.task.take()
        {
            let closed = context.closed.clone();
            tokio::spawn(async move {
                task.abort();
                _ = (&mut task).await;
                _ = io.close().await;
                _ = closed.set(());
            });
        }
    }
}

#[derive(Debug)]
pub struct InterfaceContext {
    iface: Weak<RwInterface>,
    task: Option<AbortOnDropHandle<()>>,
    closed: Arc<SetOnce<()>>,
}

impl InterfaceContext {
    pub fn new(rw_iface: Arc<RwInterface>, mut events: InterfaceEventReceiver) -> Self {
        let bind_uri = rw_iface.bind_uri();
        let device = bind_uri
            .as_iface_bind_uri()
            .map(|(_, device, _)| device.to_owned());
        let iface = Arc::downgrade(&rw_iface);

        let rw_iface = iface.clone();
        let task = async move {
            let mut receive_task = pin!(receive::Task::new(rw_iface.clone()));
            loop {
                tokio::select! {
                    // Wake-ups from receiving data packets are always far more numerous than those from interface events.
                    // `biased;` mark can improve performance.
                    biased;
                    result = &mut receive_task => {
                        match result {
                            Ok(()) => tracing::debug!(target: "interface", %bind_uri, "Receive task completed, maybe interface closed?"),
                            // TODO: use snafu::Report for better error reporting
                            Err(error) => tracing::debug!(target: "interface", %bind_uri, ?error, "Receive task failed with error"),
                        }
                    }
                    Some(event) = events.recv() => {
                        // skip events not related to this interface
                        if Some(event.device()) != device.as_deref() {
                            continue;
                        }
                        let Some(rw_iface) = rw_iface.upgrade() else { break };
                        // If the task is stopped, or the interface is not alive: rebind it, and restart receive task
                        if !receive_task.is_running() || rw_iface.borrow().is_alive().await.is_err_and(|error| {
                                tracing::debug!(target: "interface", %bind_uri, ?error, "Interface may not alive");
                                error.is_recoverable()
                            })
                        {
                            tracing::debug!(target: "interface", %bind_uri, "Rebinding interface");
                            rw_iface.rebind().await;
                            receive_task.as_mut().set(receive::Task::new(Arc::downgrade(&rw_iface)));
                        }
                    }
                }
            }
        };

        Self {
            iface,
            task: Some(AbortOnDropHandle::new(tokio::spawn(task))),
            closed: Arc::new(SetOnce::new()),
        }
    }

    // closed                <: cannot be reused
    // automatically closing <: cannot be reused
    pub fn reuse(&self) -> Option<Arc<RwInterface>> {
        (!self.is_closed()).then(|| self.iface.upgrade())?
    }

    pub fn closed(&self) -> impl Future<Output = ()> + Send + use<> {
        let closed = self.closed.clone();
        async move { _ = closed.wait().await }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.get().is_some()
    }

    /// Close the interface context and underlying interface
    pub fn close(&mut self) -> impl Future<Output = ()> + Send + use<> {
        let Some(iface) = self.iface.upgrade() else {
            return self.closed().right_future();
        };
        let Some(mut task) = self.task.take() else {
            return self.closed().right_future();
        };

        let closed = self.closed.clone();
        async move {
            task.abort();
            _ = (&mut task).await;
            _ = iface.close().await;
            _ = closed.set(());
        }
        .left_future()
    }
}

mod receive {
    use std::{
        future::Future,
        io,
        pin::Pin,
        sync::Weak,
        task::{Context, Poll, ready},
    };

    use crate::{QuicIoExt, logical::rw_iface::RwInterface, route::Router};

    pin_project_lite::pin_project! {
        #[project = TaskProj]
        pub enum Task<F> {
            Running { #[pin] future: F },
            Stopped,
        }
    }

    async fn receive_and_deliver(iface: Weak<RwInterface>) -> io::Result<()> {
        let (mut bufs, mut hdrs) = (vec![], vec![]);
        loop {
            let pkts = match iface.upgrade().map(|iface| iface.borrow()) {
                Some(mut iface) => iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await?,
                None => return Ok(()),
            };
            for (pkt, way) in pkts {
                Router::global().deliver(pkt, way).await;
            }
        }
    }

    impl Task<()> {
        pub fn new(iface: Weak<RwInterface>) -> Task<impl Future<Output = io::Result<()>> + Send> {
            Task::Running {
                future: receive_and_deliver(iface),
            }
        }
    }

    impl<F> Task<F> {
        pub fn is_running(&self) -> bool {
            matches!(self, Task::Running { .. })
        }
    }

    impl<F: Future> Future for Task<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.as_mut().project() {
                TaskProj::Running { future } => {
                    // Task completed (likely due to error), mark as stopped and wait for interface change
                    let output = ready!(future.poll(cx));
                    self.set(Task::Stopped);
                    Poll::Ready(output)
                }
                TaskProj::Stopped => Poll::Pending,
            }
        }
    }
}
