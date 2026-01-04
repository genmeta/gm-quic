use std::{
    fmt::Debug,
    future::Future,
    io, mem,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, OnceLock, Weak},
    task::{Context, Poll, ready},
};

use dashmap::{DashMap, Entry};
use futures::FutureExt;
use qbase::{net::addr::BindUri, util::UniqueIdGenerator};
use thiserror::Error;
use tokio::sync::SetOnce;
use tokio_util::task::AbortOnDropHandle;

use super::RwInterface;
use crate::{
    QuicIO, QuicIoExt,
    factory::ProductQuicIO,
    iface::{
        BindInterface, Interface, QuicInterface,
        physical::{InterfaceEventReceiver, PhysicalInterfaces},
    },
    local::Locations,
    route::Router,
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
        let context = InterfaceContext::new(iface.clone(), events);

        entry.insert(context);
        iface.publish_address();

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
            .and_then(|ctx| ctx.reuse()?.borrow().ok())
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

        SpawnOnDrop::new(Box::pin(async move {
            close_future.await;
            this.interfaces
                .remove_if(&bind_uri, |_, ctx| ctx.is_closed());
        }))
        .left_future()
    }
}

#[derive(Debug, Error)]
#[error("QuicIO bound to the interface is closing")]
pub struct QuicIoClosing;

impl From<QuicIoClosing> for io::Error {
    fn from(error: QuicIoClosing) -> Self {
        io::Error::new(io::ErrorKind::NotConnected, error)
    }
}

/// Interface lifetime:
impl Interface {
    fn new(
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
        ifaces: Arc<QuicInterfaces>,
    ) -> Self {
        let io = factory.bind(bind_uri.clone());
        match &io {
            Ok(_) => {
                tracing::debug!(target: "interface", %bind_uri, "Bind interface successfully")
            }
            Err(error) => {
                tracing::debug!(target: "interface", %bind_uri, ?error, "Failed to bind interface")
            }
        }
        Self {
            io,
            bind_id: ifaces.bind_id_generator.generate(),
            bind_uri,
            factory,
            ifaces,
            locations: Locations::global().clone(),
        }
    }

    fn rebind(&mut self) {
        self.io = self.factory.bind(self.bind_uri.clone());
        self.bind_id = self.ifaces.bind_id_generator.generate();
        match self.io.as_ref() {
            Ok(_) => {
                tracing::debug!(target: "interface", bind_uri=%self.bind_uri, "Rebind interface successfully")
            }
            Err(error) => {
                tracing::debug!(target: "interface", bind_uri=%self.bind_uri, ?error, "Failed to rebind interface")
            }
        }
    }

    pub fn close(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        let io = mem::replace(&mut self.io, Err(QuicIoClosing.into()));
        let bind_uri = self.bind_uri.clone();
        let locations = self.locations.clone();
        io.ok().map(|io| async move {
            _ = io.close().await;
            locations.close(bind_uri);
        })
    }
}

impl RwInterface {
    pub async fn rebind(self: &Arc<Self>) {
        if let Some(close) = { self.write().close() } {
            close.await
        };
        self.write().rebind();
        self.publish_address();
    }
}

#[derive(Debug)]
struct InterfaceContext {
    iface: Weak<RwInterface>,
    task: Option<AbortOnDropHandle<()>>,
    closed: Arc<SetOnce<()>>,
}

impl InterfaceContext {
    fn new(rw_iface: Arc<RwInterface>, mut events: InterfaceEventReceiver) -> Self {
        let bind_uri = rw_iface.bind_uri();
        let device = bind_uri
            .as_iface_bind_uri()
            .map(|(_, device, _)| device.to_owned());
        let iface = Arc::downgrade(&rw_iface);
        let task = AbortOnDropHandle::new(tokio::spawn({
            let rw_iface = iface.clone();
            // todo: remove box pin?
            let mut receive_task =
                ReceiveTask::Running(Box::pin(receive_and_deliver(rw_iface.clone())));
            async move {
                loop {
                    tokio::select! {
                        biased;
                        result = &mut receive_task => {
                            match result {
                                Ok(()) => tracing::debug!(target: "interface", %bind_uri, "Receive task completed due to interface freed"),
                                Err(e) => tracing::debug!(target: "interface", %bind_uri, "Receive task failed with error: {e}"),
                            }
                            // Task completed (likely due to error), mark as stopped and wait for interface change
                            receive_task = ReceiveTask::Stopped;
                        }
                        Some(event) = events.recv() => {
                            // skip events not related to this interface
                            if Some(event.device()) != device.as_deref() {
                                continue;
                            }
                            let Some(rw_iface) = rw_iface.upgrade() else { break };
                            // If the task is stopped, or the interface is not alive: rebind it, and restart receive task
                            if matches!(receive_task, ReceiveTask::Stopped)
                                || rw_iface.is_alive().await.is_err_and(|e| {
                                    tracing::debug!(target: "interface", %bind_uri, "Interface may not alive: {e}");
                                    e.is_recoverable()
                                })
                            {
                                tracing::debug!(target: "interface", %bind_uri, "Rebinding interface");
                                rw_iface.rebind().await;
                                receive_task =
                                    ReceiveTask::Running(Box::pin(receive_and_deliver(Arc::downgrade(&rw_iface))));
                            }
                        }
                    }
                }
            }
        }));

        Self {
            iface,
            task: Some(task),
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

            if let Some(close_quicio) = { iface.write().close() } {
                close_quicio.await;
            }

            _ = closed.set(());
        }
        .left_future()
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        // drop order: Arc<RwInterface>::drop -> RwInterface::drop -> Interface::drop
        // when Interface is dropped: original Arc<RwInterface> strong count is 0

        let close_quicio = self.close();

        if let Some(mut context) = self.ifaces.interfaces.get_mut(&self.bind_uri)
            && context.iface.upgrade().is_none()
            // when iface.upgrade().is_none(), rebind will not happen anymore
            && let Some(mut task) = context.task.take()
        {
            let closed = context.closed.clone();
            tokio::spawn(async move {
                task.abort();
                _ = (&mut task).await;
                if let Some(close_quicio) = close_quicio {
                    close_quicio.await;
                }
                _ = closed.set(());
            });
        }
    }
}

enum ReceiveTask<F> {
    Running(F),
    Stopped,
}

impl<F: Future + Unpin> Future for ReceiveTask<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let ReceiveTask::Running(future) = self.deref_mut() {
            return Pin::new(future).poll(cx);
        }

        Poll::Pending
    }
}

async fn receive_and_deliver(iface: Weak<RwInterface>) -> io::Result<()> {
    let (mut bufs, mut hdrs) = (vec![], vec![]);
    loop {
        let pkts = match iface.upgrade() {
            Some(iface) => iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await?,
            None => return Ok(()),
        };
        for (pkt, way) in pkts {
            Router::global().deliver(pkt, way).await;
        }
    }
}

struct SpawnOnDrop<F: Future<Output: Send + 'static> + Unpin + Send + 'static> {
    future: Option<F>,
}

impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> SpawnOnDrop<F> {
    fn new(future: F) -> Self {
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
            None => panic!("polled after completion"),
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
