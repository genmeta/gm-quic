use std::{
    fmt::Debug,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use qbase::net::addr::BindUri;
use tokio::sync::watch;
use tokio_util::task::AbortOnDropHandle;

use crate::{QuicIoExt, factory::ProductQuicIO, iface::RwInterface, route::Router};

pub struct InterfaceContext {
    iface: Arc<RwInterface>,
    _task: AbortOnDropHandle<()>,
}

impl Debug for InterfaceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceContext")
            .field("iface", &"..")
            .field("task", &"..")
            .finish()
    }
}

impl InterfaceContext {
    pub fn new(
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
        mut interfaces: watch::Receiver<()>,
    ) -> Self {
        let iface = Arc::new(RwInterface::new(
            bind_uri.clone(),
            factory.bind(bind_uri.clone()),
        ));

        let task = AbortOnDropHandle::new(tokio::spawn({
            let rw_iface = iface.clone();
            let mut receive_task =
                ReceiveTask::Running(tokio::spawn(receive_and_deliver(rw_iface.clone())));
            async move {
                loop {
                    tokio::select! {
                        Ok(()) = interfaces.changed() => {
                            // If the task is stopped, or the interface is not alive: rebind it, and restart receive task
                            if matches!(receive_task, ReceiveTask::Stopped) || matches!(rw_iface.is_alive().await, Some(false)){
                                tracing::info!(%bind_uri, "Rebinding interface");
                                _ = rw_iface.close().await;
                                rw_iface.update_with(|| factory.bind(bind_uri.clone()));
                                receive_task = ReceiveTask::Running(tokio::spawn(receive_and_deliver(rw_iface.clone())));
                            }
                        }
                        result = &mut receive_task => {
                            if let Ok(Err(io_error)) = result {
                                tracing::error!(%bind_uri, "Receive task failed with errror: {io_error:?}");
                            }
                            // Task completed (likely due to error), mark as stopped and wait for interface change
                            receive_task = ReceiveTask::Stopped;
                        }
                    }
                }
            }
        }));

        Self { iface, _task: task }
    }

    pub fn iface(&self) -> &Arc<RwInterface> {
        &self.iface
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

async fn receive_and_deliver(iface: Arc<RwInterface>) -> io::Result<()> {
    let (mut bufs, mut hdrs) = (vec![], vec![]);
    loop {
        for (pkt, way) in iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await? {
            Router::global().deliver(pkt, way).await;
        }
    }
}
