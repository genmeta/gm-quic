use std::{
    fmt::Debug,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use tokio::sync::watch;
use tokio_util::task::AbortOnDropHandle;

use crate::{QuicIO, QuicIoExt, iface::RwInterface, route::Router};

pub struct InterfaceContext {
    iface: Weak<RwInterface>,
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
    pub fn new(rw_iface: Arc<RwInterface>, mut interfaces: watch::Receiver<()>) -> Self {
        let bind_uri = rw_iface.bind_uri();
        let iface = Arc::downgrade(&rw_iface);
        let task = AbortOnDropHandle::new(tokio::spawn({
            let rw_iface = iface.clone();
            let mut receive_task =
                ReceiveTask::Running(Box::pin(receive_and_deliver(rw_iface.clone())));
            async move {
                loop {
                    tokio::select! {
                        Ok(()) = interfaces.changed() => {
                            let Some(rw_iface) = rw_iface.upgrade() else { break };
                            // If the task is stopped, or the interface is not alive: rebind it, and restart receive task
                            if matches!(receive_task, ReceiveTask::Stopped)
                                || rw_iface.is_alive().await.is_err_and(|e| {
                                    tracing::warn!(%bind_uri, "Interface may not alive: {e}");
                                    e.is_recoverable()
                                })
                            {
                                tracing::info!(%bind_uri, "Rebinding interface");
                                _ = rw_iface.close().await;
                                rw_iface.rebind();
                                receive_task =
                                    ReceiveTask::Running(Box::pin(receive_and_deliver(Arc::downgrade(&rw_iface))));
                            }
                        }
                        result = &mut receive_task => {
                            match result {
                                Ok(()) => tracing::warn!(%bind_uri, "Receive task completed due to interface freed"),
                                Err(e) => tracing::error!(%bind_uri, "Receive task failed with error: {e}"),
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

    pub fn iface(&self) -> &Weak<RwInterface> {
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
