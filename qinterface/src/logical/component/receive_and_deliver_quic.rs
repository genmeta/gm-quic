use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

#[derive(Debug, Clone)]
pub struct RouterComponent {
    router: Arc<Router>,
}

impl RouterComponent {
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }

    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }
}

impl Component for RouterComponent {
    fn reinit(&self, _quic_iface: &QuicInterface) {}

    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        _ = cx;
        Poll::Ready(())
    }
}

use crate::{
    InterfaceExt,
    logical::{QuicInterface, RebindedError, UnbondedError, WeakInterface, component::Component},
    route::Router,
};

pin_project_lite::pin_project! {
    #[project = TaskProj]
    pub enum Task<F> {
        Running { #[pin] future: F },
        Stopped,
    }
}

async fn receive_and_deliver(weak_iface: WeakInterface) -> io::Result<()> {
    let (mut bufs, mut hdrs) = (vec![], vec![]);
    loop {
        let pkts = match weak_iface.borrow() {
            Ok(iface) => match iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await {
                Err(error) if RebindedError::is_source_of(&error) => continue,
                Err(error) if UnbondedError::is_source_of(&error) => return Ok(()),
                result => result?,
            },
            Err(..) => return Ok(()),
        };
        for (pkt, way) in pkts {
            Router::global().deliver(pkt, way).await;
        }
    }
}

impl Task<()> {
    pub fn new(iface: WeakInterface) -> Task<impl Future<Output = io::Result<()>> + Send> {
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
