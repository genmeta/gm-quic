mod monitor;

use std::{
    collections::VecDeque,
    io,
    ops::Deref,
    sync::{Arc, Weak},
};

use dashmap::DashMap;
use futures::Stream;
use qbase::net::address::BindAddr;
use tokio::task::JoinHandle;

use crate::{
    QuicInterface,
    factory::ProductQuicInterface,
    router2::{Received, Router},
};

pub struct QuicInterfaces {
    interfaces: DashMap<BindAddr, InterfaceContext>,
}

impl QuicInterfaces {
    pub fn new() -> Arc<Self> {
        let this = Arc::new(Self {
            interfaces: DashMap::new(),
        });

        tokio::spawn({
            let this = this.clone();
            async move {
                let monitor = netwatch::netmon::Monitor::new().await;
            }
        });
        todo!()
    }

    pub fn insert<F>(
        self: &Arc<Self>,
        bind_addr: BindAddr,
        factory: Arc<dyn ProductQuicInterface>,
    ) -> io::Result<Arc<BorrowedInterface>> {
        let entry = self
            .interfaces
            .entry(bind_addr.clone())
            .and_modify(|ctx| ctx.task.abort());

        let iface: Arc<dyn QuicInterface> = Arc::from(factory.bind(bind_addr.clone())?);
        let borrowed_iface = Arc::new(BorrowedInterface {
            interfaces: self.clone(),
            interface: iface.clone(),
        });

        let task = tokio::spawn(Router::global().deliver_all(Box::pin(
            BorrowedInterface::pkts_stream(Arc::downgrade(&borrowed_iface)),
        )));

        entry.insert(InterfaceContext {
            iface,
            factory,
            task,
        });

        Ok(borrowed_iface)
    }
}

pub struct InterfaceContext {
    // rc = 2: in InterfaceContext and in BorrowedInterface
    iface: Arc<dyn QuicInterface>,
    factory: Arc<dyn ProductQuicInterface>,
    task: JoinHandle<()>,
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        // When the context is dropped, we abort the task that is managing this interface.
        self.task.abort();
    }
}

pub struct BorrowedInterface {
    interfaces: Arc<QuicInterfaces>,
    interface: Arc<dyn QuicInterface>,
}

impl BorrowedInterface {
    fn pkts_stream(weak: Weak<Self>) -> impl Stream<Item = Received> + Send {
        futures::stream::unfold(
            (weak, vec![], vec![], VecDeque::new()),
            |(iface, mut bufs, mut hdrs, mut pkts)| async move {
                loop {
                    if let Some(rcvd) = pkts.pop_front() {
                        return Some((rcvd, (iface, bufs, hdrs, pkts)));
                    }
                    let weak = iface.upgrade()?;
                    pkts.extend(weak.recvpkts(&mut bufs, &mut hdrs).await.ok()?);
                }
            },
        )
    }
}

impl Deref for BorrowedInterface {
    type Target = dyn QuicInterface;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.interface.as_ref()
    }
}

impl Drop for BorrowedInterface {
    fn drop(&mut self) {
        self.interfaces
            .interfaces
            .remove_if(&self.interface.bind_addr(), |_, context| {
                Arc::ptr_eq(&context.iface, &self.interface)
            });
    }
}
