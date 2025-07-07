use std::{
    io,
    sync::{Arc, RwLock, RwLockReadGuard, Weak},
    task::{Context, Poll},
};

use derive_more::Deref;
use qbase::net::{
    addr::{BindUri, RealAddr},
    route::PacketHeader,
};
use tokio::task::JoinHandle;

use crate::{QuicIO, factory::ProductQuicIO, route::Router};

pub mod global;
pub mod monitor;
// handy（qudp）是可选的
pub mod handy;

pub use global::QuicInterfaces;

pub struct RwInterface(RwLock<Box<dyn QuicIO>>);

impl From<Box<dyn QuicIO>> for RwInterface {
    fn from(iface: Box<dyn QuicIO>) -> Self {
        Self(RwLock::new(iface))
    }
}

impl RwInterface {
    pub fn borrow(&self) -> RwLockReadGuard<'_, Box<dyn QuicIO>> {
        self.0.read().unwrap()
    }

    pub fn update(&self, iface: Box<dyn QuicIO>) {
        let mut guard = self.0.write().unwrap();
        *guard = iface;
    }
}

impl QuicIO for RwInterface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.borrow().bind_uri()
    }

    #[inline]
    fn real_addr(&self) -> io::Result<RealAddr> {
        self.borrow().real_addr()
    }

    #[inline]
    fn max_segment_size(&self) -> io::Result<usize> {
        self.borrow().max_segment_size()
    }

    #[inline]
    fn max_segments(&self) -> io::Result<usize> {
        self.borrow().max_segments()
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.borrow().poll_send(cx, pkts, hdr)
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [bytes::BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.borrow().poll_recv(cx, pkts, hdrs)
    }
}

pub struct QuicInterface {
    bind_uri: BindUri,
    iface: Weak<RwInterface>,
    ifaces: Arc<QuicInterfaces>,
}

impl QuicInterface {
    pub(super) fn new(
        bind_uri: BindUri,
        iface: Weak<RwInterface>,
        ifaces: Arc<QuicInterfaces>,
    ) -> Self {
        Self {
            bind_uri,
            iface,
            ifaces,
        }
    }

    fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        let unavailable = || {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_uri),
            )
        };
        let muteable_iface = self.iface.upgrade().ok_or_else(unavailable)?;
        return Ok(f(muteable_iface.borrow().as_ref()));
    }
}

impl QuicIO for QuicInterface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    #[inline]
    fn real_addr(&self) -> io::Result<RealAddr> {
        self.borrow(|iface| iface.real_addr())?
    }

    #[inline]
    fn max_segment_size(&self) -> io::Result<usize> {
        self.borrow(|iface| iface.max_segment_size())?
    }

    #[inline]
    fn max_segments(&self) -> io::Result<usize> {
        self.borrow(|iface| iface.max_segments())?
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.borrow(|iface| iface.poll_send(cx, pkts, hdr))?
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [bytes::BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.borrow(|iface| iface.poll_recv(cx, pkts, hdrs))?
    }
}

#[derive(Deref)]
pub struct InterfaceContext {
    bind_uri: BindUri,
    /// factory to rebind the interface
    ///
    /// factory may be changed when manually rebind
    factory: Arc<dyn ProductQuicIO>,
    /// the actual interface being used
    ///
    /// the actual interface may be changed when rebind
    #[deref]
    iface: Arc<RwInterface>,
    /// recv task handle
    task: JoinHandle<()>,
}

impl InterfaceContext {
    pub fn new(bind_uri: BindUri, factory: Arc<dyn ProductQuicIO>) -> io::Result<Self> {
        let iface = factory.bind(bind_uri.clone())?;
        let iface = Arc::new(RwInterface::from(iface));

        let task = tokio::spawn({
            let iface = Arc::downgrade(&iface);
            let (mut bufs, mut hdrs) = (vec![], vec![]);
            async move {
                loop {
                    let pkts = {
                        let Some(iface) = iface.upgrade().map(|io| io as Arc<dyn QuicIO>) else {
                            return;
                        };
                        let Ok(pkts) = iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await else {
                            return;
                        };
                        pkts
                    };
                    for (pkt, way) in pkts {
                        Router::global().deliver(pkt, way).await;
                    }
                }
            }
        });

        Ok(InterfaceContext {
            bind_uri,
            factory,
            iface,
            task,
        })
    }

    pub fn rebind(&mut self, bind_uri: BindUri) -> io::Result<()> {
        self.iface.update(self.factory.bind(bind_uri.clone())?);

        // abort the current task
        self.task.abort();
        // then spawn the new one
        self.task = tokio::spawn({
            let iface = Arc::downgrade(&self.iface);
            let (mut bufs, mut hdrs) = (vec![], vec![]);
            async move {
                loop {
                    let pkts = {
                        let Some(iface) = iface.upgrade().map(|io| io as Arc<dyn QuicIO>) else {
                            return;
                        };
                        let Ok(pkts) = iface.recvmpkt(bufs.as_mut(), hdrs.as_mut()).await else {
                            return;
                        };
                        pkts
                    };
                    for (pkt, way) in pkts {
                        Router::global().deliver(pkt, way).await;
                    }
                }
            }
        });

        Ok(())
    }
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        // When the context is dropped, we abort the task that is managing this interface.
        self.task.abort();
    }
}
