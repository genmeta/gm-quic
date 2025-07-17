use std::{
    fmt::Debug,
    io,
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard, Weak},
    task::{Context, Poll},
};

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

struct RwInterface {
    bind_uri: BindUri,
    quic_io: RwLock<io::Result<Box<dyn QuicIO>>>,
}

struct RwInterfaceGuard<'a>(RwLockReadGuard<'a, io::Result<Box<dyn QuicIO>>>);

impl Deref for RwInterfaceGuard<'_> {
    type Target = Box<dyn QuicIO>;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("Interface has been checked as available")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Interface {bind_uri} is unavailable: {error}")]
struct InterfaceUnavailable {
    bind_uri: BindUri,
    #[source]
    error: io::Error,
}

impl RwInterface {
    fn borrow(&self) -> io::Result<RwInterfaceGuard<'_>> {
        let quic_io_guard = self.quic_io.read().unwrap();
        match quic_io_guard.as_ref() {
            Ok(..) => Ok(RwInterfaceGuard(quic_io_guard)),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                InterfaceUnavailable {
                    bind_uri: self.bind_uri.clone(),
                    error: io::Error::new(e.kind(), e.to_string()),
                },
            )),
        }
    }

    fn new(bind_uri: BindUri, bind_result: io::Result<Box<dyn QuicIO>>) -> Self {
        if let Err(error) = &bind_result {
            tracing::warn!("Failed to bind interface {bind_uri}: {error}",);
        }
        Self {
            bind_uri,
            quic_io: RwLock::new(bind_result),
        }
    }

    fn update_with(&self, try_bind: impl FnOnce() -> io::Result<Box<dyn QuicIO>>) {
        let mut quic_io_guard = self.quic_io.write().unwrap();
        *quic_io_guard = Err(io::ErrorKind::NotConnected.into()); // Drop the old quic_io
        *quic_io_guard = try_bind();
        if let Err(error) = quic_io_guard.as_ref() {
            tracing::warn!("Failed to update interface {}: {error}", self.bind_uri);
        }
    }
}

impl QuicIO for RwInterface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    #[inline]
    fn real_addr(&self) -> io::Result<RealAddr> {
        self.borrow()?.real_addr()
    }

    #[inline]
    fn max_segment_size(&self) -> io::Result<usize> {
        self.borrow()?.max_segment_size()
    }

    #[inline]
    fn max_segments(&self) -> io::Result<usize> {
        self.borrow()?.max_segments()
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.borrow()?.poll_send(cx, pkts, hdr)
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [bytes::BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.borrow()?.poll_recv(cx, pkts, hdrs)
    }
}

#[derive(Debug)]
pub struct QuicInterface {
    bind_uri: BindUri,
    iface: Weak<RwInterface>,
    ifaces: Arc<QuicInterfaces>,
}

impl QuicInterface {
    fn new(bind_uri: BindUri, iface: Weak<RwInterface>, ifaces: Arc<QuicInterfaces>) -> Self {
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
        return Ok(f(muteable_iface.borrow()?.as_ref()));
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

struct InterfaceContext {
    bind_uri: BindUri,
    /// factory to rebind the interface
    ///
    /// factory may be changed when manually rebind
    factory: Arc<dyn ProductQuicIO>,
    /// the actual interface being used
    ///
    /// the actual interface may be changed when rebind
    iface: Arc<RwInterface>,
    /// recv task handle
    task: JoinHandle<()>,
}

impl Debug for InterfaceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceContext")
            .field("bind_uri", &self.bind_uri)
            .field("factory", &"..")
            .field("iface", &"..")
            .field("task", &"..")
            .finish()
    }
}

impl InterfaceContext {
    pub fn new(bind_uri: BindUri, factory: Arc<dyn ProductQuicIO>) -> Self {
        let iface = Arc::new(RwInterface::new(
            bind_uri.clone(),
            factory.bind(bind_uri.clone()),
        ));

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

        InterfaceContext {
            bind_uri,
            factory,
            iface,
            task,
        }
    }

    pub fn rebind(&mut self, bind_uri: BindUri) -> io::Result<()> {
        self.iface
            .update_with(|| self.factory.bind(bind_uri.clone()));

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
