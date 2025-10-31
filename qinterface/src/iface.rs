use std::{
    any::Any,
    fmt::Debug,
    io,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    net::{
        addr::{BindUri, RealAddr},
        route::PacketHeader,
    },
    util::UniqueId,
};

use crate::{QuicIO, factory::ProductQuicIO, local::Locations};

pub mod alive;
mod collection;
pub mod physical;
// handy（qudp）是可选的
pub mod handy;

pub use collection::{QuicInterfaces, QuicIoClosing};

struct Interface {
    bind_uri: BindUri,
    factory: Arc<dyn ProductQuicIO>,
    io: io::Result<Box<dyn QuicIO>>,
    /// Unique ID generator from [`QuicInterfaces`]
    ifaces: Arc<QuicInterfaces>,
    locations: Arc<Locations>,
    /// Unique identifier for this binding
    bind_id: UniqueId,
}

impl Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("bind_uri", &self.bind_uri)
            .field("factory", &"...")
            .field("io", &"...")
            .field("ifaces", &"...")
            .field("bind_id", &self.bind_id)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Interface {bind_uri} is not available")]
pub struct InterfaceUnavailable {
    bind_uri: BindUri,
    #[source]
    error: io::Error,
}

impl Interface {
    fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        match self.io.as_ref() {
            Ok(iface) => Ok(f(iface.as_ref())),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                InterfaceUnavailable {
                    bind_uri: self.bind_uri.clone(),
                    error: io::Error::new(e.kind(), e.to_string()),
                },
            )),
        }
    }
}

#[derive(Debug)]
struct RwInterface(RwLock<Interface>);

impl From<Interface> for RwInterface {
    fn from(value: Interface) -> Self {
        Self(RwLock::new(value))
    }
}

impl RwInterface {
    fn read(&self) -> RwLockReadGuard<'_, Interface> {
        self.0.read().unwrap()
    }

    fn write(&self) -> RwLockWriteGuard<'_, Interface> {
        self.0.write().unwrap()
    }

    fn publish_address(self: &Arc<Self>) {
        if self.bind_uri().is_templorary() {
            return;
        }

        let iface = self.clone();
        // tokio::spawn(async move {
        let Ok(real_addr) = iface.real_addr() else {
            return;
        };
        iface
            .read()
            .locations
            .upsert(iface.bind_uri(), Arc::new(real_addr));
        // });
    }

    // fn rebind(self: &Arc<Self>) {
    //     self.write().rebind();
    //     self.publish_address();
    // }

    // pub fn restart(&self) -> io::Result<()> {
    //     self.read().borrow(|iface| iface.restart())?
    // }
}

impl QuicIO for RwInterface {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.read().bind_uri.clone()
    }

    #[inline]
    fn real_addr(&self) -> io::Result<RealAddr> {
        self.read().borrow(|iface| iface.real_addr())?
    }

    #[inline]
    fn max_segment_size(&self) -> io::Result<usize> {
        self.read().borrow(|iface| iface.max_segment_size())?
    }

    #[inline]
    fn max_segments(&self) -> io::Result<usize> {
        self.read().borrow(|iface| iface.max_segments())?
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.read().borrow(|iface| iface.poll_send(cx, pkts, hdr))?
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.read()
            .borrow(|iface| iface.poll_recv(cx, pkts, hdrs))?
    }

    #[inline]
    fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.read().borrow(|iface| iface.poll_close(cx))?
    }

    #[inline]
    fn restart(&self) -> io::Result<()> {
        self.read().borrow(|iface| iface.restart())?
    }
}

impl RwInterface {
    fn binding(self: &Arc<Self>) -> BindInterface {
        BindInterface {
            iface: self.clone(),
        }
    }

    fn borrow(self: &Arc<Self>) -> io::Result<QuicInterface> {
        let iface = self.read();
        iface.borrow(|_| QuicInterface {
            bind_id: iface.bind_id,
            iface: self.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BindInterface {
    iface: Arc<RwInterface>,
}

impl BindInterface {
    #[inline]
    pub fn bind_uri(&self) -> BindUri {
        self.iface.bind_uri()
    }

    #[inline]
    pub fn borrow(&self) -> io::Result<QuicInterface> {
        self.iface.borrow()
    }
}

#[derive(Debug, Clone)]
pub struct QuicInterface {
    bind_id: UniqueId,
    iface: Arc<RwInterface>,
}

impl QuicInterface {
    pub fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        if self.iface.read().bind_id != self.bind_id {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_uri()),
            ));
        }
        self.iface.read().borrow(f)
    }
}

impl QuicIO for QuicInterface {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.iface.bind_uri().clone()
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
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.borrow(|iface| iface.poll_recv(cx, pkts, hdrs))?
    }

    #[inline]
    fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.borrow(|iface| iface.poll_close(cx))?
    }

    #[inline]
    fn restart(&self) -> io::Result<()> {
        self.borrow(|iface| iface.restart())?
    }
}
