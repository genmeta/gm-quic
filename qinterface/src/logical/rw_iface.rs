use std::{
    fmt::Debug,
    io,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    net::{addr::RealAddr, route::PacketHeader},
    util::UniqueId,
};
use supply::{Want, prelude::l};
use thiserror::Error;

use crate::{
    QuicIO,
    logical::{BindUri, collection::Interface},
};

#[derive(Debug)]
pub struct RwInterface(RwLock<Interface>);

impl From<Interface> for RwInterface {
    fn from(value: Interface) -> Self {
        Self(RwLock::new(value))
    }
}

impl RwInterface {
    pub fn bind_uri(&self) -> BindUri {
        self.read().bind_uri()
    }

    fn read(&self) -> RwLockReadGuard<'_, Interface> {
        self.0.read().expect("Interface operation poisoned")
    }

    fn write(&self) -> RwLockWriteGuard<'_, Interface> {
        self.0.write().expect("Interface operation poisoned")
    }

    pub fn close(&self) -> impl Future<Output = io::Result<()>> + Send {
        core::future::poll_fn(|cx| self.write().poll_close(cx))
    }

    pub fn rebind(&self) -> impl Future<Output = ()> + Send {
        core::future::poll_fn(|cx| self.write().poll_rebind(cx))
    }

    pub fn binding(self: &Arc<Self>) -> BindInterface {
        BindInterface {
            iface: self.clone(),
        }
    }

    pub fn borrow(self: &Arc<Self>) -> QuicInterface {
        QuicInterface {
            bind_id: self.read().bind_id(),
            rw_iface: self.clone(),
        }
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
    pub fn borrow(&self) -> QuicInterface {
        self.iface.borrow()
    }
}

#[derive(Debug, Clone)]
pub struct QuicInterface {
    bind_id: UniqueId,
    rw_iface: Arc<RwInterface>,
}

#[derive(Debug, Error)]
#[error("Interface has been rebinded")]
pub struct RebindedError(());

impl From<RebindedError> for io::Error {
    fn from(value: RebindedError) -> Self {
        io::Error::new(io::ErrorKind::ConnectionReset, value)
    }
}

impl QuicInterface {
    pub fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        if self.rw_iface.read().bind_id() != self.bind_id {
            return Err(RebindedError(()).into());
        }
        Ok(f(self.rw_iface.read().deref()))
    }

    pub fn borrow_mut<T>(&self, f: impl FnOnce(&mut dyn QuicIO) -> T) -> io::Result<T> {
        if self.rw_iface.read().bind_id() != self.bind_id {
            return Err(RebindedError(()).into());
        }
        Ok(f(self.rw_iface.write().deref_mut()))
    }
}

impl QuicIO for QuicInterface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.rw_iface.bind_uri()
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
    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.borrow_mut(|iface| iface.poll_close(cx))?
    }

    #[inline]
    fn provide(&self, want: &mut dyn Want<l![]>) {
        _ = self.borrow(|iface| iface.provide(want))
    }
}
