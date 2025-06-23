use std::{
    io,
    sync::{Arc, RwLock, RwLockReadGuard, Weak},
    task::{Context, Poll},
};

use qbase::net::{
    address::{BindAddr, RealAddr},
    route::PacketHeader,
};

use super::QuicInterfaces;
use crate::QuicIO;

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
    fn bind_addr(&self) -> BindAddr {
        self.borrow().bind_addr()
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
    bind_addr: BindAddr,
    iface: Weak<RwInterface>,
    ifaces: Arc<QuicInterfaces>,
}

impl QuicInterface {
    pub(super) fn new(
        bind_addr: BindAddr,
        iface: Weak<RwInterface>,
        ifaces: Arc<QuicInterfaces>,
    ) -> Self {
        Self {
            bind_addr,
            iface,
            ifaces,
        }
    }

    fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        let unavailable = || {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_addr),
            )
        };
        let muteable_iface = self.iface.upgrade().ok_or_else(unavailable)?;
        return Ok(f(muteable_iface.borrow().as_ref()));
    }
}

impl Drop for QuicInterface {
    fn drop(&mut self) {
        self.ifaces
            .interfaces
            .remove_if(&self.bind_addr, |_, (iface_ctx, _)| {
                Weak::ptr_eq(&Arc::downgrade(&iface_ctx.iface), &self.iface)
            });
    }
}

impl QuicIO for QuicInterface {
    #[inline]
    fn bind_addr(&self) -> BindAddr {
        self.bind_addr.clone()
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
