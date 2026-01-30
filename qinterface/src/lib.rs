pub mod bind_uri;
pub mod component;
pub mod device;
pub mod io;
pub mod manager;

use std::{
    error::Error,
    fmt::Debug,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    net::{addr::BoundAddr, route::PacketHeader},
    util::UniqueId,
};
use thiserror::Error;

use crate::{
    bind_uri::BindUri,
    io::{IO, RefIO},
    manager::InterfaceContext,
};

#[derive(Debug, Clone)]
pub struct BindInterface {
    context: Arc<InterfaceContext>,
}

impl BindInterface {
    pub(crate) fn new(iface: InterfaceContext) -> Self {
        Self {
            context: Arc::new(iface),
        }
    }

    pub fn bind_uri(&self) -> BindUri {
        self.context.bind_uri()
    }

    pub fn close(&self) -> impl Future<Output = std::io::Result<()>> + Send {
        core::future::poll_fn(|cx| self.context.poll_close(cx))
    }

    pub fn rebind(&self) -> impl Future<Output = ()> + Send {
        core::future::poll_fn(|cx| self.poll_rebind(cx))
    }

    #[inline]
    pub fn borrow(&self) -> Interface {
        Interface {
            bind_id: self.context.bind_id(),
            bind_iface: self.clone(),
        }
    }

    #[inline]
    pub fn downgrade(&self) -> WeakBindInterface {
        WeakBindInterface {
            context: Arc::downgrade(&self.context),
        }
    }

    #[inline]
    pub fn borrow_weak(&self) -> WeakInterface {
        self.borrow().downgrade()
    }
}

#[derive(Debug, Clone)]
pub struct Interface {
    bind_id: UniqueId,
    bind_iface: BindInterface,
}

#[derive(Debug, Error)]
#[error("Interface has been rebinded")]
pub struct RebindedError;

impl RebindedError {
    pub fn is_source_of(mut error: &(dyn Error + 'static)) -> bool {
        loop {
            if error.is::<Self>() {
                return true;
            }
            match error.source() {
                Some(source) => error = source,
                None => return false,
            }
        }
    }
}

impl From<RebindedError> for std::io::Error {
    fn from(value: RebindedError) -> Self {
        std::io::Error::new(std::io::ErrorKind::ConnectionReset, value)
    }
}

impl Interface {
    #[inline]
    fn with_io<T>(&self, f: impl FnOnce(&dyn IO) -> T) -> std::io::Result<T> {
        self.bind_iface
            .context
            .with_bind_io(self.bind_id, f)
            .map_err(Into::into)
    }

    #[inline]
    pub fn bind_interface(&self) -> &BindInterface {
        &self.bind_iface
    }

    #[inline]
    pub fn downgrade(&self) -> WeakInterface {
        WeakInterface {
            bind_uri: self.bind_iface.bind_uri(),
            bind_id: self.bind_id,
            weak_iface: self.bind_iface.downgrade(),
        }
    }

    pub fn same_io(&self, other: &Interface) -> bool {
        self.bind_id == other.bind_id
            && Arc::ptr_eq(&self.bind_iface.context, &other.bind_iface.context)
    }
}

impl RefIO for Interface {
    type Interface = Self;

    #[inline]
    fn iface(&self) -> &Self::Interface {
        self
    }

    fn same_io(&self, other: &Self) -> bool {
        self.same_io(other)
    }
}

impl IO for Interface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.bind_iface.bind_uri()
    }

    #[inline]
    fn bound_addr(&self) -> std::io::Result<BoundAddr> {
        self.with_io(|io| io.bound_addr())?
    }

    #[inline]
    fn max_segment_size(&self) -> std::io::Result<usize> {
        self.with_io(|io| io.max_segment_size())?
    }

    #[inline]
    fn max_segments(&self) -> std::io::Result<usize> {
        self.with_io(|io| io.max_segments())?
    }

    #[inline]
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[std::io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<std::io::Result<usize>> {
        self.with_io(|io| io.poll_send(cx, pkts, hdr))?
    }

    #[inline]
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<std::io::Result<usize>> {
        self.with_io(|io| io.poll_recv(cx, pkts, hdrs))?
    }

    #[inline]
    fn poll_close(&mut self, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.bind_iface.context.poll_close(cx)
    }
}

#[derive(Debug, Error)]
#[error("Interface has been unbound")]
pub struct UnboundError;

impl UnboundError {
    pub fn is_source_of(mut error: &(dyn Error + 'static)) -> bool {
        loop {
            if error.is::<Self>() {
                return true;
            }
            match error.source() {
                Some(source) => error = source,
                None => return false,
            }
        }
    }
}

impl From<UnboundError> for std::io::Error {
    fn from(value: UnboundError) -> Self {
        std::io::Error::new(std::io::ErrorKind::ConnectionReset, value)
    }
}

#[derive(Debug, Clone)]
pub struct WeakBindInterface {
    context: Weak<InterfaceContext>,
}

impl WeakBindInterface {
    pub fn upgrade(&self) -> Result<BindInterface, UnboundError> {
        Ok(BindInterface {
            context: self.context.upgrade().ok_or(UnboundError)?,
        })
    }

    pub fn borrow(&self) -> Result<WeakInterface, UnboundError> {
        Ok(self.upgrade()?.borrow_weak())
    }

    pub fn same_io(&self, other: &WeakBindInterface) -> bool {
        Weak::ptr_eq(&self.context, &other.context)
    }
}

#[derive(Debug, Clone)]
pub struct WeakInterface {
    bind_uri: BindUri,
    bind_id: UniqueId,
    weak_iface: WeakBindInterface,
}

impl From<Interface> for WeakInterface {
    fn from(iface: Interface) -> Self {
        iface.downgrade()
    }
}

impl WeakInterface {
    pub fn upgrade(&self) -> Result<Interface, UnboundError> {
        Ok(Interface {
            bind_iface: self.weak_iface.upgrade()?,
            bind_id: self.bind_id,
        })
    }

    pub fn same_io(&self, other: &WeakInterface) -> bool {
        self.bind_id == other.bind_id && self.weak_iface.same_io(&other.weak_iface)
    }
}

impl RefIO for WeakInterface {
    type Interface = WeakInterface;

    fn iface(&self) -> &Self::Interface {
        self
    }

    fn same_io(&self, other: &Self) -> bool {
        self.same_io(other)
    }
}

impl IO for WeakInterface {
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn bound_addr(&self) -> std::io::Result<BoundAddr> {
        self.upgrade()?.bound_addr()
    }

    fn max_segment_size(&self) -> std::io::Result<usize> {
        self.upgrade()?.max_segment_size()
    }

    fn max_segments(&self) -> std::io::Result<usize> {
        self.upgrade()?.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[std::io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<std::io::Result<usize>> {
        self.upgrade()?.poll_send(cx, pkts, hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<std::io::Result<usize>> {
        self.upgrade()?.poll_recv(cx, pkts, hdrs)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.upgrade()?.poll_close(cx)
    }
}
