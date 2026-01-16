use std::{
    error::Error,
    fmt::Debug,
    io,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    net::{addr::RealAddr, route::PacketHeader},
    util::UniqueId,
};
use thiserror::Error;

use crate::{Interface, RefInterface, logical::collection::InterfaceContext};

mod bind_uri;
mod collection;

pub mod component;
pub mod handy;

pub use bind_uri::{
    BindUri, BindUriSchema, ParseBindUriError, ParseBindUriSchemeError, TryIntoSocketAddrError,
};
pub use collection::QuicInterfaces;

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

    pub fn close(&self) -> impl Future<Output = io::Result<()>> + Send {
        core::future::poll_fn(|cx| self.context.poll_close(cx))
    }

    pub fn rebind(&self) -> impl Future<Output = ()> + Send {
        core::future::poll_fn(|cx| self.poll_rebind(cx))
    }

    #[inline]
    pub fn borrow(&self) -> QuicInterface {
        QuicInterface {
            bind_id: self.context.bind_id(),
            bind_iface: self.clone(),
        }
    }

    #[inline]
    pub fn downgrade(&self) -> WeakInterface {
        WeakInterface {
            context: Arc::downgrade(&self.context),
        }
    }

    #[inline]
    pub fn borrow_weak(&self) -> WeakQuicInterface {
        self.borrow().downgrade()
    }
}

#[derive(Debug, Clone)]
pub struct QuicInterface {
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

impl From<RebindedError> for io::Error {
    fn from(value: RebindedError) -> Self {
        io::Error::new(io::ErrorKind::ConnectionReset, value)
    }
}

impl QuicInterface {
    #[inline]
    fn borrow<T>(&self, f: impl FnOnce(&InterfaceContext) -> T) -> io::Result<T> {
        if self.bind_iface.context.bind_id() != self.bind_id {
            return Err(RebindedError.into());
        }
        Ok(f(self.bind_iface.context.as_ref()))
    }

    #[inline]
    pub fn bind_interface(&self) -> &BindInterface {
        &self.bind_iface
    }

    #[inline]
    pub fn downgrade(&self) -> WeakQuicInterface {
        WeakQuicInterface {
            bind_uri: self.bind_iface.bind_uri(),
            bind_id: self.bind_id,
            weak_iface: self.bind_iface.downgrade(),
        }
    }

    pub fn same_io(&self, other: &QuicInterface) -> bool {
        self.bind_id == other.bind_id
            && Arc::ptr_eq(&self.bind_iface.context, &other.bind_iface.context)
    }

    // quic_iface(bind_id=1)
    // rebind
    // quic_iface(bind_id=1).get_component::<StunProtocolComponent>()
    // quic_iface(bind_id=2).get_component::<StunProtocolComponent>()

    pub fn with_components<T>(
        &self,
        f: impl FnOnce(&component::Components, &QuicInterface) -> T,
    ) -> T {
        self.bind_iface.with_components(f)
    }

    pub fn with_components_mut<T>(
        &self,
        f: impl FnOnce(&mut component::Components, &QuicInterface) -> T,
    ) -> T {
        self.bind_iface.with_components_mut(f)
    }
}

impl RefInterface for QuicInterface {
    type Interface = Self;

    #[inline]
    fn iface(&self) -> &Self::Interface {
        self
    }

    fn same_io(&self, other: &Self) -> bool {
        self.same_io(other)
    }
}

impl Interface for QuicInterface {
    #[inline]
    fn bind_uri(&self) -> BindUri {
        self.bind_iface.bind_uri()
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
        self.borrow(|iface| iface.poll_close(cx))?
    }
}

#[derive(Debug, Error)]
#[error("Interface has been unbound")]
pub struct UnbondedError;

impl UnbondedError {
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

impl From<UnbondedError> for io::Error {
    fn from(value: UnbondedError) -> Self {
        io::Error::new(io::ErrorKind::ConnectionReset, value)
    }
}

#[derive(Debug, Clone)]
pub struct WeakInterface {
    context: Weak<InterfaceContext>,
}

impl WeakInterface {
    pub fn upgrade(&self) -> Result<BindInterface, UnbondedError> {
        Ok(BindInterface {
            context: self.context.upgrade().ok_or(UnbondedError)?,
        })
    }

    pub fn borrow(&self) -> Result<WeakQuicInterface, UnbondedError> {
        Ok(self.upgrade()?.borrow_weak())
    }

    pub fn same_io(&self, other: &WeakInterface) -> bool {
        Weak::ptr_eq(&self.context, &other.context)
    }
}

#[derive(Debug, Clone)]
pub struct WeakQuicInterface {
    bind_uri: BindUri,
    bind_id: UniqueId,
    weak_iface: WeakInterface,
}

impl From<QuicInterface> for WeakQuicInterface {
    fn from(iface: QuicInterface) -> Self {
        iface.downgrade()
    }
}

impl WeakQuicInterface {
    pub fn upgrade(&self) -> Result<QuicInterface, UnbondedError> {
        Ok(QuicInterface {
            bind_iface: self.weak_iface.upgrade()?,
            bind_id: self.bind_id,
        })
    }

    pub fn same_io(&self, other: &WeakQuicInterface) -> bool {
        self.bind_id == other.bind_id && self.weak_iface.same_io(&other.weak_iface)
    }
}

impl RefInterface for WeakQuicInterface {
    type Interface = WeakQuicInterface;

    fn iface(&self) -> &Self::Interface {
        self
    }

    fn same_io(&self, other: &Self) -> bool {
        self.same_io(other)
    }
}

impl Interface for WeakQuicInterface {
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn real_addr(&self) -> io::Result<RealAddr> {
        self.upgrade()?.real_addr()
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        self.upgrade()?.max_segment_size()
    }

    fn max_segments(&self) -> io::Result<usize> {
        self.upgrade()?.max_segments()
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>> {
        self.upgrade()?.poll_send(cx, pkts, hdr)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>> {
        self.upgrade()?.poll_recv(cx, pkts, hdrs)
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.upgrade()?.poll_close(cx)
    }
}
