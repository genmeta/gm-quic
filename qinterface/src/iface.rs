use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard, Weak},
    task::{Context, Poll},
};

use qbase::net::{
    addr::{BindUri, BindUriSchema, RealAddr},
    route::{Link, PacketHeader},
};

use crate::{QuicIO, QuicIoExt};

pub mod global;
pub mod monitor;
// handy（qudp）是可选的
mod context;
pub mod handy;

pub use global::QuicInterfaces;

struct RwInterface {
    bind_uri: BindUri,
    quic_io: RwLock<io::Result<Box<dyn QuicIO>>>,
}

impl RwInterface {
    pub async fn is_alive(&self) -> Option<bool> {
        if self.bind_uri.scheme() == BindUriSchema::Ble {
            return None; // BLE interfaces are not supported
        }

        let RealAddr::Internet(real_addr) = self.real_addr().ok()? else {
            tracing::error!(
                "Bad QuicIO implement: QuicIO with bind URI {} has BLE real addr",
                self.bind_uri
            );
            return None;
        };

        let socket_addr = SocketAddr::try_from(&self.bind_uri).ok()?;

        if !(real_addr.ip() == socket_addr.ip()
            && (socket_addr.port() == 0 || real_addr.port() == socket_addr.port()))
        {
            tracing::warn!(bind_uri=%self.bind_uri, "Interface's real_addr should be from {socket_addr}, but got {real_addr}");
            return Some(false); // Address is changed
        }

        let link = Link::new(socket_addr, socket_addr);
        let packets = [io::IoSlice::new(&[0; 1])];
        let header = PacketHeader::new(link.into(), link.into(), 64, None, packets[0].len() as u16);
        if let Err(e) = self.sendmmsg(&packets, header).await {
            tracing::warn!(bind_uri=%self.bind_uri, "Failed to sendmmsg: {e}, interface is not alive");
            return Some(false); // Send failed, interface is not alive
        }

        Some(true)
    }
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

    #[inline]
    fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.borrow()?.poll_close(cx)
    }
}

#[derive(Debug)]
pub struct QuicInterface {
    bind_uri: BindUri,
    iface: Weak<RwInterface>,
    ifaces: Arc<QuicInterfaces>,
}

impl Deref for QuicInterface {
    type Target = dyn QuicIO;

    fn deref(&self) -> &Self::Target {
        self
    }
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

    #[inline]
    fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.borrow(|iface| iface.poll_close(cx))?
    }
}
