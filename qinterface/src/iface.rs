use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard, Weak},
    task::{Context, Poll},
};

use qbase::net::{
    addr::{BindUri, BindUriSchema, RealAddr, TryIntoSocketAddrError},
    route::{Link, PacketHeader},
};
use thiserror::Error;
use tokio::net::UdpSocket;

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

#[derive(Debug, Error)]
enum InterfaceFailure {
    #[error("BLE protocol is not supported for alive check")]
    BleProtocol,
    #[error("Invalid QuicIO implementation")]
    InvalidImplementation,
    #[error("Interface is broken: {0}")]
    InterfaceBroken(io::Error),
    #[error("Failed to parse bind URI address")]
    AddressParsingFailed(#[from] TryIntoSocketAddrError),
    #[error("Real address does not match bind URI")]
    AddressMismatch,
    #[error("Failed to bind test socket: {0}")]
    TestSocketBindFailed(io::Error),
    #[error("Failed to send test packet: {0}")]
    SendTestFailed(io::Error),
}

impl From<io::Error> for InterfaceFailure {
    fn from(error: io::Error) -> Self {
        Self::TestSocketBindFailed(error)
    }
}

impl InterfaceFailure {
    fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::InterfaceBroken(..) | Self::AddressMismatch | Self::SendTestFailed(..)
        )
    }
}

impl RwInterface {
    pub async fn is_alive(&self) -> Result<(), InterfaceFailure> {
        if self.bind_uri.scheme() == BindUriSchema::Ble {
            return Err(InterfaceFailure::BleProtocol);
        }

        let real_addr = match self
            .real_addr()
            .map_err(InterfaceFailure::InterfaceBroken)?
        {
            RealAddr::Internet(addr) => addr,
            _ => return Err(InterfaceFailure::InvalidImplementation),
        };

        let socket_addr = SocketAddr::try_from(&self.bind_uri)?;

        // Check if addresses match
        if !(real_addr.ip() == socket_addr.ip()
            && (socket_addr.port() == 0 || real_addr.port() == socket_addr.port()))
        {
            return Err(InterfaceFailure::AddressMismatch);
        }

        // Test connectivity with a local socket
        let localhost = match real_addr.ip() {
            IpAddr::V4(..) => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(..) => Ipv6Addr::LOCALHOST.into(),
        };
        let socket = UdpSocket::bind(SocketAddr::new(localhost, 0))
            .await
            .map_err(InterfaceFailure::TestSocketBindFailed)?;
        let dst_addr = socket
            .local_addr()
            .map_err(InterfaceFailure::TestSocketBindFailed)?;

        // Send test packet
        let link = Link::new(real_addr, dst_addr);
        let packets = [io::IoSlice::new(&[0; 1])];
        let header = PacketHeader::new(link.into(), link.into(), 64, None, packets[0].len() as u16);

        self.sendmmsg(&packets, header)
            .await
            .map_err(InterfaceFailure::SendTestFailed)?;

        Ok(())
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
            tracing::warn!(%bind_uri,"Failed to bind interface: {error}",);
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
            tracing::warn!(bind_uri=%self.bind_uri,"Failed to update interface: {error}");
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
        let iface = self.iface.upgrade().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_uri),
            )
        })?;
        let guard = iface.borrow()?;
        Ok(f(guard.as_ref()))
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
