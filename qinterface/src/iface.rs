use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::{
    net::{
        addr::{BindUri, BindUriSchema, RealAddr, TryIntoSocketAddrError},
        route::{Link, PacketHeader},
    },
    util::UniqueId,
};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::{QuicIO, QuicIoExt, factory::ProductQuicIO};

pub mod global;
pub mod monitor;
// handy（qudp）是可选的
mod context;
pub mod handy;

pub use global::QuicInterfaces;

struct Interface {
    bind_uri: BindUri,
    factory: Arc<dyn ProductQuicIO>,
    io: io::Result<Box<dyn QuicIO>>,
    /// Unique ID generator from [`QuicInterfaces`]
    ifaces: Arc<QuicInterfaces>,
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
#[error("Interface {bind_uri} is unavailable: {error}")]
pub struct InterfaceUnavailable {
    bind_uri: BindUri,
    #[source]
    error: io::Error,
}

impl Interface {
    fn new(
        bind_uri: BindUri,
        factory: Arc<dyn ProductQuicIO>,
        ifaces: Arc<QuicInterfaces>,
    ) -> Self {
        Self {
            io: factory.bind(bind_uri.clone()),
            bind_id: ifaces.bind_id_generator.generate(),
            bind_uri,
            factory,
            ifaces,
        }
    }

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

    fn rebind(&mut self) {
        self.io = Err(io::ErrorKind::AddrNotAvailable.into());
        self.io = self.factory.bind(self.bind_uri.clone());
        self.bind_id = self.ifaces.bind_id_generator.generate();
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
}

impl QuicIO for RwInterface {
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
        if self.bind_uri().scheme() == BindUriSchema::Ble {
            return Err(InterfaceFailure::BleProtocol);
        }

        let real_addr = match self
            .real_addr()
            .map_err(InterfaceFailure::InterfaceBroken)?
        {
            RealAddr::Internet(addr) => addr,
            _ => return Err(InterfaceFailure::InvalidImplementation),
        };

        let socket_addr = SocketAddr::try_from(&self.bind_uri())?;

        // Check if addresses match
        if !(real_addr.ip() == socket_addr.ip()
            && (socket_addr.port() == 0 || real_addr.port() == socket_addr.port()))
        {
            return Err(InterfaceFailure::AddressMismatch);
        }

        // Test connectivity with a local socket
        let localhost = match real_addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) if ip.is_unspecified() => Ipv6Addr::LOCALHOST.into(),
            IpAddr::V6(ip) => ip.into(),
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

    pub fn binding(self: &Arc<Self>) -> BindInterface {
        BindInterface {
            iface: self.clone(),
        }
    }

    pub fn borrow(self: &Arc<Self>) -> io::Result<QuicInterface> {
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

impl QuicIO for QuicInterface {
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
}

impl QuicInterface {
    pub(super) fn borrow<T>(&self, f: impl FnOnce(&dyn QuicIO) -> T) -> io::Result<T> {
        if self.iface.read().bind_id != self.bind_id {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Interface {} is not available", self.bind_uri()),
            ));
        }
        self.iface.read().borrow(f)
    }
}
