use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use qbase::net::{
    addr::{BindUriSchema, RealAddr, TryIntoSocketAddrError},
    route::{Link, PacketHeader},
};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::{QuicIO, QuicIoExt, iface::RwInterface};

#[derive(Debug, Error)]
pub(crate) enum InterfaceFailure {
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
    pub(crate) fn is_recoverable(&self) -> bool {
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
}
