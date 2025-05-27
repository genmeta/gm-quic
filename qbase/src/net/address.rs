use std::{
    fmt::Display,
    io,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddrKind {
    Inet4,
    Inet6,
}
#[non_exhaustive]
#[doc(alias = "IfaceAddr")]
#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AbstractAddr {
    Iface(InterfaceAddr),
    Specific(QuicAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

impl AbstractAddr {
    pub fn kind(&self) -> AddrKind {
        match self {
            AbstractAddr::Iface(iface) => iface.kind(),
            AbstractAddr::Specific(addr) => addr.kind(),
        }
    }
}

impl Display for AbstractAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbstractAddr::Iface(iface) => write!(f, "iface:{iface}"),
            AbstractAddr::Specific(addr) => write!(f, "{addr}"),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseAbstractAddrError {
    #[error("Missing scheme in abstract addr")]
    MissingScheme,
    #[error("Invalid scheme in abstract addr: {0}")]
    InvalidScheme(String),
    #[error("Invalid interface addr: {0}")]
    InvalidIfaceAddr(ParseInterfaceAddrError),
    #[error("Invalid inet addr: {0}")]
    InvalidInetAddr(AddrParseError),
}

impl From<ParseQuicAddrError> for ParseAbstractAddrError {
    fn from(value: ParseQuicAddrError) -> Self {
        match value {
            ParseQuicAddrError::InvalidScheme => ParseAbstractAddrError::MissingScheme,
            ParseQuicAddrError::InvalidInetAddr(e) => ParseAbstractAddrError::InvalidInetAddr(e),
        }
    }
}

impl FromStr for AbstractAddr {
    type Err = ParseAbstractAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, addr) = s
            .split_once(':')
            .ok_or(ParseAbstractAddrError::MissingScheme)?;
        match scheme {
            "iface" => addr
                .parse()
                .map(AbstractAddr::Iface)
                .map_err(ParseAbstractAddrError::InvalidIfaceAddr),
            "inet" => s
                .parse()
                .map(AbstractAddr::Specific)
                .map_err(ParseAbstractAddrError::from),
            invalid => Err(ParseAbstractAddrError::InvalidScheme(invalid.to_string())),
        }
    }
}

impl From<SocketAddr> for AbstractAddr {
    fn from(value: SocketAddr) -> Self {
        AbstractAddr::Specific(value.to_quic_addr())
    }
}

pub trait ToAbstractAddrs {
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>>;
}

impl<T: Into<AbstractAddr> + Clone> ToAbstractAddrs for T {
    #[inline]
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>> {
        Ok(std::iter::once(self.clone().into()))
    }
}

impl ToAbstractAddrs for &str {
    #[inline]
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>> {
        self.parse::<AbstractAddr>()
            .map(std::iter::once)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid abstract address"))
    }
}

impl ToAbstractAddrs for () {
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>> {
        Ok(std::iter::empty())
    }
}

impl<T: ToAbstractAddrs, const N: usize> ToAbstractAddrs for [T; N] {
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>> {
        self.iter()
            .try_fold(vec![], |mut acc, item| {
                acc.extend(item.to_abstract_addrs()?);
                Ok(acc)
            })
            .map(Vec::into_iter)
    }
}

impl<T: ToAbstractAddrs> ToAbstractAddrs for &[T] {
    fn to_abstract_addrs(&self) -> io::Result<impl Iterator<Item = AbstractAddr>> {
        self.iter()
            .try_fold(vec![], |mut acc, item| {
                acc.extend(item.to_abstract_addrs()?);
                Ok(acc)
            })
            .map(Vec::into_iter)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InterfaceAddr {
    device_name: String,
    ip_family: IpFamily,
    port: u16,
}

impl InterfaceAddr {
    pub fn kind(&self) -> AddrKind {
        match self.ip_family {
            IpFamily::V4 => AddrKind::Inet4,
            IpFamily::V6 => AddrKind::Inet6,
        }
    }
}

impl Display for InterfaceAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.device_name, self.ip_family, self.port)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseInterfaceAddrError {
    #[error("Missing device name in interface addr")]
    MissingDeviceName,
    #[error("Missing IP family in interface addr")]
    MissingIpFamily,
    #[error("Invalid IP family in interface addr: {0}")]
    InvalidIpFamily(InvalidIpFamily),
    #[error("Missing port in interface addr")]
    MissingPort,
    #[error("Invalid port in interface addr: {0}")]
    InvalidPort(<u16 as FromStr>::Err),
}

impl FromStr for InterfaceAddr {
    type Err = ParseInterfaceAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseInterfaceAddrError::MissingDeviceName);
        }
        let (device_name, ip_port) = s
            .split_once(':')
            .ok_or(ParseInterfaceAddrError::MissingIpFamily)?;
        let (ip_family, port) = ip_port
            .rsplit_once(':')
            .ok_or(ParseInterfaceAddrError::MissingPort)?;
        let ip_family = ip_family
            .parse()
            .map_err(ParseInterfaceAddrError::InvalidIpFamily)?;
        let port = port.parse().map_err(ParseInterfaceAddrError::InvalidPort)?;
        Ok(Self {
            device_name: device_name.to_owned(),
            ip_family,
            port,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

impl Display for IpFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpFamily::V4 => write!(f, "v4"),
            IpFamily::V6 => write!(f, "v6"),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("Invalid IP family: {0}")]
pub struct InvalidIpFamily(String);

impl FromStr for IpFamily {
    type Err = InvalidIpFamily;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v4" => Ok(IpFamily::V4),
            "v6" => Ok(IpFamily::V6),
            invalid => Err(InvalidIpFamily(invalid.to_string())),
        }
    }
}

#[non_exhaustive]
#[doc(alias = "SpecificAddress")]
#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuicAddr {
    // Iface/Inet => Inet
    Inet(SocketAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

impl QuicAddr {
    pub fn kind(&self) -> AddrKind {
        match self {
            QuicAddr::Inet(SocketAddr::V4(_)) => AddrKind::Inet4,
            QuicAddr::Inet(SocketAddr::V6(_)) => AddrKind::Inet6,
        }
    }
}

impl Display for QuicAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicAddr::Inet(addr) => write!(f, "inet:{addr}"),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseQuicAddrError {
    #[error("Missing scheme in QUIC addr")]
    InvalidScheme,
    #[error("Invalid inet addr: {0}")]
    InvalidInetAddr(AddrParseError),
}

impl FromStr for QuicAddr {
    type Err = ParseQuicAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, addr) = s.split_once(':').ok_or(ParseQuicAddrError::InvalidScheme)?;
        match scheme {
            "inet" => addr
                .parse()
                .map(QuicAddr::Inet)
                .map_err(ParseQuicAddrError::InvalidInetAddr),
            _ => Err(ParseQuicAddrError::InvalidScheme),
        }
    }
}

pub trait ToQuicAddr {
    fn to_quic_addr(self) -> QuicAddr;
}

impl ToQuicAddr for QuicAddr {
    fn to_quic_addr(self) -> QuicAddr {
        self
    }
}

impl ToQuicAddr for SocketAddr {
    fn to_quic_addr(self) -> QuicAddr {
        QuicAddr::Inet(self)
    }
}

impl ToQuicAddr for &str {
    fn to_quic_addr(self) -> QuicAddr {
        SocketAddr::from_str(self)
            .unwrap_or_else(|_| panic!("Invalid SocketAddr: {self}"))
            .to_quic_addr()
    }
}

impl ToQuicAddr for String {
    fn to_quic_addr(self) -> QuicAddr {
        self.as_str().to_quic_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_abstract_addr_display() {
        let iface = AbstractAddr::Iface(InterfaceAddr {
            device_name: "enp17s0".to_string(),
            ip_family: IpFamily::V4,
            port: 1234,
        });
        assert_eq!(iface.to_string(), "iface:enp17s0:v4:1234");

        let inet = AbstractAddr::Specific(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_quic_addr(),
        );
        assert_eq!(inet.to_string(), "inet:127.0.0.1:8080");
    }

    #[test]
    fn test_abstract_addr_from_str() {
        let iface: AbstractAddr = "iface:enp17s0:v4:5678".parse().unwrap();
        assert_eq!(
            iface,
            AbstractAddr::Iface(InterfaceAddr {
                device_name: "enp17s0".to_string(),
                ip_family: IpFamily::V4,
                port: 5678,
            })
        );

        let inet: AbstractAddr = "inet:127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            inet,
            AbstractAddr::Specific(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_quic_addr()
            )
        );

        let inet: AbstractAddr = "inet:[fe80::1]:8081".parse().unwrap();
        assert_eq!(
            inet,
            AbstractAddr::Specific(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 8081)
                    .to_quic_addr()
            )
        );

        // Test error cases
        assert!(matches!(
            "".parse::<AbstractAddr>(),
            Err(ParseAbstractAddrError::MissingScheme)
        ));

        assert!(matches!(
            "unknown:value".parse::<AbstractAddr>(),
            Err(ParseAbstractAddrError::InvalidScheme(_))
        ));

        assert!(matches!(
            "iface:".parse::<AbstractAddr>(),
            Err(ParseAbstractAddrError::InvalidIfaceAddr(_))
        ));

        assert!(matches!(
            "inet:invalid".parse::<AbstractAddr>(),
            Err(ParseAbstractAddrError::InvalidInetAddr(_))
        ));
    }

    #[test]
    fn test_interface_addr_display_and_parse() {
        let iface = InterfaceAddr {
            device_name: "wlp18s0".to_string(),
            ip_family: IpFamily::V6,
            port: 0,
        };
        assert_eq!(iface.to_string(), "wlp18s0:v6:0");

        let parsed: InterfaceAddr = "wlp18s0:v6:0".parse().unwrap();
        assert_eq!(parsed, iface);

        // Test error cases
        assert!(matches!(
            "".parse::<InterfaceAddr>(),
            Err(ParseInterfaceAddrError::MissingDeviceName)
        ));

        assert!(matches!(
            "enp17s0".parse::<InterfaceAddr>(),
            Err(ParseInterfaceAddrError::MissingIpFamily)
        ));

        assert!(matches!(
            "enp17s0:v7".parse::<InterfaceAddr>(),
            Err(ParseInterfaceAddrError::MissingPort)
        ));

        assert!(matches!(
            "enp17s0:v7:0".parse::<InterfaceAddr>(),
            Err(ParseInterfaceAddrError::InvalidIpFamily(..))
        ));
    }

    #[test]
    fn test_ip_family_display_and_parse() {
        assert_eq!(IpFamily::V4.to_string(), "v4");
        assert_eq!(IpFamily::V6.to_string(), "v6");

        assert_eq!("v4".parse::<IpFamily>().unwrap(), IpFamily::V4);
        assert_eq!("V4".parse::<IpFamily>().unwrap(), IpFamily::V4);
        assert_eq!("v6".parse::<IpFamily>().unwrap(), IpFamily::V6);
        assert_eq!("V6".parse::<IpFamily>().unwrap(), IpFamily::V6);

        assert!(matches!("v7".parse::<IpFamily>(), Err(InvalidIpFamily(_))));
    }
}
