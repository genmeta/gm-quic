//! Network address abstraction module
//!
//! This module provides a unified network address abstraction supporting multiple types of network addresses:
//!
//! - **Virtual Address** ([`VirtualAddr`]): Abstract representation of an address that can be bound, corresponding to a `QuicInterface`
//! - **Interface Address** ([`InterfaceAddr`]): Address bound to a specific network interface
//! - **Concrete Address** ([`ConcreteAddr`]): Concrete network addresses, such as IPv4/IPv6 socket addresses
//!
//! These addresses are used to create and bind a `QuicInterface`.
//! You can refer to the `qinterface` crate for more information.
//!
//! ## Address Formats
//!
//! ### Interface Address Format
//! ```text
//! iface:<device_name>:<ip_family>:<port>
//! ```
//!
//! Examples:
//! - `iface:enp17s0:v4:8080` - Bind to enp17s0 interface with IPv4, port 8080
//! - `iface:wlp18s0:v6:443` - Bind to wlp18s0 interface with IPv6, port 443
//!
//! ### Concrete Address Format
//! ```text
//! inet:<socket_addr>
//! ```
//!
//! Examples:
//! - `inet:127.0.0.1:8080` - IPv4 localhost address
//! - `inet:[::1]:8080` - IPv6 localhost address
//!
//! ## Usage Examples
//!
//! ```rust
//! use std::str::FromStr;
//! use std::net::SocketAddr;
//! use qbase::net::address::{ToConcreteAddr, ToVirtualAddrs, ConcreteAddr, VirtualAddr};
//!
//! // Parse interface address
//! let iface_addr: VirtualAddr = "iface:enp17s0:v4:8080".parse().unwrap();
//! let iface_addr: VirtualAddr = "iface:enp17s0:v4:8080".to_virtual_addrs().unwrap().next().unwrap();
//!
//! // Parse concrete address
//! let inet_addr: ConcreteAddr = "inet:192.168.1.1:80".parse().unwrap();
//! let inet_addr: ConcreteAddr = "inet:192.168.1.1:80".to_concrete_addr();
//!
//! // Create from SocketAddr
//! let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//! let virt_addr = VirtualAddr::from(socket_addr);
//! ```

use std::{
    fmt::Display,
    io,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Network address type
///
/// Represents different IP protocol family types.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddrKind {
    /// IPv4 address family
    Inet4,
    /// IPv6 address family
    Inet6,
}

/// Abstract representation of an address that can be bound, corresponding to a `QuicInterface`
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::address::{AddrKind ,VirtualAddr};
///
/// // Create interface address
/// let virt_addr: VirtualAddr = "iface:enp17s0:v4:8080".parse().unwrap();
///
/// // Check address type
/// assert_eq!(virt_addr.kind(), AddrKind::Inet4);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, From, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VirtualAddr {
    /// Interface address variant
    Iface(InterfaceAddr),
    /// Concrete address variant
    Concrete(ConcreteAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

impl VirtualAddr {
    /// Get the IP protocol family type of the address
    ///
    /// Returns [`AddrKind::Inet4`] or [`AddrKind::Inet6`]
    pub fn kind(&self) -> AddrKind {
        match self {
            VirtualAddr::Iface(iface) => iface.kind(),
            VirtualAddr::Concrete(addr) => addr.kind(),
        }
    }
}

impl Display for VirtualAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualAddr::Iface(iface) => write!(f, "iface:{iface}"),
            VirtualAddr::Concrete(addr) => write!(f, "{addr}"),
        }
    }
}

/// Possible errors when parsing virtual addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseVirtualAddrError {
    /// Missing scheme in address string (e.g., "iface:" or "inet:")
    #[error("Missing scheme in virtual addr")]
    MissingScheme,
    /// Unsupported scheme
    #[error("Invalid scheme in virtual addr: {0}")]
    InvalidScheme(String),
    /// Invalid interface address format
    #[error("Invalid interface addr: {0}")]
    InvalidIfaceAddr(ParseInterfaceAddrError),
    /// Invalid network address format
    #[error("Invalid inet addr: {0}")]
    InvalidInetAddr(AddrParseError),
}

impl From<ParseConcreteAddrError> for ParseVirtualAddrError {
    fn from(value: ParseConcreteAddrError) -> Self {
        match value {
            ParseConcreteAddrError::InvalidScheme => ParseVirtualAddrError::MissingScheme,
            ParseConcreteAddrError::InvalidInetAddr(e) => ParseVirtualAddrError::InvalidInetAddr(e),
        }
    }
}

impl FromStr for VirtualAddr {
    type Err = ParseVirtualAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, addr) = s
            .split_once(':')
            .ok_or(ParseVirtualAddrError::MissingScheme)?;
        match scheme {
            "iface" => addr
                .parse()
                .map(VirtualAddr::Iface)
                .map_err(ParseVirtualAddrError::InvalidIfaceAddr),
            "inet" => s
                .parse()
                .map(VirtualAddr::Concrete)
                .map_err(ParseVirtualAddrError::from),
            invalid => Err(ParseVirtualAddrError::InvalidScheme(invalid.to_string())),
        }
    }
}

impl From<SocketAddr> for VirtualAddr {
    fn from(value: SocketAddr) -> Self {
        VirtualAddr::Concrete(value.to_concrete_addr())
    }
}

/// Convert types to an iterator of virtual addresses, like [`ToSocketAddrs`]
///
/// This trait provides a unified way to generate virtual addresses from various types.
///
/// ```rust
/// use qbase::net::address::{ToVirtualAddrs, VirtualAddr};
///
/// // Create from string
/// let addrs: Vec<VirtualAddr> = "inet:127.0.0.1:8080"
///     .to_virtual_addrs()
///     .unwrap()
///     .collect();
///
/// // Create from array
/// let addr_array = ["inet:127.0.0.1:8080", "iface:enp17s0:v4:8080"];
/// let addrs: Vec<VirtualAddr> = addr_array
///     .to_virtual_addrs()
///     .unwrap()
///     .collect();
/// ```
///
/// [`ToSocketAddrs`]: std::net::ToSocketAddrs
pub trait ToVirtualAddrs {
    /// Convert current value to an iterator of virtual addresses
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>>;
}

impl<T: Into<VirtualAddr> + Clone> ToVirtualAddrs for T {
    #[inline]
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>> {
        Ok(std::iter::once(self.clone().into()))
    }
}

impl ToVirtualAddrs for &str {
    #[inline]
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>> {
        self.parse::<VirtualAddr>()
            .map(std::iter::once)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid abstract address"))
    }
}

impl ToVirtualAddrs for () {
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>> {
        Ok(std::iter::empty())
    }
}

impl<T: ToVirtualAddrs, const N: usize> ToVirtualAddrs for [T; N] {
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>> {
        self.iter()
            .try_fold(vec![], |mut acc, item| {
                acc.extend(item.to_virtual_addrs()?);
                Ok(acc)
            })
            .map(Vec::into_iter)
    }
}

impl<T: ToVirtualAddrs> ToVirtualAddrs for &[T] {
    fn to_virtual_addrs(&self) -> io::Result<impl Iterator<Item = VirtualAddr>> {
        self.iter()
            .try_fold(vec![], |mut acc, item| {
                acc.extend(item.to_virtual_addrs()?);
                Ok(acc)
            })
            .map(Vec::into_iter)
    }
}

/// Network interface address
///
/// Represents an address bound to a specific network interface, containing device name, IP protocol family, and port number.
///
/// Interface address string format: `<device_name>:<ip_family>:<port>`
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::address::{InterfaceAddr, IpFamily};
///
/// let addr = InterfaceAddr::new("lo", IpFamily::V4, 8080);
/// assert_eq!(addr.to_string(), "lo:v4:8080");
///
/// // Parse from string
/// let addr: InterfaceAddr = "wlp18s0:v6:443".parse().unwrap();
/// assert_eq!(addr.device_name(), "wlp18s0");
/// assert_eq!(addr.ip_family(), IpFamily::V6);
/// assert_eq!(addr.port(), 443);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InterfaceAddr {
    device_name: String,
    ip_family: IpFamily,
    port: u16,
}

impl InterfaceAddr {
    pub fn new(device_name: impl Into<String>, ip_family: IpFamily, port: u16) -> Self {
        Self {
            device_name: device_name.into(),
            ip_family,
            port,
        }
    }

    /// Get the IP protocol family type of the interface address
    pub fn kind(&self) -> AddrKind {
        match self.ip_family {
            IpFamily::V4 => AddrKind::Inet4,
            IpFamily::V6 => AddrKind::Inet6,
        }
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn ip_family(&self) -> IpFamily {
        self.ip_family
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Display for InterfaceAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.device_name, self.ip_family, self.port)
    }
}

/// Possible errors when parsing interface addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseInterfaceAddrError {
    /// Missing device name
    #[error("Missing device name in interface addr")]
    MissingDeviceName,
    /// Missing IP protocol family
    #[error("Missing IP family in interface addr")]
    MissingIpFamily,
    /// Invalid IP protocol family
    #[error("Invalid IP family in interface addr: {0}")]
    InvalidIpFamily(InvalidIpFamily),
    /// Missing port number
    #[error("Missing port in interface addr")]
    MissingPort,
    /// Invalid port number
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

/// IP protocol family
///
/// Represents IPv4 or IPv6 protocol family.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IpFamily {
    /// IPv4 protocol family
    V4,
    /// IPv6 protocol family
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

/// Invalid IP protocol family error
///
/// Returned when attempting to parse an unsupported IP protocol family string.
///
/// Supported values: `v4`, `V4`, `v6`, `V6`
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

/// Concrete network address
///
/// Represents concrete network addresses, currently supporting Internet socket addresses.
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::address::{AddrKind, ConcreteAddr};
///
/// // Parse from string
/// let addr: ConcreteAddr = "inet:192.168.1.1:80".parse().unwrap();
///
/// // Check address type
/// assert_eq!(addr.kind(), AddrKind::Inet4);
/// ```
#[non_exhaustive]
#[doc(alias = "SpecificAddress")]
#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConcreteAddr {
    /// Internet socket address (IPv4 or IPv6)
    // Iface/Inet => Inet
    Inet(SocketAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

impl ConcreteAddr {
    /// Get the IP protocol family type of the concrete address
    pub fn kind(&self) -> AddrKind {
        match self {
            ConcreteAddr::Inet(SocketAddr::V4(_)) => AddrKind::Inet4,
            ConcreteAddr::Inet(SocketAddr::V6(_)) => AddrKind::Inet6,
        }
    }
}

impl Display for ConcreteAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConcreteAddr::Inet(addr) => write!(f, "inet:{addr}"),
        }
    }
}

/// Possible errors when parsing concrete addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseConcreteAddrError {
    /// Missing or invalid protocol scheme
    #[error("Missing scheme in QUIC addr")]
    InvalidScheme,
    /// Invalid network address format
    #[error("Invalid inet addr: {0}")]
    InvalidInetAddr(AddrParseError),
}

impl FromStr for ConcreteAddr {
    type Err = ParseConcreteAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, addr) = s
            .split_once(':')
            .ok_or(ParseConcreteAddrError::InvalidScheme)?;
        match scheme {
            "inet" => addr
                .parse()
                .map(ConcreteAddr::Inet)
                .map_err(ParseConcreteAddrError::InvalidInetAddr),
            _ => Err(ParseConcreteAddrError::InvalidScheme),
        }
    }
}

/// Trait for converting to concrete addresses
///
/// Provides a unified interface for converting various types to concrete addresses.
///
/// ```rust
/// use std::net::SocketAddr;
/// use qbase::net::address::ToConcreteAddr;
///
/// // Convert from SocketAddr
/// let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
/// let concrete_addr = socket_addr.to_concrete_addr();
///
/// // Convert from string
/// let concrete_addr = "inet:192.168.1.1:80".to_concrete_addr();
/// ```
pub trait ToConcreteAddr {
    /// Convert current value to a concrete address
    fn to_concrete_addr(&self) -> ConcreteAddr;
}

impl ToConcreteAddr for ConcreteAddr {
    fn to_concrete_addr(&self) -> ConcreteAddr {
        *self
    }
}

impl ToConcreteAddr for SocketAddr {
    fn to_concrete_addr(&self) -> ConcreteAddr {
        ConcreteAddr::Inet(*self)
    }
}

impl ToConcreteAddr for &str {
    fn to_concrete_addr(&self) -> ConcreteAddr {
        ConcreteAddr::from_str(self)
            .unwrap_or_else(|e| panic!("Invalid ConcreteAddr {self}: {e:?}"))
    }
}

impl ToConcreteAddr for String {
    fn to_concrete_addr(&self) -> ConcreteAddr {
        self.as_str().to_concrete_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_virtual_addr_display() {
        let iface = VirtualAddr::Iface(InterfaceAddr {
            device_name: "enp17s0".to_string(),
            ip_family: IpFamily::V4,
            port: 1234,
        });
        assert_eq!(iface.to_string(), "iface:enp17s0:v4:1234");

        let inet = VirtualAddr::Concrete(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_concrete_addr(),
        );
        assert_eq!(inet.to_string(), "inet:127.0.0.1:8080");
    }

    #[test]
    fn test_virtual_addr_from_str() {
        let iface: VirtualAddr = "iface:enp17s0:v4:5678".parse().unwrap();
        assert_eq!(
            iface,
            VirtualAddr::Iface(InterfaceAddr {
                device_name: "enp17s0".to_string(),
                ip_family: IpFamily::V4,
                port: 5678,
            })
        );

        let inet: VirtualAddr = "inet:127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            inet,
            VirtualAddr::Concrete(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_concrete_addr()
            )
        );

        let inet: VirtualAddr = "inet:[fe80::1]:8081".parse().unwrap();
        assert_eq!(
            inet,
            VirtualAddr::Concrete(
                SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 8081)
                    .to_concrete_addr()
            )
        );

        // Test error cases
        assert!(matches!(
            "".parse::<VirtualAddr>(),
            Err(ParseVirtualAddrError::MissingScheme)
        ));

        assert!(matches!(
            "unknown:value".parse::<VirtualAddr>(),
            Err(ParseVirtualAddrError::InvalidScheme(_))
        ));

        assert!(matches!(
            "iface:".parse::<VirtualAddr>(),
            Err(ParseVirtualAddrError::InvalidIfaceAddr(_))
        ));

        assert!(matches!(
            "inet:invalid".parse::<VirtualAddr>(),
            Err(ParseVirtualAddrError::InvalidInetAddr(_))
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
