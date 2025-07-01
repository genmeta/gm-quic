//! Network address abstraction for QUIC interface management
//!
//! This module provides address types for creating and managing QUIC network interfaces.
//! Each [`BindAddr`] serves as a unique identifier for a QUIC interface.
//!
//! ## Address Types
//!
//! - [`BindAddr`]: Abstract address that uniquely identifies a QUIC interface binding
//! - [`BindIfaceUri`]: Binds to a specific network interface by device name  
//! - [`BindInetUri`]: Binds to a specific IP address and port
//! - [`RealAddr`]: Concrete network addresses after successful binding
//!
//! ## Address Formats
//!
//! ### Interface Addresses
//! ```text
//! iface://eth0/v4/8080     # Bind to eth0 interface, IPv4, port 8080
//! iface://lo/v4/any        # Any available port (reusable identifier)
//! iface://eth0/v6/alloc    # Allocated port (unique identifier each time)
//! ```
//!
//! ### Internet Addresses  
//! ```text
//! inet://127.0.0.1/8080    # Bind to localhost IPv4, port 8080
//! inet://127.0.0.1/any     # Any port (reusable identifier)
//! inet://10.0.0.1/alloc    # Allocated port (unique identifier)
//! 127.0.0.1:8080           # Socket address format (legacy compatibility)
//! ```
//!
//! **Note**: Socket address strings (`ip:port`) do not support port 0.
//! Use `inet://` format with `any` or `alloc` for dynamic port allocation.
//!
//! ## Port Types
//!
//! - **Numeric ports** (`8080`, `443`): Fixed port numbers
//! - **`any` port**: System-assigned port with reusable identifier semantics
//! - **`alloc` port**: System-assigned port with unique identifier semantics
//!
//! ### `any` vs `alloc` Ports
//!
//! ```rust
//! # use qbase::net::addr::BindAddr;
//! // 'any' port: Same string → Same BindAddr (reusable)
//! let addr1: BindAddr = "inet://127.0.0.1/any".parse().unwrap();
//! let addr2: BindAddr = "inet://127.0.0.1/any".parse().unwrap();
//! assert_eq!(addr1, addr2);
//!
//! // 'alloc' port: Same string → Different BindAddr (unique)
//! let addr3: BindAddr = "inet://127.0.0.1/alloc".parse().unwrap();
//! let addr4: BindAddr = "inet://127.0.0.1/alloc".parse().unwrap();
//! assert_ne!(addr3, addr4);
//! ```
//!
//! Use `any` for interface reuse and configuration-driven binding.
//! Use `alloc` for multiple instances and testing isolation.

use std::{
    fmt::{Debug, Display},
    net::{AddrParseError, IpAddr, SocketAddr},
    num::{IntErrorKind, NonZeroU16, ParseIntError},
    str::FromStr,
    sync::{Mutex, OnceLock},
};

use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{AddrFamily, Family, InvalidFamily};

/// Network address type
///
/// Represents different IP protocol family types.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddrKind {
    /// IP address
    Internet(Family),
    /// Bluetooth address
    Bluetooth,
}

/// Abstract representation of an address that can be bound, corresponding to a `QuicInterface`
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::{Family, addr::{AddrKind, BindAddr}};
///
/// // Create interface address
/// let bind_addr: BindAddr = "iface://enp17s0/v4/8080".parse().unwrap();
///
/// // Check address type
/// assert_eq!(bind_addr.kind(), AddrKind::Internet(Family::V4));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, From, PartialEq, Eq, Hash)]
pub enum BindAddr {
    Socket(BindUri),
    Bluetooth([u8; 6]),
}

impl BindAddr {
    /// Get the address type
    ///
    /// Returns the address kind indicating the protocol family and address type.
    pub fn kind(&self) -> AddrKind {
        match self {
            BindAddr::Socket(addr) => addr.family().into(),
            BindAddr::Bluetooth(_) => AddrKind::Bluetooth,
        }
    }
}

impl Display for BindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindAddr::Socket(addr) => {
                write!(f, "{addr}",)
            }
            BindAddr::Bluetooth(addr) => {
                write!(f, "ble://{addr:02x?}")
            }
        }
    }
}

impl From<BindIfaceUri> for BindAddr {
    fn from(addr: BindIfaceUri) -> Self {
        BindAddr::Socket(BindUri::Interface(addr))
    }
}

impl From<BindInetUri> for BindAddr {
    fn from(addr: BindInetUri) -> Self {
        BindAddr::Socket(BindUri::Internet(addr))
    }
}

impl From<SocketAddr> for BindAddr {
    fn from(addr: SocketAddr) -> Self {
        // This will panic if the port is 0
        match BindInetUri::try_from(addr) {
            Ok(inet_addr) => BindAddr::from(inet_addr),
            Err(e) => {
                panic!("Failed to convert SocketAddr to BindAddr: {e}");
            }
        }
    }
}

/// Possible errors when parsing bind addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseBindAddrError {
    /// Missing scheme in address string (e.g., "iface:" or "inet:")
    #[error("Missing scheme in bind addr")]
    MissingScheme,
    /// Unsupported scheme
    #[error("Invalid scheme in bind addr")]
    InvalidScheme,
    /// Invalid interface address format
    #[error("Invalid interface addr: {0}")]
    InvalidIfaceUri(ParseBindIfaceUriError),
    /// Invalid network address format
    #[error("Invalid internet addr: {0}")]
    InvalidInetUri(ParseBindInetUriError),
}

impl FromStr for BindAddr {
    type Err = ParseBindAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            // If it parses as a SocketAddr, we can convert it to InetBindAddr, then BindAddr
            return Ok(BindAddr::Socket(BindUri::Internet(
                BindInetUri::try_from(socket_addr).map_err(ParseBindAddrError::InvalidInetUri)?,
            )));
        }

        let (scheme, _) = s
            .split_once("://")
            .ok_or(ParseBindAddrError::MissingScheme)?;
        match scheme {
            BindIfaceUri::SCHEME => s
                .parse()
                .map(BindUri::Interface)
                .map(BindAddr::Socket)
                .map_err(ParseBindAddrError::InvalidIfaceUri),
            BindInetUri::SCHEME => s
                .parse()
                .map(BindUri::Internet)
                .map(BindAddr::Socket)
                .map_err(ParseBindAddrError::InvalidInetUri),
            "ble" => todo!("Bluetooth addresses are not yet supported"),
            _ => Err(ParseBindAddrError::InvalidScheme),
        }
    }
}

impl From<&str> for BindAddr {
    fn from(value: &str) -> Self {
        value
            .parse()
            .unwrap_or_else(|e| panic!("Failed to parse BindAddr from '{value}': {e}"))
    }
}

impl<T> From<&T> for BindAddr
where
    Self: From<T>,
    T: Copy,
{
    fn from(value: &T) -> Self {
        Self::from(*value)
    }
}

#[derive(Debug, Clone, From, PartialEq, Eq, Hash)]
pub enum BindUri {
    Interface(BindIfaceUri),
    Internet(BindInetUri),
}

impl AddrFamily for BindUri {
    fn family(&self) -> Family {
        match self {
            BindUri::Interface(iface) => iface.family(),
            BindUri::Internet(inet) => inet.family(),
        }
    }
}

impl Display for BindUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindUri::Interface(iface) => write!(f, "{iface}"),
            BindUri::Internet(inet) => write!(f, "{inet}"),
        }
    }
}

/// Network interface bind address
///
/// Represents an address bound to a specific network interface by name, containing device name,
/// IP protocol family, and port number.
///
/// Interface address URI format: `iface://<device_name>/<ip_family>/<port>`
///
/// ```rust
/// use std::str::FromStr;
/// use std::num::NonZeroU16;
/// use qbase::net::{Family, AddrFamily, addr::{BindIfaceUri, Port}};
///
/// let addr = BindIfaceUri::new("lo", Family::V4, Port::Special(NonZeroU16::new(8080).unwrap()));
/// assert_eq!(addr.to_string(), "iface://lo/v4/8080");
///
/// // Parse from string
/// let addr: BindIfaceUri = "iface://wlp18s0/v6/443".parse().unwrap();
/// assert_eq!(addr.device_name(), "wlp18s0");
/// assert_eq!(addr.family(), Family::V6);
/// assert_eq!(addr.port(), Port::Special(NonZeroU16::new(443).unwrap()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindIfaceUri {
    device_name: String,
    family: Family,
    port: Port,
}

impl BindIfaceUri {
    pub const SCHEME: &'static str = "iface";

    pub fn new(device_name: impl Into<String>, family: Family, port: Port) -> Self {
        Self {
            device_name: device_name.into(),
            family,
            port,
        }
    }

    /// Get the IP protocol family type of the interface address
    pub fn kind(&self) -> AddrKind {
        AddrKind::Internet(self.family)
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn port(&self) -> Port {
        self.port
    }
}

impl AddrFamily for BindIfaceUri {
    fn family(&self) -> Family {
        self.family
    }
}

impl Display for BindIfaceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}/{}/{}",
            Self::SCHEME,
            self.device_name,
            self.family,
            self.port
        )
    }
}

impl FromStr for BindIfaceUri {
    type Err = ParseBindIfaceUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, s) = s.split_once("://").ok_or(Self::Err::MissingScheme)?;
        if scheme != Self::SCHEME {
            return Err(Self::Err::IncorrectScheme);
        }
        if s.is_empty() {
            return Err(Self::Err::MissingDeviceName);
        }
        let (device_name, ip_port) = s.split_once('/').ok_or(Self::Err::MissingFamily)?;
        let (ip_family, port) = ip_port.rsplit_once('/').ok_or(Self::Err::MissingPort)?;
        Ok(Self {
            device_name: device_name.to_owned(),
            family: ip_family.parse().map_err(Self::Err::InvalidFamily)?,
            port: port.parse().map_err(Self::Err::InvalidPort)?,
        })
    }
}

/// Possible errors when parsing interface addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseBindIfaceUriError {
    /// Invalid interface address format
    #[error("Missing scheme `{}` in interface addr", BindIfaceUri::SCHEME)]
    MissingScheme,
    /// Invalid scheme in interface address
    #[error("Invalid scheme in interface addr, expect `{}`", BindIfaceUri::SCHEME)]
    IncorrectScheme,
    /// Missing device name
    #[error("Missing device name in interface addr")]
    MissingDeviceName,
    /// Missing IP protocol family
    #[error("Missing IP family in interface addr")]
    MissingFamily,
    /// Invalid IP protocol family
    #[error("Invalid IP family in interface addr: {0}")]
    InvalidFamily(InvalidFamily),
    /// Missing port number
    #[error("Missing port in interface addr")]
    MissingPort,
    /// Invalid port number
    #[error("Invalid port in interface addr: {0}")]
    InvalidPort(ParsePortError),
}

#[derive(Debug, Clone, Copy, From, PartialEq, Eq, Hash)]
pub struct BindInetUri {
    ip: IpAddr,
    port: Port,
}

impl BindInetUri {
    pub const SCHEME: &'static str = "inet";

    pub fn new(ip: IpAddr, port: Port) -> Self {
        Self { ip, port }
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn port(&self) -> Port {
        self.port
    }
}

impl From<BindInetUri> for SocketAddr {
    fn from(addr: BindInetUri) -> Self {
        SocketAddr::new(addr.ip, u16::from(addr.port))
    }
}

impl Display for BindInetUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}/{}", Self::SCHEME, self.ip, self.port)
    }
}

impl AddrFamily for BindInetUri {
    fn family(&self) -> Family {
        self.ip.family()
    }
}

impl FromStr for BindInetUri {
    type Err = ParseBindInetUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_uri = |s: &str| -> Result<BindInetUri, Self::Err> {
            let (scheme, s) = s.split_once("://").ok_or(Self::Err::MissingScheme)?;
            if scheme != Self::SCHEME {
                return Err(Self::Err::IncorrectScheme);
            }
            let (ip, port) = s.split_once('/').ok_or(Self::Err::MissingPort)?;
            let ip = ip.parse().map_err(Self::Err::InvalidIp)?;
            let port = port.parse().map_err(Self::Err::InvalidPort)?;
            Ok(Self { ip, port })
        };
        match s.parse::<SocketAddr>() {
            Ok(socket_addr) => socket_addr.try_into(),
            Err(_) => parse_uri(s),
        }
    }
}

impl TryFrom<SocketAddr> for BindInetUri {
    type Error = ParseBindInetUriError;

    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        let ip = addr.ip();
        let port = NonZeroU16::try_from(addr.port())
            .map(Port::Special)
            .map_err(|_| Self::Error::InvalidPort(ParsePortError::ZeroPort))?;
        Ok(Self { ip, port })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseBindInetUriError {
    /// Missing scheme in inet address
    #[error("Missing scheme `{}` in internet addr", BindInetUri::SCHEME)]
    MissingScheme,
    /// Invalid scheme in inet address
    #[error("Invalid scheme in internet addr, expect `{}`", BindInetUri::SCHEME)]
    IncorrectScheme,
    /// Invalid IP address format
    #[error("Invalid IP address: {0}")]
    InvalidIp(AddrParseError),
    /// Missing port number
    #[error("Missing port in internet addr")]
    MissingPort,
    /// Invalid port number
    #[error("Invalid port number: {0}")]
    InvalidPort(ParsePortError),
}

#[derive(Debug, Clone, Copy, From, PartialEq, Eq, Hash)]
pub enum Port {
    Special(NonZeroU16),
    /// Reuse port 0
    Any,
    Alloc(AllocPort),
}

impl Port {
    pub const ANY: &'static str = "any";
    pub const ALLOC: &'static str = "alloc";

    /// Check if this is a specific port number
    pub fn is_specific(&self) -> bool {
        matches!(self, Port::Special(_))
    }

    /// Check if this is the "any" port (port 0)
    pub fn is_any(&self) -> bool {
        matches!(self, Port::Any)
    }

    /// Check if this is an allocated port
    pub fn is_alloc(&self) -> bool {
        matches!(self, Port::Alloc(_))
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        match port {
            Port::Special(non_zero) => non_zero.into(),
            Port::Any | Port::Alloc(..) => 0,
        }
    }
}

impl Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Port::Special(port) => write!(f, "{}", port.get()),
            Port::Any => write!(f, "any"),
            Port::Alloc(..) => write!(f, "alloc"),
        }
    }
}

impl FromStr for Port {
    type Err = ParsePortError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::ALLOC => Ok(Self::Alloc(AllocPort::default())),
            Self::ANY => Ok(Self::Any),
            number => NonZeroU16::from_str(number)
                .map(Self::Special)
                .map_err(|e| {
                    if e.kind() == &IntErrorKind::Zero {
                        ParsePortError::ZeroPort
                    } else {
                        ParsePortError::InvalidPort(e)
                    }
                }),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParsePortError {
    #[error("Invalid port number: {0}")]
    InvalidPort(ParseIntError),
    #[error("Port number cannot be zero")]
    ZeroPort,
}

/// An opaque ID that uniquely identifies a alloc port.
#[derive(Debug, Clone, Copy, From, PartialEq, Eq, Hash)]
pub struct AllocPort(u128);

impl AllocPort {
    pub fn new() -> AllocPort {
        static ALLOCATED: OnceLock<Mutex<u128>> = OnceLock::new();
        let mut allocated = ALLOCATED.get_or_init(Mutex::default).lock().unwrap();
        *allocated += 1;
        AllocPort(*allocated - 1)
    }
}

impl Default for AllocPort {
    fn default() -> Self {
        Self::new()
    }
}

/// Concrete network address
///
/// Represents concrete network addresses, currently supporting Internet socket addresses and Bluetooth addresses.
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::{Family, addr::{AddrKind, RealAddr}};
///
/// // Parse from string
/// let addr: RealAddr = "inet://192.168.1.1/80".parse().unwrap();
///
/// // Check address type
/// assert_eq!(addr.kind(), AddrKind::Internet(Family::V4));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RealAddr {
    /// Internet socket address (IPv4 or IPv6)
    // Iface/Inet => Inet
    Internet(SocketAddr),
    // TODO
    Bluetooth([u8; 6]),
}

impl RealAddr {
    /// Get the IP protocol family type of the concrete address
    pub fn kind(&self) -> AddrKind {
        match self {
            RealAddr::Internet(SocketAddr::V4(_)) => AddrKind::Internet(Family::V4),
            RealAddr::Internet(SocketAddr::V6(_)) => AddrKind::Internet(Family::V6),
            RealAddr::Bluetooth(_) => AddrKind::Bluetooth,
        }
    }
}

impl Display for RealAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RealAddr::Internet(addr) => write!(f, "inet://{}/{}", addr.ip(), addr.port()),
            RealAddr::Bluetooth(addr) => write!(f, "ble://{addr:02x?}"),
        }
    }
}

impl FromStr for RealAddr {
    type Err = ParseRealAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseRealAddrError::MissingScheme);
        }

        // Try parsing as socket address first (e.g., "127.0.0.1:8080", "[::1]:8080")
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(RealAddr::Internet(socket_addr));
        }

        // Fall back to URI format parsing
        let (scheme, addr) = s
            .split_once("://")
            .ok_or(ParseRealAddrError::MissingScheme)?;

        match scheme {
            "inet" => {
                if addr.is_empty() {
                    return Err(ParseRealAddrError::MissingInetPort);
                }

                let (ip, port) = addr
                    .split_once('/')
                    .ok_or(ParseRealAddrError::MissingInetPort)?;

                let ip = ip
                    .parse::<IpAddr>()
                    .map_err(ParseRealAddrError::InvalidInetAddr)?;
                let port = port
                    .parse::<u16>()
                    .map_err(ParseRealAddrError::InvalidInetPort)?;
                Ok(RealAddr::Internet(SocketAddr::new(ip, port)))
            }
            "ble" => {
                // TODO: Implement Bluetooth address parsing
                Err(ParseRealAddrError::InvalidScheme)
            }
            _ => Err(ParseRealAddrError::InvalidScheme),
        }
    }
}

/// Possible errors when parsing concrete addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseRealAddrError {
    /// Missing protocol scheme (e.g., "inet://")
    #[error("Missing scheme in real addr")]
    MissingScheme,
    /// Invalid scheme
    #[error("Invalid scheme in real addr")]
    InvalidScheme,
    /// Invalid network address format
    #[error("Invalid inet addr: {0}")]
    InvalidInetAddr(AddrParseError),
    /// Missing port number in inet address
    #[error("Missing port in inet addr")]
    MissingInetPort,
    /// Invalid port number in inet address
    #[error("Invalid inet port number: {0}")]
    InvalidInetPort(ParseIntError),
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        num::NonZeroU16,
    };

    use super::*;

    #[test]
    fn test_bind_addr_display() {
        // Test interface address display
        let iface = BindAddr::Socket(BindUri::Interface(BindIfaceUri::new(
            "enp17s0",
            Family::V4,
            Port::Special(NonZeroU16::new(1234).unwrap()),
        )));
        assert_eq!(iface.to_string(), "iface://enp17s0/v4/1234");

        // Test internet address display
        let inet = BindAddr::Socket(BindUri::Internet(BindInetUri::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::Special(NonZeroU16::new(8080).unwrap()),
        )));
        assert_eq!(inet.to_string(), "inet://127.0.0.1/8080");

        // Test special ports
        let any_port = BindAddr::Socket(BindUri::Internet(BindInetUri::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::Any,
        )));
        assert_eq!(any_port.to_string(), "inet://127.0.0.1/any");

        let alloc_port = BindAddr::Socket(BindUri::Internet(BindInetUri::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::Alloc(AllocPort::new()),
        )));
        assert_eq!(alloc_port.to_string(), "inet://127.0.0.1/alloc");

        // Test Bluetooth address (when supported)
        let ble = BindAddr::Bluetooth([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(ble.to_string(), "ble://[aa, bb, cc, dd, ee, ff]");
    }

    #[test]
    fn test_bind_addr_from_str() {
        // Test interface address parsing
        let iface: BindAddr = "iface://enp17s0/v4/5678".parse().unwrap();
        if let BindAddr::Socket(BindUri::Interface(iface_addr)) = iface {
            assert_eq!(iface_addr.device_name(), "enp17s0");
            assert_eq!(iface_addr.family(), Family::V4);
            assert_eq!(
                iface_addr.port(),
                Port::Special(NonZeroU16::new(5678).unwrap())
            );
        } else {
            panic!("Expected IfaceBindAddr");
        }

        // Test internet address parsing
        let inet: BindAddr = "inet://127.0.0.1/8080".parse().unwrap();
        if let BindAddr::Socket(BindUri::Internet(inet_addr)) = inet {
            assert_eq!(inet_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(
                inet_addr.port(),
                Port::Special(NonZeroU16::new(8080).unwrap())
            );
        } else {
            panic!("Expected InetBindAddr");
        }

        // Test IPv6 address parsing
        let inet6: BindAddr = "inet://fe80::1/8081".parse().unwrap();
        if let BindAddr::Socket(BindUri::Internet(inet_addr)) = inet6 {
            assert_eq!(
                inet_addr.ip(),
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            );
            assert_eq!(
                inet_addr.port(),
                Port::Special(NonZeroU16::new(8081).unwrap())
            );
        } else {
            panic!("Expected InetBindAddr");
        }

        // Test special port parsing
        let any_port: BindAddr = "inet://127.0.0.1/any".parse().unwrap();
        if let BindAddr::Socket(BindUri::Internet(inet_addr)) = any_port {
            assert_eq!(inet_addr.port(), Port::Any);
        } else {
            panic!("Expected InetBindAddr with any port");
        }

        let alloc_port: BindAddr = "iface://eth0/v4/alloc".parse().unwrap();
        if let BindAddr::Socket(BindUri::Interface(iface_addr)) = alloc_port {
            assert!(matches!(iface_addr.port(), Port::Alloc(_)));
        } else {
            panic!("Expected IfaceBindAddr with alloc port");
        }

        // Test error cases
        assert!(matches!(
            "".parse::<BindAddr>(),
            Err(ParseBindAddrError::MissingScheme)
        ));

        assert!(matches!(
            "unknown://value".parse::<BindAddr>(),
            Err(ParseBindAddrError::InvalidScheme)
        ));

        assert!(matches!(
            "iface://".parse::<BindAddr>(),
            Err(ParseBindAddrError::InvalidIfaceUri(_))
        ));

        assert!(matches!(
            "inet://invalid".parse::<BindAddr>(),
            Err(ParseBindAddrError::InvalidInetUri(_))
        ));
    }

    #[test]
    fn test_bind_addr_from_socket_addr() {
        // Test conversion from SocketAddr with non-zero port
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let bind_addr = BindAddr::from(socket_addr);

        if let BindAddr::Socket(BindUri::Internet(inet_addr)) = bind_addr {
            assert_eq!(inet_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(
                inet_addr.port(),
                Port::Special(NonZeroU16::new(8080).unwrap())
            );
        } else {
            panic!("Expected InetBindAddr");
        }
    }

    #[test]
    #[should_panic]
    fn test_bind_addr_from_socket_addr_port_0() {
        // Test conversion from SocketAddr with port 0
        let socket_addr_zero = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        _ = BindAddr::from(socket_addr_zero);
    }

    #[test]
    fn test_iface_bind_addr_display_and_parse() {
        let iface = BindIfaceUri::new(
            "wlp18s0",
            Family::V6,
            Port::Special(NonZeroU16::new(443).unwrap()),
        );
        assert_eq!(iface.to_string(), "iface://wlp18s0/v6/443");

        let parsed: BindIfaceUri = "iface://wlp18s0/v6/443".parse().unwrap();
        assert_eq!(parsed.device_name(), iface.device_name());
        assert_eq!(parsed.family(), iface.family());
        assert_eq!(parsed.port(), iface.port());

        // Test with special ports
        let any_port: BindIfaceUri = "iface://eth0/v4/any".parse().unwrap();
        assert_eq!(any_port.port(), Port::Any);

        let alloc_port: BindIfaceUri = "iface://eth0/v4/alloc".parse().unwrap();
        assert!(matches!(alloc_port.port(), Port::Alloc(_)));

        // Test error cases
        assert!(matches!(
            "".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::MissingScheme)
        ));

        assert!(matches!(
            "inet://enp17s0/v4/8080".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::IncorrectScheme)
        ));

        assert!(matches!(
            "iface://".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::MissingDeviceName)
        ));

        assert!(matches!(
            "iface://enp17s0".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::MissingFamily)
        ));

        assert!(matches!(
            "iface://enp17s0/v4".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::MissingPort)
        ));

        assert!(matches!(
            "iface://enp17s0/v7/8080".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::InvalidFamily(_))
        ));

        assert!(matches!(
            "iface://enp17s0/v4/invalid".parse::<BindIfaceUri>(),
            Err(ParseBindIfaceUriError::InvalidPort(_))
        ));
    }

    #[test]
    fn test_inet_bind_addr_display_and_parse() {
        let inet = BindInetUri::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Port::Special(NonZeroU16::new(80).unwrap()),
        );
        assert_eq!(inet.to_string(), "inet://192.168.1.1/80");

        let parsed: BindInetUri = "inet://192.168.1.1/80".parse().unwrap();
        assert_eq!(parsed.ip(), inet.ip());
        assert_eq!(parsed.port(), inet.port());

        // Test socket address parsing
        let from_socket: BindInetUri = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(from_socket.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            from_socket.port(),
            Port::Special(NonZeroU16::new(8080).unwrap())
        );

        // Test IPv6 parsing
        let ipv6: BindInetUri = "inet://::1/443".parse().unwrap();
        assert_eq!(ipv6.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));

        // Test error cases
        assert!(matches!(
            "".parse::<BindInetUri>(),
            Err(ParseBindInetUriError::MissingScheme)
        ));

        assert!(matches!(
            "iface://127.0.0.1/8080".parse::<BindInetUri>(),
            Err(ParseBindInetUriError::IncorrectScheme)
        ));

        assert!(matches!(
            "inet://invalid_ip/8080".parse::<BindInetUri>(),
            Err(ParseBindInetUriError::InvalidIp(_))
        ));

        assert!(matches!(
            "inet://127.0.0.1".parse::<BindInetUri>(),
            Err(ParseBindInetUriError::MissingPort)
        ));

        assert!(matches!(
            "inet://127.0.0.1/invalid_port".parse::<BindInetUri>(),
            Err(ParseBindInetUriError::InvalidPort(_))
        ));
    }

    #[test]
    fn test_port_display_and_parse() {
        // Test special port numbers
        let port = Port::Special(NonZeroU16::new(8080).unwrap());
        assert_eq!(port.to_string(), "8080");
        assert_eq!("8080".parse::<Port>().unwrap(), port);

        // Test any port
        let any_port = Port::Any;
        assert_eq!(any_port.to_string(), "any");
        assert_eq!("any".parse::<Port>().unwrap(), any_port);

        // Test alloc port
        let alloc_port = Port::Alloc(AllocPort::new());
        assert_eq!(alloc_port.to_string(), "alloc");
        assert!(matches!("alloc".parse::<Port>().unwrap(), Port::Alloc(_)));

        // Test conversion to u16
        assert_eq!(u16::from(port), 8080);
        assert_eq!(u16::from(any_port), 0);
        assert_eq!(u16::from(alloc_port), 0);

        // Test error cases
        assert!(matches!("0".parse::<Port>(), Err(ParsePortError::ZeroPort)));

        assert!(matches!(
            "invalid".parse::<Port>(),
            Err(ParsePortError::InvalidPort(_))
        ));

        assert!(matches!(
            "65536".parse::<Port>(),
            Err(ParsePortError::InvalidPort(_))
        ));
    }

    #[test]
    fn test_real_addr_display_and_parse() {
        let inet = RealAddr::Internet(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
        ));
        assert_eq!(inet.to_string(), "inet://192.168.1.1/80");

        // Test URI format parsing
        let parsed: RealAddr = "inet://192.168.1.1/80".parse().unwrap();
        assert_eq!(parsed, inet);

        // Test socket address literal format parsing
        let socket_parsed: RealAddr = "192.168.1.1:80".parse().unwrap();
        assert_eq!(socket_parsed, inet);

        // Test IPv6 socket address literal format
        let ipv6_inet = RealAddr::Internet(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            8080,
        ));
        let ipv6_socket_parsed: RealAddr = "[fe80::1]:8080".parse().unwrap();
        assert_eq!(ipv6_socket_parsed, ipv6_inet);

        // Test port 0 support (not available in socket address format, only URI)
        let port_zero_uri: RealAddr = "inet://127.0.0.1/0".parse().unwrap();
        assert_eq!(
            port_zero_uri,
            RealAddr::Internet(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        );

        // Test port 0 with socket address format (should work with RealAddr, unlike BindAddr)
        let port_zero_socket: RealAddr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(port_zero_socket, port_zero_uri);

        let ble = RealAddr::Bluetooth([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(ble.to_string(), "ble://[aa, bb, cc, dd, ee, ff]");

        // Test kind method
        assert_eq!(inet.kind(), AddrKind::Internet(Family::V4));
        assert_eq!(ble.kind(), AddrKind::Bluetooth);

        // Test error cases
        assert!(matches!(
            "invalid://addr".parse::<RealAddr>(),
            Err(ParseRealAddrError::InvalidScheme)
        ));

        assert!(matches!(
            "inet://invalid_ip/80".parse::<RealAddr>(),
            Err(ParseRealAddrError::InvalidInetAddr(_))
        ));

        assert!(matches!(
            "inet://127.0.0.1".parse::<RealAddr>(),
            Err(ParseRealAddrError::MissingInetPort)
        ));

        // Test invalid socket address format
        assert!("invalid:port".parse::<RealAddr>().is_err());
        assert!("256.256.256.256:8080".parse::<RealAddr>().is_err());
    }

    #[test]
    fn test_addr_kind() {
        let v4_iface = BindAddr::Socket(BindUri::Interface(BindIfaceUri::new(
            "eth0",
            Family::V4,
            Port::Any,
        )));
        assert_eq!(v4_iface.kind(), AddrKind::Internet(Family::V4));

        let v6_inet = BindAddr::Socket(BindUri::Internet(BindInetUri::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Port::Special(NonZeroU16::new(8080).unwrap()),
        )));
        assert_eq!(v6_inet.kind(), AddrKind::Internet(Family::V6));

        let ble = BindAddr::Bluetooth([0; 6]);
        assert_eq!(ble.kind(), AddrKind::Bluetooth);
    }

    #[test]
    fn test_alloc_port_uniqueness() {
        let port1 = AllocPort::new();
        let port2 = AllocPort::new();
        assert_ne!(port1, port2);

        let port3 = AllocPort::default();
        let port4 = AllocPort::default();
        assert_ne!(port3, port4);
    }
}
