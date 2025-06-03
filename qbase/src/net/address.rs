//! Network address abstraction for QUIC interface management
//!
//! This module provides address types for creating and managing QUIC network interfaces.
//! Each [`BindAddr`] serves as a unique identifier for a QUIC interface.
//!
//! ## Address Types
//!
//! - [`BindAddr`]: Abstract address that uniquely identifies a QUIC interface binding
//! - [`IfaceBindAddr`]: Binds to a specific network interface by device name  
//! - [`InetBindAddr`]: Binds to a specific IP address and port
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
//! # use qbase::net::address::BindAddr;
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

/// Network address type
///
/// Represents different IP protocol family types.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, From, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddrKind {
    /// IP address
    Ip(IpFamily),
    /// Bluetooth address
    Ble,
}

/// Abstract representation of an address that can be bound, corresponding to a `QuicInterface`
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::address::{AddrKind, BindAddr, IpFamily};
///
/// // Create interface address
/// let bind_addr: BindAddr = "iface://enp17s0/v4/8080".parse().unwrap();
///
/// // Check address type
/// assert_eq!(bind_addr.kind(), AddrKind::Ip(IpFamily::V4));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, From, PartialEq, Eq, Hash)]
pub enum BindAddr {
    Socket(SocketBindAddr),
    Bluetooth([u8; 6]),
}

impl BindAddr {
    /// Get the address type
    ///
    /// Returns the address kind indicating the protocol family and address type.
    pub fn kind(&self) -> AddrKind {
        match self {
            BindAddr::Socket(addr) => addr.ip_family().into(),
            BindAddr::Bluetooth(_) => AddrKind::Ble,
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

impl From<IfaceBindAddr> for BindAddr {
    fn from(addr: IfaceBindAddr) -> Self {
        BindAddr::Socket(SocketBindAddr::Iface(addr))
    }
}

impl From<InetBindAddr> for BindAddr {
    fn from(addr: InetBindAddr) -> Self {
        BindAddr::Socket(SocketBindAddr::Inet(addr))
    }
}

impl From<SocketAddr> for BindAddr {
    fn from(addr: SocketAddr) -> Self {
        // This will panic if the port is 0
        match InetBindAddr::try_from(addr) {
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
    InvalidIfaceAddr(ParseIfaceBindAddrError),
    /// Invalid network address format
    #[error("Invalid internet addr: {0}")]
    InvalidInetAddr(ParseInetBindAddrError),
}

impl FromStr for BindAddr {
    type Err = ParseBindAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            // If it parses as a SocketAddr, we can convert it to InetBindAddr, then BindAddr
            return Ok(BindAddr::Socket(SocketBindAddr::Inet(
                InetBindAddr::try_from(socket_addr).map_err(ParseBindAddrError::InvalidInetAddr)?,
            )));
        }

        let (scheme, _) = s
            .split_once("://")
            .ok_or(ParseBindAddrError::MissingScheme)?;
        match scheme {
            IfaceBindAddr::SCHEME => s
                .parse()
                .map(SocketBindAddr::Iface)
                .map(BindAddr::Socket)
                .map_err(ParseBindAddrError::InvalidIfaceAddr),
            InetBindAddr::SCHEME => s
                .parse()
                .map(SocketBindAddr::Inet)
                .map(BindAddr::Socket)
                .map_err(ParseBindAddrError::InvalidInetAddr),
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
pub enum SocketBindAddr {
    Iface(IfaceBindAddr),
    Inet(InetBindAddr),
}

impl SocketBindAddr {
    pub fn ip_family(&self) -> IpFamily {
        match self {
            SocketBindAddr::Iface(iface) => iface.ip_family(),
            SocketBindAddr::Inet(inet) => inet.ip_family(),
        }
    }
}

impl Display for SocketBindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketBindAddr::Iface(iface) => write!(f, "{iface}"),
            SocketBindAddr::Inet(inet) => write!(f, "{inet}"),
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
/// use qbase::net::address::{IfaceBindAddr, IpFamily, Port};
///
/// let addr = IfaceBindAddr::new("lo", IpFamily::V4, Port::Special(NonZeroU16::new(8080).unwrap()));
/// assert_eq!(addr.to_string(), "iface://lo/v4/8080");
///
/// // Parse from string
/// let addr: IfaceBindAddr = "iface://wlp18s0/v6/443".parse().unwrap();
/// assert_eq!(addr.device_name(), "wlp18s0");
/// assert_eq!(addr.ip_family(), IpFamily::V6);
/// assert_eq!(addr.port(), Port::Special(NonZeroU16::new(443).unwrap()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IfaceBindAddr {
    device_name: String,
    ip_family: IpFamily,
    port: Port,
}

impl IfaceBindAddr {
    pub const SCHEME: &'static str = "iface";

    pub fn new(device_name: impl Into<String>, ip_family: IpFamily, port: Port) -> Self {
        Self {
            device_name: device_name.into(),
            ip_family,
            port,
        }
    }

    /// Get the IP protocol family type of the interface address
    pub fn kind(&self) -> AddrKind {
        AddrKind::Ip(self.ip_family)
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn ip_family(&self) -> IpFamily {
        self.ip_family
    }

    pub fn port(&self) -> Port {
        self.port
    }
}

impl Display for IfaceBindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}/{}/{}",
            Self::SCHEME,
            self.device_name,
            self.ip_family,
            self.port
        )
    }
}

impl FromStr for IfaceBindAddr {
    type Err = ParseIfaceBindAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, s) = s
            .split_once("://")
            .ok_or(ParseIfaceBindAddrError::MissingScheme)?;
        if scheme != Self::SCHEME {
            return Err(ParseIfaceBindAddrError::IncorrectScheme);
        }
        if s.is_empty() {
            return Err(ParseIfaceBindAddrError::MissingDeviceName);
        }
        let (device_name, ip_port) = s
            .split_once('/')
            .ok_or(ParseIfaceBindAddrError::MissingIpFamily)?;
        let (ip_family, port) = ip_port
            .rsplit_once('/')
            .ok_or(ParseIfaceBindAddrError::MissingPort)?;
        Ok(Self {
            device_name: device_name.to_owned(),
            ip_family: ip_family
                .parse()
                .map_err(ParseIfaceBindAddrError::InvalidIpFamily)?,
            port: port.parse().map_err(ParseIfaceBindAddrError::InvalidPort)?,
        })
    }
}

/// Possible errors when parsing interface addresses
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseIfaceBindAddrError {
    /// Invalid interface address format
    #[error("Missing scheme `{}` in interface addr", IfaceBindAddr::SCHEME)]
    MissingScheme,
    /// Invalid scheme in interface address
    #[error("Invalid scheme in interface addr, expect `{}`", IfaceBindAddr::SCHEME)]
    IncorrectScheme,
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
    InvalidPort(ParsePortError),
}

#[derive(Debug, Clone, Copy, From, PartialEq, Eq, Hash)]
pub struct InetBindAddr {
    ip: IpAddr,
    port: Port,
}

impl InetBindAddr {
    pub const SCHEME: &'static str = "inet";

    pub fn new(ip: IpAddr, port: Port) -> Self {
        Self { ip, port }
    }

    pub fn ip_family(&self) -> IpFamily {
        match self.ip {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        }
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn port(&self) -> Port {
        self.port
    }
}

impl From<InetBindAddr> for SocketAddr {
    fn from(addr: InetBindAddr) -> Self {
        SocketAddr::new(addr.ip, u16::from(addr.port))
    }
}

impl Display for InetBindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}/{}", Self::SCHEME, self.ip, self.port)
    }
}

impl FromStr for InetBindAddr {
    type Err = ParseInetBindAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_uri = |s: &str| -> Result<InetBindAddr, ParseInetBindAddrError> {
            let (scheme, s) = s
                .split_once("://")
                .ok_or(ParseInetBindAddrError::MissingScheme)?;
            if scheme != Self::SCHEME {
                return Err(ParseInetBindAddrError::IncorrectScheme);
            }
            let (ip, port) = s
                .split_once('/')
                .ok_or(ParseInetBindAddrError::MissingPort)?;
            let ip = ip.parse().map_err(ParseInetBindAddrError::InvalidIp)?;
            let port = port.parse().map_err(ParseInetBindAddrError::InvalidPort)?;
            Ok(Self { ip, port })
        };
        match s.parse::<SocketAddr>() {
            Ok(socket_addr) => socket_addr.try_into(),
            Err(_) => parse_uri(s),
        }
    }
}

impl TryFrom<SocketAddr> for InetBindAddr {
    type Error = ParseInetBindAddrError;

    fn try_from(addr: SocketAddr) -> Result<Self, Self::Error> {
        let ip = addr.ip();
        let port = NonZeroU16::try_from(addr.port())
            .map(Port::Special)
            .map_err(|_| ParseInetBindAddrError::InvalidPort(ParsePortError::ZeroPort))?;
        Ok(Self { ip, port })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseInetBindAddrError {
    /// Missing scheme in inet address
    #[error("Missing scheme `{}` in internet addr", InetBindAddr::SCHEME)]
    MissingScheme,
    /// Invalid scheme in inet address
    #[error("Invalid scheme in internet addr, expect `{}`", InetBindAddr::SCHEME)]
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
/// Represents concrete network addresses, currently supporting Internet socket addresses and Bluetooth addresses.
///
/// ```rust
/// use std::str::FromStr;
/// use qbase::net::address::{AddrKind, RealAddr, IpFamily};
///
/// // Parse from string
/// let addr: RealAddr = "inet://192.168.1.1/80".parse().unwrap();
///
/// // Check address type
/// assert_eq!(addr.kind(), AddrKind::Ip(IpFamily::V4));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RealAddr {
    /// Internet socket address (IPv4 or IPv6)
    // Iface/Inet => Inet
    Inet(SocketAddr),
    // TODO
    Ble([u8; 6]),
}

impl RealAddr {
    /// Get the IP protocol family type of the concrete address
    pub fn kind(&self) -> AddrKind {
        match self {
            RealAddr::Inet(SocketAddr::V4(_)) => AddrKind::Ip(IpFamily::V4),
            RealAddr::Inet(SocketAddr::V6(_)) => AddrKind::Ip(IpFamily::V6),
            RealAddr::Ble(_) => AddrKind::Ble,
        }
    }
}

impl Display for RealAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RealAddr::Inet(addr) => write!(f, "inet://{}/{}", addr.ip(), addr.port()),
            RealAddr::Ble(addr) => write!(f, "ble://{addr:02x?}"),
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
            return Ok(RealAddr::Inet(socket_addr));
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
                Ok(RealAddr::Inet(SocketAddr::new(ip, port)))
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
        let iface = BindAddr::Socket(SocketBindAddr::Iface(IfaceBindAddr::new(
            "enp17s0",
            IpFamily::V4,
            Port::Special(NonZeroU16::new(1234).unwrap()),
        )));
        assert_eq!(iface.to_string(), "iface://enp17s0/v4/1234");

        // Test internet address display
        let inet = BindAddr::Socket(SocketBindAddr::Inet(InetBindAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::Special(NonZeroU16::new(8080).unwrap()),
        )));
        assert_eq!(inet.to_string(), "inet://127.0.0.1/8080");

        // Test special ports
        let any_port = BindAddr::Socket(SocketBindAddr::Inet(InetBindAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Port::Any,
        )));
        assert_eq!(any_port.to_string(), "inet://127.0.0.1/any");

        let alloc_port = BindAddr::Socket(SocketBindAddr::Inet(InetBindAddr::new(
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
        if let BindAddr::Socket(SocketBindAddr::Iface(iface_addr)) = iface {
            assert_eq!(iface_addr.device_name(), "enp17s0");
            assert_eq!(iface_addr.ip_family(), IpFamily::V4);
            assert_eq!(
                iface_addr.port(),
                Port::Special(NonZeroU16::new(5678).unwrap())
            );
        } else {
            panic!("Expected IfaceBindAddr");
        }

        // Test internet address parsing
        let inet: BindAddr = "inet://127.0.0.1/8080".parse().unwrap();
        if let BindAddr::Socket(SocketBindAddr::Inet(inet_addr)) = inet {
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
        if let BindAddr::Socket(SocketBindAddr::Inet(inet_addr)) = inet6 {
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
        if let BindAddr::Socket(SocketBindAddr::Inet(inet_addr)) = any_port {
            assert_eq!(inet_addr.port(), Port::Any);
        } else {
            panic!("Expected InetBindAddr with any port");
        }

        let alloc_port: BindAddr = "iface://eth0/v4/alloc".parse().unwrap();
        if let BindAddr::Socket(SocketBindAddr::Iface(iface_addr)) = alloc_port {
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
            Err(ParseBindAddrError::InvalidIfaceAddr(_))
        ));

        assert!(matches!(
            "inet://invalid".parse::<BindAddr>(),
            Err(ParseBindAddrError::InvalidInetAddr(_))
        ));
    }

    #[test]
    fn test_bind_addr_from_socket_addr() {
        // Test conversion from SocketAddr with non-zero port
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let bind_addr = BindAddr::from(socket_addr);

        if let BindAddr::Socket(SocketBindAddr::Inet(inet_addr)) = bind_addr {
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
        let iface = IfaceBindAddr::new(
            "wlp18s0",
            IpFamily::V6,
            Port::Special(NonZeroU16::new(443).unwrap()),
        );
        assert_eq!(iface.to_string(), "iface://wlp18s0/v6/443");

        let parsed: IfaceBindAddr = "iface://wlp18s0/v6/443".parse().unwrap();
        assert_eq!(parsed.device_name(), iface.device_name());
        assert_eq!(parsed.ip_family(), iface.ip_family());
        assert_eq!(parsed.port(), iface.port());

        // Test with special ports
        let any_port: IfaceBindAddr = "iface://eth0/v4/any".parse().unwrap();
        assert_eq!(any_port.port(), Port::Any);

        let alloc_port: IfaceBindAddr = "iface://eth0/v4/alloc".parse().unwrap();
        assert!(matches!(alloc_port.port(), Port::Alloc(_)));

        // Test error cases
        assert!(matches!(
            "".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::MissingScheme)
        ));

        assert!(matches!(
            "inet://enp17s0/v4/8080".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::IncorrectScheme)
        ));

        assert!(matches!(
            "iface://".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::MissingDeviceName)
        ));

        assert!(matches!(
            "iface://enp17s0".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::MissingIpFamily)
        ));

        assert!(matches!(
            "iface://enp17s0/v4".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::MissingPort)
        ));

        assert!(matches!(
            "iface://enp17s0/v7/8080".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::InvalidIpFamily(_))
        ));

        assert!(matches!(
            "iface://enp17s0/v4/invalid".parse::<IfaceBindAddr>(),
            Err(ParseIfaceBindAddrError::InvalidPort(_))
        ));
    }

    #[test]
    fn test_inet_bind_addr_display_and_parse() {
        let inet = InetBindAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Port::Special(NonZeroU16::new(80).unwrap()),
        );
        assert_eq!(inet.to_string(), "inet://192.168.1.1/80");

        let parsed: InetBindAddr = "inet://192.168.1.1/80".parse().unwrap();
        assert_eq!(parsed.ip(), inet.ip());
        assert_eq!(parsed.port(), inet.port());

        // Test socket address parsing
        let from_socket: InetBindAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(from_socket.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(
            from_socket.port(),
            Port::Special(NonZeroU16::new(8080).unwrap())
        );

        // Test IPv6 parsing
        let ipv6: InetBindAddr = "inet://::1/443".parse().unwrap();
        assert_eq!(ipv6.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));

        // Test error cases
        assert!(matches!(
            "".parse::<InetBindAddr>(),
            Err(ParseInetBindAddrError::MissingScheme)
        ));

        assert!(matches!(
            "iface://127.0.0.1/8080".parse::<InetBindAddr>(),
            Err(ParseInetBindAddrError::IncorrectScheme)
        ));

        assert!(matches!(
            "inet://invalid_ip/8080".parse::<InetBindAddr>(),
            Err(ParseInetBindAddrError::InvalidIp(_))
        ));

        assert!(matches!(
            "inet://127.0.0.1".parse::<InetBindAddr>(),
            Err(ParseInetBindAddrError::MissingPort)
        ));

        assert!(matches!(
            "inet://127.0.0.1/invalid_port".parse::<InetBindAddr>(),
            Err(ParseInetBindAddrError::InvalidPort(_))
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
    fn test_ip_family_display_and_parse() {
        assert_eq!(IpFamily::V4.to_string(), "v4");
        assert_eq!(IpFamily::V6.to_string(), "v6");

        assert_eq!("v4".parse::<IpFamily>().unwrap(), IpFamily::V4);
        assert_eq!("V4".parse::<IpFamily>().unwrap(), IpFamily::V4);
        assert_eq!("v6".parse::<IpFamily>().unwrap(), IpFamily::V6);
        assert_eq!("V6".parse::<IpFamily>().unwrap(), IpFamily::V6);

        assert!(matches!("v7".parse::<IpFamily>(), Err(InvalidIpFamily(_))));
        assert!(matches!(
            "invalid".parse::<IpFamily>(),
            Err(InvalidIpFamily(_))
        ));
    }

    #[test]
    fn test_real_addr_display_and_parse() {
        let inet = RealAddr::Inet(SocketAddr::new(
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
        let ipv6_inet = RealAddr::Inet(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            8080,
        ));
        let ipv6_socket_parsed: RealAddr = "[fe80::1]:8080".parse().unwrap();
        assert_eq!(ipv6_socket_parsed, ipv6_inet);

        // Test port 0 support (not available in socket address format, only URI)
        let port_zero_uri: RealAddr = "inet://127.0.0.1/0".parse().unwrap();
        assert_eq!(
            port_zero_uri,
            RealAddr::Inet(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        );

        // Test port 0 with socket address format (should work with RealAddr, unlike BindAddr)
        let port_zero_socket: RealAddr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(port_zero_socket, port_zero_uri);

        let ble = RealAddr::Ble([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(ble.to_string(), "ble://[aa, bb, cc, dd, ee, ff]");

        // Test kind method
        assert_eq!(inet.kind(), AddrKind::Ip(IpFamily::V4));
        assert_eq!(ble.kind(), AddrKind::Ble);

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
        let v4_iface = BindAddr::Socket(SocketBindAddr::Iface(IfaceBindAddr::new(
            "eth0",
            IpFamily::V4,
            Port::Any,
        )));
        assert_eq!(v4_iface.kind(), AddrKind::Ip(IpFamily::V4));

        let v6_inet = BindAddr::Socket(SocketBindAddr::Inet(InetBindAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Port::Special(NonZeroU16::new(8080).unwrap()),
        )));
        assert_eq!(v6_inet.kind(), AddrKind::Ip(IpFamily::V6));

        let ble = BindAddr::Bluetooth([0; 6]);
        assert_eq!(ble.kind(), AddrKind::Ble);
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
