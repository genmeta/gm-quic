use std::{
    borrow::Cow,
    fmt::Display,
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};

use derive_more::{Display, From, Into, TryInto};
use http::Uri;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{net::Family, util::UniqueIdGenerator};

#[derive(Debug, Display, Clone, Into, PartialEq, Eq, Hash)]
pub struct BindUri(Uri);

#[derive(Debug, Error)]
pub enum ParseBindUriError {
    #[error("Invalid uri {0}")]
    InvalidUri(<Uri as FromStr>::Err),
    #[error("Missing scheme")]
    MissingSchema,
    #[error("Invalid bind uri scheme: {0}")]
    InvalidSchema(ParseBindUriSchemeError),
    #[error("Path must be empty")]
    HasPath,
    #[error("Missing ip family for iface scheme BindUri")]
    MissingIpFamily,
    #[error("Missing port for iface scheme BindUri")]
    MissingPort,
    #[error("Too many parts for iface scheme BindUri")]
    TooManyParts,
    #[error("Invalid IP address family for iface scheme")]
    InvalidIpFamily,
    #[error("Invalid IP address for inet scheme BindUri: {0}")]
    InvalidIpAddr(AddrParseError),
}

fn parse_iface_bind_uri(uri: &Uri) -> Result<(Family, String, u16), ParseBindUriError> {
    let authority = uri.authority().expect("BindUri is absolute URI");
    let (ip_family, interface) = authority
        .host()
        .split_once('.')
        .ok_or(ParseBindUriError::MissingIpFamily)?;
    if interface.contains('.') {
        return Err(ParseBindUriError::TooManyParts);
    }
    let port = authority.port_u16().ok_or(ParseBindUriError::MissingPort)?;
    let ip_family: Family = ip_family
        .parse()
        .or(Err(ParseBindUriError::InvalidIpFamily))?;
    Ok((ip_family, interface.to_string(), port))
}

fn parse_inet_bind_uri(uri: &Uri) -> Result<SocketAddr, ParseBindUriError> {
    let authority = uri.authority().expect("BindUri is absolute URI");
    let port = authority.port_u16().ok_or(ParseBindUriError::MissingPort)?;
    let host = match authority.host().as_bytes() {
        [b'[', .., b']'] => authority.host().trim_matches(|c| matches!(c, '[' | ']')),
        _ => authority.host(),
    };
    match IpAddr::from_str(host) {
        Ok(ip) => Ok(SocketAddr::new(ip, port)),
        Err(e) => Err(ParseBindUriError::InvalidIpAddr(e)),
    }
}

fn parse_ble_bind_uri(_: &Uri) -> ! {
    unimplemented!("BLE address is not implemented yet")
}

impl FromStr for BindUri {
    type Err = ParseBindUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(socket_addr) = s.parse::<SocketAddr>() {
            return Ok(socket_addr.into());
        }

        let uri: Uri = s.parse().map_err(ParseBindUriError::InvalidUri)?;

        let schema = uri
            .scheme()
            .ok_or(ParseBindUriError::MissingSchema)?
            .as_str()
            .parse()
            .map_err(ParseBindUriError::InvalidSchema)?;
        debug_assert!(uri.authority().is_some(), "BindUri should be absolute URI");

        if uri.path() != "/" {
            return Err(ParseBindUriError::HasPath);
        }

        match schema {
            BindUriSchema::Iface => {
                parse_iface_bind_uri(&uri)?;
            }
            BindUriSchema::Inet => {
                parse_inet_bind_uri(&uri)?;
            }
            BindUriSchema::Ble => {
                parse_ble_bind_uri(&uri);
            }
        }

        Ok(Self(uri))
    }
}

impl From<&str> for BindUri {
    #[inline]
    fn from(value: &str) -> Self {
        match BindUri::from_str(value) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("bind uri should be valid: {e}"),
        }
    }
}

impl From<SocketAddr> for BindUri {
    #[inline]
    fn from(value: SocketAddr) -> Self {
        match BindUri::from_str(&format!("inet://{value}")) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("{e}"),
        }
    }
}

impl<T: Copy + Into<BindUri>> From<&T> for BindUri {
    #[inline]
    fn from(value: &T) -> Self {
        (*value).into()
    }
}

impl BindUri {
    pub fn scheme(&self) -> BindUriSchema {
        self.0
            .scheme()
            .expect("Invalid BindUri: Missing schema")
            .as_str()
            .parse()
            .expect("Invalid BindUri: Invalid schema")
    }

    #[inline]
    pub fn as_uri(&self) -> &Uri {
        &self.0
    }

    pub fn addr_kind(&self) -> AddrKind {
        match self.scheme() {
            BindUriSchema::Iface => AddrKind::Internet(
                self.as_iface_bind_uri()
                    .expect("Already checked BindUriSchema is iface")
                    .0,
            ),
            BindUriSchema::Inet => {
                match self
                    .as_inet_bind_uri()
                    .expect("Already checked BindUriSchema is inet")
                {
                    SocketAddr::V4(_) => AddrKind::Internet(Family::V4),
                    SocketAddr::V6(_) => AddrKind::Internet(Family::V6),
                }
            }
            BindUriSchema::Ble => AddrKind::Bluetooth,
        }
    }

    pub fn as_iface_bind_uri(&self) -> Option<(Family, String, u16)> {
        if self.scheme() != BindUriSchema::Iface {
            return None;
        }
        Some(parse_iface_bind_uri(&self.0).expect("BindUri should be valid"))
    }

    pub fn as_inet_bind_uri(&self) -> Option<SocketAddr> {
        if self.scheme() != BindUriSchema::Inet {
            return None;
        }
        Some(parse_inet_bind_uri(&self.0).expect("BindUri should be valid"))
    }

    pub fn as_ble_bind_uri(&self) -> ! {
        parse_ble_bind_uri(&self.0)
    }

    pub fn add_prop(&mut self, key: &str, value: &str) {
        let mut uri_parts = self.0.clone().into_parts();
        uri_parts.path_and_query = uri_parts.path_and_query.map(|pq| {
            let query = match pq.query() {
                Some(exist_query) => format!("{exist_query}&{key}={value}"),
                None => format!("{key}={value}"),
            };
            format!("{}?{}", pq.path(), query)
                .parse()
                .expect("Path and query should be valid")
        });
        self.0 = Uri::from_parts(uri_parts).expect("BindUri should be valid");
    }

    pub const TEMPORARY: &'static str = "temporary";
    pub const ALLOC_PORT_ID: &'static str = "alloc_port_id";

    pub fn alloc_port(&self) -> Self {
        match self.scheme() {
            BindUriSchema::Iface => {
                let (.., port) = self
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriSchema is iface");
                assert_eq!(port, 0, "Only port 0 is allocatable");
            }
            BindUriSchema::Inet => {
                let addr = self
                    .as_inet_bind_uri()
                    .expect("Already checked BindUriSchema is inet");
                assert_eq!(addr.port(), 0, "Only port 0 is allocatable");
            }
            BindUriSchema::Ble => panic!("BLE address cannot allocate port"),
        }

        let mut new_uri = self.clone();

        static ID_GENERATOR: UniqueIdGenerator = UniqueIdGenerator::new();
        let alloc_port_id = usize::from(ID_GENERATOR.generate()).to_string();
        new_uri.add_prop(Self::ALLOC_PORT_ID, &alloc_port_id);

        new_uri
    }

    #[inline]
    pub fn prop(&self, key: &str) -> Option<Cow<'_, str>> {
        // http://127.0.0.1/fx     ?key=value
        self.0
            .query()?
            .split('&')
            .find_map(|pair| match pair.split_once('=') {
                Some((k, v)) if k == key => Some(Cow::Borrowed(v)),
                None if pair == key => Some(Cow::Borrowed("")),
                _ => None,
            })
    }

    pub fn is_templorary(&self) -> bool {
        match self.prop(Self::TEMPORARY) {
            Some(bool) if bool == "true" => true,
            None | Some(..) => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum TryIntoSocketAddrError {
    #[error("Only inet or iface schema BindUri can be converted to SocketAddr")]
    NotSocketBindUri,
    #[error("Device not found")]
    InterfaceNotFound,
    #[error("Link not found")]
    LinkNotFound,
}

impl TryFrom<&BindUri> for SocketAddr {
    type Error = TryIntoSocketAddrError;

    fn try_from(bind_uri: &BindUri) -> Result<Self, Self::Error> {
        match bind_uri.scheme() {
            BindUriSchema::Iface => {
                let (ip_family, interface, port) = bind_uri
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriSchema is iface");
                let interface = netdev::get_interfaces()
                    .into_iter()
                    .find(|iface| iface.name == interface)
                    .ok_or(TryIntoSocketAddrError::InterfaceNotFound)?;
                let ip_addr = match ip_family {
                    Family::V4 => interface
                        .ipv4
                        .first()
                        .map(|ipnet| ipnet.addr())
                        .map(IpAddr::V4)
                        .ok_or(TryIntoSocketAddrError::LinkNotFound)?,
                    Family::V6 => interface
                        .ipv6
                        .iter()
                        .map(|ipnet| ipnet.addr())
                        .find(|ip| !matches!(ip.octets(), [0xfe, 0x80, ..]))
                        .map(IpAddr::V6)
                        .ok_or(TryIntoSocketAddrError::LinkNotFound)?,
                };

                Ok(SocketAddr::new(ip_addr, port))
            }
            BindUriSchema::Inet => Ok(bind_uri
                .as_inet_bind_uri()
                .expect("Already checked BindUriSchema is inet")),
            BindUriSchema::Ble => Err(TryIntoSocketAddrError::NotSocketBindUri),
        }
    }
}

impl TryFrom<BindUri> for SocketAddr {
    type Error = TryIntoSocketAddrError;

    fn try_from(bind_uri: BindUri) -> Result<Self, Self::Error> {
        SocketAddr::try_from(&bind_uri)
    }
}
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindUriSchema {
    Iface,
    Inet,
    Ble,
}

#[derive(Debug, Error)]
#[error("Expect one of: iface, inet, ble")]
pub struct ParseBindUriSchemeError;

impl FromStr for BindUriSchema {
    type Err = ParseBindUriSchemeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iface" => Ok(BindUriSchema::Iface),
            "inet" => Ok(BindUriSchema::Inet),
            "ble" => Ok(BindUriSchema::Ble),
            _ => Err(ParseBindUriSchemeError),
        }
    }
}

impl Display for BindUriSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindUriSchema::Iface => write!(f, "iface"),
            BindUriSchema::Inet => write!(f, "inet"),
            BindUriSchema::Ble => write!(f, "ble"),
        }
    }
}

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
            RealAddr::Internet(addr) => write!(f, "{addr}"),
            RealAddr::Bluetooth(addr) => write!(f, "{addr:02x?}"),
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid real address format")]
pub struct ParseRealAddrError(AddrParseError);

impl FromStr for RealAddr {
    type Err = ParseRealAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: SocketAddr = s.parse().map_err(ParseRealAddrError)?;
        Ok(RealAddr::Internet(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_uri() {
        assert!(matches!(
            BindUri::from_str("iface://"),
            Err(ParseBindUriError::InvalidUri(_))
        ));
    }

    #[test]
    fn missing_schema() {
        assert!(matches!(
            BindUri::from_str("invalid_uri"),
            Err(ParseBindUriError::MissingSchema)
        ));
    }

    #[test]
    fn invalid_schema() {
        assert!(matches!(
            BindUri::from_str("invalid://example.com"),
            Err(ParseBindUriError::InvalidSchema(_))
        ));
    }

    #[test]
    fn has_path() {
        assert!(matches!(
            BindUri::from_str("iface://v4.wlan0/1234"),
            Err(ParseBindUriError::HasPath)
        ));
    }

    #[test]
    fn missing_ip_family() {
        assert!(matches!(
            BindUri::from_str("iface://wlan0:8080"),
            Err(ParseBindUriError::MissingIpFamily)
        ));
    }

    #[test]
    fn missing_port() {
        assert!(matches!(
            BindUri::from_str("iface://v4.wlan0"),
            Err(ParseBindUriError::MissingPort)
        ));
    }

    #[test]
    fn too_many_parts() {
        assert!(matches!(
            BindUri::from_str("iface://v4.wlan0.extra:8080"),
            Err(ParseBindUriError::TooManyParts)
        ));
    }

    #[test]
    fn invalid_ip_family() {
        assert!(matches!(
            BindUri::from_str("iface://invalid.wlan0:8080"),
            Err(ParseBindUriError::InvalidIpFamily)
        ));
    }

    #[test]
    fn invalid_ip_addr() {
        assert!(matches!(
            BindUri::from_str("inet://example.com:8080"),
            Err(ParseBindUriError::InvalidIpAddr(..))
        ));
    }

    #[test]
    fn iface_bind_uri() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
        assert_eq!(bind_uri.scheme(), BindUriSchema::Iface);
        let (family, interface, port) = bind_uri.as_iface_bind_uri().unwrap();
        assert_eq!(family, Family::V4);
        assert_eq!(interface, "wlan0");
        assert_eq!(port, 8080);
        assert_eq!(bind_uri.prop(BindUri::TEMPORARY).as_deref(), Some("true"));
    }

    #[test]
    fn inet_bind_uri() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:7777").unwrap();
        assert_eq!(bind_uri.scheme(), BindUriSchema::Inet);
        let addr = bind_uri.as_inet_bind_uri().unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 7777)
        );
        assert!(bind_uri.as_uri().query().is_none());
    }

    #[test]
    fn interface_not_found() {
        let bind_uri = BindUri::from_str(
            "iface://v4.ygiubiougbuyasiudbahsdbadfbkjadbhvkjabvckagdoiuehfjoiajhrpfhrbovhaelvkamdjkfs:8080",
        )
        .unwrap();
        assert!(matches!(
            SocketAddr::try_from(bind_uri),
            Err(TryIntoSocketAddrError::InterfaceNotFound)
        ))
    }

    #[test]
    fn to_socket_addr() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
        assert_eq!(
            SocketAddr::try_from(bind_uri).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    #[test]
    fn alloc_port() {
        let bind_uri = BindUri::from_str("inet://0.0.0.0:0").unwrap();
        assert_ne!(bind_uri.clone().alloc_port(), bind_uri.clone().alloc_port());
    }

    #[test]
    #[should_panic]
    fn alloc_port_for_non_zero_port1() {
        let bind_uri = BindUri::from_str("inet://127.0.0.1:8080").unwrap();
        bind_uri.alloc_port();
    }

    #[test]
    #[should_panic]
    fn alloc_port_for_non_zero_port2() {
        let bind_uri = BindUri::from_str("inet://v4.lo:12345").unwrap();
        bind_uri.alloc_port();
    }

    #[test]
    fn temporary() {
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=true").unwrap();
        assert!(bind_uri.is_templorary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=false").unwrap();
        assert!(!bind_uri.is_templorary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(!bind_uri.is_templorary());

        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        bind_uri.add_prop(BindUri::TEMPORARY, "true");
        assert_eq!(
            bind_uri.to_string(),
            "iface://v4.wlan0:8080/?temporary=true"
        );
        assert!(bind_uri.is_templorary());
    }
}
