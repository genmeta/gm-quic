use std::{
    borrow::Cow,
    fmt::Display,
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use derive_more::{Display, Into};
use http::Uri;
use qbase::{
    net::{Family, addr::AddrKind},
    util::UniqueIdGenerator,
};
use thiserror::Error;

#[derive(Debug, Display, Clone, Into, PartialEq, Eq, Hash)]
pub struct BindUri(Arc<Uri>);

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
    #[error("Invalid IP address family for iface scheme")]
    InvalidIpFamily,
    #[error("Invalid IP address for inet scheme BindUri: {0}")]
    InvalidIpAddr(AddrParseError),
}

fn parse_iface_bind_uri(uri: &Uri) -> Result<(Family, &str, u16), ParseBindUriError> {
    let authority = uri.authority().expect("BindUri is absolute URI");
    let (ip_family, interface) = authority
        .host()
        .split_once('.')
        .ok_or(ParseBindUriError::MissingIpFamily)?;
    let port = authority.port_u16().ok_or(ParseBindUriError::MissingPort)?;
    let ip_family: Family = ip_family
        .parse()
        .or(Err(ParseBindUriError::InvalidIpFamily))?;
    Ok((ip_family, interface, port))
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

        Ok(Self(Arc::new(uri)))
    }
}

impl From<String> for BindUri {
    #[inline]
    fn from(value: String) -> Self {
        match BindUri::from_str(&value) {
            Ok(bind_uri) => bind_uri,
            Err(e) => panic!("bind uri should be valid: {e}"),
        }
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
    pub const TEMPORARY_PROP: &str = "temporary";
    pub const STUN_PROP: &str = "stun";
    pub const STUN_SERVER_PROP: &str = "stun_server";
    pub const RELAY_PROP: &str = "relay";

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

    pub fn as_iface_bind_uri(&self) -> Option<(Family, &str, u16)> {
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

    fn uri_mut(&mut self) -> &mut Uri {
        Arc::make_mut(&mut self.0)
    }

    pub fn add_prop(&mut self, key: &str, value: &str) {
        let uri = self.uri_mut();
        let mut uri_parts = uri.clone().into_parts();
        uri_parts.path_and_query = uri_parts.path_and_query.map(|pq| {
            let query = match pq.query() {
                Some(exist_query) => format!("{exist_query}&{key}={value}"),
                None => format!("{key}={value}"),
            };
            format!("{}?{}", pq.path(), query)
                .parse()
                .expect("Path and query should be valid")
        });
        *uri = Uri::from_parts(uri_parts).expect("BindUri should be valid");
    }

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

    pub fn is_temporary(&self) -> bool {
        match self.prop(Self::TEMPORARY_PROP) {
            Some(bool) if bool == "true" => true,
            None | Some(..) => false,
        }
    }

    pub fn enable_stun(&mut self) {
        self.add_prop(Self::STUN_PROP, "true");
    }

    pub fn is_stun_enabled(&self) -> bool {
        match self.prop(Self::STUN_PROP) {
            Some(bool) if bool == "true" => true,
            None | Some(..) => false,
        }
    }

    pub fn with_stun_server(&mut self, stun_server: &str) {
        self.add_prop(Self::STUN_SERVER_PROP, stun_server);
    }

    pub fn stun_server(&self) -> Option<Cow<'_, str>> {
        self.prop(Self::STUN_SERVER_PROP)
    }

    pub fn with_relay(&mut self, relay: &str) {
        self.add_prop(Self::RELAY_PROP, relay);
    }

    pub fn relay(&self) -> Option<Cow<'_, str>> {
        self.prop(Self::RELAY_PROP)
    }

    pub fn resolve(&self) -> Result<SocketAddr, TryIntoSocketAddrError> {
        match self.scheme() {
            BindUriSchema::Iface => {
                let (ip_family, interface, port) = self
                    .as_iface_bind_uri()
                    .expect("Already checked BindUriSchema is iface");

                let devices = crate::device::Devices::global();
                devices
                    .get(interface)
                    .ok_or(TryIntoSocketAddrError::InterfaceNotFound)?;
                let ip_addr = devices
                    .resolve(interface, ip_family)
                    .ok_or(TryIntoSocketAddrError::LinkNotFound)?;

                Ok(SocketAddr::new(ip_addr, port))
            }
            BindUriSchema::Inet => Ok(self
                .as_inet_bind_uri()
                .expect("Already checked BindUriSchema is inet")),
            BindUriSchema::Ble => Err(TryIntoSocketAddrError::NotSocketBindUri),
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
        bind_uri.resolve()
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

impl BindUriSchema {
    pub const fn to_str(&self) -> &'static str {
        match self {
            BindUriSchema::Iface => "iface",
            BindUriSchema::Inet => "inet",
            BindUriSchema::Ble => "ble",
        }
    }
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
        assert_eq!(
            bind_uri.prop(BindUri::TEMPORARY_PROP).as_deref(),
            Some("true")
        );
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

    // tokio runtime requeired for device listing
    #[tokio::test]
    async fn interface_not_found() {
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
        assert!(bind_uri.is_temporary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?temporary=false").unwrap();
        assert!(!bind_uri.is_temporary());
        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(!bind_uri.is_temporary());
        let bind_uri =
            BindUri::from_str("iface://v4.C5563ED1-2BC9-42C5-8177-59F2F0AF37C8:8080").unwrap();
        assert!(!bind_uri.is_temporary());

        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        bind_uri.add_prop(BindUri::TEMPORARY_PROP, "true");
        assert_eq!(
            bind_uri.to_string(),
            "iface://v4.wlan0:8080/?temporary=true"
        );
        assert!(bind_uri.is_temporary());
    }

    #[test]
    fn stun_enabled() {
        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(!bind_uri.is_stun_enabled());

        bind_uri.enable_stun();
        assert!(bind_uri.is_stun_enabled());

        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=true").unwrap();
        assert!(bind_uri.is_stun_enabled());

        let bind_uri = BindUri::from_str("iface://v4.wlan0:8080?stun=false").unwrap();
        assert!(!bind_uri.is_stun_enabled());
    }

    #[test]
    fn stun_server() {
        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(bind_uri.stun_server().is_none());

        bind_uri.with_stun_server("stun.example.com:3478");
        assert_eq!(
            bind_uri.stun_server().as_deref(),
            Some("stun.example.com:3478")
        );

        let bind_uri =
            BindUri::from_str("iface://v4.wlan0:8080?stun_server=stun.l.google.com:19302").unwrap();
        assert_eq!(
            bind_uri.stun_server().as_deref(),
            Some("stun.l.google.com:19302")
        );
    }

    #[test]
    fn relay() {
        let mut bind_uri = BindUri::from_str("iface://v4.wlan0:8080").unwrap();
        assert!(bind_uri.relay().is_none());

        bind_uri.with_relay("turn.example.com:3478");
        assert_eq!(bind_uri.relay().as_deref(), Some("turn.example.com:3478"));

        let bind_uri =
            BindUri::from_str("iface://v4.wlan0:8080?relay=turn.l.google.com:19302").unwrap();
        assert_eq!(bind_uri.relay().as_deref(), Some("turn.l.google.com:19302"));
    }
}
