use std::{
    fmt::Display,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AbstractAddress {
    Iface(InterfaceAddress),
    Inet(SocketAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

impl Display for AbstractAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbstractAddress::Iface(iface) => write!(f, "iface:{iface}"),
            AbstractAddress::Inet(addr) => write!(f, "inet:{addr}"),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseAbstractAddressError {
    #[error("Missing scheme in abstract address")]
    MissingScheme,
    #[error("Invalid scheme in abstract address: {0}")]
    InvalidScheme(String),
    #[error("Invalid interface address: {0}")]
    InvalidIfaceAddress(ParseInterfaceAddressError),
    #[error("Invalid inet address: {0}")]
    InvalidInetAddress(AddrParseError),
}

impl FromStr for AbstractAddress {
    type Err = ParseAbstractAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, address) = s
            .split_once(':')
            .ok_or(ParseAbstractAddressError::MissingScheme)?;
        match scheme {
            "iface" => address
                .parse()
                .map(AbstractAddress::Iface)
                .map_err(ParseAbstractAddressError::InvalidIfaceAddress),
            "inet" => address
                .parse()
                .map(AbstractAddress::Inet)
                .map_err(ParseAbstractAddressError::InvalidInetAddress),
            invalid => Err(ParseAbstractAddressError::InvalidScheme(
                invalid.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    device_name: String,
    ip_family: IpFamily,
}

impl Display for InterfaceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.device_name, self.ip_family)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseInterfaceAddressError {
    #[error("Missing device name in interface address")]
    MissingDeviceName,
    #[error("Missing IP family in interface address")]
    MissingIpFamily,
    #[error("Invalid IP family in interface address: {0}")]
    InvalidIpFamily(InvalidIpFamily),
}

impl FromStr for InterfaceAddress {
    type Err = ParseInterfaceAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseInterfaceAddressError::MissingDeviceName);
        }
        let (device_name, ip_family) = s
            .split_once(':')
            .ok_or(ParseInterfaceAddressError::MissingIpFamily)?;
        let ip_family = ip_family
            .parse()
            .map_err(ParseInterfaceAddressError::InvalidIpFamily)?;
        Ok(Self {
            device_name: device_name.to_owned(),
            ip_family,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QuicAddress {
    // Iface/Inet => Inet
    Inet(SocketAddr),
    // Future: Bluetooth, UnixSocket, etc.
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_abstract_address_display() {
        let iface = AbstractAddress::Iface(InterfaceAddress {
            device_name: "enp17s0".to_string(),
            ip_family: IpFamily::V4,
        });
        assert_eq!(iface.to_string(), "iface:enp17s0:v4");

        let inet = AbstractAddress::Inet(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ));
        assert_eq!(inet.to_string(), "inet:127.0.0.1:8080");
    }

    #[test]
    fn test_abstract_address_from_str() {
        let iface: AbstractAddress = "iface:enp17s0:v4".parse().unwrap();
        assert_eq!(
            iface,
            AbstractAddress::Iface(InterfaceAddress {
                device_name: "enp17s0".to_string(),
                ip_family: IpFamily::V4,
            })
        );

        let inet: AbstractAddress = "inet:127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            inet,
            AbstractAddress::Inet(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8080
            ))
        );

        let inet: AbstractAddress = "inet:[fe80::1]:8081".parse().unwrap();
        assert_eq!(
            inet,
            AbstractAddress::Inet(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                8081
            ))
        );

        // Test error cases
        assert!(matches!(
            "".parse::<AbstractAddress>(),
            Err(ParseAbstractAddressError::MissingScheme)
        ));

        assert!(matches!(
            "unknown:value".parse::<AbstractAddress>(),
            Err(ParseAbstractAddressError::InvalidScheme(_))
        ));

        assert!(matches!(
            "iface:".parse::<AbstractAddress>(),
            Err(ParseAbstractAddressError::InvalidIfaceAddress(_))
        ));

        assert!(matches!(
            "inet:invalid".parse::<AbstractAddress>(),
            Err(ParseAbstractAddressError::InvalidInetAddress(_))
        ));
    }

    #[test]
    fn test_interface_address_display_and_parse() {
        let iface = InterfaceAddress {
            device_name: "wlp18s0".to_string(),
            ip_family: IpFamily::V6,
        };
        assert_eq!(iface.to_string(), "wlp18s0:v6");

        let parsed: InterfaceAddress = "wlp18s0:v6".parse().unwrap();
        assert_eq!(parsed, iface);

        // Test error cases
        assert!(matches!(
            "".parse::<InterfaceAddress>(),
            Err(ParseInterfaceAddressError::MissingDeviceName)
        ));

        assert!(matches!(
            "enp17s0".parse::<InterfaceAddress>(),
            Err(ParseInterfaceAddressError::MissingIpFamily)
        ));

        assert!(matches!(
            "enp17s0:v7".parse::<InterfaceAddress>(),
            Err(ParseInterfaceAddressError::InvalidIpFamily(_))
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
