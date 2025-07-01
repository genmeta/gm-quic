use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod addr;
pub mod route;
pub mod tx;

/// IP protocol family
///
/// Represents IPv4 or IPv6 protocol family.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4 protocol family
    V4,
    /// IPv6 protocol family
    V6,
}

impl Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Family::V4 => write!(f, "v4"),
            Family::V6 => write!(f, "v6"),
        }
    }
}

/// Invalid IP protocol family error
///
/// Returned when attempting to parse an unsupported IP protocol family string.
///
/// Supported values: `v4`, `V4`, `v6`, `V6`
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("Invalid inet family: {0}")]
pub struct InvalidFamily(String);

impl FromStr for Family {
    type Err = InvalidFamily;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v4" => Ok(Family::V4),
            "v6" => Ok(Family::V6),
            invalid => Err(InvalidFamily(invalid.to_string())),
        }
    }
}

pub trait AddrFamily {
    /// Get the IP protocol family
    ///
    /// Returns `IpFamily::V4` for IPv4 addresses and `IpFamily::V6` for IPv6 addresses.
    fn family(&self) -> Family;
}

impl AddrFamily for std::net::Ipv4Addr {
    fn family(&self) -> Family {
        Family::V4
    }
}

impl AddrFamily for std::net::Ipv6Addr {
    fn family(&self) -> Family {
        Family::V6
    }
}

impl AddrFamily for std::net::IpAddr {
    fn family(&self) -> Family {
        match self {
            std::net::IpAddr::V4(_) => Family::V4,
            std::net::IpAddr::V6(_) => Family::V6,
        }
    }
}

impl AddrFamily for std::net::SocketAddr {
    fn family(&self) -> Family {
        self.ip().family()
    }
}
