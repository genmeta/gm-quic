use std::{
    fmt::Display,
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{frame::EncodeSize, net::Family};

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

//TODO：
// Bound address
#[non_exhaustive]
#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BoundAddr {
    /// Internet socket address (IPv4 or IPv6)
    // Iface/Inet => Inet
    Internet(SocketAddr),
    // TODO
    Bluetooth([u8; 6]),
}

impl BoundAddr {
    /// Get the IP protocol family type of the concrete address
    pub fn kind(&self) -> AddrKind {
        match self {
            BoundAddr::Internet(SocketAddr::V4(_)) => AddrKind::Internet(Family::V4),
            BoundAddr::Internet(SocketAddr::V6(_)) => AddrKind::Internet(Family::V6),
            BoundAddr::Bluetooth(_) => AddrKind::Bluetooth,
        }
    }
}

impl EncodeSize for BoundAddr {
    fn encoding_size(&self) -> usize {
        match self {
            BoundAddr::Internet(SocketAddr::V4(_)) => 2 + 4,
            BoundAddr::Internet(SocketAddr::V6(_)) => 2 + 16,
            BoundAddr::Bluetooth(_) => unreachable!(),
        }
    }

    fn max_encoding_size(&self) -> usize {
        18
    }
}

impl Display for BoundAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundAddr::Internet(addr) => write!(f, "{addr}"),
            BoundAddr::Bluetooth(addr) => write!(f, "{addr:02x?}"),
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid real address format")]
pub struct ParseRealAddrError(AddrParseError);

impl FromStr for BoundAddr {
    type Err = ParseRealAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: SocketAddr = s.parse().map_err(ParseRealAddrError)?;
        Ok(BoundAddr::Internet(addr))
    }
}
