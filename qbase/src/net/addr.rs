use std::{
    convert::Infallible,
    fmt::{self, Display},
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use bytes::BufMut;
use derive_more::{Deref, From, TryInto};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    frame::EncodeSize,
    net::{Family, be_socket_addr},
};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketEndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Agent {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}

impl SocketEndpointAddr {
    pub fn direct(addr: SocketAddr) -> Self {
        SocketEndpointAddr::Direct { addr }
    }

    pub fn with_agent(agent: SocketAddr, outer: SocketAddr) -> Self {
        SocketEndpointAddr::Agent { agent, outer }
    }

    /// Returns the outer addr of this SocketEndpointAddr
    ///
    /// Note: Before successful hole punching with this Endpoint, packets should be sent to the addr
    /// returned by deref() to establish communication. Once hole punching is successful or about to
    /// begin, use the addr returned by this function.
    pub fn addr(&self) -> SocketAddr {
        match self {
            SocketEndpointAddr::Direct { addr } => *addr,
            SocketEndpointAddr::Agent { outer, .. } => *outer,
        }
    }

    pub fn encoding_size(&self) -> usize {
        match self {
            SocketEndpointAddr::Direct {
                addr: SocketAddr::V4(_),
            } => 2 + 4,
            SocketEndpointAddr::Direct {
                addr: SocketAddr::V6(_),
            } => 2 + 16,
            SocketEndpointAddr::Agent {
                agent: SocketAddr::V4(_),
                outer: SocketAddr::V4(_),
            } => 2 + 4 + 2 + 4,
            SocketEndpointAddr::Agent {
                agent: SocketAddr::V6(_),
                outer: SocketAddr::V6(_),
            } => 2 + 16 + 2 + 16,
            _ => unimplemented!("Unix socket addresses are not supported"),
        }
    }
}

pub trait WriteSocketEndpointAddr {
    fn put_socket_endpoint_addr(&mut self, endpoint: SocketEndpointAddr);
}

impl<T: BufMut> WriteSocketEndpointAddr for T {
    fn put_socket_endpoint_addr(&mut self, endpoint: SocketEndpointAddr) {
        use crate::net::WriteSocketAddr;
        match endpoint {
            SocketEndpointAddr::Direct { addr } => self.put_socket_addr(&addr),
            SocketEndpointAddr::Agent {
                agent,
                outer: inner,
            } => {
                self.put_socket_addr(&agent);
                self.put_socket_addr(&inner);
            }
        }
    }
}

pub fn be_socket_endpoint_addr(
    input: &[u8],
    relay: u8,
    family: Family,
) -> nom::IResult<&[u8], SocketEndpointAddr> {
    if relay != 0 {
        let (remain, agent) = be_socket_addr(input, family)?;
        let (remain, outer) = be_socket_addr(remain, family)?;
        Ok((remain, SocketEndpointAddr::with_agent(agent, outer)))
    } else {
        let (remain, addr) = be_socket_addr(input, family)?;
        Ok((remain, SocketEndpointAddr::direct(addr)))
    }
}

impl fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointAddr::Socket(ep) => write!(f, "{ep}"),
            EndpointAddr::Ble(ble) => write!(f, "{ble}"),
        }
    }
}

impl Display for SocketEndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketEndpointAddr::Direct { addr } => write!(f, "{addr}"),
            SocketEndpointAddr::Agent { agent, outer } => write!(f, "{agent}-{outer}"),
        }
    }
}

impl Deref for SocketEndpointAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            SocketEndpointAddr::Direct { addr } => addr,
            SocketEndpointAddr::Agent { agent, .. } => agent,
        }
    }
}

impl FromStr for SocketEndpointAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = s.split_once("-") {
            // Agent format: "inet:1.12.124.56:1234-inet:202.106.68.43:6080"
            let agent = first.trim().parse()?;
            let outer = second.trim().parse()?;
            Ok(SocketEndpointAddr::with_agent(agent, outer))
        } else {
            // Direct format: "1.12.124.56:1234"
            let addr = s.trim().parse()?;
            Ok(SocketEndpointAddr::direct(addr))
        }
    }
}

impl From<SocketAddr> for SocketEndpointAddr {
    fn from(addr: SocketAddr) -> Self {
        SocketEndpointAddr::direct(addr)
    }
}

impl From<(SocketAddr, SocketAddr)> for SocketEndpointAddr {
    fn from((agent, outer): (SocketAddr, SocketAddr)) -> Self {
        SocketEndpointAddr::with_agent(agent, outer)
    }
}

#[derive(
    Debug, Clone, Copy, Deref, From, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct BleEndpontAddr([u8; 6]);

impl BleEndpontAddr {
    pub fn new(addr: [u8; 6]) -> Self {
        BleEndpontAddr(addr)
    }
}

impl Display for BleEndpontAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.0)
    }
}

impl FromStr for BleEndpontAddr {
    type Err = Infallible;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        unimplemented!()
    }
}

#[derive(
    Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum EndpointAddr {
    Socket(SocketEndpointAddr),
    Ble(BleEndpontAddr),
}

impl EndpointAddr {
    pub fn addr_kind(&self) -> AddrKind {
        match self {
            EndpointAddr::Socket(addr) => AddrKind::Internet(match addr.deref() {
                SocketAddr::V4(..) => Family::V4,
                SocketAddr::V6(..) => Family::V6,
            }),
            EndpointAddr::Ble(_) => AddrKind::Bluetooth,
        }
    }
}

impl From<BoundAddr> for EndpointAddr {
    fn from(addr: BoundAddr) -> Self {
        match addr {
            BoundAddr::Internet(socket_addr) => SocketEndpointAddr::direct(socket_addr).into(),
            BoundAddr::Bluetooth(ble_addr) => BleEndpontAddr::new(ble_addr).into(),
        }
    }
}

impl From<SocketAddr> for EndpointAddr {
    fn from(addr: SocketAddr) -> Self {
        SocketEndpointAddr::from(addr).into()
    }
}

impl From<(SocketAddr, SocketAddr)> for EndpointAddr {
    fn from((agent, outer): (SocketAddr, SocketAddr)) -> Self {
        SocketEndpointAddr::from((agent, outer)).into()
    }
}

impl From<[u8; 6]> for EndpointAddr {
    fn from(addr: [u8; 6]) -> Self {
        BleEndpontAddr::from(addr).into()
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
