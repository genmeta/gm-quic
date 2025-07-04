use std::{
    convert::Infallible,
    fmt::Display,
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use derive_more::{Deref, From, TryInto};
use serde::{Deserialize, Serialize};

use crate::net::{
    Family,
    addr::{AddrKind, RealAddr},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
}

impl Display for SocketEndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketEndpointAddr::Direct { addr } => write!(f, "Direct({addr})"),
            SocketEndpointAddr::Agent { agent, outer } => write!(f, "Agent({agent}-{outer})"),
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

#[derive(Debug, Clone, Copy, Deref, From, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, From, TryInto, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

impl Display for EndpointAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointAddr::Socket(addr) => addr.fmt(f),
            EndpointAddr::Ble(addr) => addr.fmt(f),
        }
    }
}

impl From<RealAddr> for EndpointAddr {
    fn from(addr: RealAddr) -> Self {
        match addr {
            RealAddr::Internet(socket_addr) => SocketEndpointAddr::direct(socket_addr).into(),
            RealAddr::Bluetooth(ble_addr) => BleEndpontAddr::new(ble_addr).into(),
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pathway<E = EndpointAddr> {
    local: E,
    remote: E,
}

impl<E> Pathway<E> {
    #[inline]
    pub fn new(local: E, remote: E) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> E
    where
        E: Clone,
    {
        self.local.clone()
    }

    #[inline]
    pub fn remote(&self) -> E
    where
        E: Clone,
    {
        self.remote.clone()
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

impl<E: Display> Display for Pathway<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}---{}", self.local, self.remote)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link<A = RealAddr> {
    src: A,
    dst: A,
}

impl<A: Display> Display for Link<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<->{}", self.src, self.dst)
    }
}

impl<A> Link<A> {
    #[inline]
    pub fn new(src: A, dst: A) -> Self {
        Self { src, dst }
    }

    #[inline]
    pub fn src(&self) -> A
    where
        A: Clone,
    {
        self.src.clone()
    }

    #[inline]
    pub fn dst(&self) -> A
    where
        A: Clone,
    {
        self.dst.clone()
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

impl<A, E: From<A>> From<Link<A>> for Pathway<E> {
    fn from(link: Link<A>) -> Self {
        Pathway::new(E::from(link.src), E::from(link.dst))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pathway: Pathway,
    link: Link,
    ttl: u8,
    ecn: Option<u8>,
    seg_size: u16,
}

impl PacketHeader {
    pub fn new(pathway: Pathway, link: Link, ttl: u8, ecn: Option<u8>, seg_size: u16) -> Self {
        Self {
            pathway,
            link,
            ttl,
            ecn,
            seg_size,
        }
    }

    /// Create a new empty packet header for receive packets.
    pub fn empty() -> Self {
        let src = SocketAddr::from(([0, 0, 0, 0], 0));
        let dst = SocketAddr::from(([0, 0, 0, 0], 0));
        let link = Link::new(RealAddr::from(src), RealAddr::from(dst));
        Self::new(link.into(), link, 0, None, 0)
    }

    pub fn pathway(&self) -> Pathway {
        self.pathway
    }

    pub fn link(&self) -> Link {
        self.link
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn ecn(&self) -> Option<u8> {
        self.ecn
    }

    pub fn seg_size(&self) -> u16 {
        self.seg_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_addr_from_str() {
        // Test direct format
        let addr = "127.0.0.1:8080".parse::<SocketEndpointAddr>().unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Direct { .. }));

        // Test agent format
        let addr = "127.0.0.1:8080-192.168.1.1:9000"
            .parse::<SocketEndpointAddr>()
            .unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Agent { .. }));

        // Test with whitespace
        let addr = "  127.0.0.1:8080  -  192.168.1.1:9000  "
            .parse::<SocketEndpointAddr>()
            .unwrap();
        assert!(matches!(addr, SocketEndpointAddr::Agent { .. }));

        // Test invalid format
        assert!("invalid".parse::<SocketEndpointAddr>().is_err());
    }
}
