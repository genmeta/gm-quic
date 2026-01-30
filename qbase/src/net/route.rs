use std::{
    convert::Infallible,
    fmt::{self, Display},
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use bytes::BufMut;
use derive_more::{Deref, From, TryInto};
use nom::number::streaming::be_u8;
use serde::{Deserialize, Serialize};

use crate::{
    frame::EncodeSize,
    net::{
        Family,
        addr::{AddrKind, BoundAddr},
        be_socket_addr,
    },
};

// 放到 addr
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub fn map<E1>(self, mut f: impl FnMut(E) -> E1) -> Pathway<E1> {
        Pathway {
            local: f(self.local),
            remote: f(self.remote),
        }
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

impl From<Pathway<SocketEndpointAddr>> for Pathway<EndpointAddr> {
    fn from(value: Pathway<SocketEndpointAddr>) -> Self {
        Pathway::new(
            EndpointAddr::Socket(value.local),
            EndpointAddr::Socket(value.remote),
        )
    }
}

impl TryInto<Pathway<SocketEndpointAddr>> for Pathway<EndpointAddr> {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Pathway<SocketEndpointAddr>, Self::Error> {
        match (self.local, self.remote) {
            (EndpointAddr::Socket(local), EndpointAddr::Socket(remote)) => {
                Ok(Pathway::new(local, remote))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid socket endpoint address type",
            )),
        }
    }
}

impl<E: Display> Display for Pathway<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}---{}", self.local, self.remote)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link<A = BoundAddr> {
    src: A,
    dst: A,
}

impl<A: Display> Display for Link<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<->{}", self.src, self.dst)
    }
}

pub fn be_link(input: &[u8]) -> nom::IResult<&[u8], Link<SocketAddr>> {
    let (remain, family) = be_u8(input)?;
    let family = match family {
        0 => Family::V4,
        1 => Family::V6,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )));
        }
    };
    let (remain, src) = be_socket_addr(remain, family)?;
    let (remain, dst) = be_socket_addr(remain, family)?;
    Ok((remain, Link::<SocketAddr> { src, dst }))
}

pub trait WriteLink {
    fn put_link(&mut self, link: &Link<SocketAddr>);
}

impl<T: BufMut> WriteLink for T {
    fn put_link(&mut self, link: &Link<SocketAddr>) {
        use crate::net::WriteSocketAddr;
        self.put_u8(link.src().is_ipv6() as u8);
        self.put_socket_addr(&link.src);
        self.put_socket_addr(&link.dst);
    }
}

impl From<Link<SocketAddr>> for Link<BoundAddr> {
    fn from(value: Link<SocketAddr>) -> Self {
        Self {
            src: BoundAddr::from(value.src),
            dst: BoundAddr::from(value.dst),
        }
    }
}

impl TryInto<Link<SocketAddr>> for Link<BoundAddr> {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Link<SocketAddr>, Self::Error> {
        match (self.src, self.dst) {
            (BoundAddr::Internet(src), BoundAddr::Internet(dst)) => Ok(Link::new(src, dst)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid socket address type",
            )),
        }
    }
}

impl EncodeSize for Link<SocketAddr> {
    fn max_encoding_size(&self) -> usize {
        1 + self.src.max_encoding_size() + self.dst.max_encoding_size()
    }

    fn encoding_size(&self) -> usize {
        1 + self.src.encoding_size() + self.dst.encoding_size()
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
    pub fn map<A1>(self, mut f: impl FnMut(A) -> A1) -> Link<A1> {
        Link {
            src: f(self.src),
            dst: f(self.dst),
        }
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
        let link = Link::new(BoundAddr::from(src), BoundAddr::from(dst));
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
