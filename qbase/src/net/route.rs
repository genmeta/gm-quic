use std::{
    fmt,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    combinator::{flat_map, map},
    number::streaming::{be_u16, be_u32, be_u128},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Agent {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}

impl EndpointAddr {
    pub fn direct(addr: SocketAddr) -> Self {
        EndpointAddr::Direct { addr }
    }

    pub fn with_agent(agent: SocketAddr, outer: SocketAddr) -> Self {
        EndpointAddr::Agent { agent, outer }
    }

    pub fn addr(&self) -> SocketAddr {
        match self {
            EndpointAddr::Direct { addr } => *addr,
            EndpointAddr::Agent { agent, .. } => *agent,
        }
    }
}

impl fmt::Display for EndpointAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointAddr::Direct { addr } => write!(f, "Direct({addr})"),
            EndpointAddr::Agent { agent, outer } => write!(f, "Agent({agent}-{outer})"),
        }
    }
}

impl Deref for EndpointAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Agent { agent, .. } => agent,
        }
    }
}

impl FromStr for EndpointAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = s.split_once("-") {
            // Agent format: "1.12.124.56:1234-202.106.68.43:6080"
            let agent = first.trim().parse()?;
            let outer = second.trim().parse()?;
            Ok(EndpointAddr::with_agent(agent, outer))
        } else {
            // Direct format: "1.12.124.56:1234"
            let addr = s.trim().parse()?;
            Ok(EndpointAddr::direct(addr))
        }
    }
}

pub trait PutEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: EndpointAddr);
}

impl<T: BufMut> PutEndpointAddr for T {
    fn put_endpoint_addr(&mut self, endpoint: EndpointAddr) {
        match endpoint {
            EndpointAddr::Direct { addr } => self.put_socket_addr(&addr),
            EndpointAddr::Agent {
                agent,
                outer: inner,
            } => {
                self.put_socket_addr(&agent);
                self.put_socket_addr(&inner);
            }
        }
    }
}

pub trait PutSocketAddr {
    fn put_socket_addr(&mut self, addr: &SocketAddr);
}

impl<T: BufMut> PutSocketAddr for T {
    fn put_socket_addr(&mut self, addr: &SocketAddr) {
        self.put_u16(addr.port());
        match addr.ip() {
            IpAddr::V4(ipv4) => self.put_u32(ipv4.into()),
            IpAddr::V6(ipv6) => self.put_u128(ipv6.into()),
        }
    }
}

pub fn be_socket_addr(input: &[u8], is_ipv6: bool) -> IResult<&[u8], SocketAddr> {
    flat_map(be_u16, |port| {
        map(be_ip_addr(is_ipv6), move |ip| SocketAddr::new(ip, port))
    })
    .parse(input)
}

pub fn be_ip_addr(is_v6: bool) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match is_v6 {
        true => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        false => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
    }
}

pub trait ToEndpointAddr {
    fn to_endpoint_addr(self) -> EndpointAddr;
}

impl ToEndpointAddr for EndpointAddr {
    fn to_endpoint_addr(self) -> EndpointAddr {
        self
    }
}

impl ToEndpointAddr for SocketAddr {
    fn to_endpoint_addr(self) -> EndpointAddr {
        EndpointAddr::direct(self)
    }
}

impl ToEndpointAddr for &'static str {
    fn to_endpoint_addr(self) -> EndpointAddr {
        SocketAddr::from_str(self).unwrap().to_endpoint_addr()
    }
}

impl ToEndpointAddr for String {
    fn to_endpoint_addr(self) -> EndpointAddr {
        EndpointAddr::from_str(self.as_str()).unwrap()
    }
}

impl ToEndpointAddr for (SocketAddr, SocketAddr) {
    fn to_endpoint_addr(self) -> EndpointAddr {
        EndpointAddr::with_agent(self.0, self.1)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Pathway {
    local: EndpointAddr,
    remote: EndpointAddr,
}

impl fmt::Display for Pathway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.local, self.remote)
    }
}

impl Pathway {
    #[inline]
    pub fn new(local: EndpointAddr, remote: EndpointAddr) -> Self {
        Self { local, remote }
    }

    #[inline]
    pub fn local(&self) -> EndpointAddr {
        self.local
    }

    #[inline]
    pub fn remote(&self) -> EndpointAddr {
        self.remote
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

/// Network way, representing the quadruple of source and destination addresses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link {
    src: SocketAddr,
    dst: SocketAddr,
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <-> {}", self.src, self.dst)
    }
}

impl Link {
    #[inline]
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    #[inline]
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    #[inline]
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }

    #[inline]
    pub fn flip(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
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
        let way = Pathway::new(src.to_endpoint_addr(), dst.to_endpoint_addr());
        let link = Link::new(src, dst);
        Self::new(way, link, 0, None, 0)
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
        let addr = "127.0.0.1:8080".parse::<EndpointAddr>().unwrap();
        assert!(matches!(addr, EndpointAddr::Direct { .. }));

        // Test agent format
        let addr = "127.0.0.1:8080-192.168.1.1:9000"
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Agent { .. }));

        // Test with whitespace
        let addr = "  127.0.0.1:8080  -  192.168.1.1:9000  "
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Agent { .. }));

        // Test invalid format
        assert!("invalid".parse::<EndpointAddr>().is_err());
    }
}
