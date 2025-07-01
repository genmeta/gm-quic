use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    str::FromStr,
};

use bytes::BufMut;
use nom::{
    IResult, Parser,
    combinator::{flat_map, map},
    number::complete::{be_u16, be_u32, be_u128},
};
use serde::{Deserialize, Serialize};

use super::{
    Family,
    addr::{ParseRealAddrError, RealAddr},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EndpointAddr {
    Direct { addr: RealAddr },
    Agent { agent: RealAddr, outer: RealAddr },
}

impl EndpointAddr {
    pub fn direct(addr: impl Into<RealAddr>) -> Self {
        EndpointAddr::Direct { addr: addr.into() }
    }

    pub fn with_agent(agent: impl Into<RealAddr>, outer: impl Into<RealAddr>) -> Self {
        EndpointAddr::Agent {
            agent: agent.into(),
            outer: outer.into(),
        }
    }

    /// Returns the outer addr of this EndpointAddr
    ///
    /// Note: Before successful hole punching with this Endpoint, packets should be sent to the addr
    /// returned by deref() to establish communication. Once hole punching is successful or about to
    /// begin, use the addr returned by this function.
    pub fn addr(&self) -> RealAddr {
        match self {
            EndpointAddr::Direct { addr } => *addr,
            EndpointAddr::Agent { outer, .. } => *outer,
        }
    }

    // pub fn encoding_size(&self) -> usize {
    //     let addr_size = |addr: &RealAddr| {
    //         if addr.is_ipv6() { 2 + 16 } else { 2 + 4 }
    //     };
    //     match self {
    //         EndpointAddr::Direct { addr } => addr_size(addr),
    //         EndpointAddr::Agent {
    //             agent,
    //             outer: inner,
    //         } => addr_size(agent) + addr_size(inner),
    //     }
    // }
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
    type Target = RealAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            EndpointAddr::Direct { addr } => addr,
            EndpointAddr::Agent { agent, .. } => agent,
        }
    }
}

impl FromStr for EndpointAddr {
    type Err = ParseRealAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = s.split_once("-") {
            // Agent format: "inet:1.12.124.56:1234-inet:202.106.68.43:6080"
            let agent: RealAddr = first.trim().parse()?;
            let outer: RealAddr = second.trim().parse()?;
            Ok(EndpointAddr::with_agent(agent, outer))
        } else {
            // Direct format: "1.12.124.56:1234"
            let addr: RealAddr = s.trim().parse()?;
            Ok(EndpointAddr::direct(addr))
        }
    }
}

pub trait WriteEndpointAddr {
    fn put_endpoint_addr(&mut self, endpoint: EndpointAddr);
}

impl<T: BufMut> WriteEndpointAddr for T {
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

pub fn be_endpoint_addr(
    input: &[u8],
    is_relay: bool,
    family: Family,
) -> nom::IResult<&[u8], EndpointAddr> {
    if is_relay {
        let (remain, agent) = be_socket_addr(input, family)?;
        let (remain, outer) = be_socket_addr(remain, family)?;
        Ok((remain, EndpointAddr::Agent { agent, outer }))
    } else {
        let (remain, addr) = be_socket_addr(input, family)?;
        Ok((remain, EndpointAddr::Direct { addr }))
    }
}

pub trait WriteRealAddr {
    fn put_socket_addr(&mut self, addr: &RealAddr);
}

impl<T: BufMut> WriteRealAddr for T {
    fn put_socket_addr(&mut self, addr: &RealAddr) {
        match addr {
            RealAddr::Internet(sock_addr) => {
                self.put_u16(sock_addr.port());
                match sock_addr.ip() {
                    IpAddr::V4(ipv4) => self.put_u32(ipv4.into()),
                    IpAddr::V6(ipv6) => self.put_u128(ipv6.into()),
                }
            }
            _ => {
                unimplemented!("Unix socket addresses are not supported in this context");
            }
        }
    }
}

pub fn be_socket_addr(input: &[u8], family: Family) -> IResult<&[u8], RealAddr> {
    flat_map(be_u16, |port| {
        map(be_ip_addr(family), move |ip| {
            RealAddr::Internet(SocketAddr::new(ip, port))
        })
    })
    .parse(input)
}

pub fn be_ip_addr(family: Family) -> impl Fn(&[u8]) -> IResult<&[u8], IpAddr> {
    move |input| match family {
        Family::V6 => map(be_u128, |ip| IpAddr::V6(Ipv6Addr::from(ip))).parse(input),
        Family::V4 => map(be_u32, |ip| IpAddr::V4(Ipv4Addr::from(ip))).parse(input),
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

impl<T: Into<RealAddr>> ToEndpointAddr for T {
    fn to_endpoint_addr(self) -> EndpointAddr {
        EndpointAddr::direct(self.into())
    }
}

impl<A: Into<RealAddr>, O: Into<RealAddr>> ToEndpointAddr for (A, O) {
    fn to_endpoint_addr(self) -> EndpointAddr {
        EndpointAddr::with_agent(self.0.into(), self.1.into())
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

/// Network way, representing the quadruple of source and destination addres.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Link {
    src: RealAddr,
    dst: RealAddr,
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <-> {}", self.src, self.dst)
    }
}

impl Link {
    #[inline]
    pub fn new(src: impl Into<RealAddr>, dst: impl Into<RealAddr>) -> Self {
        Self {
            src: src.into(),
            dst: dst.into(),
        }
    }

    #[inline]
    pub fn src(&self) -> RealAddr {
        self.src
    }

    #[inline]
    pub fn dst(&self) -> RealAddr {
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

impl From<Link> for Pathway {
    fn from(link: Link) -> Self {
        Pathway::new(
            EndpointAddr::direct(link.src),
            EndpointAddr::direct(link.dst),
        )
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
        let addr = "inet://127.0.0.1/8080".parse::<EndpointAddr>().unwrap();
        assert!(matches!(addr, EndpointAddr::Direct { .. }));

        // Test agent format
        let addr = "inet://127.0.0.1/8080-inet://192.168.1.1/9000"
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Agent { .. }));

        // Test with whitespace
        let addr = "  inet://127.0.0.1/8080  -  inet://192.168.1.1/9000  "
            .parse::<EndpointAddr>()
            .unwrap();
        assert!(matches!(addr, EndpointAddr::Agent { .. }));

        // Test invalid format
        assert!("invalid".parse::<EndpointAddr>().is_err());
    }
}
