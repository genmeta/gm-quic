use std::{
    fmt,
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
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
            EndpointAddr::Direct { addr } => write!(f, "Direct({addr}"),
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
