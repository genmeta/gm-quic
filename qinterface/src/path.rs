use std::{net::SocketAddr, ops::Deref};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    Direct {
        addr: SocketAddr,
    },
    Relay {
        agent: SocketAddr,
        inner: SocketAddr,
    },
}

impl Deref for Endpoint {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        match self {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { inner, .. } => inner,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pathway {
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl Pathway {
    pub fn new(local: Endpoint, remote: Endpoint) -> Self {
        Self { local, remote }
    }

    pub fn flip(self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }

    pub fn src(&self) -> SocketAddr {
        match self.local {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }

    pub fn dst(&self) -> SocketAddr {
        match self.remote {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }
}
