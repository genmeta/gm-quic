use std::{net, ops::Deref};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endpoint {
    Direct {
        addr: net::SocketAddr,
    },
    Relay {
        agent: net::SocketAddr,
        inner: net::SocketAddr,
    },
}

impl Deref for Endpoint {
    type Target = net::SocketAddr;

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

    pub fn src(&self) -> net::SocketAddr {
        match self.local {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }

    pub fn dst(&self) -> net::SocketAddr {
        match self.remote {
            Endpoint::Direct { addr } => addr,
            Endpoint::Relay { agent, .. } => agent,
        }
    }
}
