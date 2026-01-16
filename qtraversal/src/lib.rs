use std::net::SocketAddr;

use qbase::net::route::SocketEndpointAddr;

pub mod addr;
pub mod frame;
mod future;
pub mod nat;
pub mod packet;
pub mod punch;
pub mod route;

pub type Link<A = SocketAddr> = qbase::net::route::Link<A>;
pub type PathWay<E = SocketEndpointAddr> = qbase::net::route::Pathway<E>;
