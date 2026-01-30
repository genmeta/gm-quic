use std::net::SocketAddr;

use qbase::net::addr::SocketEndpointAddr;

pub mod addr;
pub mod frame;
mod future;
pub mod nat;
pub mod packet;
pub mod punch;
pub mod resolver;
pub mod route;

pub use resolver::Resolve;

pub type Link<A = SocketAddr> = qbase::net::route::Link<A>;
pub type PathWay<E = SocketEndpointAddr> = qbase::net::route::Pathway<E>;
