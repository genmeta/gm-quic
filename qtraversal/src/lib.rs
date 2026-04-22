use qbase::net::addr::SocketEndpointAddr;

pub mod addr;
mod future;
pub mod nat;
pub mod packet;
pub mod punch;
pub mod route;

pub type PathWay<E = SocketEndpointAddr> = qbase::net::route::Pathway<E>;
