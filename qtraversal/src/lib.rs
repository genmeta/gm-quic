use qbase::net::addr::EndpointAddr;

pub mod addr;
mod future;
pub mod nat;
pub mod packet;
pub mod punch;
pub mod route;

pub type PathWay<E = EndpointAddr> = qbase::net::route::Pathway<E>;
