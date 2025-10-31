use std::net::SocketAddr;

use qbase::net::route::SocketEndpointAddr;

pub mod addr;
pub mod frame;
mod future;
pub mod iface;
pub mod nat;
pub mod packet;
pub mod punch;

pub type Link = qbase::net::route::Link<SocketAddr>;
pub type Pathway = qbase::net::route::Pathway<SocketEndpointAddr>;
