use std::{net::SocketAddr, sync::LazyLock};

use dashmap::DashMap;
use qconnection::{connection::QuicConnection, path::Pathway};
use qudp::ArcUsc;

pub mod client;
pub mod server;

pub use client::QuicClient;
pub use server::QuicServer;

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
static _USC_REGISTRY: LazyLock<DashMap<SocketAddr, ArcUsc>> = LazyLock::new(DashMap::new);
/// 全局的QuicConnection注册管理，用于查找已有的QuicConnection，key是初期的Pathway
/// 包括被动接收的连接和主动发起的连接
static _CONNECTIONS: LazyLock<DashMap<Pathway, QuicConnection>> = LazyLock::new(DashMap::new);

#[cfg(test)]
mod tests {}
