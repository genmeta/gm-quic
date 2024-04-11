// quic协议的实现

use std::{
    io::Result,
    pin::Pin,
    task::{Context, Poll},
};

struct QuicDriver {
    // 一个协议识别实例，可能是全局的

    // 所有连接ID对应的数据包缓冲列表

    // 所有连接ID的waker哈希表

    // 新连接的Init包的列表

    // Acceptor子waker

    // 协议内部轮询接收子的Handle，drop时要取消该任务
}

impl QuicDriver {
    fn new() -> Self {
        todo!("创建quic协议，并spawn协议内部轮询接收子，不停地收quic协议的数据包")
    }

    fn poll_send(self: Pin<&mut Self>, cx: &mut Context, packet: &Packet) -> Poll<Result<usize>> {
        todo!("将quic数据包编码成Message，并发送")
    }

    fn loop_poll_recv(self: Pin<&mut Self>) {
        todo!("不停地收取数据包，并解析属于那个连接id，将其放到相应连接ID接收队列，并适时唤醒对应连接的waker.如果没找到连接ID，看是否Init包，唤醒Accept子")
    }
}

impl Drop for QuicDriver {
    fn drop(&mut self) {
        todo!("别忘了关停quic内部轮询接收子")
    }
}

mod config;
mod connection;
mod varint;
use connection::Connection;

impl QuicDriver {
    fn poll_accept(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Connection>> {
        todo!("等待新连接的：扫描是否有新的没找到连接id的init数据包到达，无则Pending；有则响应")
    }
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; 20],
}

// quic协议的数据包，有长包头、短包头之分
pub(crate) struct Packet {
    flag: u8,
    version: u8,
    // 如果是发送出去的数据包，这个连接id是对方的连接id
    // 如果是接收到的数据包，这个连接id要路由到本地具体的连接
    // 根据连接ID，能找到对应的path
    dest_cid: ConnectionId,
    // TODO: 区分长包头、短包头
    payload: Vec<u8>,
}

impl QuicDriver {
    fn poll_conn_recv(
        self: Pin<&mut Self>,
        cx: &mut Context,
        cid: &ConnectionId,
    ) -> Poll<Result<Packet>> {
        todo!("一个连接ID，接收数据包；查看该连接ID下是否有数据包，有返回Ready；无则等待，并注册waker待唤醒")
    }

    fn poll_conn_send(
        self: Pin<&mut Self>,
        cx: &mut Context,
        packet: &Packet,
    ) -> Poll<Result<usize>> {
        todo!("一个连接ID发送一个数据包，将数据包打包成message，通过协议底层发送子发送")
    }
}
