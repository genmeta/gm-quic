// 这里封装协议识别层

use std::{io::Result, net::{UdpSocket, SocketAddr}, task::{Context, Poll}, pin::Pin};

// 所有协议列表
#[repr(u8)]
enum Proto {
    STUN,
    QUIC,
}

// 所有协议在这里注册，一个协议只能有一个实例
struct Protocol {
    // raw io实例

    // 各个协议的接收数据包列表

    // 各个协议的waker哈希表

    // 不停的读取数据包的task的handle
}

impl Protocol {
    fn new(fd: UdpSocket) -> Self {
        todo!("创建Protocol实例，并spawn永不停歇的任务，不停地读数据包、分析数据包、入各协议队列、唤醒各个协议")
    }

    fn poll_send(self: Pin<&mut Self>, cx: &mut Context, packet: &Message) -> Poll<Result<usize>> {
        todo!("inline函数，调用原始发送子")
    }

    fn loop_poll_recv(self: Pin<&mut Self>) {
        todo!("不停地调用原始接收子，接收到数据包解析，放入协议队列，并适时唤醒各协议的接收子")
    }
}

impl Drop for Protocol {
    fn drop(&mut self) {
        todo!("别忘了将不停向原始io读取数据包的内部轮询接收子task取消")
    }
}

struct Path {
    // 发送时，src可为None；若显式指定了src addr，则要找绑定了src addr的socket来发送。
    // 实际上，只有一个socket的情况下，是没有意义的。
    // 接收时，会通过cmsg获取到本地地址。
    local: Option<SocketAddr>,
    // 发送时的目标地址，必须的
    // 接收时，代表对方地址
    remote: SocketAddr,
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    #[doc(hidden)]
    Ect0 = 0b10,
    #[doc(hidden)]
    Ect1 = 0b01,
    #[doc(hidden)]
    Ce = 0b11,
}

struct Message {
    path: Path,
    // Explicit congestion notification bits to set on the packet
    ecn: Option<EcnCodepoint>,
    // 若不为None，表示设定ttl发送 或者 读取到的数据包的ttl
    ttl: Option<u8>,
    // 内容，带着所有权的内容
    content: Vec<u8>,
}

// 实现quic协议的收发包
impl Protocol {
    fn poll_quic_recv(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Message>> {
        todo!("查看有没有quic协议的包可读，有则返回；无则将quic协议的waker注册，等读到了再唤醒")
    }

    fn poll_quic_send(self: Pin<&mut Self>, cx: &mut Context, packet: &Message) -> Poll<Result<usize>> {
        todo!("直接调用原始io的发送数据包能力即可，原始io发送子已经将waker注册了")
    }
}

// 实现stun协议的收发包
impl Protocol {
    fn poll_stun_recv(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Message>> {
        todo!("查看有没有stun协议的包可读，有则返回；无则将stun协议的waker注册，等读到了再唤醒之")
    }

    fn poll_stun_send(self: Pin<&mut Self>, cx: &mut Context, packet: &Message) -> Poll<Result<usize>> {
        todo!("直接调用原始io发送子")
    }
}