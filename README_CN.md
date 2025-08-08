# gm-quic

[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/gm-quic)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)
[![crates.io](https://img.shields.io/crates/v/gm-quic.svg)](https://crates.io/crates/gm-quic)
[![Documentation](https://docs.rs/gm-quic/badge.svg)](https://docs.rs/gm-quic/)

[English](README.md) | 中文

QUIC协议是下一代互联网重要的基础设施，而`gm-quic`则是一个原生异步Rust的QUIC协议实现，一个高效的、可扩展的[RFC 9000][1]实现，同时工程质量优良。
`gm-quic`不仅实现了标准QUIC协议，还额外实现了[RFC 9221 (Unreliable Datagram Extension)][3]、[qlog (QUIC event logging)][2]等扩展。

众所周知，QUIC拥有许多优良特性，以及极致的安全性，十分适合在高性能传输、数据隐私安全、物联网领域推广使用:

**高性能数据传输：**
- 0-RTT握手，最小化建连时延
- 流的多路复用，消除了头端阻塞，提升吞吐率
- 多路径传输，提升传输能力
- BBR等高效的传输控制算法，保证低时延、高带宽利用率

**数据隐私安全：**
- 默认集成TLS 1.3端到端加密
- 实现前向安全密钥和经过身份验证的数据包头，以抵御篡改。

**IoT和边缘计算：**
- 支持连接迁移，以便在网络变化（例如从Wi-Fi切换到蜂窝网络）时保持会话。
- 实现轻量级通信，支持不可靠数据报（RFC 9221），适用于实时物联网场景。

## 设计原则

QUIC协议可谓一个相当复杂的、IO密集型的协议，因此正是适合异步大显身手的地方。异步IO中最基本的事件有数据可读、可写，以及定时器，但纵观整个QUIC协议实现，内部的事件错综复杂、令人眼花缭乱。然而，仔细探查之下还是能发现一些结构，会发现QUIC协议核心是由一层层底层IO事件逐步向上驱动应用层行为的。比如当一个流接收数据至连续，这也是一个事件，将唤醒对应的应用层来读；再比如，当Initial数据交互完毕获得Handshake密钥之后，这也是一个事件，将唤醒Handshake数据包任务的处理。以上这些事件就是经典的Reactor模式，`gm-quic`正是对这些QUIC内部形形色色的Reactor的拆分细化和封装，让各个模块更加独立，让整个系统各模块配合的更加清晰，进而整体设计也更加人性化。

注意到QUIC协议内部，还能分出很多层。在传输层，有很多功能比如打开新连接、接收、发送、读取、写入、Accept新连接，它们大都是异步的，在这里称之为各种“算子”，且每层都有自己的算子，有了这些分层之后，就会发现，其实Accept算子和Read算子、Write算子根本不在同一层，很有意思。

![image](https://github.com/genmeta/gm-quic/blob/main/images/arch.png)


## 概览

- **qbase**: QUIC协议的基础结构，包括可变整型编码VarInt、连接ID管理、流ID、各种帧以及包类型定义、异步密钥等
- **qrecovery**: QUIC的可靠传输部分，包括发送端/接收端的状态机演变、应用层与传输层的内部逻辑交互等
- **qcongestion**: QUIC的拥塞控制，抽象了统一的拥塞控制接口，并实现了BBRv1，未来还会实现Cubic、ETC等更多的传输控制算法
- **qinterface**: QUIC的数据包路由和对底层I/O接口(`QuicIO`)的定义，令gm-quic可以运行在各种环境。内含一个可选的基于qudp的`QuicIO`实现
- **qconnection**： QUIC连接封装，将QUIC连接内部所需的各组件、任务串联起来，最终能够完美运行
- **gm-quic**: QUIC协议的顶层封装，包括QUIC客户端和服务端2部分的接口
- **qudp**： QUIC的高性能UDP封装，使用GSO、GRO等手段极致优化UDP的性能
- **qunreliable**: 基于QUIC的不可靠数据报传输的扩展，相比于直接用UDP发送不可靠数据报，该扩展拥有QUIC的传输控制和极致安全性。详情参考[RFC 9221][3]
- **qevent**: [qlog][2]的实现，支持以json形式记录单个quic连接内部活动，兼容qlog 3，支持[qvis][4]可视化分析。请注意，开启qlog虽有助于分析问题，但相当影响性能

![image](https://github.com/genmeta/gm-quic/blob/main/images/qvis.png?raw=true)

## 使用方式

#### 样例演示

本仓库提供了三组样例：
- `echo-client`和`echo-server`: 位于`gm-quic/examples/`文件夹下，展示了gm-quic的基本使用方法。
- `http-client`和`http-server`: 位于`gm-quic/examples/`文件夹下，展示了在gm-quic上运行HTTP/0.9协议。
- `h3-client`和`h3-server`: 位于`h3-shim/examples/`文件夹下，展示了在gm-quic上运行HTTP/3协议。

以H3为例，运行一个H3服务器:

``` shell
cargo run --example h3-server --package h3-shim -- --dir ./h3-shim
```

发起一个H3请求:

``` shell
cargo run --example h3-client --package h3-shim -- https://localhost:4433/examples/h3-server.rs
```

#### API简介

`gm-quic`提供了人性化的接口创建客户端和服务端的连接，同时还支持一些符合现代网络需求的附加功能设置。

除了可以绑定到ip地址+端口，`gm-quic`还支持绑定到网络接口上，以动态地适应实际地址变化，这使得`gm-quic`拥有了良好的移动性。

QUIC客户端不仅提供了QUIC协议所规定的Parameters选项配置，可选的0RTT功能，还有一些额外的高级选项，比如QUIC客户端可设置自己的证书以供服务端验证，也可设置自己的Token管理器，管理着各服务器颁发的Token，以便未来和这些服务器再次连接时用的上。

QUIC客户端支持多路径握手，即同时尝试连接到服务器的IPv4和IPv6地址，即使某些路径不可达，但只要有一条路径能够联通，连接就可以建立。如果对端的实现同样是gm-quic，则还支持多路径传输。

以下为简单示例，更多细节请参阅文档。

```rust
// 设置根证书存储
let mut roots = rustls::RootCertStore::empty();

// 加载系统证书
roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

// 加载自定义证书（可与系统证书独立使用）
use gm_quic::ToCertificate;
roots.add_parsable_certificates(PathBuf::from("path/to/your/cert.pem").to_certificate()); // 运行时加载
roots.add_parsable_certificates(include_bytes!("path/to/your/cert.pem").to_certificate()); // 编译时嵌入

// 构建QUIC客户端
let quic_client = gm_quic::QuicClient::builder()
    .with_root_certificates(roots)
    .without_cert()                                      // 通常不需要客户端证书验证
    // .with_parameters(your_parameters)                 // 自定义传输参数
    // .bind(["iface://v4.eth0:0", "iface://v6.eth0:0"]) // 绑定到指定网络接口eth0的IPv4和IPv6地址
    // .enable_0rtt()                                    // 启用0-RTT
    // .enable_sslkeylog()                               // 启用SSL密钥日志
    // .with_qlog(Arc::new(gm_quic::handy::LegacySeqLogger::new(
    //     PathBuf::from("/path/to/qlog_dir"),
    // )))                                               // 启用qlog，可用qvis工具可视化
    .build();

// 连接到服务器
let server_addresses = tokio::net::lookup_host("localhost:4433").await?;
let connection = quic_client.connect("localhost", server_addresses)?;

// 开始使用QUIC连接！
// 更多使用示例请参考 gm-quic/examples 和 h3-shim/examples

Ok(())
```

QUIC服务端表现为`QuicListeners`，支持SNI（Server Name Indication），在一个进程启动多个Server，分别有自己的证书和密钥，每个服务端又可以绑定到多个地址上，支持多个Server绑定同一个地址。Client必须正确连接到对应的Server的对应接口上，否则连接会被自动拒绝。

QuicListeners支持通过多种方法验证客客户端的身份，包括通过`client_name`传输参数，验证客户端证书的内容等。QuicListeners还支持抗端口扫描功能，只有在初步验证客户端的身份后才会做出响应。

```rust
// 创建QUIC监听器（每个程序只能有一个实例）
let quic_listeners = gm_quic::QuicListeners::builder()?
    .without_client_cert_verifier()         // 通常不需要客户端证书验证
    // .with_parameters(your_parameters)    // 自定义传输参数
    // .enable_0rtt()                       // 为服务器启用0-RTT
    // .enable_anti_port_scan()             // 抗端口扫描保护
    .listen(8192);                          // 开始监听，设置积压队列（类似Unix listen）

// 添加可连接的服务器
quic_listeners.add_server(
    "localhost",
    // 证书和密钥文件的字节数组或路径
    include_bytes!("/path/to/server.crt"),
    include_bytes!("/path/to/server.key"),
    [
        "192.168.1.106:4433",   // 绑定到此IPv4地址
        "iface://v6.eth0:4433", // 绑定到eth0的IPv6地址
    ],
    None, // ocsp
);

// 继续调用 `quic_listeners.add_server()` 来添加更Server
// 调用 `quic_listeners.remove_server()` 来移除一个Serer

// 接受可信的新连接
while let Ok((connection, server_name, pathway, link)) = quic_listeners.accept().await {
    // 处理传入的QUIC连接！
    // 可以参考 gm-quic/examples 和 h3-shim/examples 中的示例
}
```

关于如何从QUIC Connection中创建单向QUIC流，或者双向QUIC流，抑或是从QUIC Connection监听来自对方的流，都有一套异步的接口，这套接口几乎与[`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport)的接口相同。

至于如何从QUIC流中读写数据，则为QUIC流实现了标准的 **`AsyncRead`** 、 **`AsyncWrite`** 接口，可以很方便地使用。

## 性能

github action会定期运行[基准测试][5]，效果如下。go-quic和quiche、tquic、quinn都具备优良性能，在三种基准测试场景下互有千秋。须知传输性能跟传输控制算法也有很大关系，gm-quic的性能在未来一段时间还会持续优化，如果想获得更高性能，gm-quic提供了抽象接口，可使用DPDK或者XDP代替UdpSocket！

<img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_15KB.png?raw=true" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_30KB.png?raw=true" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_2048KB.png?raw=true" width=33% height=33%>


## 贡献

欢迎所有反馈和PR，包括bug反馈、功能请求、文档修缮、代码重构等。

如果不确定一个功能或者其实现是否合理，请首先在[issue列表](https://github.com/genmeta/gm-quic/issues)中创建一个issue，大家一起讨论，以确保功能是合理的，并有一个良好的实现方案。

## 社区交流

- [用户论坛](https://github.com/genmeta/gm-quic/discussions)
- 聊天群：[发送邮件](mailto:quic_team@genmeta.net)介绍一下您的贡献，我们将邮件回复您加群链接及群二维码。

## Rust版本要求（MSRV）
gm-quic支持的Rust版本为`1.75`及以上版本。

目前的策略是在主要版本更新时改变它。

[1]: https://www.rfc-editor.org/rfc/rfc9000.html
[2]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/
[3]: https://datatracker.ietf.org/doc/html/rfc9221
[4]: https://qvis.quictools.info/#/files
[5]: https://github.com/genmeta/gm-quic/actions
