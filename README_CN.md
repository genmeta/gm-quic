# gm-quic

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)
[![crates.io](https://img.shields.io/crates/v/gm-quic.svg)](https://crates.io/crates/gm-quic)

[English](README.md) | 中文

QUIC协议是下一代互联网重要的基础设施，而`gm-quic`则是一个原生异步Rust的QUIC协议实现，一个高效的、可扩展的[RFC 9000][1]实现，同时工程质量优良。`qm-quic`的实现，尽量保持了[RFC 9000][1]原汁原味的概念，包括变量、结构命名，都尽力做到与[RFC 9000][1]保持一致，因此`gm-quic`还极具学习价值，[RFC 9000][1]及其相关RFC则是了解`gm-quic`的极佳入门文档。


## 设计原则

QUIC协议可谓一个相当复杂的、IO密集型的协议，因此正是适合异步大显身手的地方。异步IO中最基本的事件有数据可读、可写，以及定时器，但纵观整个QUIC协议实现，内部的事件错综复杂、令人眼花缭乱。然而，仔细探查之下还是能发现一些结构，会发现QUIC协议核心是由一层层底层IO事件逐步向上驱动应用层行为的。比如当一个流接收数据至连续，这也是一个事件，将唤醒对应的应用层来读；再比如，当Initial数据交互完毕获得Handshake密钥之后，这也是一个事件，将唤醒Handshake数据包任务的处理。以上这些事件就是经典的Reactor模式，`gm-quic`正是对这些QUIC内部形形色色的Reactor的拆分细化和封装，让各个模块更加独立，让整个系统各模块配合的更加清晰，进而整体设计也更加人性化。

注意到QUIC协议内部，还能分出很多层。在传输层，有很多功能比如打开新连接、接收、发送、读取、写入、Accept新连接，它们大都是异步的，在这里称之为各种“算子”，且每层都有自己的算子，有了这些分层之后，就会发现，其实Accept算子和Read算子、Write算子根本不在同一层，很有意思。

![image](https://github.com/genmeta/gm-quic/blob/main/images/arch.png)


## 概览

- **qbase**: QUIC协议的基础结构，包括可变整型编码VarInt、连接ID管理、流ID、各种帧以及包类型定义、异步密钥等
- **qrecovery**: QUIC的可靠传输部分，包括发送端/接收端的状态机演变、应用层与传输层的内部逻辑交互等
- **qcongestion**: QUIC的拥塞控制，抽象了统一的拥塞控制接口，并实现了BBRv1，未来还会实现Cubic、ETC等更多的传输控制算法
- **qinterface**: QUIC的数据包路由和对底层IO接口(`QuicInterface`)的定义，令gm-quic可以运行在各种环境。内含一个可选的基于qudp的`QuicInterface`实现
- **qconnection**： QUIC连接封装，将QUIC连接内部所需的各组件、任务串联起来，最终能够完美运行
- **gm-quic**: QUIC协议的顶层封装，包括QUIC客户端和服务端2部分的接口
- **qudp**： QUIC的高性能UDP封装，普通的UDP每收发一个包就是一次系统调用，性能低下。qudp则使用GSO、GRO等手段极致优化UDP的性能，如发送的压测效果如下：

```
> # sendmmsg with gso
> strace -c -e trace=%net ../target/debug/examples/sender --gso
sent 1200000000 bytes
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
100.00    0.191681         660       290           sendmmsg
  0.00    0.000002           0         3           getsockname
  0.00    0.000001           0         2           getsockopt
  0.00    0.000000           0         3           socket
  0.00    0.000000           0         3           bind
  0.00    0.000000           0         1           socketpair
  0.00    0.000000           0        11         2 setsockopt
------ ----------- ----------- --------- --------- ----------------
100.00    0.191684         612       313         2 total

> # sendmmsg without gso
> strace -c -e trace=%net ../target/debug/examples/sender
sent 1200000000 bytes
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
100.00    5.670731         362     15625           sendmmsg
  0.00    0.000118          10        11         2 setsockopt
  0.00    0.000046          15         3           socket
  0.00    0.000028           9         3           bind
  0.00    0.000016           5         3           getsockname
  0.00    0.000014          14         1           socketpair
  0.00    0.000008           4         2           getsockopt
------ ----------- ----------- --------- --------- ----------------
100.00    5.670961         362     15648         2 total
```

## 使用方式

`gm-quic`提供了人性化的接口创建客户端和服务端的连接，同时还支持一些符合现代网络需求的附加功能设置。

QUIC客户端不仅提供了QUIC协议所规定的Parameters选项配置，也有一些额外选项比如复用连接、启用IPv6优先的Happy Eyeballs算法等。更高级地，QUIC客户端可设置自己的证书以供服务端验证，也可设置自己的Token管理器，管理着各服务器颁发的Token，以便未来和这些服务器再次连接时用的上。

```rust
let quic_client = QuicClient::builder()
    // 允许复用到服务器的连接，而不是每次都发起新连接
    .reuse_connection()
    // 自动在连接空闲时发送数据包保持连接活跃
    .defer_idle_timeout(HeartbeatConfig::new(Durnation::from_secs(30)))       
    .prefer_versions([1u32])                      // QUIC的版本协商机制，会优先使用靠前的版本，目前仅支持V1
    // .with_parameter(&client_parameters)        // 不设置即为使用默认参数
    // .with_stream_concurrency_strategy(factory) // 指定流并发策略
    // .with_token_sink(token_sink)               // 管理各服务器颁发的Token
    .with_root_certificates(root_certificates)
    // .with_webpki_verifier(verifier)            // 更高级地验证服务端证书的办法
    .without_cert()                               // 一般客户端不必设置证书
    // 指定客户端怎么绑定接口
    // 默认的接口为qudp提供的高性能实现
    // .with_iface_factory(binder)
    // 令client只使用给定的地址
    // 默认client每次建立连接时会创建一个新的接口，绑定系统随机分配的地址端口
    // 即绑定0.0.0.0:0 或 [::]:0
    // .bind(&local_addrs[..])?
    .build();

let quic_client_conn = quic_client
    .connect("localhost", "127.0.0.1:5000".parse().unwrap())
    .unwrap();
```

QUIC服务端支持SNI（Server Name Indication），可以设置多台Server的名字、证书等信息。

```rust
let quic_server = QuicServer::builder()
    // 同client
    .defer_idle_timeout(HeartbeatConfig::new(Durnation::from_secs(30)))       
    .with_supported_versions([1u32])
    .without_client_cert_verifier()  // 一般不验证客户端身份
    .enable_sni()
    .add_host("www.genmeta.net", www_cert, www_key)
    .add_host("developer.genmeta.net", dev_cert, dev_key)
    .listen(&[
        "[2001:db8::1]:8080".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
    ][..]);

while let Ok(quic_server_conn) = quic_server.accept().await? {
    // 以下为演示
    tokio::spawn(handle_quic_conn(quic_server_conn));
}
```

完整用例请翻阅`h3-shim`，`gm-quic`以及`qconnection`文件夹下的`examples`文件夹。

关于如何从QUIC Connection中创建单向QUIC流，或者双向QUIC流，抑或是从QUIC Connection监听来自对方的流，都有一套异步的接口，这套接口几乎与[`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport)的接口相同。

至于如何从QUIC流中读写数据，则为QUIC流实现了标准的`AsyncRead`、`AsyncWrite`接口，可以很方便地使用。

## 进展

早期版本已经发布，目前仍在不断优化改进中，欢迎使用 :D

## 文档

随版本发布的在线文档位于docs.rs，也可查看代码中的最新文档。

## 贡献

欢迎所有反馈和PR，包括bug反馈、功能请求、文档修缮、代码重构等。但需注意，对于涉及到代码和文档的，`gm-quic`有着极其严格的质量要求，代码、文档质量会经过严格的审查才会合并，请贡献者务必理解并耐心解决完所有意见后，方可合并。

如果不确定一个功能或者其实现是否合理，请首先在[issue列表](https://github.com/genmeta/gm-quic/issues)中创建一个issue，大家一起讨论，以确保功能是合理的，并有一个良好的实现方案。

## 社区交流

- [用户论坛](https://github.com/genmeta/gm-quic/discussions)
- 聊天群：[发送邮件](mailto:quic_team@genmeta.net)介绍一下您的贡献，我们将邮件回复您加群链接及群二维码。

[1]: https://www.rfc-editor.org/rfc/rfc9000.html
