# gm-quic

`gm-quic`一个用原生异步Rust实现的quic传输协议，一个高效的、可扩展的RFC9000实现，同时工程质量优良，极具学习价值。


## 设计原则

QUIC协议可谓一个相当复杂的、IO密集型的协议，因此正是适合异步大显身手的地方。异步IO中最基本的事件有数据可读、可写，以及定时器，但纵观整个QUIC协议实现，内部的事件错综复杂、令人眼花缭乱。然而，仔细探查之下还是能发现一些结构，会发现QUIC协议核心是由一层层底层IO事件逐步向上驱动应用层行为的。比如当一个流的数据连续，这也是一个事件，将唤醒对应的应用层来读；再比如，当Initial数据交互完毕获得Handshake密钥之后，这也是一个事件，将唤醒Handshake数据包任务的处理。以上这些事件就是经典的Reactor模式，`gm-quic`正是对这些QUIC内部形形色色的Reactor的拆分细化和封装，让各个模块更加独立，让整个系统各模块配合的更加清晰，进而整体设计也更加人性化。

注意到QUIC协议内部，还能分出很多层。在传输层，有很多功能比如打开新连接、接收、发送、读取、写入、Accept新连接，它们大都是异步的，在这里称之为各种“算子”，且每层都有自己的算子，有了这些分层之后，就会发现，其实Accept算子和Read算子、Write算子根本不在同一层，很有意思。

![image](https://github.com/genmeta/gm-quic/blob/main/images/arch.png)


## 概览

- **qbase**: QUIC协议的基础结构，包括可变整型编码VarInt、连接ID管理、流ID、各种帧以及包类型定义、异步密钥等
- **qrecovery**: QUIC的可靠传输部分，包括发送端/接收端的状态机演变、应用层与传输层的内部逻辑交互等
- **qcongestion**: QUIC的拥塞控制，抽象了统一的拥塞控制接口，并实现了BBRv1，未来还会实现Cubic、ETC等更多的传输控制算法
- **qconnection**： QUIC连接封装，将QUIC连接内部所需的各组件、任务串联起来，最终能够完美运行
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

## 进展

`gm-quic`尚未100%完成，但其中大部分基础功能模块都已经可用，仅剩`qconnection`中的查漏补缺和各模块串联，核心团队正努力完成这最后的拼图，敬请期待。

## 文档

在`gm-quic`尚未完成之际，其文档也不会上传托管到`crate.io`。请暂且先查看代码中的文档！

## 贡献

欢迎所有反馈和PR，包括bug反馈、功能请求、文档修缮、代码重构等。但需注意，对于涉及到代码和文档的，`gm-quic`有着极其严格的质量要求，代码、文档质量会经过严格的审查才会合并，请贡献者务必理解并耐心解决完所有意见后，方可合并。

如果不确定一个功能或者其实现是否合理，请首先在[issue列表](https://github.com/genmeta/gm-quic/issues)中创建一个issue，大家一起讨论，以确保功能是合理的，并有一个良好的实现方案。

## 社区交流

- [用户论坛](https://github.com/genmeta/gm-quic/discussions)
- 飞书聊天群：[发送邮件](mailto:quic@genmeta.net)介绍一下您的贡献，我们将邮件回复您加群链接及群二维码。