# gm-quic

[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/gm-quic)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)
[![crates.io](https://img.shields.io/crates/v/gm-quic.svg)](https://crates.io/crates/gm-quic)
[![Documentation](https://docs.rs/gm-quic/badge.svg)](https://docs.rs/gm-quic/)

English | [中文](README_CN.md)

The QUIC protocol is an important infrastructure for the next generation Internet, and `gm-quic` is a native asynchronous Rust implementation of the QUIC protocol, an efficient and scalable [RFC 9000][1] implementation with excellent engineering quality.
`gm-quic` not only implements the standard QUIC protocol but also includes additional extensions such as [RFC 9221 (Unreliable Datagram Extension)][3] and [qlog (QUIC event logging)][2]. Furthermore, it provides [a pure QUIC-based SSH][4] key exchange implementation demonstrating secure authentication mechanisms over QUIC.

As widely recognized, QUIC possesses numerous advanced features and unparalleled security, making it highly suitable for applications in:

**High-performance data transmission:**
- Achieves 0-RTT connection establishment to minimize latency.
- Utilizes multiplexed streams to eliminate head-of-line blocking and improve throughput.
- Multi-path transmission to improve transmission capacity.
- Efficient transmission control algorithms such as BBR ensure low latency and high bandwidth utilization.

**Data privacy and security:**
- Integrates TLS 1.3 encryption by default for end-to-end security.
- Implements forward-secure keys and authenticated packet headers to resist tampering.

**IoT and edge computing:**
- Supports connection migration to maintain sessions across network changes (e.g., Wi-Fi to cellular).
- Enables lightweight communication with unreliable datagrams (RFC 9221) for real-time IoT scenarios.

These characteristics position QUIC as a transformative protocol for modern networks, combining performance optimizations with robust cryptographic guarantees

## Design

The QUIC protocol is a rather complex, IO-intensive protocol, making it extremely fit for asynchronous programming. 
The basic events in asynchronous IO are read, write, and timers. However, throughout the implementation of the QUIC protocol, the internal events are intricate and dazzling. 
If you look at the protocol carefully, you will found that certain structures become evident, revealing that the core of the QUIC protocol is driven by layers of underlying IO events progressively influencing the application layer behavior. 
For example, when the receiving data of a stream is contiguous, it constitutes an event that awakens the corresponding application 
layer to read; 
similarly, when the Initial data exchange completes and the Handshake keys are obtained, this is another event that awakens the task processing the Handshake data packet. 
These events illustrate the classic Reactor pattern. 
`gm-quic` refines and encapsulates these various internal Reactors of QUIC, making each module more independent, clarifying the cooperation between the system's modules, and thereby making the overall design more user-friendly.

It is noticeable that the QUIC protocol has multiple layers. In the transport layer, there are many functions such as opening new connections, receiving, sending, reading, writing, and accepting new connections, most of which are asynchronous. 
Here, we call these functions as various functors with each layer having its own functor. 
With these layers in place, it becomes clear that the `Accept Functor` and the `Read Functor`, or the `Write Functor`, do not belong to the same layer, which is quite interesting.

![image](https://github.com/genmeta/gm-quic/blob/main/images/arch.png)


## Overview

- **qbase**: Core structure of the QUIC protocol, including variable integer encoding (VarInt), connection ID management, stream ID, various frame and packet type definitions, and asynchronous keys.
- **qrecovery**: The reliable transport part of QUIC, encompassing the state machine evolution of the sender/receiver, and the internal logic interaction between the application layer and the transport layer.
- **qcongestion**: Congestion control in QUIC, which abstracts a unified congestion control interface and implements BBRv1. In the future, it will also implement more transport control algorithms such as Cubic and others.
- **qinterface**: QUIC's packet routing and definition of the underlying IO interface (`QuicInterface`) enable gm-quic to run in various environments. Contains an optional qudp-based `QuicInterface` implementation
- **qunreliable**: The extension for unreliable datagram transmission based on QUIC offers transmission control mechanisms and enhanced security compared to directly sending unreliable datagrams over UDP. See [RFC 9221][3]. 
- **qconnection**: Encapsulation of QUIC connections, linking the necessary components and tasks within a QUIC connection to ensure smooth operation.
- **gm-quic**: The top-level encapsulation of the QUIC protocol, including interfaces for both the QUIC client and server.
- **qudp**: High-performance UDP encapsulation for QUIC. Ordinary UDP incurs a system call for each packet sent or received, resulting in poor performance. 
- **qevent**: The implementation of [qlog][2] supports logging internal activities of individual QUIC connections in JSON format, maintains compatibility with qlog 3, and enables visualization analysis through [qvis][5]. However, it is important to note that enabling qlog can significantly impact performance despite its utility in troubleshooting.

![image](https://github.com/genmeta/gm-quic/blob/main/images/qvis.png)

## Usage

#### Demos

Run h3 example server:

``` shell
cargo run --example=h3-server --package=h3-shim -- --dir=./h3-shim
```

Send a h3 request:

``` shell
cargo run --example=h3-client --package=h3-shim -- https://localhost:4433/examples/h3-server.rs
```


For more complete examples, please refer to the `examples` folders under the `h3-shim` and `gm-quic` folders.

#### API

`gm-quic` provides user-friendly interfaces for creating client and server connections, while also supporting additional features that meet modern network requirements.

The QUIC client not only offers configuration options specified by the QUIC protocol's Parameters but also includes additional options such as `reuse_connection` and `enable_happy_eyeballs` enabling the IPv6-preferred Happy Eyeballs algorithm. More advanced features allow the QUIC client to set its own certificates as its ID for server verification and manage the Tokens issued by servers for future connections with these servers.

```rust
let quic_client = QuicClient::builder()
    // Allows reusing a connection to the server when there is already one,
    // instead of initiating a new connection every time.
    .reuse_connection()
    // Keep the connection alive when it is idle
    .defer_idle_timeout(HeartbeatConfig::new(Durnation::from_secs(30)))       
    // The QUIC version negotiation mechanism prioritizes using the earlier versions, 
    // currently only supporting V1.
    .prefer_versions([1u32])                
    // .with_parameter(&client_parameters)      // If not set, the default parameters will be used
    // .with_streams_concurrency_strategy(factory)     // Specify the streams concurrency strategy for the client
    // .with_token_sink(token_sink)             // Manage Tokens issued by various servers
    .with_root_certificates(root_certificates)
    // .with_webpki_verifier(verifier)          // More advanced ways to verify server certificates
    .without_cert()                             // Generally, clients do not need to set certificates
    // Specify how client bind interfaces
    // The default interface is the high-performance udp implementation provided by qudp.
    // .with_iface_factory(binder)
    // Let the client only use the interface on specified address.
    // By default, a new interface will be used every time initiates a connection.
    // like 0.0.0.0:0 or [::]:0
    // .bind(&local_addrs[..])?
    .build();

let quic_client_conn = quic_client
    .connect("localhost", "127.0.0.1:8443".parse().unwrap())
    .unwrap();
```

The QUIC server provides SNI(Server Name Indication) support in TLS, allowing the configuration of multiple server names and certificates. 

```rust
let quic_server = QuicServer::builder()
    // Keep the accepted connection alive when it is idle
    .defer_idle_timeout(HeartbeatConfig::new(Durnation::from_secs(30)))       
    .with_supported_versions([1u32])
    .without_client_cert_verifier()      // Generally, client identity is not verified
    .enable_sni()
    .add_host("www.example.com", www_cert, www_key)
    .add_host("chat.example.com", chat_cert, chat_key)
    .listen(&[
        "[2001:db8::1]:8443".parse().unwrap(),
        "127.0.0.1:8443".parse().unwrap(),
    ][..]);

while let Ok(quic_server_conn) = quic_server.accept().await? {
    // The following is a demonstration
    tokio::spawn(handle_quic_conn(quic_server_conn));
}
```

There is an asynchronous interface for creating unidirectional or bidirectional QUIC streams from a QUIC Connection, or for listening to incoming streams from the other side of a QUIC Connection. This interface is almost identical to the one in [`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport).

We also implement the interface defined by [`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport) in `h3-shim` crate to facilitate with other crates integrated. We have a frok of `reqwest` that use `gm-quic` as the transport layer, you can find it [here](https://github.com/genmeta/reqwest/tree/gm-quic).

As for reading and writing data from a QUIC stream, the tokio's **`AsyncRead`** and **`AsyncWrite`** interfaces are implemented for QUIC streams, making it very convenient to use.

## Performance

GitHub Actions periodically runs [benchmark tests][6]. The results show that go-quic, quiche, tquic and quinn all deliver excellent performance, with each excelling in different benchmark testing scenarios. It is critical to note that ​transmission performance is also heavily influenced by congestion control algorithms. While ​gm-quic​'s performance will continue to be optimized in the near future, developers seeking even higher throughput can leverage its abstract interface to replace UdpSocket with ​DPDK​ (Data Plane Development Kit) or ​XDP​ (eXpress Data Path).

<img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_15KB.png" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_30KB.png" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_2048KB.png" width=33% height=33%>

## Contribution 

All feedback and PRs are welcome, including bug reports, feature requests, documentation improvements, code refactoring, and more. 

If you are unsure whether a feature or its implementation is reasonable, please first create an issue in the [issue list](https://github.com/genmeta/gm-quic/issues) for discussion. 
This ensures the feature is reasonable and has a solid implementation plan.

## Community 

- [Official Community](https://github.com/genmeta/gm-quic/discussions)
- chat group：[send email](mailto:quic_team@genmeta.net) to introduce your contribution, 
and we will reply to your email with an invitation link and QR code to join the group.

## Rust version requirements (MSRV)
The gm-quic supports **Rustc version 1.75 or greater**.

The current policy is that this will only be updated in the next major gm-quic release.  

[1]: https://www.rfc-editor.org/rfc/rfc9000.html
[2]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/
[3]: https://datatracker.ietf.org/doc/html/rfc9221
[4]: https://github.com/genmeta/gm-quic/blob/main/h3-shim/examples/
[5]: https://qvis.quictools.info/#/files
[6]: https://github.com/genmeta/gm-quic/actions
