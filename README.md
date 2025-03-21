# gm-quic

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)
[![crates.io](https://img.shields.io/crates/v/gm-quic.svg)](https://crates.io/crates/gm-quic)

English | [中文](README_CN.md)

The QUIC protocol is an important infrastructure for the next generation Internet, and `gm-quic` is a native asynchronous Rust implementation of the QUIC protocol, an efficient and scalable [RFC 9000][1] implementation with excellent engineering quality. The implementation of `gm-quic` tries its best to maintain the original concepts of [RFC 9000][1], including variable and structure naming, and strives to be consistent with [RFC 9000][1], so `gm-quic` is also of great learning value , [RFC 9000][1] and its related RFCs are excellent introductory documents for understanding `gm-quic`.


## Design Principles

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


## Code Structure 

- **qbase**: Core structure of the QUIC protocol, including variable integer encoding (VarInt), connection ID management, stream ID, various frame and packet type definitions, and asynchronous keys.
- **qrecovery**: The reliable transport part of QUIC, encompassing the state machine evolution of the sender/receiver, and the internal logic interaction between the application layer and the transport layer.
- **qcongestion**: Congestion control in QUIC, which abstracts a unified congestion control interface and implements BBRv1. In the future, it will also implement more transport control algorithms such as Cubic and others.
- **qinterface**: QUIC's packet routing and definition of the underlying IO interface (`QuicInterface`) enable gm-quic to run in various environments. Contains an optional qudp-based `QuicInterface` implementation
- **qconnection**: Encapsulation of QUIC connections, linking the necessary components and tasks within a QUIC connection to ensure smooth operation.
- **gm-quic**: The top-level encapsulation of the QUIC protocol, including interfaces for both the QUIC client and server.
- **qudp**: High-performance UDP encapsulation for QUIC. Ordinary UDP incurs a system call for each packet sent or received, resulting in poor performance. 
qudp optimizes UDP performance to the extreme using techniques like GSO (Generic Segmentation Offload) and GRO (Generic Receive Offload). The performance test results for sending are as follows:

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

## Usage

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
    // .with_stream_concurrency_strategy(factory)     // Specify the streams concurrency strategy for the client
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
    .connect("localhost", "127.0.0.1:5000".parse().unwrap())
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
    .add_host("www.genmeta.net", www_cert, www_key)
    .add_host("developer.genmeta.net", dev_cert, dev_key)
    .listen(&[
        "[2001:db8::1]:8080".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
    ][..]);

while let Ok(quic_server_conn) = quic_server.accept().await? {
    // The following is a demonstration
    tokio::spawn(handle_quic_conn(quic_server_conn));
}
```

For complete examples, please refer to the `examples` folders under the `h3-shim`, `gm-quic` and `qconnection` folders.

There is an asynchronous interface for creating unidirectional or bidirectional QUIC streams from a QUIC Connection, or for listening to incoming streams from the other side of a QUIC Connection. This interface is almost identical to the one in [`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport).

We also implement the interface defined by [`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport) in `h3-shim` crate to facilitate with other crates integrated. We have a frok of `reqwest` that use `gm-quic` as the transport layer, you can find it [here](https://github.com/genmeta/reqwest/tree/gm-quic).

As for reading and writing data from a QUIC stream, the tokio's `AsyncRead` and `AsyncWrite` interfaces are implemented for QUIC streams, making it very convenient to use.

## Progress

The early version has been released and is still being continuously optimized and improved. Welcome to use it :D

## Documentation 

Online documentation released with the release is at docs.rs. You can also view the latest documentation in the code.

## Contribution 

All feedback and PRs are welcome, including bug reports, feature requests, documentation improvements, code refactoring, and more. 
However, please note that `gm-quic` has extremely high-quality standards for both code and documentation. 
Contributions will undergo rigorous review before merging.
Contributors are kindly asked to understand and patiently address all feedback before the merge can be completed.

If you are unsure whether a feature or its implementation is reasonable, please first create an issue in the [issue list](https://github.com/genmeta/gm-quic/issues) for discussion. 
This ensures the feature is reasonable and has a solid implementation plan.

## Community 

- [Official Community](https://github.com/genmeta/gm-quic/discussions)
- chat group：[send email](mailto:quic_team@genmeta.net) to introduce your contribution, 
and we will reply to your email with an invitation link and QR code to join the group.

[1]: https://www.rfc-editor.org/rfc/rfc9000.html
