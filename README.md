# gm-quic

[![License: Apache-2.0](https://img.shields.io/github/license/genmeta/gm-quic)](https://www.apache.org/licenses/LICENSE-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)
[![crates.io](https://img.shields.io/crates/v/gm-quic.svg)](https://crates.io/crates/gm-quic)
[![Documentation](https://docs.rs/gm-quic/badge.svg)](https://docs.rs/gm-quic/)

English | [中文](README_CN.md)

The QUIC protocol is an important infrastructure for the next generation Internet, and `gm-quic` is a native asynchronous Rust implementation of the QUIC protocol, an efficient and scalable [RFC 9000][1] implementation with excellent engineering quality.
`gm-quic` not only implements the standard QUIC protocol but also includes additional extensions such as [RFC 9221 (Unreliable Datagram Extension)][3] and [qlog (QUIC event logging)][2].

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

These characteristics position QUIC as a transformative protocol for modern networks, combining performance optimizations with robust cryptographic guarantees.

## Design

The QUIC protocol is a rather complex, IO-intensive protocol, making it extremely fit for asynchronous programming. 
The basic events in asynchronous IO are read, write, and timers. However, throughout the implementation of the QUIC protocol, the internal events are intricate and dazzling. 
If you look at the protocol carefully, you will found that certain structures become evident, revealing that the core of the QUIC protocol is driven by layers of underlying IO events progressively influencing the application layer behavior. 
For example, when the receiving data of a stream is contiguous, it constitutes an event that awakens the corresponding application layer to read; 
similarly, when the Initial data exchange completes and the Handshake keys are obtained, this is another event that awakens the task processing the Handshake data packet. 
These events illustrate the classic Reactor pattern. 
`gm-quic` refines and encapsulates these various internal Reactors of QUIC, making each module more independent, clarifying the cooperation between the system's modules, and thereby making the overall design more user-friendly.

It is noticeable that the QUIC protocol has multiple layers. In the transport layer, there are many functions such as opening new connections, receiving, sending, reading, writing, and accepting new connections, most of which are asynchronous. 
Here, we call these functions as various functors with each layer having its own functor. 
With these layers in place, it becomes clear that the `Accept Functor` and the `Read Functor`, or the `Write Functor`, do not belong to the same layer, which is quite interesting.

![image](https://github.com/genmeta/gm-quic/blob/main/images/arch.png?raw=true)


## Overview

- **qbase**: Core structure of the QUIC protocol, including variable integer encoding (VarInt), connection ID management, stream ID, various frame and packet type definitions, and asynchronous keys.
- **qrecovery**: The reliable transport part of QUIC, encompassing the state machine evolution of the sender/receiver, and the internal logic interaction between the application layer and the transport layer.
- **qcongestion**: Congestion control in QUIC, which abstracts a unified congestion control interface and implements BBRv1. In the future, it will also implement more transport control algorithms such as Cubic and others.
- **qinterface**: QUIC's packet routing and definition of the underlying I/O interface (`QuicIO`) enable gm-quic to run in various environments. Contains an optional qudp-based `QuicIO` implementation
- **qunreliable**: The extension for unreliable datagram transmission based on QUIC offers transmission control mechanisms and enhanced security compared to directly sending unreliable datagrams over UDP. See [RFC 9221][3]. 
- **qconnection**: Encapsulation of QUIC connections, linking the necessary components and tasks within a QUIC connection to ensure smooth operation.
- **gm-quic**: The top-level encapsulation of the QUIC protocol, including interfaces for both the QUIC client and server.
- **qudp**: High-performance UDP encapsulation for QUIC. Ordinary UDP incurs a system call for each packet sent or received, resulting in poor performance. 
- **qevent**: The implementation of [qlog][2] supports logging internal activities of individual QUIC connections in JSON format, maintains compatibility with qlog 3, and enables visualization analysis through [qvis][4]. However, it is important to note that enabling qlog can significantly impact performance despite its utility in troubleshooting.

![image](https://github.com/genmeta/gm-quic/blob/main/images/qvis.png?raw=true)

## Usage

#### Demos

Run h3 example server:

``` shell
cargo run --example h3-server --package h3-shim -- --dir ./h3-shim
```

Send a h3 request:

``` shell
cargo run --example h3-client --package h3-shim -- https://localhost:4433/examples/h3-server.rs
```


For more complete examples, please refer to the `examples` folders under the `h3-shim` and `gm-quic` folders.

#### API

`gm-quic` provides user-friendly interfaces for creating client and server connections, while also supporting additional features that meet modern network requirements.

In addition to traditional IP address + port binding mode, `gm-quic` also supports binding to network interfaces, dynamically adapting to actual address changes, which provides good mobility for gm-quic.

The QUIC client not only provides configuration options specified by the QUIC protocol's Parameters and optional 0-RTT functionality, but also includes some additional advanced options. For example, the QUIC client can set its own certificate for server verification, and can also set its own Token manager to manage Tokens issued by various servers for future connections with these servers.

The QUIC client supports simultaneously attempting to connect to multiple server addresses. Even if some paths are unreachable, as long as one path can be connected, the connection can be established. If the peer implementation is also gm-quic, it also supports multipath transmission, while maintaining compatibility with other implementations. Tested implementations include cloudflare/quiche, quic-go/quic-go, quinn-rs/quinn, tencent/tquic.

The following is a simple example, please refer to the documentation for more details.

```rust
// Set up root certificate store
let mut roots = rustls::RootCertStore::empty();

// Load system certificates
roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);

// Load custom certificates (can be used independently of system certificates)
// use gm_quic::ToCertificate;
// roots.add_parsable_certificates(PathBuf::from("path/to/your/cert.pem").to_certificate()); // Load at runtime
// roots.add_parsable_certificates(include_bytes!("path/to/your/cert.pem").to_certificate()); // Embed at compile time

// Build the QUIC client
let quic_client = gm_quic::QuicClient::builder()
    .with_root_certificates(roots)
    .without_cert() // Client certificate verification is typically not required
    // .with_parameters(your_parameters) // Custom transport parameters
    // .bind(["iface://v4.eth0:0", "iface://v6.eth0:0"]) // Bind to specific network interfaces
    // .enable_0rtt() // Enable 0-RTT
    // .enable_sslkeylog() // Enable SSL key logging
    // .with_qlog(Arc::new(gm_quic::handy::DefaultSeqLogger::new(
    //     PathBuf::from("/path/to/qlog_dir"),
    // ))) // Enable qlog for visualization with qvis tool
    .build();

// Connect to the server
// Supports multiple addresses - connection is established if any address is reachable
// When connecting to gm-quic servers, multipath transmission is supported
// Compatible with existing QUIC implementations: cloudflare/quiche, quic-go/quic-go, quinn-rs/quinn, tencent/tquic
let server_addresses = tokio::net::lookup_host("localhost:4433").await?;
let connection = quic_client.connect("localhost", server_addresses)?;

// Start using the QUIC connection!
// For more usage examples, see gm-quic/examples and h3-shim/examples

Ok(())
```

The QUIC server is represented as `QuicListeners`, supporting SNI (Server Name Indication), allowing multiple Servers to be started in one process, each with their own certificates and keys. Each server can also bind to multiple addresses, and multiple Servers can bind to the same address. Clients must correctly connect to the corresponding interface of the corresponding Server, otherwise the connection will be automatically rejected.

QuicListeners supports verifying client identity through various methods, including through `client_name` transport parameters, verifying client certificate content, etc. QuicListeners also supports anti-port scanning functionality, only responding after preliminary verification of client identity.

```rust
// Create QUIC listeners (only one instance allowed per program)
let quic_listeners = gm_quic::QuicListeners::builder()?
    // Client certificate verification is typically not required
    .without_client_cert_verifier()
    // .with_parameters(your_parameters)    // Custom transport parameters
    // .enable_0rtt()                       // Enable 0-RTT for servers
    // .enable_anti_port_scan()             // Anti-port scanning protection
    // Start listening with backlog (similar to Unix listen)
    .listen(8192);

// Add a server that can be connected
quic_listeners.add_server(
    "localhost",
    // Certificate and key files as byte arrays or paths
    include_bytes!("/path/to/server.crt"),
    include_bytes!("/path/to/server.key"),
    [
        "iface://v4.eth0:4433", // Bind to eth0's IPv4 address
        "iface://v6.eth0:4433", // Bind to eth0's IPv6 address
    ],
    None, // ocsp
);

// Continue calling `quic_listeners.add_server()` to add more servers
// Call `quic_listeners.remove_server()` to remove a server

// Accept trusted new connections
while let Ok((connection, server_name, pathway, link)) = quic_listeners.accept().await {
    // Handle the incoming QUIC connection!
    // You can refer to examples in gm-quic/examples and h3-shim/examples
}
```

There is an asynchronous interface for creating unidirectional or bidirectional QUIC streams from a QUIC Connection, or for listening to incoming streams from the other side of a QUIC Connection. This interface is almost identical to the one in [`hyperium/h3`](https://github.com/hyperium/h3/blob/master/docs/PROPOSAL.md#5-quic-transport).

For reading and writing data from QUIC streams, the standard **`AsyncRead`** and **`AsyncWrite`** interfaces are implemented for QUIC streams, making them very convenient to use.

## Performance

GitHub Actions periodically runs [benchmark tests][5]. The results show that gm-quic, quiche, tquic and quinn all deliver excellent performance, with each excelling in different benchmark testing scenarios. It should be noted that transmission performance is also greatly related to congestion control algorithms. gm-quic's performance will continue to be optimized in the coming period. If you want higher performance, gm-quic provides abstract interfaces that can use DPDK or XDP to replace UdpSocket!

<img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_15KB.png?raw=true" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_30KB.png?raw=true" width=33% height=33%><img src="https://github.com/genmeta/gm-quic/blob/main/images/benchmark_2048KB.png?raw=true" width=33% height=33%>

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
[4]: https://qvis.quictools.info/#/files
[5]: https://github.com/genmeta/gm-quic/actions
