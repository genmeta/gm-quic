# gm-quic

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/genmeta/gm-quic/rust.yml)](https://github.com/genmeta/gm-quic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/genmeta/gm-quic/graph/badge.svg)](https://codecov.io/gh/genmeta/gm-quic)

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
- **qconnection**: Encapsulation of QUIC connections, linking the necessary components and tasks within a QUIC connection to ensure smooth operation.
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

## Progress Updates

`gm-quic` is not fully complete yet, but most of its basic functional modules are already usable. 
The remaining tasks involve filling gaps in qconnection and linking various modules together. 
The core team is working hard to complete this final piece of the puzzle. Stay tuned!

## Documentation 

While `gm-quic` is not yet complete, its documentation will not be uploaded to `crate.io`. 
Please refer to the documentation within the code for now!

## Contribution 

All feedback and PRs are welcome, including bug reports, feature requests, documentation improvements, code refactoring, and more. 
However, please note that `gm-quic` has extremely high-quality standards for both code and documentation. 
Contributions will undergo rigorous review before merging.
Contributors are kindly asked to understand and patiently address all feedback before the merge can be completed.

If you are unsure whether a feature or its implementation is reasonable, please first create an issue in the [issue list](https://github.com/genmeta/gm-quic/issues) for discussion. 
This ensures the feature is reasonable and has a solid implementation plan.

## Community 

- [Official Community](https://github.com/genmeta/gm-quic/discussions)
- feishu group：[send email](mailto:quic_team@genmeta.net) to introduce your contribution, 
and we will reply to your email with an invitation link and QR code to join the group.

[1]: https://www.rfc-editor.org/rfc/rfc9000.html
