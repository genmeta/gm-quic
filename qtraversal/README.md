# qtraversal

`qtraversal` is a NAT traversal library designed for QUIC. It implements sophisticated hole-punching strategies to establish peer-to-peer connections even behind difficult NATs (Symmetric, Restricted, etc.).

## Features

- **STUN Client**: Detects NAT type and external IP/Port.
- **Hole Punching**: Implements various strategies including:
    - Direct Connection (Full Cone)
    - Reverse Punching
    - Birthday Attack (for Symmetric NATs)
    - Port prediction

## STUN Configuration

The library uses `nat.genmeta.net:20004` as the default STUN server in examples. You can configure your own STUN server when initializing the client.

## Usage

See `examples/` for details on how to use the `Client` and `Puncher`.

