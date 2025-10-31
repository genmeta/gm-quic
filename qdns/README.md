# qdns

`qdns` is a flexible DNS resolution library for the gm-quic project. It provides a unified `Resolve` trait and implements several resolvers:

- **HttpResolver**: Resolves DNS queries over HTTPS (DoH).
- **MdnsResolver**: Resolves local services using mDNS.

## Configuration

By default, `qdns` uses public DNS servers (e.g., Google DNS, Cloudflare DoH). You can customize the resolvers by implementing the `Resolve` trait or configuring the existing ones.


