pub mod factory;
// handy（qudp）是可选的
pub mod handy;
pub mod packet;
pub mod queue;
pub mod router;
pub mod util;

use std::{
    io,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::{
    address::{ConcreteAddr, VirtualAddr},
    route::PacketHeader,
};

/// QUIC network interface trait
///
/// Provides a unified interface for different network transport implementations.
/// Note that some implementations may not support all virtual address types.
///
/// `gm-quic` uses [`ProductQuicInterface`] to create (bind) a new [`QuicInterface`] instance.
/// Read its documentation for more information.
///
/// Wrapping a new [`QuicInterface`] is easy,
/// you can refer to the [`UdpSocketController`] implementation in the [`handy`] module.
///
/// [`ProductQuicInterface`]: crate::factory::ProductQuicInterface
/// [`UdpSocketController`]: crate::handy::UdpSocketController
pub trait QuicInterface: Send + Sync {
    /// Get the virtual address that this interface is bound to
    ///
    /// This value cannot change after the interface is bound,
    /// as it is used as the unique identifier for the interface.
    fn virt_addr(&self) -> VirtualAddr;

    /// Get the actual address that this interface is bound to.
    ///
    /// For example, if this interface is bound to an [`InterfaceAddr`],
    /// this function should return the actual IP address and port address of this interface.
    ///
    /// Just like [`UdpSocket::local_addr`] may return an error,
    /// sometimes an interface cannot get its own actual address,
    /// then the implementation should return an error as well.
    ///
    /// [`InterfaceAddr`]: qbase::net::address::InterfaceAddr
    /// [`UdpSocket::local_addr`]: std::net::UdpSocket::local_addr
    fn concrete_addr(&self) -> io::Result<ConcreteAddr>;

    /// Maximum size of a single network segment in bytes
    fn max_segment_size(&self) -> usize;

    /// Maximum number of segments that can be sent in a single batch
    fn max_segments(&self) -> usize;

    /// Poll for sending packets
    ///
    /// Attempts to send multiple packets in a single operation.
    /// Return the number of packets sent,
    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        hdr: PacketHeader,
    ) -> Poll<io::Result<usize>>;

    /// Poll for receiving packets
    ///
    /// Attempts to receive multiple packets in a single operation.
    /// The number of packets received is limited by the smaller of
    /// `pkts.capacity()` and `hdrs.len()`.
    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut Vec<BytesMut>,
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>>;
}
