pub mod factory;
pub mod ifaces;
pub mod packet;
pub mod queue;
pub mod route;
pub mod util;

use std::{
    io,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use qbase::net::{
    address::{BindAddr, RealAddr},
    route::PacketHeader,
};

/// QUIC network interface trait
///
/// Provides a unified interface for different network transport implementations.
/// Note that some implementations may not support all bind address types.
///
/// `gm-quic` uses [`ProductQuicInterface`] to create (bind) a new [`QuicInterface`] instance.
/// Read its documentation for more information.
///
/// Wrapping a new [`QuicInterface`] is easy,
/// you can refer to the [`UdpSocketController`] implementation in the [`handy`] module.
///
/// [`ProductQuicInterface`]: crate::factory::ProductQuicInterface
/// [`UdpSocketController`]: crate::ifaces::handy::UdpSocketController
/// [`handy`]: crate::ifaces::handy
pub trait QuicInterface: Send + Sync {
    /// Get the bind address that this interface is bound to
    ///
    /// This value cannot change after the interface is bound,
    /// as it is used as the unique identifier for the interface.
    fn bind_addr(&self) -> BindAddr;

    /// Get the actual address that this interface is bound to.
    ///
    /// For example, if this interface is bound to an [`BindAddr`],
    /// this function should return the actual IP address and port address of this interface.
    ///
    /// Just like [`UdpSocket::local_addr`] may return an error,
    /// sometimes an interface cannot get its own actual address,
    /// then the implementation should return an error as well.
    ///
    /// [`UdpSocket::local_addr`]: std::net::UdpSocket::local_addr
    fn real_addr(&self) -> io::Result<RealAddr>;

    /// Maximum size of a single network segment in bytes
    fn max_segment_size(&self) -> io::Result<usize>;

    /// Maximum number of segments that can be sent in a single batch
    fn max_segments(&self) -> io::Result<usize>;

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
        pkts: &mut [BytesMut],
        hdrs: &mut [PacketHeader],
    ) -> Poll<io::Result<usize>>;
}

impl dyn QuicInterface {
    pub async fn sendmsgs(
        &self,
        mut bufs: &[io::IoSlice<'_>],
        hdr: PacketHeader,
    ) -> io::Result<()> {
        while !bufs.is_empty() {
            let sent = core::future::poll_fn(|cx| self.poll_send(cx, bufs, hdr)).await?;
            bufs = &bufs[sent..];
        }
        Ok(())
    }

    pub async fn recvmsgs<'b>(
        &self,
        bufs: &'b mut Vec<BytesMut>,
        hdrs: &'b mut Vec<PacketHeader>,
    ) -> io::Result<impl Iterator<Item = (BytesMut, PacketHeader)> + Send + 'b> {
        let rcvd = std::future::poll_fn(|cx| {
            let max_segments = self.max_segments()?;
            let max_segment_size = self.max_segment_size()?;
            bufs.resize_with(max_segments, || {
                Bytes::from_owner(vec![0u8; max_segment_size]).into()
            });
            hdrs.resize_with(max_segments, PacketHeader::empty);
            self.poll_recv(cx, bufs, hdrs)
        })
        .await?;

        Ok(bufs
            .drain(..rcvd)
            .zip(hdrs.drain(..rcvd))
            .map(|(mut seg, hdr)| (seg.split_to(seg.len().min(hdr.seg_size() as _)), hdr)))
    }

    pub async fn recvpkts<'b>(
        &self,
        bufs: &'b mut Vec<BytesMut>,
        hdrs: &'b mut Vec<PacketHeader>,
    ) -> io::Result<impl Iterator<Item = (route::Packet, route::Way)> + Send + 'b> {
        use qbase::packet::{self, Packet, PacketReader};
        fn is_initial_packet(pkt: &Packet) -> bool {
            matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))))
        }

        let bind_addr = self.bind_addr();
        Ok(self
            .recvmsgs(bufs, hdrs)
            .await?
            .flat_map(move |(buf, hdr)| {
                let size = buf.len();
                let bind_addr = bind_addr.clone();
                PacketReader::new(buf, 8)
                    .flatten()
                    .filter(move |pkt| !(is_initial_packet(pkt) && size < 1200))
                    .map(move |pkt| (pkt, (bind_addr.clone(), hdr.pathway(), hdr.link())))
            }))
    }
}
