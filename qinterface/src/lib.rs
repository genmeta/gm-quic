pub mod factory;
pub mod local;
pub mod logical;
pub mod physical;
pub mod route;

use std::{
    any::Any,
    future::Future,
    io,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::{addr::RealAddr, route::PacketHeader};

use crate::logical::BindUri;

/// QUIC network I/O trait
///
/// Provides a unified interface for different network transport implementations.
/// Note that some implementations may not support all bind address types.
///
/// `gm-quic` uses [`ProductQuicIO`] to create (bind) a new [`QuicIO`] instance.
/// Read its documentation for more information.
///
/// Wrapping a new [`QuicIO`] is easy,
/// you can refer to the implementations in the [`iface::handy`] module.
///
/// [`ProductQuicIO`]: crate::factory::ProductQuicIO
#[async_trait::async_trait]
pub trait Interface: Send + Sync + Any {
    /// Get the bind address that this interface is bound to
    ///
    /// This value cannot change after the interface is bound,
    /// as it is used as the unique identifier for the interface.
    fn bind_uri(&self) -> BindUri;

    /// Get the actual address that this interface is bound to.
    ///
    /// For example, if this interface is bound to an [`BindUri`],
    /// this function should return the actual IP address and port
    /// address of this interface.
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

    /// Asynchronously destroy the QuicIO.
    ///
    /// When it returns [`Poll::Ready`] (whether with `Ok` or `Err`),
    /// it must indicate that the resource has been completely destroyed,
    /// and the same [`BindUri`] can be successfully bound again.
    ///
    /// Even if this method is not called,
    /// the implementation should ensure that [`QuicIO`] does not
    /// leak any resources when it is dropped.
    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
}

pub trait InterfaceExt: Interface {
    #[inline]
    fn sendmmsg(
        &self,
        mut bufs: &[io::IoSlice<'_>],
        hdr: PacketHeader,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while !bufs.is_empty() {
                let sent = core::future::poll_fn(|cx| self.poll_send(cx, bufs, hdr)).await?;
                bufs = &bufs[sent..];
            }
            Ok(())
        }
    }

    fn recvmmsg<'b>(
        &self,
        bufs: &'b mut Vec<BytesMut>,
        hdrs: &'b mut Vec<PacketHeader>,
    ) -> impl Future<Output = io::Result<impl Iterator<Item = (BytesMut, PacketHeader)> + Send + 'b>>
    + Send {
        async move {
            let rcvd = std::future::poll_fn(|cx| {
                let max_segments = self.max_segments()?;
                let max_segment_size = self.max_segment_size()?;
                bufs.resize_with(max_segments, || BytesMut::zeroed(max_segment_size));
                hdrs.resize_with(max_segments, PacketHeader::empty);
                self.poll_recv(cx, bufs, hdrs)
            })
            .await?;

            Ok(bufs
                .drain(..rcvd)
                .zip(hdrs.drain(..rcvd))
                .map(|(mut seg, hdr)| (seg.split_to(seg.len().min(hdr.seg_size() as _)), hdr)))
        }
    }

    #[inline]
    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        async { core::future::poll_fn(|cx| self.poll_close(cx)).await }
    }

    fn recvmpkt<'b>(
        &self,
        bufs: &'b mut Vec<BytesMut>,
        hdrs: &'b mut Vec<PacketHeader>,
    ) -> impl Future<
        Output = io::Result<impl Iterator<Item = (route::Packet, route::Way)> + Send + 'b>,
    > + Send {
        async {
            use qbase::packet::{self, Packet, PacketReader};
            fn is_initial_packet(pkt: &Packet) -> bool {
                matches!(pkt, Packet::Data(packet) if matches!(packet.header, packet::DataHeader::Long(packet::long::DataHeader::Initial(..))))
            }

            let bind_uri = self.bind_uri();
            Ok(self
                .recvmmsg(bufs, hdrs)
                .await?
                .flat_map(move |(buf, hdr)| {
                    let size = buf.len();
                    let bind_uri = bind_uri.clone();
                    PacketReader::new(buf, 8)
                        .flatten()
                        .filter(move |pkt| !(is_initial_packet(pkt) && size < 1100))
                        .map(move |pkt| (pkt, (bind_uri.clone(), hdr.pathway(), hdr.link())))
                }))
        }
    }
}

impl<IO: Interface + ?Sized> InterfaceExt for IO {}

pub trait RefInterface: Clone + Send + Sync {
    type Interface: Interface + ?Sized;

    fn iface(&self) -> &Self::Interface;

    fn same_io(&self, other: &Self) -> bool;
}

impl<IO: Interface + ?Sized> RefInterface for Arc<IO> {
    type Interface = IO;

    #[inline]
    fn iface(&self) -> &Self::Interface {
        self.as_ref()
    }

    fn same_io(&self, other: &Self) -> bool {
        Arc::ptr_eq(self, other)
    }
}
