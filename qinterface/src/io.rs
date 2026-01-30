use std::{
    any::Any,
    future::Future,
    io,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use qbase::net::{addr::BoundAddr, route::PacketHeader};

pub mod handy;

mod factory;
pub use factory::*;

use crate::bind_uri::BindUri;

/// Network I/O trait
///
/// Provides a unified interface for different network transport implementations.
/// Note that some implementations may not support all bind address types.
///
/// `gm-quic` uses [`ProductIO`] to create (bind) new [`IO`] instances.
/// Read its documentation for more information.
///
/// Wrapping a new [`IO`] is easy,
/// you can refer to the implementations in the [`handy`] module.
///
/// [`ProductIO`]: crate::io::ProductIO
pub trait IO: Send + Sync + Any {
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
    fn bound_addr(&self) -> io::Result<BoundAddr>;

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

    /// Asynchronously destroy the IO.
    ///
    /// When it returns [`Poll::Ready`] (whether with `Ok` or `Err`),
    /// it must indicate that the resource has been completely destroyed,
    /// and the same [`BindUri`] can be successfully bound again.
    ///
    /// Even if this method is not called,
    /// the implementation should ensure that [`IO`] does not
    /// leak any resources when it is dropped.
    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
}

pub trait IoExt: IO {
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
}

impl<I: IO + ?Sized> IoExt for I {}

pub trait RefIO: Clone + Send + Sync {
    type Interface: IO + ?Sized;

    fn iface(&self) -> &Self::Interface;

    fn same_io(&self, other: &Self) -> bool;
}

impl<I: IO + ?Sized> RefIO for Arc<I> {
    type Interface = I;

    #[inline]
    fn iface(&self) -> &Self::Interface {
        self.as_ref()
    }

    fn same_io(&self, other: &Self) -> bool {
        Arc::ptr_eq(self, other)
    }
}
