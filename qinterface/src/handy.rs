#[cfg(feature = "qudp")]
mod qudp {
    use std::{
        io::{self, IoSliceMut},
        net::SocketAddr,
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{Link, Pathway, ToEndpointAddr};
    use qudp::{BATCH_SIZE, UdpSocketController};

    use crate::{PacketHeader, QuicInterface};

    impl QuicInterface for UdpSocketController {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            UdpSocketController::local_addr(self)
        }

        fn max_segments(&self) -> usize {
            BATCH_SIZE
        }

        fn max_segment_size(&self) -> usize {
            1500
        }

        fn poll_send(
            &self,
            cx: &mut Context,
            ptks: &[io::IoSlice],
            hdr: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            debug_assert_eq!(hdr.ecn(), None);
            debug_assert_eq!(hdr.link().src(), self.local_addr()?);
            let hdr = qudp::DatagramHeader::new(
                hdr.link().src(),
                hdr.link().dst(),
                hdr.ttl(),
                hdr.ecn(),
                hdr.seg_size(),
            );
            UdpSocketController::poll_send(self, cx, ptks, &hdr)
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            pkts: &mut Vec<BytesMut>,
            qbase_hdrs: &mut [PacketHeader],
        ) -> Poll<io::Result<usize>> {
            let mut hdrs = Vec::with_capacity(qbase_hdrs.len());
            hdrs.resize_with(qbase_hdrs.len(), qudp::DatagramHeader::default);
            let mut bufs = pkts
                .iter_mut()
                .map(|p| IoSliceMut::new(p.as_mut()))
                .collect::<Vec<_>>();
            let rcvd = ready!(UdpSocketController::poll_recv(
                self, cx, &mut bufs, &mut hdrs
            ))?;

            for (idx, qudp_hdr) in hdrs[..rcvd].iter().enumerate() {
                let dst = self.local_addr()?;
                let way = Pathway::new(qudp_hdr.src.to_endpoint_addr(), dst.to_endpoint_addr());
                let link = Link::new(qudp_hdr.src, self.local_addr()?);
                qbase_hdrs[idx] = PacketHeader::new(
                    way.flip(),
                    link.flip(),
                    qudp_hdr.ttl,
                    qudp_hdr.ecn,
                    qudp_hdr.seg_size,
                );
            }

            Poll::Ready(Ok(rcvd))
        }
    }
}

#[cfg(feature = "qudp")]
pub use ::qudp::UdpSocketController;
