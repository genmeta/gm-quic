#[cfg(feature = "qudp")]
mod qudp {
    use std::{
        io::{self, IoSliceMut},
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{
        address::{AbstractAddr, QuicAddr},
        route::{Link, Pathway, ToEndpointAddr},
    };
    use qudp::BATCH_SIZE;

    use crate::{PacketHeader, QuicInterface};

    pub struct UdpSocketController {
        inner: qudp::UdpSocketController,
        address: AbstractAddr,
    }

    impl UdpSocketController {
        pub fn bind(addr: AbstractAddr) -> io::Result<Self> {
            let addr = match addr {
                AbstractAddr::Specific(QuicAddr::Inet(socket_addr)) => socket_addr,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "USC can only bind to specific addresses (SocketAddr), got: {addr:?}"
                        ),
                    ));
                }
            };
            let usc = qudp::UdpSocketController::bind(addr)?;
            Ok(Self {
                address: AbstractAddr::Specific(usc.local_addr()?.into()),
                inner: usc,
            })
        }
    }

    impl QuicInterface for UdpSocketController {
        fn abstract_addr(&self) -> AbstractAddr {
            self.address.clone()
        }

        fn local_addr(&self) -> io::Result<QuicAddr> {
            self.inner.local_addr().map(QuicAddr::Inet)
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
            pkts: &[io::IoSlice],
            hdr: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            debug_assert_eq!(hdr.ecn(), None);
            debug_assert_eq!(hdr.link().src(), self.local_addr()?);
            let hdr = qudp::DatagramHeader::new(
                hdr.link().src().try_into().expect("Must be SocketAddr"),
                hdr.link().dst().try_into().expect("Must be SocketAddr"),
                hdr.ttl(),
                hdr.ecn(),
                hdr.seg_size(),
            );
            self.inner.poll_send(cx, pkts, &hdr)
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
            let rcvd = ready!(self.inner.poll_recv(cx, &mut bufs, &mut hdrs))?;

            for (idx, qudp_hdr) in hdrs[..rcvd].iter().enumerate() {
                let dst = self.local_addr()?;
                let way = Pathway::new(qudp_hdr.src.to_endpoint_addr(), dst.to_endpoint_addr());
                let link = Link::new(qudp_hdr.src, self.inner.local_addr()?);
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
pub use qudp::UdpSocketController;
