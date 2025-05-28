#[cfg(feature = "qudp")]
mod qudp {
    use std::{
        io::{self, IoSliceMut},
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{
        address::{ConcreteAddr, VirtualAddr},
        route::{Link, Pathway, ToEndpointAddr},
    };
    use qudp::BATCH_SIZE;

    use crate::{PacketHeader, QuicInterface};

    pub struct UdpSocketController {
        inner: qudp::UdpSocketController,
        address: VirtualAddr,
    }

    impl UdpSocketController {
        pub fn bind(addr: VirtualAddr) -> io::Result<Self> {
            let addr = match addr {
                VirtualAddr::Concrete(ConcreteAddr::Inet(socket_addr)) => socket_addr,
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
                address: VirtualAddr::Concrete(usc.local_addr()?.into()),
                inner: usc,
            })
        }
    }

    impl QuicInterface for UdpSocketController {
        fn virt_addr(&self) -> VirtualAddr {
            self.address.clone()
        }

        fn concrete_addr(&self) -> io::Result<ConcreteAddr> {
            self.inner.local_addr().map(ConcreteAddr::Inet)
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
            debug_assert_eq!(hdr.link().src(), self.concrete_addr()?);
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
            let len = qbase_hdrs.len().min(pkts.len());
            let mut hdrs = Vec::with_capacity(len);
            hdrs.resize_with(qbase_hdrs.len(), qudp::DatagramHeader::default);
            let mut bufs = pkts[..len]
                .iter_mut()
                .map(|p| IoSliceMut::new(p.as_mut()))
                .collect::<Vec<_>>();
            debug_assert_eq!(hdrs.len(), bufs.len());
            let rcvd = ready!(self.inner.poll_recv(cx, &mut bufs, &mut hdrs))?;

            for (idx, qudp_hdr) in hdrs[..rcvd].iter().enumerate() {
                let dst = self.concrete_addr()?;
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
