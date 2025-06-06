#[cfg(feature = "qudp")]
mod qudp {
    use std::{
        io::{self, IoSliceMut},
        net::SocketAddr,
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{
        address::{BindAddr, RealAddr, SocketBindAddr},
        route::{Link, Pathway, ToEndpointAddr},
    };
    use qudp::BATCH_SIZE;

    use super::super::monitor::InterfacesMonitor;
    use crate::{PacketHeader, QuicInterface};

    pub struct UdpSocketController {
        inner: qudp::UdpSocketController,
        bind_addr: BindAddr,
    }

    impl UdpSocketController {
        pub fn bind(bind_addr: BindAddr) -> io::Result<Self> {
            let socket_addr = match &bind_addr {
                BindAddr::Socket(SocketBindAddr::Inet(inet_bind_addr)) => {
                    SocketAddr::from(*inet_bind_addr)
                }
                BindAddr::Socket(SocketBindAddr::Iface(iface_bind_addr)) => {
                    InterfacesMonitor::global()
                        .get(iface_bind_addr)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("Interface not found: {iface_bind_addr}"),
                            )
                        })?
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("USC can only bind to socket addresses, got: {bind_addr:?}"),
                    ));
                }
            };
            let usc = qudp::UdpSocketController::bind(socket_addr)?;
            Ok(Self {
                bind_addr,
                inner: usc,
            })
        }
    }

    impl QuicInterface for UdpSocketController {
        fn bind_addr(&self) -> BindAddr {
            self.bind_addr.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            self.inner.local_addr().map(RealAddr::Inet)
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
            debug_assert_eq!(hdr.link().src(), self.real_addr()?);
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
            pkts: &mut [BytesMut],
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
                let dst = self.real_addr()?;
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
