#[cfg(all(feature = "qudp", any(unix, windows)))]
pub mod qudp {
    use std::{
        any::Any,
        io::{self, IoSliceMut},
        net::SocketAddr,
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::net::{
        addr::{BindUri, RealAddr, TryIntoSocketAddrError},
        route::{Link, Pathway},
    };
    use qudp::BATCH_SIZE;

    use crate::{PacketHeader, QuicIO};

    pub struct UdpSocketController {
        inner: qudp::UdpSocketController,
        bind_uri: BindUri,
    }

    impl UdpSocketController {
        pub fn bind(bind_uri: BindUri) -> io::Result<Self> {
            match SocketAddr::try_from(&bind_uri) {
                Ok(socket_addr) => Ok(Self {
                    bind_uri,
                    inner: qudp::UdpSocketController::bind(socket_addr)?,
                }),
                Err(error) => match error {
                    TryIntoSocketAddrError::NotSocketBindUri => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Failed to bind {bind_uri}: BLE is not supported by UdpSocketController",
                        ),
                    )),
                    e @ (TryIntoSocketAddrError::InterfaceNotFound
                    | TryIntoSocketAddrError::LinkNotFound) => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Failed to bind {bind_uri}: {e}"),
                    )),
                },
            }
        }
    }

    impl QuicIO for UdpSocketController {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            self.inner.local_addr().map(RealAddr::Internet)
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(BATCH_SIZE)
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1500)
        }

        fn poll_send(
            &self,
            cx: &mut Context,
            pkts: &[io::IoSlice],
            hdr: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            debug_assert_eq!(hdr.ecn(), None);
            // TODO: (qinterface/qconnection) Better adaptability to interface rebinding
            // debug_assert_eq!(
            //     hdr.link().src(),
            //     self.real_addr()?,
            //     "Interface changed? bind_uri={}",
            //     self.bind_uri
            // );
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
                let way = Pathway::new(qudp_hdr.src.into(), dst.into());
                let link = Link::new(qudp_hdr.src.into(), self.inner.local_addr()?.into());
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

        fn poll_close(&self, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

pub mod unsupported {
    use std::{
        any::Any,
        io,
        task::{Context, Poll},
    };

    use bytes::BytesMut;
    use qbase::net::{
        addr::{BindUri, RealAddr},
        route::PacketHeader,
    };

    use crate::QuicIO;

    pub struct Unsupported(());

    impl Unsupported {
        pub fn bind(_: BindUri) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "qudp feature is not enabled or target platform is not supported, you should use your own ProductQuicIO implementation, not DEFAULT_QUIC_IO_FACTORY",
            ))
        }
    }

    impl QuicIO for Unsupported {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn bind_uri(&self) -> BindUri {
            unreachable!()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            unreachable!()
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            unreachable!()
        }

        fn max_segments(&self) -> io::Result<usize> {
            unreachable!()
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            unreachable!()
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [PacketHeader],
        ) -> Poll<io::Result<usize>> {
            unreachable!()
        }

        fn poll_close(&self, _: &mut Context) -> Poll<io::Result<()>> {
            unreachable!()
        }
    }
}
