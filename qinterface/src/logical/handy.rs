#[cfg(all(feature = "qudp", any(unix, windows)))]
pub mod qudp {
    use std::{
        error::{Error, Error as StdError},
        fmt::Display,
        io::{self, IoSliceMut},
        net::SocketAddr,
        sync::Arc,
        task::{Context, Poll, ready},
    };

    use bytes::BytesMut;
    use qbase::{
        net::{
            addr::RealAddr,
            route::{Link, Pathway},
        },
        util::Wakers,
    };
    use qudp::BATCH_SIZE;
    use thiserror::Error;

    use crate::{
        PacketHeader, QuicIO,
        logical::{BindUri, TryIntoSocketAddrError},
    };

    pub struct UdpSocketController {
        bind_uri: BindUri,
        send_wakers: Arc<Wakers<64>>,
        recv_wakers: Arc<Wakers>,
        io: Result<Result<qudp::UdpSocketController, Closed>, BindFailed>,
    }

    #[derive(Debug, Clone, Copy, Error)]
    #[error("UdpSocketController closed")]
    pub struct Closed(());

    impl From<Closed> for io::Error {
        fn from(error: Closed) -> Self {
            io::Error::other(error)
        }
    }

    #[derive(Debug, Clone)]
    pub struct BindFailed(Arc<io::Error>);

    impl Display for BindFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Failed to bind UdpSocketController")
        }
    }

    impl StdError for BindFailed {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    impl From<BindFailed> for io::Error {
        fn from(error: BindFailed) -> Self {
            io::Error::other(error)
        }
    }

    impl UdpSocketController {
        pub fn bind(bind_uri: BindUri) -> Self {
            let io = match SocketAddr::try_from(&bind_uri) {
                Ok(socket_addr) => qudp::UdpSocketController::bind(socket_addr),
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
            };
            UdpSocketController {
                bind_uri,
                send_wakers: Arc::new(Wakers::new()),
                recv_wakers: Arc::new(Wakers::new()),
                io: io.map(Ok).map_err(|e| BindFailed(Arc::new(e))),
            }
        }

        fn usc(&self) -> io::Result<&qudp::UdpSocketController> {
            self.io
                .as_ref()
                .map_err(|e| io::Error::from(e.clone()))
                .and_then(|result| result.as_ref().map_err(|e| (*e).into()))
        }
    }

    impl QuicIO for UdpSocketController {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            self.usc()?.local_addr().map(RealAddr::Internet)
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
            let io = self.usc()?;
            self.send_wakers.combine_with(cx, |cx| {
                debug_assert_eq!(hdr.ecn(), None);
                let hdr = qudp::DatagramHeader::new(
                    hdr.link().src().try_into().expect("Must be SocketAddr"),
                    hdr.link().dst().try_into().expect("Must be SocketAddr"),
                    hdr.ttl(),
                    hdr.ecn(),
                    hdr.seg_size(),
                );
                io.poll_send(cx, pkts, &hdr)
            })
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            pkts: &mut [BytesMut],
            qbase_hdrs: &mut [PacketHeader],
        ) -> Poll<io::Result<usize>> {
            let io = self.usc()?;
            self.recv_wakers.combine_with(cx, |cx| {
                let dst = RealAddr::Internet(io.local_addr()?);
                let len = qbase_hdrs.len().min(pkts.len());
                let mut hdrs = Vec::with_capacity(len);
                hdrs.resize_with(qbase_hdrs.len(), qudp::DatagramHeader::default);
                let mut bufs = pkts[..len]
                    .iter_mut()
                    .map(|p| IoSliceMut::new(p.as_mut()))
                    .collect::<Vec<_>>();
                debug_assert_eq!(hdrs.len(), bufs.len());
                let rcvd = ready!(io.poll_recv(cx, &mut bufs, &mut hdrs))?;

                for (idx, qudp_hdr) in hdrs[..rcvd].iter().enumerate() {
                    let way = Pathway::new(qudp_hdr.src.into(), dst.into());
                    let link = Link::new(qudp_hdr.src.into(), io.local_addr()?.into());
                    qbase_hdrs[idx] = PacketHeader::new(
                        way.flip(),
                        link.flip(),
                        qudp_hdr.ttl,
                        qudp_hdr.ecn,
                        qudp_hdr.seg_size,
                    );
                }

                Poll::Ready(Ok(rcvd))
            })
        }

        fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
            self.usc()?;
            self.send_wakers.wake_all();
            self.recv_wakers.wake_all();
            self.io = Ok(Err(Closed(())));
            Poll::Ready(Ok(()))
        }
    }
}

pub mod unsupported {
    use std::{
        io,
        task::{Context, Poll},
    };

    use bytes::BytesMut;
    use qbase::net::{addr::RealAddr, route::PacketHeader};
    use thiserror::Error;

    use crate::{QuicIO, logical::BindUri};

    #[derive(Debug, Clone)]
    pub struct Unsupported {
        bind_uri: BindUri,
    }

    #[derive(Debug, Clone, Copy, Error)]
    #[error(
        "qudp feature is not enabled or target platform is not supported, you should use your own ProductQuicIO implementation, not the default"
    )]
    pub struct UnsupportedError(());

    impl From<UnsupportedError> for io::Error {
        fn from(error: UnsupportedError) -> Self {
            io::Error::new(io::ErrorKind::Unsupported, error)
        }
    }

    impl Unsupported {
        pub fn bind(bind_uri: BindUri) -> Self {
            Unsupported { bind_uri }
        }
    }

    impl QuicIO for Unsupported {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn real_addr(&self) -> io::Result<RealAddr> {
            Err(UnsupportedError(()).into())
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Err(UnsupportedError(()).into())
        }

        fn max_segments(&self) -> io::Result<usize> {
            Err(UnsupportedError(()).into())
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: PacketHeader,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(UnsupportedError(()).into()))
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [PacketHeader],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(UnsupportedError(()).into()))
        }

        fn poll_close(&mut self, _: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
