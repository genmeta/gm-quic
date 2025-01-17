#[cfg(feature = "qudp")]
mod qudp {
    use std::{
        io,
        net::SocketAddr,
        sync::Mutex,
        task::{Context, Poll},
    };

    use bytes::BytesMut;

    use crate::{
        path::{Endpoint, Pathway, Socket},
        QuicInterface,
    };

    struct ReceiveBuffers {
        unread: usize,
        bufs: Vec<BytesMut>,
        hdrs: Vec<qudp::PacketHeader>,
    }

    impl ReceiveBuffers {
        fn empty(gro_size: u16) -> Self {
            Self {
                unread: 0,
                bufs: vec![bytes::BytesMut::zeroed(1200); gro_size as _],
                hdrs: vec![qudp::PacketHeader::default(); gro_size as _],
            }
        }
    }

    pub struct Usc {
        inner: qudp::UdpSocketController,
        recv_bufs: Mutex<ReceiveBuffers>,
    }

    impl Usc {
        pub fn bind(addr: SocketAddr) -> io::Result<Self> {
            let usc = qudp::UdpSocketController::new(addr)?;
            let bufs = ReceiveBuffers::empty(usc.gro_size()).into();
            Ok(Self {
                inner: usc,
                recv_bufs: bufs,
            })
        }
    }

    impl QuicInterface for Usc {
        fn reversed_bytes(&self, _on: Pathway) -> io::Result<usize> {
            Ok(0)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(self.inner.gso_size() as _)
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1200)
        }

        fn poll_send(
            &self,
            cx: &mut Context,
            ptks: &[io::IoSlice],
            _way: Pathway,
            dst: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            let src = self.local_addr()?;
            let hdr = qudp::PacketHeader {
                src,
                dst,
                ttl: 64,
                ecn: None,
                seg_size: self.max_segment_size()? as _,
                gso: true,
            };

            self.inner.poll_send(ptks, &hdr, cx)
        }

        fn poll_recv(&self, cx: &mut Context) -> Poll<io::Result<(BytesMut, Pathway, Socket)>> {
            let mut recv_buffer = self.recv_bufs.lock().unwrap();

            while recv_buffer.unread == 0 {
                let ReceiveBuffers { bufs, hdrs, .. } = &mut *recv_buffer;
                // 想不vec!也行，但是那样就得处理自引用结构之类的...，太复杂而了
                // 之后可以考虑用small_vec这样的库，array小于一个阈值就放在栈上，更可接受
                let mut io_slices = bufs
                    .iter_mut()
                    .map(|buf| io::IoSliceMut::new(&mut buf[..]))
                    .collect::<Vec<_>>(); // :(
                recv_buffer.unread =
                    core::task::ready!(self.inner.poll_recv(&mut io_slices, hdrs, cx)?);
            }

            recv_buffer.unread -= 1;
            let mut bytes_mut = recv_buffer.bufs[recv_buffer.unread].clone();
            bytes_mut.truncate(recv_buffer.hdrs[recv_buffer.unread].seg_size as _);
            // let local = recv_buffer.hdrs[recv_buffer.unread].dst;
            let local = self.local_addr()?;
            let remote = recv_buffer.hdrs[recv_buffer.unread].src;
            let socket = Socket::new(local, remote);
            let local = Endpoint::Direct { addr: local };
            let remote = Endpoint::Direct { addr: remote };
            let pathway = Pathway::new(local, remote);

            Poll::Ready(Ok((bytes_mut, pathway, socket)))
        }
    }
}

#[cfg(feature = "qudp")]
pub use qudp::Usc;
