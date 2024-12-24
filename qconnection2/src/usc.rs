use std::{
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{ready, Context, Poll},
};

use dashmap::DashMap;
use deref_derive::Deref;
use qcongestion::MSS;
use tokio::task::JoinHandle;

use crate::path::Pathway;

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
static USC_REGISTRY: LazyLock<DashMap<SocketAddr, (ArcUsc, JoinHandle<()>)>> =
    LazyLock::new(DashMap::new);

/// A interface to get or create the [`ArcUsc`] that corresponding to local udp socket.
pub struct UscRegistry;

impl UscRegistry {
    /// Get the exist [`ArcUsc`] which bound the given [`SocketAddr`], or crate one.
    ///
    /// The `recv_task` generate a future task to receive and process datagrams from the udp socket,
    /// the task spawned must take the ownership of the [`ArcUsc`], and dont drop it until a udp error
    /// occur.
    ///
    /// When the [`ArcUsc`] is no longer used, the task spawned will be aborted, and the bound address
    /// will be free automatically.
    ///
    /// For client, when all of the connections which use the address are closed, the [`ArcUsc`] will
    /// be dropped, the spawned task will be aborted, bound address will be free.
    ///
    /// For server, the address will not be freed until the address is unbined by server, or the server
    /// is closed.
    pub fn get_or_create_usc<Task, F>(addr: SocketAddr, recv_task: F) -> io::Result<ArcUsc>
    where
        Task: Future<Output = ()> + Send + 'static,
        F: FnOnce(ArcUsc) -> Task,
    {
        // for port 0, its always create a new usc
        if addr.port() == 0 {
            return UscRegistry::create_new_usc(addr, recv_task);
        }

        // for other ports, lock the entry for avoiding the racing condition
        let entry = USC_REGISTRY.entry(addr);
        if let dashmap::Entry::Occupied(entry) = entry {
            return Ok(entry.get().0.clone());
        }

        let usc = Arc::new(qudp::UdpSocketController::new(addr)?);
        let addr = usc.local_addr()?;

        let usc = ArcUsc { usc, addr };

        let recv_task = tokio::spawn(recv_task(usc.clone()));
        entry.insert((usc.clone(), recv_task));

        Ok(usc)
    }

    /// Create a *new* [`ArcUsc`] that bound the given [`SocketAddr`].
    ///
    /// This is similar to [`UscRegistry::get_or_create_usc`], but it will return an error if the
    /// address is already bound.
    pub fn create_new_usc<Task, F>(addr: SocketAddr, recv_task: F) -> io::Result<ArcUsc>
    where
        Task: Future<Output = ()> + Send + 'static,
        F: FnOnce(ArcUsc) -> Task,
    {
        let usc = Arc::new(qudp::UdpSocketController::new(addr)?);
        let addr = usc.local_addr()?;

        let usc = ArcUsc { usc, addr };

        let recv_task = tokio::spawn(recv_task(usc.clone()));
        USC_REGISTRY.insert(addr, (usc.clone(), recv_task));

        Ok(usc)
    }
}

/// A wrapper around the [`UdpSocketController`] that can be shared across threads.
///
/// This struct also provide useful methods to send datagrams via a given [`Pathway`].
///
/// [`UdpSocketController`]: qudp::UdpSocketController
#[derive(Debug, Clone, Deref)]
pub struct ArcUsc {
    #[deref]
    usc: Arc<qudp::UdpSocketController>,
    addr: SocketAddr,
}

impl ArcUsc {
    /// Get the local address that the udp socket bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Poll send the datagrams via the given pathway.
    pub fn poll_send_via(
        &self,
        cx: &mut Context,
        iovecs: &[IoSlice],
        pathway: Pathway,
    ) -> Poll<io::Result<usize>> {
        // todo: append relay hdr
        let hdr = qudp::PacketHeader {
            src: pathway.local_addr(),
            dst: pathway.dst_addr(),
            ttl: 64,
            ecn: None,
            seg_size: MSS as u16,
            gso: true,
        };
        self.usc.poll_send(iovecs, &hdr, cx)
    }

    /// Send all the datagrams via the given pathway.
    ///
    /// The returned future completes when all the datagrams are sent, or an error occurs(or occured)
    /// on udp socket.
    pub fn send_all_via_pathway<'s>(
        &'s self,
        iovecs: &'s [IoSlice<'s>],
        pathway: Pathway,
    ) -> SendAllViaPathWay<'s> {
        SendAllViaPathWay {
            usc: self,
            iovecs,
            pathway,
        }
    }
}

// TOOD: its not a good idea to use strong_count to determine whether the usc is dropped
impl Drop for ArcUsc {
    fn drop(&mut self) {
        // 3 = self, registry, recv_task
        // for server, it will hold one instance of usc
        if Arc::strong_count(&self.usc) == 3 {
            if let Some((_addr, (_usc, recvtask))) = USC_REGISTRY.remove(&self.addr) {
                recvtask.abort();
            }
        }
    }
}

/// A future that send all the datagrams via the given pathway.
///
/// The future completes when all the datagrams are sent, or an error occurs(or occured) on udp socket.
pub struct SendAllViaPathWay<'s> {
    usc: &'s ArcUsc,
    iovecs: &'s [IoSlice<'s>],
    pathway: Pathway,
}

impl Unpin for SendAllViaPathWay<'_> {}

impl Future for SendAllViaPathWay<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let iovecs = &mut this.iovecs;
        while !iovecs.is_empty() {
            let send_once = this.usc.poll_send_via(cx, iovecs, this.pathway);
            let n = ready!(send_once)?;
            *iovecs = &iovecs[n..];
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind() {
        let recv_task = |usc: ArcUsc| async move {
            let _usc = usc;
            core::future::pending::<()>().await;
        };

        let unspecified: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let specified: SocketAddr = "127.0.0.1:18123".parse().unwrap();

        {
            // bind unspecified
            // hold the usc or it will be dropped immediately.
            let usc = UscRegistry::get_or_create_usc(unspecified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 1);

            let usc = UscRegistry::get_or_create_usc(unspecified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 2);

            let usc = UscRegistry::create_new_usc(unspecified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 3);

            let usc = UscRegistry::create_new_usc(unspecified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 4);

            // bind specified, and reuse the address
            let usc = UscRegistry::create_new_usc(specified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 5);

            // faild beacuse the address is already bound
            let usc = UscRegistry::create_new_usc(specified, recv_task);
            assert!(usc.is_err());
            assert_eq!(USC_REGISTRY.len(), 5);

            // its ok to get the exist usc
            let usc = UscRegistry::get_or_create_usc(specified, recv_task);
            assert!(usc.is_ok());
            assert_eq!(USC_REGISTRY.len(), 5);
        }
        // empty because all usage of the usc is dropped
        assert!(USC_REGISTRY.is_empty());
    }
}
