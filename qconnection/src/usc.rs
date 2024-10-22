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
static USC_REGISTRY: LazyLock<DashMap<SocketAddr, UscRegistry>> = LazyLock::new(DashMap::new);

pub struct UscRegistry {
    usc: ArcUsc,
    recv_task: JoinHandle<()>,
}

impl UscRegistry {
    /// Create a new [`ArcUsc`] and spawn a task to receive packets or return the existing one.
    ///
    /// Note that the future returned by `recv_task` must not be complete unless a udp error occurs.
    pub fn get_or_create_usc<Task, F>(addr: SocketAddr, recv_task: F) -> io::Result<ArcUsc>
    where
        Task: Future<Output = ()> + Send + 'static,
        F: FnOnce(ArcUsc) -> Task,
    {
        if let Some(UscRegistry { usc, .. }) = USC_REGISTRY.get(&addr).as_deref() {
            return Ok(usc.clone());
        }

        let usc = Arc::new(qudp::UdpSocketController::new(addr)?);
        let addr = usc.local_addr()?;

        let usc = ArcUsc { usc, addr };

        let recv_task = tokio::spawn(recv_task(usc.clone()));
        let registry = UscRegistry {
            usc: usc.clone(),
            recv_task,
        };
        USC_REGISTRY.insert(addr, registry);

        Ok(usc)
    }
}

#[derive(Clone, Deref)]
pub struct ArcUsc {
    #[deref]
    usc: Arc<qudp::UdpSocketController>,
    addr: SocketAddr,
}

impl ArcUsc {
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

impl Drop for ArcUsc {
    fn drop(&mut self) {
        // 3 = self, registry, recv_task
        if Arc::strong_count(&self.usc) == 3 {
            // is possible that: recv_task is complete because usc error
            //                   or, while this drop is called, another drop is called,
            // so, pattern matching is necessary here, expect will panic
            if let Some((_addr, registry)) = USC_REGISTRY.remove(&self.addr) {
                registry.recv_task.abort();
            }
        }
    }
}

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
