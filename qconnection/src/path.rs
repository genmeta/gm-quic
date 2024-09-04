use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qbase::cid::{ArcCidCell, ConnectionId};
use qcongestion::{congestion::MSS, CongestionControl};
use qrecovery::{reliable::ArcReliableFrameDeque, space::Epoch};
use qudp::ArcUsc;

mod anti_amplifier;
mod raw;
mod state;
mod util;

pub mod pathway;
pub mod read;

pub use anti_amplifier::ArcAntiAmplifier;
pub use pathway::Pathway;
pub use raw::RawPath;
pub use util::{RecvBuffer, SendBuffer};

pub trait ViaPathway {
    fn poll_send_via_pathway(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
        pathway: Pathway,
    ) -> Poll<io::Result<usize>>;

    fn sync_send_via_path_way(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()>;
}

impl ViaPathway for ArcUsc {
    fn poll_send_via_pathway<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
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
        ArcUsc::poll_send(self.get_mut(), bufs, &hdr, cx)
    }

    fn sync_send_via_path_way(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()> {
        // todo: append relay hdr
        let hdr = qudp::PacketHeader {
            src: pathway.local_addr(),
            dst: pathway.dst_addr(),
            ttl: 64,
            ecn: None,
            seg_size: MSS as u16,
            gso: true,
        };
        self.sync_send(iovec, &hdr)
    }
}

pub trait ViaPathWayExt: ViaPathway {
    fn send_via_pathway<'s>(
        &'s mut self,
        iovecs: &'s [IoSlice<'s>],
        pathway: Pathway,
    ) -> SendViaPathWay<'s, Self>
    where
        Self: Unpin,
    {
        SendViaPathWay {
            sender: self,
            iovecs,
            pathway,
        }
    }

    fn send_all_via_pathway<'s>(
        &'s mut self,
        iovecs: &'s [IoSlice<'s>],
        pathway: Pathway,
    ) -> SendAllViaPathWay<'s, Self>
    where
        Self: Unpin,
    {
        SendAllViaPathWay {
            sender: self,
            iovecs,
            pathway,
        }
    }
}

impl<V: ViaPathway + ?Sized> ViaPathWayExt for V {}

pub struct SendViaPathWay<'s, S: ?Sized> {
    sender: &'s mut S,
    iovecs: &'s [IoSlice<'s>],
    pathway: Pathway,
}

impl<S: Unpin + ?Sized> Unpin for SendViaPathWay<'_, S> {}

impl<S: ViaPathway + Unpin + ?Sized> Future for SendViaPathWay<'_, S> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        Pin::new(&mut *this.sender).poll_send_via_pathway(cx, this.iovecs, this.pathway)
    }
}

pub struct SendAllViaPathWay<'s, S: ?Sized> {
    sender: &'s mut S,
    iovecs: &'s [IoSlice<'s>],
    pathway: Pathway,
}

impl<S: Unpin + ?Sized> Unpin for SendAllViaPathWay<'_, S> {}

impl<S: ViaPathway + Unpin + ?Sized> Future for SendAllViaPathWay<'_, S> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut iovecs = this.iovecs;
        while !iovecs.is_empty() {
            let send_once =
                Pin::new(&mut *this.sender).poll_send_via_pathway(cx, iovecs, this.pathway);
            let n = ready!(send_once)?;
            iovecs = &iovecs[n..];
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Deref)]
pub struct ArcPath(Arc<RawPath>);

impl ArcPath {
    pub fn new(usc: ArcUsc, scid: ConnectionId, dcid: ArcCidCell<ArcReliableFrameDeque>) -> Self {
        Self(Arc::new(RawPath::new(usc, scid, dcid)))
    }
}

#[derive(Deref, DerefMut)]
pub struct Pathes {
    #[deref]
    map: DashMap<Pathway, ArcPath>,
    creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>,
}

impl Pathes {
    fn new(creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>) -> Self {
        Self {
            map: DashMap::new(),
            creator,
        }
    }

    pub fn get_or_create(&self, pathway: Pathway, usc: ArcUsc) -> ArcPath {
        let map_clone = self.map.clone();
        self.map
            .entry(pathway)
            .or_insert_with(|| {
                let path = (self.creator)(pathway, usc);
                let state = path.state.clone();
                tokio::spawn({
                    let state = state.clone();
                    let cc = path.cc.clone();
                    async move {
                        loop {
                            tokio::select! {
                                _ = state.has_been_inactivated() => break,
                                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => cc.do_tick(),
                            }
                        }
                        map_clone.remove(&pathway);
                    }
                });
                path
            })
            .value()
            .clone()
    }
}

#[derive(Clone, Deref, DerefMut)]
pub struct ArcPathes(Arc<Pathes>);

impl ArcPathes {
    pub fn new(creator: Box<dyn Fn(Pathway, ArcUsc) -> ArcPath + Send + Sync + 'static>) -> Self {
        Self(Arc::new(Pathes::new(creator)))
    }
}
