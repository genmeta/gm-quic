use std::{
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use dashmap::DashMap;
use qbase::frame::{AckFrame, PathChallengeFrame, PathResponseFrame};
use qcongestion::congestion::MSS;
use qrecovery::space::Epoch;
use qudp::ArcUsc;
use raw::RawPath;

use crate::connection::raw::RawConnection;

mod anti_amplifier;
mod raw;
mod util;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct RelayAddr {
    pub agent: SocketAddr, // 代理人
    pub addr: SocketAddr,
}

/// 无论哪种Pathway，socket都必须绑定local地址
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Pathway {
    Direct {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay {
        local: RelayAddr,
        remote: RelayAddr,
    },
}

enum PathState {
    Alive(RawPath),
    Dead,
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

impl ArcPath {
    pub fn on_ack(&self, epoch: Epoch, ack: &AckFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.on_ack(epoch, ack);
        }
    }

    pub fn on_recv_pkt(&self, epoch: Epoch, pn: u64, is_ackeliciting: bool) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.on_recv_pkt(epoch, pn, is_ackeliciting);
        }
    }

    /// 收到对方的路径挑战帧，如果不是 Alive 状态，直接忽略
    pub fn recv_challenge(&self, frame: PathChallengeFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_challenge(frame)
        }
    }

    /// 收到对方的路径响应帧，如果不是 Alive 状态，直接忽略
    pub fn recv_response(&self, frame: PathResponseFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_response(frame)
        }
    }

    /// 失活检测器
    pub fn has_been_inactivated(&self) -> HasBeenInactivated {
        HasBeenInactivated(self.clone())
    }
}

pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    connection: &RawConnection,
    _pathes: DashMap<Pathway, ArcPath>,
) -> ArcPath {
    let raw_path = RawPath::new(usc, pathway, connection);
    ArcPath(Arc::new(Mutex::new(PathState::Alive(raw_path.clone()))))
}

pub struct HasBeenInactivated(ArcPath);

impl Future for HasBeenInactivated {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match *self.0 .0.lock().unwrap() {
            PathState::Alive(_) => Poll::Pending,
            // PathState::Dying(_) => Poll::Ready(()),
            PathState::Dead => Poll::Ready(()),
        }
    }
}

pub trait ViaPathway {
    fn send_via_pathway<'a>(
        &mut self,
        iovecs: &'a [IoSlice<'a>],
        pathway: Pathway,
    ) -> qudp::Sender<'a>;

    fn sync_send_via_pathway(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()>;
}

impl ViaPathway for ArcUsc {
    fn send_via_pathway<'a>(
        &mut self,
        iovecs: &'a [IoSlice<'a>],
        pathway: Pathway,
    ) -> qudp::Sender<'a> {
        let (src, dst) = match &pathway {
            Pathway::Direct { local, remote } => (*local, *remote),
            // todo: append relay hdr
            Pathway::Relay { local, remote } => (local.addr, remote.agent),
        };
        let hdr = qudp::PacketHeader {
            src,
            dst,
            ttl: 64,
            ecn: None,
            seg_size: MSS as u16,
            gso: true,
        };
        let sender = self.sender(iovecs, hdr);
        sender
    }

    fn sync_send_via_pathway(&mut self, iovec: Vec<u8>, pathway: Pathway) -> io::Result<()> {
        let (src, dst) = match &pathway {
            Pathway::Direct { local, remote } => (*local, *remote),
            // todo: append relay hdr
            Pathway::Relay { local, remote } => (local.addr, remote.agent),
        };
        let hdr = qudp::PacketHeader {
            src,
            dst,
            ttl: 64,
            ecn: None,
            seg_size: MSS as u16,
            gso: true,
        };
        self.sync_send(iovec, hdr)
    }
}
