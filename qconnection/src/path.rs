#![allow(dead_code)]

use std::{
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use dashmap::DashMap;
use dying::DyingPath;
use qbase::{
    cid::{ConnectionId, Registry},
    flow::FlowController,
    frame::{ConnectionCloseFrame, PathChallengeFrame, PathResponseFrame},
    packet::SpinBit,
};
use qcongestion::congestion::MSS;
use qrecovery::space::Epoch;
use qudp::ArcUsc;
use raw::{AllKeys, AllSpaces, RawPath};

mod anti_amplifier;
mod dying;
mod raw;

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
    Dying(DyingPath),
    Dead,
}

#[derive(Clone)]
pub struct ArcPath(Arc<Mutex<PathState>>);

impl ArcPath {
    /// 收到对方的路径挑战帧，如果不是 Alive 状态，直接忽略
    fn recv_challenge(&self, frame: PathChallengeFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_challenge(frame)
        }
    }

    /// 收到对方的路径响应帧，如果不是 Alive 状态，直接忽略
    fn recv_response(&self, frame: PathResponseFrame) {
        let mut guard = self.0.lock().unwrap();
        if let PathState::Alive(path) = &mut *guard {
            path.recv_response(frame)
        }
    }

    /// 失活检测器
    fn has_been_inactivated(&self) -> HasBeenInactivated {
        HasBeenInactivated(self.clone())
    }

    /// 收到 connection frame ，如果是 Alive 或者 Dying 状态，可以发一个 ccf 再进入 Dead
    /// Dead 状态则忽略
    fn recv_ccf(&self, frame: ConnectionCloseFrame, epoch: Epoch) {
        let mut guard = self.0.lock().unwrap();
        let dying = match &mut *guard {
            PathState::Alive(raw) => {
                let ccf = raw.read_connection_close_frame(frame, epoch);
                DyingPath::new(raw.usc.clone(), raw.pathway, ccf, raw.pto_time())
            }
            PathState::Dying(dying) => dying.clone(),
            PathState::Dead => {
                log::trace!("recv_ccf: path is dead");
                return;
            }
        };

        // send ccf
        tokio::spawn({
            let dying = dying.clone();
            async move {
                let ret = dying.send_ccf().await;
                log::trace!("send_ccf: ret={:?}", ret);
            }
        });
        *guard = PathState::Dead;
    }

    // 当 connection 发生错误时或要主动结束时，进入 Cosing 状态
    fn enter_closing(&self, frame: ConnectionCloseFrame, epoch: Epoch) {
        let mut guard = self.0.lock().unwrap();

        let dying = if let PathState::Alive(raw) = &mut *guard {
            let ccf = raw.read_connection_close_frame(frame, epoch);
            DyingPath::new(raw.usc.clone(), raw.pathway, ccf, raw.pto_time())
        } else {
            log::debug!("enter_closing: path is not Alive");
            return;
        };

        *guard = PathState::Dying(dying.clone());
        tokio::spawn({
            async move {
                for _ in 0..3 {
                    let ret = dying.send_ccf().await;
                    log::trace!("send_ccf: ret={:?}", ret);
                    tokio::time::sleep(dying.pto).await;
                }
            }
        });
    }
}

// TODO: 从 connection 构造，不需要这么多参数
#[allow(clippy::too_many_arguments)]
pub fn create_path(
    usc: ArcUsc,
    pathway: Pathway,
    spaces: AllSpaces,
    keys: AllKeys,
    flow_controller: FlowController,
    cid_registry: Registry,
    spin: SpinBit,
    scid: ConnectionId,
    token: Vec<u8>,
    _pathes: DashMap<Pathway, ArcPath>,
) -> ArcPath {
    let dcid = cid_registry.remote.apply_cid();
    let raw_path = RawPath::new(
        usc,
        pathway,
        spaces,
        keys,
        flow_controller,
        dcid,
        scid,
        token.clone(),
        spin,
    );
    ArcPath(Arc::new(Mutex::new(PathState::Alive(raw_path.clone()))))
}

struct HasBeenInactivated(ArcPath);

impl Future for HasBeenInactivated {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match *self.0 .0.lock().unwrap() {
            PathState::Alive(_) => Poll::Pending,
            PathState::Dying(_) => Poll::Ready(()),
            PathState::Dead => Poll::Ready(()),
        }
    }
}

pub trait ViaPathway {
    fn poll_send_via_pathway(
        &mut self,
        iovecs: &[IoSlice<'_>],
        pathway: Pathway,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<usize>>;
}

impl ViaPathway for ArcUsc {
    fn poll_send_via_pathway(
        &mut self,
        iovecs: &[IoSlice<'_>],
        pathway: Pathway,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<usize>> {
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
        self.poll_send(iovecs, &hdr, cx)
    }
}
