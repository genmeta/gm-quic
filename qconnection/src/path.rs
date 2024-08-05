use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::frame::PathChallengeFrame;
use qcongestion::{congestion::MSS, CongestionControl};
use qrecovery::space::Epoch;
use qudp::{ArcUsc, Sender, BATCH_SIZE};
use raw::RawPath;
use tokio::task::JoinHandle;

use crate::connection::raw::RawConnection;

mod anti_amplifier;
mod raw;
mod util;

pub use util::PathFrameBuffer;

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

#[derive(Clone)]
pub struct ArcPath {
    raw_path: Arc<Mutex<RawPath>>,
    send_handle: Arc<Mutex<JoinHandle<()>>>,
    inactive_waker: Option<Waker>,
}

impl ArcPath {
    pub fn new(usc: ArcUsc, pathway: Pathway, connection: &RawConnection) -> ArcPath {
        let path = RawPath::new(usc, connection);

        let send_handle = tokio::spawn({
            let mut path = path.clone();
            async move {
                let mut buffers = vec![[0u8; MSS]; BATCH_SIZE];
                let io_slices: Vec<IoSliceMut> =
                    buffers.iter_mut().map(|buf| IoSliceMut::new(buf)).collect();

                let dcid = path.dcid.clone().await;
                let reader = path.packet_reader(dcid, io_slices);

                loop {
                    let count = reader.clone().await;
                    let ioves: Vec<IoSlice<'_>> = buffers
                        .iter()
                        .take(count)
                        .map(|buf| IoSlice::new(buf))
                        .collect();

                    let ret = path.usc.send_via_pathway(ioves.as_slice(), pathway).await;
                    match ret {
                        Ok(_) => todo!(),
                        Err(_) => todo!(),
                    }
                }
            }
        });

        let path = ArcPath {
            raw_path: Arc::new(Mutex::new(path)),
            send_handle: Arc::new(Mutex::new(send_handle)),
            inactive_waker: None,
        };

        tokio::spawn({
            let path = path.clone();
            async move {
                let challenge = PathChallengeFrame::random();

                let mut success = false;
                for _ in 0..3 {
                    // Write to the buffer, and the sending task actually sends it
                    // Reliability is not maintained through reliable transmission, but a stop-and-wait protocol
                    path.lock_guard().challenge_buffer.write(challenge);
                    let pto = path.lock_guard().cc.get_pto_time(Epoch::Data);
                    let listener = path.lock_guard().response_listner.clone();
                    match tokio::time::timeout(pto, listener).await {
                        Ok(Some(resp)) if resp.deref() == challenge.deref() => {
                            path.lock_guard().anti_amplifier.take();
                            success = true;
                            break;
                        }
                        // listner inactive, stop the task
                        Ok(None) => break,
                        // timout or reponse don't match, try again
                        _ => continue,
                    }
                }
                // Path verification failed, inactivate the path
                if !success {
                    path.inactive();
                }
            }
        });

        path
    }

    pub fn lock_guard(&self) -> MutexGuard<'_, RawPath> {
        self.raw_path.lock().unwrap()
    }

    /// Externally observe whether the path is inactive.
    /// The main reason for internal inactivation is path verification failure.
    pub fn has_been_inactivated(&self) -> HasBeenInactivated {
        HasBeenInactivated(self.clone())
    }

    pub fn pto_time(&self) -> Duration {
        self.raw_path.lock().unwrap().pto_time()
    }

    /// Mark the path as inactive due to one of the following reasons:
    /// 1. The connection is closed actively.
    /// 2. The connection is closed due to an error.
    /// 3. Path verification fails.
    pub fn inactive(&self) {
        self.lock_guard().inactive();
        self.send_handle.lock().unwrap().abort();

        if let Some(waker) = &self.inactive_waker {
            waker.wake_by_ref();
        }
    }
}

pub struct HasBeenInactivated(ArcPath);

impl Future for HasBeenInactivated {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.0.lock_guard().is_inactive() {
            Poll::Ready(())
        } else {
            this.0.inactive_waker = Some(cx.waker().clone());
            Poll::Pending
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
        Sender {
            usc: self.clone(),
            iovecs,
            hdr: qudp::PacketHeader {
                src,
                dst,
                ttl: 64,
                ecn: None,
                seg_size: MSS as u16,
                gso: true,
            },
        }
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
