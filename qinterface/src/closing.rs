use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use qbase::{cid::ConnectionId, frame::ConnectionCloseFrame};

use crate::{path::Pathway, router::QuicProto};

pub struct ClosingInterface {
    router_iface: Arc<QuicProto>,
    last_recv_time: Mutex<Instant>,
    rcvd_packets: AtomicUsize,
    scid: Option<ConnectionId>,
    dcid: Option<ConnectionId>,
    ccf: ConnectionCloseFrame,
}

impl ClosingInterface {
    pub(crate) fn new(
        router_iface: Arc<QuicProto>,
        last_recv_time: Mutex<Instant>,
        rcvd_packets: AtomicUsize,
        scid: Option<ConnectionId>,
        dcid: Option<ConnectionId>,
        ccf: ConnectionCloseFrame,
    ) -> Self {
        Self {
            router_iface,
            last_recv_time,
            rcvd_packets,
            scid,
            dcid,
            ccf,
        }
    }

    pub fn should_send(&self) -> bool {
        let mut last_recv_time = self.last_recv_time.lock().unwrap();
        let last_recv_time = core::mem::replace(&mut *last_recv_time, Instant::now());
        let rcvd_packets = self.rcvd_packets.fetch_add(1, Ordering::AcqRel);
        last_recv_time.elapsed() > Duration::from_secs(1) || rcvd_packets % 3 == 0
    }

    pub async fn try_send_with<W>(&self, way: Pathway, dst: SocketAddr, write: W) -> io::Result<()>
    where
        W: for<'a> FnOnce(
            &'a mut [u8],
            Option<ConnectionId>,
            Option<ConnectionId>,
            &'a ConnectionCloseFrame,
        ) -> Option<usize>,
    {
        let send_capability = self.router_iface.send_capability(way)?;
        let mut buf = vec![0; send_capability.max_segment_size as usize];
        if let Some(packet_size) = write(&mut buf, self.scid, self.dcid, &self.ccf) {
            self.router_iface
                .send_packets(&[io::IoSlice::new(&buf[..packet_size])], way, dst)
                .await?;
        }
        Ok(())
    }
}
