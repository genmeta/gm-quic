use std::{
    convert::Infallible,
    io,
    ops::ControlFlow,
    sync::{atomic::AtomicBool, Arc},
};

use qbase::{cid::ConnectionId, Epoch};

use crate::{
    space::{DataSpace, Spaces},
    tx::{DcidCell, Transaction},
    FlowController,
};

pub struct Burst<S> {
    path: Arc<super::Path>,
    scid: ConnectionId,
    dcid: DcidCell,
    spin: Arc<AtomicBool>,
    flow_ctrl: FlowController,
    space: S,
}

impl super::Path {
    pub fn new_one_rtt_burst(
        self: &Arc<Self>,
        dcid: DcidCell,
        flow_ctrl: FlowController,
        space: DataSpace,
    ) -> Burst<DataSpace> {
        let path = self.clone();
        let spin = Arc::new(AtomicBool::new(false));
        Burst {
            path,
            scid: Default::default(),
            dcid,
            spin,
            flow_ctrl,
            space,
        }
    }

    pub fn new_all_level_burst(
        self: &Arc<Self>,
        scid: ConnectionId,
        dcid: DcidCell,
        flow_ctrl: FlowController,
        space: Spaces,
    ) -> Burst<Spaces> {
        let path = self.clone();
        let spin = Arc::new(AtomicBool::new(false));
        Burst {
            path,
            scid,
            dcid,
            spin,
            flow_ctrl,
            space,
        }
    }
}

impl<S> Burst<S> {
    async fn new_transaction(&self) -> io::Result<Transaction> {
        Transaction::prepare(
            self.scid,
            &self.dcid,
            &self.path.cc,
            &self.path.anti_amplifier,
            &self.flow_ctrl,
        )
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }
}

impl Burst<Spaces> {
    pub async fn launch(self) -> io::Result<Infallible> {
        let mut buffers = vec![];
        loop {
            let segs = {
                let mut transaction = self.new_transaction().await?;
                let send_capability = self.path.send_capability()?;

                let max_segs = send_capability.max_segments as usize;
                let max_seg_size = send_capability.max_segment_size as usize;
                let reversed_size = send_capability.reversed_size as usize;

                if buffers.len() < max_segs {
                    buffers.resize_with(max_segs, || vec![0; max_seg_size]);
                }

                let (ControlFlow::Break(segs) | ControlFlow::Continue(segs)) = buffers
                    .iter_mut()
                    .map(|buf| {
                        if buf.len() < max_seg_size {
                            buf.resize(max_seg_size, 0);
                        }
                        &mut buf[..max_seg_size]
                    })
                    .try_fold(Vec::with_capacity(max_segs), |mut segs, buffer| {
                        let packets_size = transaction.load_spaces(
                            buffer,
                            &self.space,
                            &self.spin,
                            &self.path.challenge_sndbuf,
                            &self.path.response_sndbuf,
                        );

                        if packets_size == 0 {
                            return ControlFlow::Break(segs);
                        }

                        segs.push(io::IoSlice::new(&buffer[..reversed_size + packets_size]));

                        if reversed_size + packets_size < max_seg_size {
                            ControlFlow::Break(segs)
                        } else {
                            ControlFlow::Continue(segs)
                        }
                    });
                segs
            };
            self.path.send_packets(&segs, self.path.way.dst()).await?;
        }
    }
}

impl Burst<DataSpace> {
    pub async fn launch(self) -> io::Result<Infallible> {
        let mut buffers = vec![];
        loop {
            let segs = {
                let mut transaction = self.new_transaction().await?;
                let send_capability = self.path.send_capability()?;

                let max_segs = send_capability.max_segments as usize;
                let max_seg_size = send_capability.max_segment_size as usize;
                let reversed_size = send_capability.reversed_size as usize;

                if buffers.len() < max_segs {
                    buffers.resize_with(max_segs, || vec![0; max_seg_size]);
                }

                let (ControlFlow::Break(segs) | ControlFlow::Continue(segs)) = buffers
                    .iter_mut()
                    .map(|buf| {
                        if buf.len() < max_seg_size {
                            buf.resize(max_seg_size, 0);
                        }
                        &mut buf[..max_seg_size]
                    })
                    .try_fold(Vec::with_capacity(max_segs), |mut segs, buffer| {
                        let load_1rtt_data = transaction.load_1rtt_data(
                            buffer,
                            &self.spin,
                            &self.path.challenge_sndbuf,
                            &self.path.response_sndbuf,
                            &self.space,
                        );

                        let Some((mid_packet, ack, fresh_data)) = load_1rtt_data else {
                            return ControlFlow::Break(segs);
                        };

                        let packet = mid_packet.resume(buffer).encrypt_and_protect();
                        let packet_size = packet.size();

                        transaction.commit(Epoch::Data, packet, fresh_data, ack);
                        segs.push(io::IoSlice::new(&buffer[..reversed_size + packet_size]));

                        if reversed_size + packet_size < max_seg_size {
                            ControlFlow::Break(segs)
                        } else {
                            ControlFlow::Continue(segs)
                        }
                    });
                segs
            };
            self.path.send_packets(&segs, self.path.way.dst()).await?;
        }
    }
}
