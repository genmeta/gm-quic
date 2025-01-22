use std::{
    convert::Infallible,
    io,
    ops::ControlFlow,
    pin::pin,
    sync::{atomic::Ordering, Arc},
};

use qbase::Epoch;
use tokio::sync::Notify;

use crate::{
    space::Spaces, tx::Transaction, ArcDcidCell, ArcLocalCids, Components, FlowController,
};

pub struct Burst {
    path: Arc<super::Path>,
    local_cids: ArcLocalCids,
    dcid: ArcDcidCell,
    spin: bool,
    flow_ctrl: FlowController,
    spaces: Spaces,
    conn_send_notify: Arc<Notify>,
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        let local_cids = components.cid_registry.local.clone();
        let dcid = components.cid_registry.remote.apply_dcid();
        let flow_ctrl = components.flow_ctrl.clone();
        let path = self.clone();
        let spin = false;
        let spaces = components.spaces.clone();
        let conn_send_notify = components.send_notify.clone();
        Burst {
            path,
            local_cids,
            dcid,
            spin,
            flow_ctrl,
            spaces,
            conn_send_notify,
        }
    }
}

impl Burst {
    fn prepare_buffers<'b>(
        &self,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> io::Result<impl Iterator<Item = &'b mut [u8]>> {
        let max_segments = self.path.interface.max_segments()?;
        let max_segment_size = self.path.interface.max_segment_size()?;

        if buffers.len() < max_segments {
            buffers.resize_with(max_segments, || vec![0; max_segment_size]);
        }

        Ok(buffers.iter_mut().map(move |buffer| {
            if buffer.len() < max_segment_size {
                buffer.resize(max_segment_size, 0);
            }
            &mut buffer[..max_segment_size]
        }))
    }

    async fn load_into_buffers<'b>(
        &'b self,
        prepared_buffers: impl Iterator<Item = &'b mut [u8]> + 'b,
    ) -> io::Result<impl Iterator<Item = io::IoSlice<'b>>> {
        let scid = self.local_cids.initial_scid();
        let mut transaction = Transaction::prepare(
            scid.unwrap_or_default(),
            &self.dcid,
            self.path.cc(),
            &self.path.anti_amplifier,
            &self.flow_ctrl,
        )
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        let reversed_size = self.path.interface.reversed_bytes(self.path.pathway)?;

        Ok(prepared_buffers
            .map(move |buffer| {
                let packet_size = if scid.is_some() {
                    transaction.load_spaces(
                        &mut buffer[reversed_size..],
                        &self.spaces,
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                    )
                } else if self.path.validated.load(Ordering::Acquire) {
                    let (mid_pkt, ack, fresh_data) = transaction.load_1rtt_data(
                        &mut buffer[reversed_size..],
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                        self.spaces.data(),
                    )?;
                    let packet = mid_pkt.resume(buffer).encrypt_and_protect();
                    transaction.commit(Epoch::Data, packet, fresh_data, ack);
                    packet.size()
                } else {
                    let packet = transaction.load_validation(
                        &mut buffer[reversed_size..],
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                        self.spaces.data(),
                    )?;
                    transaction.commit(Epoch::Data, packet, 0, None);
                    packet.size()
                };

                if packet_size == 0 {
                    None
                } else {
                    Some(io::IoSlice::new(&buffer[..reversed_size + packet_size]))
                }
            })
            // (0..10).filter_map(|x| x % 2 == 0) ==> [0, 2, 4, 6, 8].iter()
            // what we want is [0].iter(), so we need to take_while(Option::is_some).flatten()
            .take_while(Option::is_some)
            .flatten())
    }

    fn collect_filled_buffers<'b>(
        &self,
        mut filled_buffers: impl Iterator<Item = io::IoSlice<'b>>,
    ) -> io::Result<Vec<io::IoSlice<'b>>> {
        let max_segments = self.path.interface.max_segments()?;
        let max_segment_size = self.path.interface.max_segment_size()?;
        let (ControlFlow::Break(filled_buffers) | ControlFlow::Continue(filled_buffers)) =
            filled_buffers.try_fold(
                Vec::with_capacity(max_segments),
                |mut filled_buffers, io_slice| {
                    filled_buffers.push(io_slice);
                    if io_slice.len() == max_segment_size {
                        ControlFlow::Continue(filled_buffers)
                    } else {
                        ControlFlow::Break(filled_buffers)
                    }
                },
            );
        Ok(filled_buffers)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn launch(self) -> io::Result<Infallible> {
        let mut buffers = vec![];
        let mut path_sendable = pin!(self.path.sendable.notified());
        let mut conn_sendable = pin!(self.conn_send_notify.notified());
        loop {
            path_sendable.as_mut().enable();
            conn_sendable.as_mut().enable();
            let buffers = self.prepare_buffers(&mut buffers)?;
            let buffers = self.load_into_buffers(buffers).await?;
            let segments = self.collect_filled_buffers(buffers)?;
            if !segments.is_empty() {
                tracing::trace!(
                    packets = ?segments.iter().map(|seg| seg.len()).collect::<Vec<_>>(),
                    "sending packets"
                );
                self.path.send_packets(&segments).await?;
            } else {
                tracing::trace!("no packet to send, waiting for notification");
                tokio::select! {
                    _ = path_sendable.as_mut() => {},
                    _ = conn_sendable.as_mut() => {},
                }
                path_sendable.set(self.path.sendable.notified());
                conn_sendable.set(self.conn_send_notify.notified());
            }
        }
    }
}
