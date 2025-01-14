use std::{convert::Infallible, io, ops::ControlFlow, pin::pin, sync::Arc};

use qbase::Epoch;
use qinterface::SendCapability;
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
    fn prepare_buffer<'b>(
        &self,
        send_capability: &SendCapability,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> impl Iterator<Item = &'b mut [u8]> {
        let max_segments = send_capability.max_segments as usize;
        let max_segment_size = send_capability.max_segment_size as usize;
        let reversed_size = send_capability.reversed_size as usize;

        if buffers.len() < max_segments {
            buffers.resize_with(max_segments, || vec![0; max_segment_size]);
        }

        buffers.iter_mut().map(move |buffer| {
            if buffer.len() < max_segment_size {
                buffer.resize(max_segment_size, 0);
            }
            &mut buffer[reversed_size..max_segment_size]
        })
    }

    async fn load_into_buffers<'b>(
        &'b self,
        send_capability: &SendCapability,
        prepared_buffers: impl Iterator<Item = &'b mut [u8]> + 'b,
    ) -> io::Result<impl Iterator<Item = io::IoSlice<'b>>> {
        let scid = self.local_cids.initial_scid();
        let mut transaction = Transaction::prepare(
            scid.unwrap_or_default(),
            &self.dcid,
            &self.path.cc,
            &self.path.anti_amplifier,
            &self.flow_ctrl,
        )
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        let reversed_size = send_capability.reversed_size as usize;
        Ok(prepared_buffers.filter_map(move |buffer| {
            let packet_size = if scid.is_some() && self.path.kind.is_initial() {
                transaction.load_spaces(
                    &mut buffer[reversed_size..],
                    &self.spaces,
                    self.spin.into(),
                    &self.path.challenge_sndbuf,
                    &self.path.response_sndbuf,
                )
            } else {
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
            };

            if packet_size == 0 {
                None
            } else {
                Some(io::IoSlice::new(&buffer[..reversed_size + packet_size]))
            }
        }))
    }

    fn collect_filled_buffers<'b>(
        send_capability: &SendCapability,
        mut filled_buffers: impl Iterator<Item = io::IoSlice<'b>>,
    ) -> Vec<io::IoSlice<'b>> {
        let mac_segments = send_capability.max_segments as usize;
        let max_segment_size = send_capability.max_segment_size as usize;
        let (ControlFlow::Break(filled_buffers) | ControlFlow::Continue(filled_buffers)) =
            filled_buffers.try_fold(
                Vec::with_capacity(mac_segments),
                |mut filled_buffers, io_slice| {
                    filled_buffers.push(io_slice);
                    if io_slice.len() == max_segment_size {
                        ControlFlow::Continue(filled_buffers)
                    } else {
                        ControlFlow::Break(filled_buffers)
                    }
                },
            );
        filled_buffers
    }

    pub async fn launch(self) -> io::Result<Infallible> {
        let mut buffers = vec![];
        let mut send_notified1 = pin!(self.path.send_notify.notified());
        let mut send_notified2 = pin!(self.conn_send_notify.notified());
        loop {
            send_notified1.as_mut().enable();
            send_notified2.as_mut().enable();
            let send_capability = self.path.send_capability()?;
            let prepared_buffers = self.prepare_buffer(&send_capability, &mut buffers);
            let filled_buffers = self
                .load_into_buffers(&send_capability, prepared_buffers)
                .await?;
            let segments = Self::collect_filled_buffers(&send_capability, filled_buffers);
            if !segments.is_empty() {
                self.path
                    .send_packets(&segments, self.path.pathway.dst())
                    .await?;
            } else {
                tokio::select! {
                    _ = send_notified1.as_mut() => {},
                    _ = send_notified2.as_mut() => {},
                }
                send_notified1.set(self.path.send_notify.notified());
                send_notified2.set(self.conn_send_notify.notified());
            }
        }
    }
}
