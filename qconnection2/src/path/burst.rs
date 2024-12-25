use std::sync::{atomic::AtomicBool, Arc};

use qbase::cid;

use crate::{builder, conn, tx};

pub struct Burst {
    path: Arc<super::Path>,
    scid: cid::ConnectionId,
    dcid: tx::DcidCell,
    spin: Arc<AtomicBool>,
    flow_ctrl: conn::FlowController,
    spaces: builder::Spaces,
}

impl super::Path {
    pub fn new_burst(
        self: &Arc<Self>,
        scid: cid::ConnectionId,
        dcid: tx::DcidCell,
        flow_ctrl: conn::FlowController,
        spaces: builder::Spaces,
    ) -> Burst {
        let path = self.clone();
        let spin = Arc::new(AtomicBool::new(false));
        Burst {
            path,
            scid,
            dcid,
            spin,
            flow_ctrl,
            spaces,
        }
    }
}

impl Burst {
    pub async fn fill_datagram(&self, mut buf: &mut [u8]) -> Option<usize> {
        let origin_size = buf.len();
        let mut transaction = tx::Transaction::prepare(
            self.scid,
            &self.dcid,
            &self.path.cc,
            &self.path.anti_amplifier,
            &self.flow_ctrl,
        )
        .await?;

        let send_initial = self.spaces.initial.has_pending_data();
        let send_handshake = self.spaces.handshake.has_pending_data();
        let send_0rtt = self.spaces.data.has_early_data();
        let send_1rtt = self.spaces.data.has_pending_data();

        if send_initial {
            let fill_initial = !(send_handshake || send_0rtt || send_1rtt);
            let load_initial_space =
                transaction.load_initial_space(buf, &self.spaces.initial, fill_initial);
            if let Some((packet, ack)) = load_initial_space {
                transaction.commit(qbase::Epoch::Initial, &packet, 0, ack);
                let size = packet.size();
                buf = &mut buf[size..];
            }
        }

        if send_handshake {
            let fill_handshake = !(send_0rtt || send_1rtt);
            if let Some((packet, ack)) =
                transaction.load_handshake_space(buf, &self.spaces.handshake, fill_handshake)
            {
                transaction.commit(qbase::Epoch::Handshake, &packet, 0, ack);
                let size = packet.size();
                buf = &mut buf[size..];
            }
        }

        if send_0rtt {
            let fill_0rtt = !send_1rtt;
            let path_challenge_frames = &self.path.challenge_sndbuf;
            if let Some((packet, fresh_data)) =
                transaction.load_0rtt_data(buf, path_challenge_frames, &self.spaces.data, fill_0rtt)
            {
                transaction.commit(qbase::Epoch::Data, &packet, fresh_data, None);
                let size = packet.size();
                buf = &mut buf[size..];
            }
        }

        if send_1rtt {
            let path_challenge_frames = &self.path.challenge_sndbuf;
            let path_response_frames = &self.path.response_sndbuf;
            if let Some((packet, ack, fresh_data)) = transaction.load_1rtt_data(
                buf,
                &self.spin,
                path_challenge_frames,
                path_response_frames,
                &self.spaces.data,
                true,
            ) {
                transaction.commit(qbase::Epoch::Data, &packet, fresh_data, ack);
                // let size = packet.size();
                // buf = &mut buf[size..];
            }
        }

        if buf.len() != origin_size {
            Some(origin_size - buf.len())
        } else {
            None
        }
    }

    pub fn begin_sending<F>(self, on_failed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        tokio::spawn(async move {
            loop {
                let Some(mut pkt) = self.path.new_packet() else {
                    break;
                };
                if let Some(size) = self.fill_datagram(&mut pkt).await {
                    let dst = self.path.way.dst();
                    let Ok(()) = self.path.send_packet(&pkt[..size], dst).await else {
                        break;
                    };
                }
            }
            on_failed();
        })
    }
}

impl Drop for Burst {
    fn drop(&mut self) {
        self.dcid.retire();
    }
}
