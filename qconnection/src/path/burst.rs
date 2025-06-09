use std::{
    io,
    ops::ControlFlow,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};

use qbase::net::tx::Signals;
use qinterface::QuicInterface;

use crate::{
    ArcDcidCell, ArcLocalCids, Components, FlowController, space::Spaces, tls::ArcSendGate,
    tx::Transaction,
};

pub struct Burst {
    path: Arc<super::Path>,
    local_cids: ArcLocalCids,
    dcid: ArcDcidCell,
    spin: bool,
    flow_ctrl: FlowController,
    spaces: Spaces,
    send_gate: Option<ArcSendGate>,
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        let local_cids = components.cid_registry.local.clone();
        let dcid = components.cid_registry.remote.apply_dcid();
        let flow_ctrl = components.flow_ctrl.clone();
        let path = self.clone();
        let spin = false;
        let spaces = components.spaces.clone();
        let send_gate = match &components.specific {
            crate::SpecificComponents::Client => None,
            crate::SpecificComponents::Server(server_components) => {
                Some(server_components.send_gate.clone())
            }
        };
        Burst {
            path,
            local_cids,
            dcid,
            spin,
            flow_ctrl,
            spaces,
            send_gate,
        }
    }
}

impl Burst {
    fn prepare<'b>(
        &self,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> Result<Option<(impl Iterator<Item = &'b mut [u8]>, Transaction<'_>)>, Signals> {
        let Ok(max_segments) = self.path.interface.max_segments() else {
            return Ok(None);
        };
        let Ok(max_segment_size) = self.path.interface.max_segment_size() else {
            return Ok(None);
        };

        if buffers.len() < max_segments {
            buffers.resize_with(max_segments, || vec![0; max_segment_size]);
        }

        let buffers = buffers.iter_mut().map(move |buffer| {
            if buffer.len() < max_segment_size {
                buffer.resize(max_segment_size, 0);
            }
            &mut buffer[..max_segment_size]
        });

        let scid = self.local_cids.initial_scid();
        let transaction = Transaction::prepare(
            scid.unwrap_or_default(),
            &self.dcid,
            self.path.cc(),
            &self.path.anti_amplifier,
            &self.flow_ctrl,
            self.path.tx_waker.clone(),
        )?;
        if transaction.is_none() {
            return Ok(None);
        }
        Ok(Some((buffers, transaction.unwrap())))
    }

    fn load_segments<'b>(
        &'b self,
        prepared_buffers: impl Iterator<Item = &'b mut [u8]> + 'b,
        mut transaction: Transaction<'b>,
    ) -> io::Result<Result<Vec<usize>, Signals>> {
        use core::ops::ControlFlow::*;

        let scid = self.local_cids.initial_scid();
        let reversed_size = 0; // TODO
        let max_segments = self.path.interface.max_segments()?;

        let (ControlFlow::Break(result) | ControlFlow::Continue(result)) = prepared_buffers
            .map(move |segment| {
                let buffer_size = segment.len().min(self.path.mtu() as _);
                let buffer = &mut segment[..buffer_size];
                if scid.is_some() {
                    transaction.load_spaces(
                        &mut buffer[reversed_size..],
                        &self.spaces,
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                    )
                } else if self.path.validated.load(Ordering::Acquire) {
                    transaction.load_one_rtt(
                        &mut buffer[reversed_size..],
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                        self.spaces.data(),
                    )
                } else {
                    transaction.load_validation(
                        &mut buffer[reversed_size..],
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                        self.spaces.data(),
                    )
                }
                .or_else(|signals| {
                    transaction
                        .load_ping(&mut buffer[reversed_size..], self.spin.into(), &self.spaces)
                        .map_err(|s| s | signals)
                })
                .map(|packet_size| io::IoSlice::new(&buffer[..reversed_size + packet_size]))
            })
            .try_fold(
                Ok(Vec::with_capacity(max_segments)),
                |segments, load_result| match (segments, load_result) {
                    (Ok(segments), Err(signals)) if segments.is_empty() => Break(Err(signals)),
                    (Ok(segments), Err(_signals)) => Break(Ok(segments)),
                    (Ok(mut segments), Ok(segment))
                        if segment.len() < segments.last().copied().unwrap_or_default() =>
                    {
                        segments.push(segment.len());
                        Break(Ok(segments))
                    }
                    (Ok(mut segments), Ok(segment)) => {
                        segments.push(segment.len());
                        Continue(Ok(segments))
                    }
                    (Err(_), _) => unreachable!(),
                },
            );
        Ok(result)
    }

    fn poll_burst(
        &self,
        cx: &mut Context,
        buffers: &mut Vec<Vec<u8>>,
    ) -> Poll<io::Result<Vec<usize>>> {
        let (buffers, transaction) = match self.prepare(buffers) {
            Ok(Some((buffers, transaction))) => (buffers, transaction),
            Ok(None) => return Poll::Pending, // 发送任务停止但是不结束
            Err(siginals) => {
                self.path.tx_waker.wait_for(cx, siginals);
                return Poll::Pending;
            }
        };
        match self.load_segments(buffers, transaction)? {
            Ok(segments) => {
                debug_assert!(!segments.is_empty());
                Poll::Ready(io::Result::Ok(segments))
            }
            Err(signals) => {
                self.path.tx_waker.wait_for(cx, signals);
                Poll::Pending
            }
        }
    }

    async fn burst(&self, buffers: &mut Vec<Vec<u8>>) -> io::Result<Vec<usize>> {
        core::future::poll_fn(|cx| self.poll_burst(cx, buffers)).await
    }

    pub async fn launch(self) -> io::Result<()> {
        let mut buffers = vec![];

        if let Some(send_gate) = &self.send_gate {
            send_gate.request_permit().await;
        }

        loop {
            let segment_lens = self.burst(&mut buffers).await?;

            let segments = segment_lens
                .into_iter()
                .enumerate()
                .map(|(seg_idx, seg_len)| io::IoSlice::new(&buffers[seg_idx][..seg_len]))
                .collect::<Vec<_>>();

            self.path.send_packets(&segments).await?;
        }
    }
}
