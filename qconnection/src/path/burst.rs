use std::{
    convert::Infallible,
    io,
    ops::ControlFlow,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, ready},
};

use futures::FutureExt;
use qbase::net::tx::Signals;

use crate::{
    ArcDcidCell, ArcLocalCids, Components, FlowController, space::Spaces, tx::Transaction,
};

pub struct Burst {
    path: Arc<super::Path>,
    local_cids: ArcLocalCids,
    dcid: ArcDcidCell,
    spin: bool,
    flow_ctrl: FlowController,
    spaces: Spaces,
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        let local_cids = components.cid_registry.local.clone();
        let dcid = components.cid_registry.remote.apply_dcid();
        let flow_ctrl = components.flow_ctrl.clone();
        let path = self.clone();
        let spin = false;
        let spaces = components.spaces.clone();
        Burst {
            path,
            local_cids,
            dcid,
            spin,
            flow_ctrl,
            spaces,
        }
    }
}

impl Burst {
    fn poll_prepare<'b>(
        &self,
        cx: &mut Context<'_>,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> Poll<io::Result<(impl Iterator<Item = &'b mut [u8]> + use<'b>, Transaction)>> {
        let max_segments = self.path.interface.max_segments()?;
        let max_segment_size = self.path.interface.max_segment_size()?;

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
        let transaction = ready!(
            Transaction::prepare(
                scid.unwrap_or_default(),
                &self.dcid,
                self.path.cc(),
                &self.path.anti_amplifier,
                &self.flow_ctrl,
                max_segment_size,
            )
            .poll_unpin(cx)
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        Poll::Ready(Ok((buffers, transaction)))
    }

    fn load_into_buffers<'b>(
        &'b self,
        prepared_buffers: impl Iterator<Item = &'b mut [u8]> + 'b,
        mut transaction: Transaction<'b>,
    ) -> io::Result<Result<Vec<usize>, Signals>> {
        let scid = self.local_cids.initial_scid();
        let reversed_size = self.path.interface.reversed_bytes(self.path.pathway)?;
        use core::ops::ControlFlow::*;
        // dont acquire max_segment_size here because it may have changed and is different from when the buffer was prepared
        // let max_segment_size = self.path.interface.max_segment_size()?;
        let max_segments = self.path.interface.max_segments()?;

        let (ControlFlow::Break(result) | ControlFlow::Continue(result)) = prepared_buffers
            .map(move |buffer| {
                let load_result = if scid.is_some() {
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
                };
                debug_assert_ne!(load_result, Ok(0));
                load_result
                    .map(|packet_size| io::IoSlice::new(&buffer[..reversed_size + packet_size]))
            })
            .try_fold(
                Ok(Vec::with_capacity(max_segments)),
                |segments, load_result| match (segments, load_result) {
                    (Ok(segments), Err(limiter)) if segments.is_empty() => Break(Err(limiter)),
                    (Ok(segments), Err(_limiter)) => Break(Ok(segments)),
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

    fn poll_burst<'b>(
        &'b self,
        cx: &mut Context<'_>,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> Poll<io::Result<Vec<usize>>> {
        let (buffers, transcation) = ready!(self.poll_prepare(cx, buffers))?;
        match self.load_into_buffers(buffers, transcation)? {
            Ok(segments) => {
                debug_assert!(!segments.is_empty());
                Poll::Ready(Ok(segments))
            }
            Err(signals) => {
                self.path.tx_waker.wait_for(cx, signals);
                Poll::Pending
            }
        }
    }

    pub async fn launch(self) -> io::Result<Infallible> {
        let mut buffers = vec![];
        loop {
            let segment_lens =
                core::future::poll_fn(|cx| self.poll_burst(cx, &mut buffers)).await?;
            let segments = segment_lens
                .into_iter()
                .enumerate()
                .map(|(seg_idx, seg_len)| io::IoSlice::new(&buffers[seg_idx][..seg_len]))
                .collect::<Vec<_>>();
            self.path.send_packets(&segments).await?;
        }
    }
}
