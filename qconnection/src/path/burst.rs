use std::{
    io,
    ops::ControlFlow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use qbase::net::tx::Signals;
use qinterface::QuicIO;
use tracing::Instrument;

use crate::{
    ArcDcidCell, CidRegistry, Components, space::Spaces, tls::ArcSendLock, tx::Transaction,
};

pub struct Burst {
    path: Arc<super::Path>,
    cid_registry: CidRegistry,
    dcid_cell: ArcDcidCell,
    launched: AtomicBool,
    spin: bool,
    spaces: Spaces,
    send_lock: ArcSendLock,
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        Burst {
            path: self.clone(),
            cid_registry: components.cid_registry.clone(),
            dcid_cell: components.cid_registry.remote.apply_dcid(),
            launched: AtomicBool::new(false),
            spin: false,
            spaces: components.spaces.clone(),
            send_lock: components.send_lock.clone(),
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

        let Some(transaction) = Transaction::prepare(
            self.cid_registry.local.initial_scid(),
            // Not using initial DCID after 1RTT ready
            self.cid_registry.remote.initial_dcid(),
            &self.dcid_cell,
            self.path.validated.load(Ordering::Acquire),
            !self.launched.swap(true, Ordering::Acquire),
            self.path.cc(),
            &self.path.anti_amplifier,
            self.path.tx_waker.clone(),
        )?
        else {
            return Ok(None);
        };

        Ok(Some((buffers, transaction)))
    }

    fn load_segments<'b>(
        &'b self,
        prepared_buffers: impl Iterator<Item = &'b mut [u8]> + 'b,
        mut transaction: Transaction<'b>,
    ) -> io::Result<Result<Vec<usize>, Signals>> {
        use core::ops::ControlFlow::*;

        let reversed_size = 0; // TODO
        let max_segments = self.path.interface.max_segments()?;

        let (ControlFlow::Break(result) | ControlFlow::Continue(result)) = prepared_buffers
            .map(move |segment| {
                let buffer_size = segment.len().min(self.path.mtu() as _);
                let buffer = &mut segment[..buffer_size];
                transaction
                    .load_spaces(
                        &mut buffer[reversed_size..],
                        &self.spaces,
                        self.spin.into(),
                        &self.path.challenge_sndbuf,
                        &self.path.response_sndbuf,
                    )
                    .or_else(|signals| {
                        transaction
                            .load_one_ping(
                                &mut buffer[reversed_size..],
                                self.spin.into(),
                                &self.spaces,
                            )
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
                    (Err(_), _) => unreachable!("segments should not be Err in this context"),
                },
            );
        Ok(result)
    }

    async fn burst(&self, buffers: &mut Vec<Vec<u8>>) -> io::Result<Vec<usize>> {
        loop {
            let (buffers, transaction) = match self.prepare(buffers) {
                Ok(Some((buffers, transaction))) => (buffers, transaction),
                // When a connection error occurs, we should not try to load the segment again.
                // We should also not end the send task, otherwise the path will be removed.
                Ok(None) => return std::future::pending().await,
                Err(signals) => {
                    self.path.tx_waker.wait_for(signals).await;
                    continue; // try load again
                }
            };
            match self.load_segments(buffers, transaction)? {
                Ok(segments_lens) => {
                    debug_assert!(!segments_lens.is_empty());
                    return Ok(segments_lens);
                }
                Err(signals) => {
                    self.path.tx_waker.wait_for(signals).await;
                    continue; // try load again
                }
            }
        }
    }

    pub async fn launch(self) -> io::Result<()> {
        let mut buffers = vec![];

        // Anti port scan
        self.send_lock.request_permit().await;

        loop {
            let segment_lens = self
                .burst(&mut buffers)
                .instrument(tracing::debug_span!("burst", link = %self.path.link))
                .await?;

            let segments = segment_lens
                .into_iter()
                .enumerate()
                .map(|(seg_idx, seg_len)| io::IoSlice::new(&buffers[seg_idx][..seg_len]))
                .collect::<Vec<_>>();

            self.path.send_packets(&segments).await?;
        }
    }
}
