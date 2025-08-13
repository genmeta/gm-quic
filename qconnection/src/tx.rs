use bytes::BufMut;
use derive_more::Deref;
use qbase::{
    frame::{CryptoFrame, Frame, FrameFeture, ReliableFrame, Spec},
    net::tx::Signals,
    packet::{
        AssemblePacket, PacketProperties, PacketWriter as BasePacketWriter, RecordFrame,
        header::{EncodeHeader, GetType, io::WriteHeader, long::LongHeader, short::OneRttHeader},
        keys::DirectionalKeys,
        signal::KeyPhaseBit,
    },
    util::ContinuousData,
};
use qevent::packet::PacketWriter as QEventPacketWriter;
use qrecovery::journal::{ArcSentJournal, NewPacketGuard};
use tokio::time::Duration;

use crate::GuaranteedFrame;

#[derive(Deref)]
pub struct PacketWriter<'b, 's, F> {
    #[deref]
    writer: QEventPacketWriter<'b>,
    // 不同空间的send guard类型不一样
    clerk: NewPacketGuard<'s, F>,
    retran_timeout: Duration,
    expire_timeout: Duration,
}

impl<'b, F> AsRef<BasePacketWriter<'b>> for PacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &BasePacketWriter<'b> {
        &self.writer
    }
}

impl<'b, F> AsRef<QEventPacketWriter<'b>> for PacketWriter<'b, '_, F> {
    #[inline]
    fn as_ref(&self) -> &QEventPacketWriter<'b> {
        &self.writer
    }
}

impl<'b, 's, F> PacketWriter<'b, 's, F> {
    pub fn new_long<S>(
        header: LongHeader<S>,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        journal: &'s ArcSentJournal<F>,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Result<Self, Signals>
    where
        S: EncodeHeader + 'static,
        LongHeader<S>: GetType,
        for<'a> &'a mut [u8]: WriteHeader<LongHeader<S>>,
    {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_long(&header, buffer, pn, keys)?,
            expire_timeout,
            retran_timeout,
        })
    }

    pub fn new_short(
        header: OneRttHeader,
        buffer: &'b mut [u8],
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
        journal: &'s ArcSentJournal<F>,
        retran_timeout: Duration,
        expire_timeout: Duration,
    ) -> Result<Self, Signals> {
        let clerk = journal.new_packet();
        let pn = clerk.pn();
        Ok(Self {
            clerk,
            writer: QEventPacketWriter::new_short(&header, buffer, pn, keys, key_phase)?,
            expire_timeout,
            retran_timeout,
        })
    }
}

unsafe impl<'b, 's, F> BufMut for PacketWriter<'b, 's, F> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.writer.remaining_mut()
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe { self.writer.advance_mut(cnt) };
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.writer.chunk_mut()
    }

    // steam/datagram可能会手动padding，padding也要被记录，所以这里不能用默认实现
    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        self.writer.put_bytes(val, cnt);
    }
}

impl<F> AssemblePacket for PacketWriter<'_, '_, F> {
    fn encrypt_and_protect_packet(self) -> (usize, PacketProperties) {
        self.clerk
            .build_with_time(self.retran_timeout, self.expire_timeout);
        self.writer.encrypt_and_protect_packet()
    }
}

impl<D: ContinuousData> RecordFrame<D> for PacketWriter<'_, '_, CryptoFrame> {
    fn record_frame(&mut self, frame: &Frame<D>) {
        if let Frame::Crypto(frame, ..) = &frame {
            self.clerk.record_frame(*frame);
        } else {
            self.clerk.record_trivial();
        }

        self.writer.record_frame(frame);
    }
}

impl<D: ContinuousData + Clone> RecordFrame<D> for PacketWriter<'_, '_, GuaranteedFrame> {
    fn record_frame(&mut self, frame: &Frame<D>) {
        if let Frame::Crypto(frame, ..) = &frame {
            self.clerk.record_frame(GuaranteedFrame::Crypto(*frame));
        } else if let Frame::Stream(frame, ..) = &frame {
            self.clerk.record_frame(GuaranteedFrame::Stream(*frame));
        } else if let Ok(frame) = ReliableFrame::try_from(frame.clone()) {
            self.clerk.record_frame(GuaranteedFrame::Reliable(frame));
        } else {
            assert!(frame.specs() & Spec::NonAckEliciting as u8 != 0);
            self.clerk.record_trivial();
        }

        self.writer.record_frame(frame);
    }
}
