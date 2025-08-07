use bytes::BufMut;
use derive_more::Deref;
use qbase::{
    frame::{
        CryptoFrame, DatagramFrame, EncodeSize, Frame, FrameFeture, PathChallengeFrame,
        PathResponseFrame, ReliableFrame, StreamFrame,
        io::{WriteDataFrame, WriteFrame},
    },
    net::tx::Signals,
    packet::{
        MarshalDataFrame, MarshalFrame, MarshalPathFrame,
        header::{EncodeHeader, GetType, io::WriteHeader, long::LongHeader, short::OneRttHeader},
        io::{AssemblePacket, FinalPacketLayout, PacketWriter as BasePacketWriter},
        keys::DirectionalKeys,
        signal::KeyPhaseBit,
    },
    util::{ContinuousData, WriteData},
};
use qevent::{packet::PacketWriter as QEventPacketWriter, quic::QuicFrame as QEventFrame};
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
    fn encrypt_and_protect_packet(self) -> FinalPacketLayout {
        self.clerk
            .build_with_time(self.retran_timeout, self.expire_timeout);
        self.writer.encrypt_and_protect_packet()
    }
}

/// 对IH空间有效
impl<'b, F> MarshalFrame<F> for PacketWriter<'b, '_, CryptoFrame>
where
    F: EncodeSize + FrameFeture + Clone + Into<Frame>,
    for<'f> &'f F: Into<QEventFrame>,
    BasePacketWriter<'b>: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        // TOOD: check belongs_to?
        self.writer.dump_frame(frame).map(|frame| {
            self.clerk.record_trivial();
            frame
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketWriter<'b, '_, CryptoFrame>
where
    D: ContinuousData + Clone,
    BasePacketWriter<'b>: WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        // no matter to clone, currently, except for datagrams, all other `D`s impl Copy
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .and_then(|frame| {
                self.clerk.record_frame(frame);
                None
            })
    }
}

impl<'b> MarshalPathFrame<PathChallengeFrame> for PacketWriter<'b, '_, GuaranteedFrame>
where
    BasePacketWriter<'b>: WriteFrame<PathChallengeFrame>,
{
    fn dump_path_frame(&mut self, frame: PathChallengeFrame) -> Option<PathChallengeFrame> {
        self.writer.dump_frame(frame).map(|frame| {
            self.clerk.record_trivial();
            frame
        })
    }
}

impl<'b> MarshalPathFrame<PathResponseFrame> for PacketWriter<'b, '_, GuaranteedFrame>
where
    BasePacketWriter<'b>: WriteFrame<PathResponseFrame>,
{
    fn dump_path_frame(&mut self, frame: PathResponseFrame) -> Option<PathResponseFrame> {
        self.writer.dump_frame(frame).map(|frame| {
            self.clerk.record_trivial();
            frame
        })
    }
}

impl<'b, F> MarshalFrame<F> for PacketWriter<'b, '_, GuaranteedFrame>
where
    F: EncodeSize + FrameFeture + Clone + Into<Frame>,
    for<'f> &'f F: Into<QEventFrame>,
    BasePacketWriter<'b>: WriteFrame<F>,
{
    fn dump_frame(&mut self, frame: F) -> Option<F> {
        self.writer.dump_frame(frame).map(|frame| {
            match ReliableFrame::try_from(frame.clone().into()) {
                Ok(reliable_frame) => {
                    self.clerk
                        .record_frame(GuaranteedFrame::Reliable(reliable_frame));
                }
                Err(_frame) => {
                    self.clerk.record_trivial();
                }
            };
            frame
        })
    }
}

impl<'b, D> MarshalDataFrame<CryptoFrame, D> for PacketWriter<'b, '_, GuaranteedFrame>
where
    D: ContinuousData + Clone,
    BasePacketWriter<'b>: WriteData<D> + WriteDataFrame<CryptoFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: CryptoFrame, data: D) -> Option<CryptoFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .map(|frame| {
                self.clerk.record_frame(GuaranteedFrame::Crypto(frame));
                frame
            })
    }
}

impl<'b, D> MarshalDataFrame<StreamFrame, D> for PacketWriter<'b, '_, GuaranteedFrame>
where
    D: ContinuousData + Clone,
    BasePacketWriter<'b>: WriteData<D> + WriteDataFrame<StreamFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: StreamFrame, data: D) -> Option<StreamFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .map(|frame| {
                self.clerk.record_frame(GuaranteedFrame::Stream(frame));
                frame
            })
    }
}

impl<'b, D> MarshalDataFrame<DatagramFrame, D> for PacketWriter<'b, '_, GuaranteedFrame>
where
    D: ContinuousData + Clone,
    BasePacketWriter<'b>: WriteData<D> + WriteDataFrame<DatagramFrame, D>,
{
    fn dump_frame_with_data(&mut self, frame: DatagramFrame, data: D) -> Option<DatagramFrame> {
        self.writer
            .dump_frame_with_data(frame, data.clone())
            .map(|frame| {
                self.clerk.record_trivial();
                frame
            })
    }
}
