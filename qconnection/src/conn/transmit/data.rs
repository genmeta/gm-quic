use std::{sync::Arc, time::Instant};

use qbase::{
    cid::ConnectionId,
    frame::{PathChallengeFrame, PathResponseFrame},
    packet::{
        keys::{ArcKeys, ArcOneRttKeys, ArcOneRttPacketKeys},
        writer::{CompletePacket, OneRttPacketWriter, ZeroRttPacketWriter},
        LongHeaderBuilder, OneRttHeader, SpinBit,
    },
};
use qrecovery::{
    crypto::CryptoStreamOutgoing,
    journal::DataJournal,
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
};
use qunreliable::DatagramFlow;
use rustls::quic::HeaderProtectionKey;

use crate::{conn::DataStreams, path::SendBuffer};

#[derive(Clone)]
pub struct DataSpaceReader {
    pub journal: DataJournal,
    pub zero_rtt_keys: ArcKeys,
    pub one_rtt_keys: ArcOneRttKeys,
    // 数据源
    pub challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    pub response_sndbuf: SendBuffer<PathResponseFrame>,
    pub crypto_stream_outgoing: CryptoStreamOutgoing,
    pub reliable_frames: ArcReliableFrameDeque,
    pub streams: DataStreams,
    pub datagrams: DatagramFlow,
    // 为了各个流的公平性，包括不可靠数据帧，需要额外维护一些信息
}

impl DataSpaceReader {
    pub fn one_rtt_keys(&self) -> Option<(Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys)> {
        self.one_rtt_keys.get_local_keys()
    }

    /// Returns (pn, is_ack_eliciting, is_just_ack, sent_size, fresh_bytes, in_flight, sent_ack) or None
    #[allow(clippy::type_complexity)]
    pub fn try_read_1rtt(
        &self,
        buf: &mut [u8],
        mut flow_limit: usize,
        dcid: ConnectionId,
        spin: SpinBit,
        ack_pkt: Option<(u64, Instant)>,
        (hpk, pk): (Arc<dyn HeaderProtectionKey>, ArcOneRttPacketKeys),
    ) -> Option<(CompletePacket, usize, Option<u64>)> {
        let (key_phase, hpk, pk) = {
            let pk_guard = pk.lock_guard();
            let (key_phase, pk) = pk_guard.get_local();
            (key_phase, hpk, pk)
        };

        // 0. 检查1rtt keys是否有效，没有则回退到0rtt包
        // 1. 生成包头，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = OneRttHeader { spin, dcid };
        // 2. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_journal = self.journal.sent();
        let mut journal_guard = sent_journal.send();
        let pn = journal_guard.next_pn();

        let mut writer = OneRttPacketWriter::new(&hdr, buf, pn, pk.tag_len())?;

        // 3. 检查PathFrameBuffer，尝试写，但发送记录并不记录，若写入，则constraints开始记录
        if self.challenge_sndbuf.try_read(&mut writer) > 0 {
            journal_guard.record_trivial();
        }
        if self.response_sndbuf.try_read(&mut writer) > 0 {
            journal_guard.record_trivial();
        }

        // 4. 检查是否需要发送Ack，若是，且符合（constraints + buf）节制，生成ack并写入，但发送记录并不记录
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.journal.rcvd();
            rcvd_pkt_records
                .read_ack_frame_util(&mut writer, largest, recv_time)
                .expect("its always have enough space to put a ack frame");
            journal_guard.record_trivial();
            sent_ack = Some(largest);
        }

        // 5. 检查可靠帧，若有且符合（constraints + buf）节制，写入，burst、发包记录都记录
        while let Some(frame) = self.reliable_frames.try_read(&mut writer) {
            journal_guard.record_frame(GuaranteedFrame::Reliable(frame));
        }

        // 6. 检查NewToken，是否需要发送

        // 7. 检查一下CryptoStream，服务器可能会发送一些数据
        while let Some(frame) = self.crypto_stream_outgoing.try_read_data(&mut writer) {
            journal_guard.record_frame(GuaranteedFrame::Crypto(frame));
        }

        // 8. 检查Datagrams是否需要发送，若有，且符合(constraints + buf) 节制，写入，burst、发包记录都记录
        while let Some(_frame) = self.datagrams.try_read_datagram(&mut writer) {
            journal_guard.record_trivial();
        }

        // 9. 检查DataStreams是否需要发送，若有，且符合（constraints + buf）节制，写入，burst、发包记录都记录
        let mut fresh_bytes = 0;
        while let Some((frame, m)) = self.streams.try_read_data(&mut writer, flow_limit) {
            journal_guard.record_frame(GuaranteedFrame::Stream(frame));
            flow_limit -= m;
            fresh_bytes += m;
        }

        drop(journal_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        if writer.is_empty() {
            return None;
        }

        let packet = writer.encrypt(key_phase, hpk.as_ref(), pk.as_ref());
        Some((packet, fresh_bytes, sent_ack))
    }

    /// Returns (pn, is_ack_eliciting, sent_size, fresh_bytes, in_flight) or None
    pub fn try_read_0rtt(
        &self,
        buf: &mut [u8],
        mut flow_limit: usize,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) -> Option<(CompletePacket, usize)> {
        // 1. 检查0rtt keys是否有效，没有则结束
        let k = self.zero_rtt_keys.get_local_keys()?;
        let pk = k.local.packet.as_ref();
        let hpk = k.local.header.as_ref();

        // 2. 生成包头，预留2字节len，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).zero_rtt();

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.journal.sent();
        let mut send_guard = sent_pkt_records.send();
        let pn = send_guard.next_pn();

        let mut writer = ZeroRttPacketWriter::new(&hdr, buf, pn, pk.tag_len())?;

        // 4. 只检查PathChallengeBuffer，尝试写，但发送记录并不记录，若写入一个帧，则constraints开始记录
        //    可能没有Challenge帧，所以仍要继续
        if self.challenge_sndbuf.try_read(&mut writer) > 0 {
            send_guard.record_trivial();
        }

        // 5. 检查可靠帧，若有且符合（constraints + buf）节制，写入，burst、发包记录都记录
        // TODO: 可靠帧包括握手完成帧，但是0rtt包不能发送握手完成帧
        // while let Some(frame) = self.reliable_frames.try_read(&mut writer) {
        //     send_guard.record_frame(GuaranteedFrame::Reliable(frame));
        // }

        // 6. 检查DataStreams是否需要发送，若有，且符合（constraints + buf）节制，写入，burst、发包记录都记录
        // TODO: 要注意和Datagrams的公平了
        let mut fresh_bytes = 0;
        while let Some((frame, m)) = self.streams.try_read_data(&mut writer, flow_limit) {
            send_guard.record_frame(GuaranteedFrame::Stream(frame));
            flow_limit -= m;
            fresh_bytes += m;
        }

        // 7. 检查Datagrams是否需要发送，若有，且符合(constraints + buf) 节制，写入，burst、发包记录都记录
        while let Some(_frame) = self.datagrams.try_read_datagram(&mut writer) {
            send_guard.record_trivial();
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        if writer.is_empty() {
            return None;
        }

        // 8. 填充，保护头部，加密
        let _remain = writer.seal_packet();

        // 0RTT包不能发送Ack
        Some((writer.encrypt(hpk, pk), fresh_bytes))
    }
}
