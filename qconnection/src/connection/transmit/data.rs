use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::BufMut;
use qbase::{
    cid::ConnectionId,
    frame::{DataFrame, PathChallengeFrame, PathResponseFrame},
    packet::{
        encrypt::{encrypt_packet, protect_long_header, protect_short_header},
        header::{WriteLongHeader, WriteOneRttHeader},
        keys::{ArcKeys, ArcOneRttKeys, OneRttPacketKeys},
        Encode, LongHeaderBuilder, OneRttHeader, SpinBit, WritePacketNumber,
    },
    varint::{EncodeBytes, VarInt, WriteVarInt},
};
use qrecovery::{
    reliable::{ArcReliableFrameDeque, GuaranteedFrame},
    space::DataSpace,
    streams::{crypto::CryptoStreamOutgoing, DataStreams},
};
use qunreliable::DatagramFlow;
use rustls::quic::HeaderProtectionKey;

use crate::path::SendBuffer;

pub struct DataSpaceReader {
    pub(crate) space: DataSpace,
    pub(crate) zero_rtt_keys: ArcKeys,
    pub(crate) one_rtt_keys: ArcOneRttKeys,
    // 数据源
    pub(crate) challenge_sndbuf: SendBuffer<PathChallengeFrame>,
    pub(crate) response_sndbuf: SendBuffer<PathResponseFrame>,
    pub(crate) crypto_stream_outgoing: CryptoStreamOutgoing,
    pub(crate) reliable_frames: ArcReliableFrameDeque,
    pub(crate) data_streams: DataStreams,
    pub(crate) datagrams: DatagramFlow,
    // 为了各个流的公平性，包括不可靠数据帧，需要额外维护一些信息
}

impl DataSpaceReader {
    pub fn one_rtt_keys(
        &self,
    ) -> Option<(Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>)> {
        self.one_rtt_keys.get_local_keys()
    }

    pub fn try_read_1rtt(
        &self,
        buf: &mut [u8],
        mut flow_limit: usize,
        dcid: ConnectionId,
        spin: SpinBit,
        ack_pkt: Option<(u64, Instant)>,
        keys: (Arc<dyn HeaderProtectionKey>, Arc<Mutex<OneRttPacketKeys>>),
    ) -> Option<(u64, bool, bool, usize, usize, bool, Option<u64>)> {
        // 0. 检查1rtt keys是否有效，没有则回退到0rtt包
        // 1. 生成包头，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = OneRttHeader { spin, dcid };
        // 20字节为最小Payload长度，为了保护包头的Sample至少16字节
        if buf.len() < hdr.size() + 20 {
            return None;
        }
        let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size());

        // 2. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.space.sent_packets();
        let mut send_guard = sent_pkt_records.send();
        let (pn, encoded_pn) = send_guard.next_pn();
        if payload_buf.remaining_mut() <= encoded_pn.size() {
            return None;
        }
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(encoded_pn.size());

        let mut is_ack_eliciting = false;
        let mut is_just_ack = true;
        let mut in_flight = false;
        let body_size = body_buf.remaining_mut();

        // 3. 检查PathFrameBuffer，尝试写，但发送记录并不记录，若写入，则constraints开始记录
        let n = self.challenge_sndbuf.try_read(body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }
        let n = self.response_sndbuf.try_read(body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }

        // 4. 检查是否需要发送Ack，若是，且符合（constraints + buf）节制，生成ack并写入，但发送记录并不记录
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.space.rcvd_packets();
            let n = rcvd_pkt_records.read_ack_frame_util(body_buf, largest, recv_time)?;
            send_guard.record_trivial();
            sent_ack = Some(largest);
            body_buf = &mut body_buf[n..];
        }

        // 5. 检查可靠帧，若有且符合（constraints + buf）节制，写入，burst、发包记录都记录
        while let Some((frame, n)) = self.reliable_frames.try_read(body_buf) {
            send_guard.record_frame(GuaranteedFrame::Reliable(frame));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
        }

        // 6. 检查NewToken，是否需要发送

        // 7. 象征性地检查一下CryptoStream
        while let Some((frame, n)) = self.crypto_stream_outgoing.try_read_data(body_buf) {
            send_guard.record_frame(GuaranteedFrame::Data(DataFrame::Crypto(frame)));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
        }

        // 8. 检查DataStreams是否需要发送，若有，且符合（constraints + buf）节制，写入，burst、发包记录都记录
        let mut fresh_bytes = 0;
        while let Some((frame, n, m)) = self.data_streams.try_read_data(body_buf, flow_limit) {
            send_guard.record_frame(GuaranteedFrame::Data(DataFrame::Stream(frame)));
            flow_limit -= m;
            fresh_bytes += m;
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
        }

        // 9. 检查Datagrams是否需要发送，若有，且符合(constraints + buf) 节制，写入，burst、发包记录都记录
        while let Some((_frame, n)) = self.datagrams.try_read_datagram(body_buf) {
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            is_just_ack = false;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let mut body_size = body_size - body_buf.remaining_mut();
        // payload(pn + body)长度不足20字节，填充之
        if body_size + pn_len < 20 {
            let padding_len = 20 - body_size - pn_len;
            body_buf.put_bytes(0, padding_len);
            body_size += padding_len;
        }
        let sent_size = hdr_len + pn_len + body_size;

        hdr_buf.put_one_rtt_header(&hdr);
        pn_buf.put_packet_number(encoded_pn);

        // 11 保护包头，加密数据
        let pk_guard = keys.1.lock().unwrap();
        let (key_phase, pk) = pk_guard.get_local();
        encrypt_packet(pk.as_ref(), pn, buf, hdr_len + pn_len);
        protect_short_header(keys.0.as_ref(), key_phase, buf, hdr_len, encoded_pn.size());

        Some((
            pn,
            is_ack_eliciting,
            is_just_ack,
            sent_size,
            fresh_bytes,
            in_flight,
            sent_ack,
        ))
    }

    pub fn try_read_0rtt(
        &self,
        buf: &mut [u8],
        mut flow_limit: usize,
        scid: ConnectionId,
        dcid: ConnectionId,
    ) -> Option<(u64, bool, usize, usize, bool)> {
        // 1. 检查0rtt keys是否有效，没有则结束
        let k = self.zero_rtt_keys.get_local_keys()?;

        // 2. 生成包头，预留2字节len，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).zero_rtt();
        // length字段预留2字节, 20字节为最小Payload长度，为了保护包头的Sample至少16字节
        if buf.len() < hdr.size() + 2 + 20 {
            return None;
        }
        let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size() + 2);

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.space.sent_packets();
        let mut send_guard = sent_pkt_records.send();
        let (pn, encoded_pn) = send_guard.next_pn();
        if payload_buf.remaining_mut() <= encoded_pn.size() {
            return None;
        }
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(encoded_pn.size());

        let mut is_ack_eliciting = false;
        let mut in_flight = false;
        let body_size = body_buf.remaining_mut();

        // 4. 只检查PathChallengeBuffer，尝试写，但发送记录并不记录，若写入一个帧，则constraints开始记录
        //    可能没有Challenge帧，所以仍要继续
        let n = self.challenge_sndbuf.try_read(body_buf);
        if n > 0 {
            send_guard.record_trivial();
            is_ack_eliciting = true;
            in_flight = true;
            body_buf = &mut body_buf[n..];
        }

        // 5. 检查可靠帧，若有且符合（constraints + buf）节制，写入，burst、发包记录都记录
        while let Some((frame, n)) = self.reliable_frames.try_read(body_buf) {
            send_guard.record_frame(GuaranteedFrame::Reliable(frame));
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 6. 检查DataStreams是否需要发送，若有，且符合（constraints + buf）节制，写入，burst、发包记录都记录
        // TODO: 要注意和Datagrams的公平了
        let mut fresh_bytes = 0;
        while let Some((frame, n, m)) = self.data_streams.try_read_data(body_buf, flow_limit) {
            send_guard.record_frame(GuaranteedFrame::Data(DataFrame::Stream(frame)));
            body_buf = &mut body_buf[n..];
            flow_limit -= m;
            fresh_bytes += m;
            is_ack_eliciting = true;
            in_flight = true;
        }

        // 7. 检查Datagrams是否需要发送，若有，且符合(constraints + buf) 节制，写入，burst、发包记录都记录
        while let Some((_frame, n)) = self.datagrams.try_read_datagram(body_buf) {
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        // 8. 填充，保护头部，加密
        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let mut body_size = body_size - body_buf.remaining_mut();
        // payload(pn + body)长度不足20字节，填充之
        if body_size + pn_len < 20 {
            let padding_len = 20 - body_size - pn_len;
            body_buf.put_bytes(0, padding_len);
            body_size += padding_len;
        }
        let sent_size = hdr_len + 2 + pn_len + body_size;

        hdr_buf.put_long_header(&hdr);
        hdr_buf.encode_varint(
            &VarInt::try_from(pn_len + body_size).unwrap(),
            EncodeBytes::Two,
        );
        pn_buf.put_packet_number(encoded_pn);

        encrypt_packet(k.remote.packet.as_ref(), pn, buf, hdr_len + pn_len);
        protect_long_header(k.remote.header.as_ref(), buf, hdr_len, pn_len);

        // 0RTT包不能发送Ack
        Some((pn, is_ack_eliciting, sent_size, fresh_bytes, in_flight))
    }
}
