use std::time::Instant;

use bytes::BufMut;
use qbase::{
    cid::ConnectionId,
    packet::{
        encrypt::{encrypt_packet, protect_long_header},
        header::WriteLongHeader,
        keys::ArcKeys,
        Encode, LongHeaderBuilder, WritePacketNumber,
    },
    util::Burst,
    varint::{EncodeBytes, VarInt, WriteVarInt},
};
use qrecovery::{space::HandshakeSpace, streams::crypto::CryptoStreamOutgoing};

pub struct HandshakeSpaceReader {
    pub(crate) keys: ArcKeys,
    pub(crate) space: HandshakeSpace,
    pub(crate) crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl HandshakeSpaceReader {
    pub fn try_read(
        &self,
        burst: &mut Burst,
        buf: &mut [u8],
        scid: ConnectionId,
        dcid: ConnectionId,
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(u64, bool, usize, bool, Option<u64>)> {
        // 1. 判定keys是否有效，无效或者尚未拿到，直接返回
        let k = self.keys.get_local_keys()?;

        // 2. 生成包头，预留2字节len，根据包头大小，配合burst、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).handshake();
        let b = burst.measure(hdr.size() + 2, buf.remaining_mut())?;
        let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size() + 2);

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_pkt_records = self.space.sent_packets();
        let mut send_guard = sent_pkt_records.send();
        let (pn, pkt_no) = send_guard.next_pn();
        let mut b = b.measure(pkt_no.size(), payload_buf.remaining_mut())?;
        let (mut pn_buf, mut body_buf) = payload_buf.split_at_mut(pkt_no.size());

        let mut is_ack_eliciting = false;
        let mut in_flight = false;
        let body_size = body_buf.remaining_mut();

        // 4. 检查是否需要发送Ack，若是，生成ack
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.space.rcvd_packets();
            let n = rcvd_pkt_records.read_ack_frame_util(&mut b, body_buf, largest, recv_time)?;
            send_guard.record_trivial();
            sent_ack = Some(largest);
            body_buf = &mut body_buf[n..];
        }

        // 5. 从CryptoStream提取数据，当前无流控，仅最大努力，提取限制之内的最大数据量
        while let Some((frame, n)) = self.crypto_stream_outgoing.try_read_data(&mut b, body_buf) {
            send_guard.record_frame(frame);
            body_buf = &mut body_buf[n..];
            is_ack_eliciting = true;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        // 6. 记录burst变化，后面肯定要发送了，反馈给拥塞控制，抗放大攻击(该空间不涉及流控)
        *burst = b;

        // 7. 填充，保护头部，加密
        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let body_size = body_size - body_buf.remaining_mut();
        let pkt_size = hdr.size() + 2 + pkt_no.size() + body_size;

        hdr_buf.put_long_header(&hdr);
        hdr_buf.encode_varint(
            &VarInt::try_from(pn_len + body_size).unwrap(),
            EncodeBytes::Two,
        );
        pn_buf.put_packet_number(pkt_no);

        encrypt_packet(
            k.remote.packet.as_ref(),
            pn,
            &mut buf[..pkt_size],
            hdr_len + pn_len,
        );
        protect_long_header(
            k.remote.header.as_ref(),
            &mut buf[..pkt_size],
            hdr_len,
            pn_len,
        );

        Some((pn, is_ack_eliciting, pkt_size, in_flight, sent_ack))
    }
}
