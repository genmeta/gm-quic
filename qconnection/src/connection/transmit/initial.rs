use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use bytes::BufMut;
use qbase::{
    cid::ConnectionId,
    packet::{
        encrypt::{encode_long_first_byte, encrypt_packet, protect_header},
        header::WriteLongHeader,
        keys::ArcKeys,
        EncodeHeader, LongHeaderBuilder, WritePacketNumber,
    },
    varint::{EncodeBytes, VarInt, WriteVarInt},
};
use qrecovery::{crypto::CryptoStreamOutgoing, space::InitialSpace};

#[derive(Clone)]
pub struct InitialSpaceReader {
    pub(crate) token: Arc<Mutex<Vec<u8>>>,
    pub(crate) keys: ArcKeys,
    pub(crate) space: InitialSpace,
    pub(crate) crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl InitialSpaceReader {
    pub fn try_read(
        &self,
        buf: &mut [u8],
        scid: ConnectionId,
        dcid: ConnectionId,
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(
        impl FnOnce(&mut [u8], usize) -> (u64, bool, bool, usize, bool, Option<u64>),
        usize,
        bool,
    )> {
        // 1. 判定keys是否有效，无效或者尚未拿到，直接返回
        let k = self.keys.get_local_keys()?;

        // 2. 生成包头，预留2字节len，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let token = self.token.lock().unwrap();
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).initial(token.clone());
        // length字段预留2字节, 20字节为最小Payload长度，为了保护包头的Sample至少16字节
        if buf.len() < hdr.size() + 2 + 20 {
            return None;
        }
        let (mut hdr_buf, payload_tag) = buf.split_at_mut(hdr.size() + 2);
        let payload_tag_len = payload_tag.len();
        let tag_len = k.local.packet.as_ref().tag_len();
        let payload_buf = &mut payload_tag[..payload_tag_len - tag_len];

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
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

        // 4. 检查是否需要发送Ack，若是，生成ack
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.space.rcvd_packets();
            let n = rcvd_pkt_records
                .read_ack_frame_util(body_buf, largest, recv_time)
                .unwrap();
            send_guard.record_trivial();
            sent_ack = Some(largest);
            body_buf = &mut body_buf[n..];
        }

        // 5. 从CryptoStream提取数据，当前无流控，仅最大努力，提取限制之内的最大数据量
        while let Some((frame, n)) = self.crypto_stream_outgoing.try_read_data(body_buf) {
            send_guard.record_frame(frame);
            body_buf = &mut body_buf[n..];
            is_just_ack = false;
            is_ack_eliciting = true;
            in_flight = true;
        }
        drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        let hdr_len = hdr_buf.len();
        let pn_len = pn_buf.len();
        let mut body_len = body_size - body_buf.remaining_mut();
        if body_len == 0 {
            return None;
        }
        let mut pkt_size = hdr_len + pn_len + body_len + tag_len;

        hdr_buf.put_long_header(&hdr);
        pn_buf.put_packet_number(encoded_pn);

        Some((
            move |buf: &mut [u8], len: usize| -> (u64, bool, bool, usize, bool, Option<u64>) {
                // 6. 填充，保护头部，加密
                let (_hdr_buf, remain) = buf.split_at_mut(hdr_len - 2);
                let (mut length_buf, remain) = remain.split_at_mut(2);
                let (_pn_buf, remain) = remain.split_at_mut(pn_len);
                let (_body, mut remain) = remain.split_at_mut(body_len);

                // 追加padding
                if len > pkt_size {
                    remain.put_bytes(0, len - pkt_size);
                    is_just_ack = false;
                    body_len += len - pkt_size;
                    pkt_size = len;
                }
                // payload(pn + body)长度不足20字节，填充之
                if pn_len + body_len + tag_len < 20 {
                    let padding_len = 20 - pn_len - body_len - tag_len;
                    remain.put_bytes(0, padding_len);
                    body_len += padding_len;
                    pkt_size += padding_len;
                }

                length_buf.encode_varint(
                    &VarInt::try_from(pn_len + body_len + tag_len).unwrap(),
                    EncodeBytes::Two,
                );

                encode_long_first_byte(&mut buf[0], pn_len);
                encrypt_packet(
                    k.local.packet.as_ref(),
                    pn,
                    &mut buf[..pkt_size],
                    hdr_len + pn_len,
                );
                protect_header(
                    k.local.header.as_ref(),
                    &mut buf[..pkt_size],
                    hdr_len,
                    pn_len,
                );
                (
                    pn,
                    is_ack_eliciting,
                    is_just_ack,
                    pkt_size,
                    in_flight,
                    sent_ack,
                )
            },
            hdr_len + pn_len + body_len + tag_len,
            is_just_ack,
        ))
    }
}
