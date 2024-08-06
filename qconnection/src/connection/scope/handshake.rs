use std::{ops::Deref, time::Instant};

use bytes::BufMut;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::ConnectionId,
    frame::{AckFrame, DataFrame, Frame, FrameReader},
    packet::{
        decrypt::{decrypt_packet, remove_protection_of_long_packet},
        header::{Encode, GetType, WriteLongHeader},
        keys::ArcKeys,
        LongClearBits, LongHeaderBuilder, WritePacketNumber,
    },
    util::Burst,
};
use qrecovery::{
    space::{Epoch, HandshakeSpace},
    streams::crypto::CryptoStream,
};

use crate::{
    connection::{PacketEntry, RcvdPacket},
    error::ConnError,
    path::ArcPath,
    pipe,
    transmit::{read_long_header_and_encrypt, FillPolicy},
};

#[derive(Clone)]
pub struct HandshakeScope {
    pub keys: ArcKeys,
    pub space: HandshakeSpace,
    pub crypto_stream: CryptoStream,
    pub packets_entry: PacketEntry,
}

impl HandshakeScope {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(packets_entry: PacketEntry) -> Self {
        Self {
            keys: ArcKeys::new_pending(),
            space: HandshakeSpace::with_capacity(16),
            crypto_stream: CryptoStream::new(4096, 4096),
            packets_entry,
        }
    }

    pub fn build(&self, rcvd_packets: RcvdPacket, conn_error: ConnError) {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = {
            let conn_error = conn_error.clone();
            move |frame: Frame, path: &ArcPath| match frame {
                Frame::Ack(ack_frame) => {
                    path.lock_guard().on_ack(Epoch::Initial, &ack_frame);
                    _ = ack_frames_entry.unbounded_send(ack_frame);
                }
                Frame::Close(ccf) => {
                    conn_error.on_ccf_rcvd(&ccf);
                }
                Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                    _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                }
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in handshake packet", frame),
            }
        };
        let on_ack = {
            let crypto_stream_outgoing = self.crypto_stream.outgoing();
            let sent_pkt_records = self.space.sent_packets();
            move |ack_frame: &AckFrame| {
                let mut recv_guard = sent_pkt_records.receive();
                recv_guard.update_largest(ack_frame.largest.into_inner());

                for pn in ack_frame.iter().flat_map(|r| r.rev()) {
                    for frame in recv_guard.on_pkt_acked(pn) {
                        crypto_stream_outgoing.on_data_acked(&frame);
                    }
                }
            }
        };

        pipe!(rcvd_crypto_frames |> self.crypto_stream.incoming(), recv_crypto_frame);
        pipe!(rcvd_ack_frames |> on_ack);
        self.parse_rcvd_packets_and_dispatch_frames(rcvd_packets, dispatch_frame, conn_error);
    }

    fn parse_rcvd_packets_and_dispatch_frames(
        &self,
        mut rcvd_packets: RcvdPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            async move {
                while let Some((mut packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let Some(keys) = keys.get_remote_keys().await else {
                        break;
                    };
                    let undecoded_pn = match remove_protection_of_long_packet(
                        keys.remote.header.as_ref(),
                        packet.bytes.as_mut(),
                        packet.offset,
                    ) {
                        Ok(Some(pn)) => pn,
                        Ok(None) => continue,
                        Err(_e) => {
                            // conn_error.on_error(e);
                            return;
                        }
                    };

                    let pn = match rcvd_pkt_records.decode_pn(undecoded_pn) {
                        Ok(pn) => pn,
                        // TooOld/TooLarge/HasRcvd
                        Err(_e) => continue,
                    };
                    let body_offset = packet.offset + undecoded_pn.size();
                    decrypt_packet(
                        keys.remote.packet.as_ref(),
                        pn,
                        packet.bytes.as_mut(),
                        body_offset,
                    )
                    .unwrap();
                    let body = packet.bytes.split_off(body_offset);
                    match FrameReader::new(body.freeze(), pty).try_fold(
                        false,
                        |is_ack_packet, frame| {
                            let (frame, is_ack_eliciting) = frame?;
                            dispatch_frame(frame, &path);
                            Ok(is_ack_packet || is_ack_eliciting)
                        },
                    ) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.lock_guard()
                                .on_recv_pkt(Epoch::Handshake, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }

    pub fn reader(
        &self,
    ) -> impl FnMut(
        &mut Burst,
        &mut [u8],
        ConnectionId,
        ConnectionId,
        Option<(u64, Instant)>,
    ) -> Option<(u64, bool, usize, bool, Option<u64>)> {
        let keys = self.keys.clone();
        let crypto_stream_outgoing = self.crypto_stream.outgoing();
        let space = self.space.clone();
        move |burst: &mut Burst,
              buf: &mut [u8],
              scid: ConnectionId,
              dcid: ConnectionId,
              ack_pkt: Option<(u64, Instant)>|
              -> Option<(u64, bool, usize, bool, Option<u64>)> {
            // 1. 判定keys是否有效，无效或者尚未拿到，直接返回
            let k = keys.get_local_keys()?;

            // 2. 生成包头，预留2字节len，根据包头大小，配合burst、剩余空间，检查是否能发送，不能的话，直接返回
            let hdr = LongHeaderBuilder::with_cid(dcid, scid).handshake();
            let b = burst.measure(hdr.size() + 2, buf.remaining_mut())?;
            let (mut hdr_buf, payload_buf) = buf.split_at_mut(hdr.size() + 2);

            // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
            let sent_pkt_records = space.sent_packets();
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
                let rcvd_pkt_records = space.rcvd_packets();
                let n =
                    rcvd_pkt_records.read_ack_frame_util(&mut b, body_buf, largest, recv_time)?;
                send_guard.record_trivial();
                sent_ack = Some(largest);
                body_buf = &mut body_buf[n..];
            }

            // 5. 从CryptoStream提取数据，当前无流控，仅最大努力，提取限制之内的最大数据量
            while let Some((frame, n)) = crypto_stream_outgoing.try_read_data(&mut b, body_buf) {
                send_guard.record_frame(frame);
                body_buf = &mut body_buf[n..];
                is_ack_eliciting = true;
                in_flight = true;
            }
            drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

            // 6. 记录burst变化，后面肯定要发送了，反馈给拥塞控制，抗放大攻击(该空间不涉及流控)
            *burst = b;

            // 7. 填充，保护头部，加密
            hdr_buf.put_long_header(&hdr);
            let clear_bits = LongClearBits::from_pn(&pkt_no);
            hdr_buf[0] |= clear_bits.deref();
            pn_buf.put_packet_number(pkt_no);
            let body_size = body_size - body_buf.remaining_mut();
            let sent_size = hdr.size() + 2 + pkt_no.size() + body_size;
            read_long_header_and_encrypt(
                buf,
                &hdr,
                pn,
                pkt_no.size(),
                body_size,
                &k,
                FillPolicy::Redundancy,
            );
            Some((pn, is_ack_eliciting, sent_size, in_flight, sent_ack))
        }
    }
}
