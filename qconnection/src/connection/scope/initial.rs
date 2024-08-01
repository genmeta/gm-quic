use std::time::Instant;

use bytes::BufMut;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::ConnectionId,
    frame::{AckFrame, DataFrame, Frame, FrameReader},
    packet::{
        header::{Encode, GetType, WriteLongHeader},
        keys::ArcKeys,
        LongHeaderBuilder, WritePacketNumber,
    },
    util::Burst,
};
use qrecovery::{
    space::{Epoch, InitialSpace},
    streams::crypto::CryptoStream,
};

use crate::{
    connection::{decode_long_header_packet, InitialPacketEntry, RcvdInitialPacket},
    error::ConnError,
    path::ArcPath,
    pipe,
    transmit::{read_long_header_and_encrypt, FillPolicy},
};

pub struct InitialScope {
    pub keys: ArcKeys,
    pub space: InitialSpace,
    pub crypto_stream: CryptoStream,
    pub packets_entry: InitialPacketEntry,
}

impl InitialScope {
    // Initial keys应该是预先知道的，或者传入dcid，可以构造出来
    pub fn new(keys: ArcKeys, packets_entry: InitialPacketEntry) -> Self {
        let space = InitialSpace::with_capacity(16);
        let crypto_stream = CryptoStream::new(0, 0);

        Self {
            keys,
            space,
            crypto_stream,
            packets_entry,
        }
    }

    pub fn build(&self, rcvd_packets: RcvdInitialPacket, conn_error: ConnError) {
        let (crypto_frames_entry, rcvd_crypto_frames) = mpsc::unbounded();
        let (ack_frames_entry, rcvd_ack_frames) = mpsc::unbounded();

        let dispatch_frame = move |frame: Frame, path: &ArcPath| {
            match frame {
                Frame::Ack(ack_frame) => {
                    path.on_ack(Epoch::Initial, &ack_frame);
                    _ = ack_frames_entry.unbounded_send(ack_frame);
                }
                Frame::Data(DataFrame::Crypto(crypto), bytes) => {
                    _ = crypto_frames_entry.unbounded_send((crypto, bytes));
                }
                Frame::Close(_) => { /* trustless */ }
                Frame::Padding(_) | Frame::Ping(_) => {}
                _ => unreachable!("unexpected frame: {:?} in initial packet", frame),
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
        mut rcvd_packets: RcvdInitialPacket,
        dispatch_frame: impl Fn(Frame, &ArcPath) + Send + 'static,
        conn_error: ConnError,
    ) {
        tokio::spawn({
            let rcvd_pkt_records = self.space.rcvd_packets();
            let keys = self.keys.clone();
            async move {
                while let Some((packet, path)) = rcvd_packets.next().await {
                    let pty = packet.header.get_type();
                    let decode_pn = |pn| rcvd_pkt_records.decode_pn(pn).ok();
                    let (pn, payload) =
                        match decode_long_header_packet(packet, &keys, decode_pn).await {
                            Some((pn, payload)) => (pn, payload),
                            None => return,
                        };
                    match FrameReader::new(payload, pty).try_fold(false, |is_ack_packet, frame| {
                        let (frame, is_ack_eliciting) = frame?;
                        dispatch_frame(frame, &path);
                        Ok(is_ack_packet || is_ack_eliciting)
                    }) {
                        Ok(is_ack_packet) => {
                            rcvd_pkt_records.register_pn(pn);
                            path.on_recv_pkt(Epoch::Initial, pn, is_ack_packet);
                        }
                        Err(e) => conn_error.on_error(e),
                    }
                }
            }
        });
    }

    pub fn sending_closure(
        &self,
        token: Vec<u8>, // if no token, use empty Vec
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
            let hdr = LongHeaderBuilder::with_cid(dcid, scid).initial(Vec::new());
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
                send_guard.push_back(frame);
                body_buf = &mut body_buf[n..];
                is_ack_eliciting = true;
                in_flight = true;
            }
            drop(send_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

            // 毋需担心不够1200字节，详见 RFC 9000 section 14.1，初始数据包甚至可以与无效数据包合并，接收方将丢弃这些数据包
            // 6. 记录burst变化，后面肯定要发送了，反馈给拥塞控制，抗放大攻击(该空间不涉及流控)
            *burst = b;

            // 7. 填充，保护头部，加密
            hdr_buf.put_long_header(&hdr);
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
