use crate::{crypto::TlsIO, frame_queue::ArcFrameQueue, path::ArcPath};
use futures::StreamExt;
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, ConnFrame, Frame, FrameReader, PureFrame},
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        keys::{ArcKeys, ArcOneRttKeys},
        OneRttPacket, PacketNumber,
    },
    SpaceId,
};
use qrecovery::{
    crypto::{CryptoStreamReader, CryptoStreamWriter},
    space::{Receive, SpaceFrame},
};
use rustls::quic::KeyChange;
use tokio::sync::mpsc;

fn parse_packet_and_then_dispatch(
    payload: bytes::Bytes,
    space_id: SpaceId,
    path: &ArcPath,
    conn_frames: &ArcFrameQueue<ConnFrame>,
    space_frames: &ArcFrameQueue<SpaceFrame>,
) -> Result<bool, Error> {
    let mut space_frame_writer = space_frames.writer();
    let mut conn_frame_writer = conn_frames.writer();
    let mut path_frame_writer = path.frames().writer();
    let mut frame_reader = FrameReader::new(payload);
    let mut is_ack_eliciting = false;
    while let Some(result) = frame_reader.next() {
        match result {
            Ok(frame) => match frame {
                Frame::Pure(f) => {
                    if !f.belongs_to(space_id) {
                        space_frame_writer.rollback();
                        conn_frame_writer.rollback();
                        path_frame_writer.rollback();
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            f.frame_type(),
                            format!("cann't be received in {}", space_id),
                        ));
                    }

                    match f {
                        PureFrame::Padding(_) => continue,
                        PureFrame::Ping(_) => is_ack_eliciting = true,
                        PureFrame::Ack(ack) => {
                            space_frame_writer.push(SpaceFrame::Ack(ack, path.rtt()))
                        }
                        PureFrame::Conn(f) => {
                            is_ack_eliciting = true;
                            conn_frame_writer.push(f);
                        }
                        PureFrame::Stream(f) => {
                            is_ack_eliciting = true;
                            space_frame_writer.push(SpaceFrame::Stream(f));
                        }
                        PureFrame::Path(f) => {
                            is_ack_eliciting = true;
                            path_frame_writer.push(f);
                        }
                    }
                }
                Frame::Data(f, data) => {
                    if !f.belongs_to(space_id) {
                        space_frame_writer.rollback();
                        conn_frame_writer.rollback();
                        path_frame_writer.rollback();
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            f.frame_type(),
                            format!("cann't be received in {}", space_id),
                        ));
                    }

                    is_ack_eliciting = true;
                    space_frame_writer.push(SpaceFrame::Data(f, data));
                }
            },
            Err(e) => {
                // If frame parsing fails, discard it and roll back,
                // as if this packet has never been received.
                space_frame_writer.rollback();
                conn_frame_writer.rollback();
                path_frame_writer.rollback();
                return Err(e.into());
            }
        }
    }
    Ok(is_ack_eliciting)
}

pub(crate) async fn loop_read_long_packet_and_then_dispatch_to_space_frame_queue<P, S>(
    mut packet_rx: mpsc::UnboundedReceiver<(P, ArcPath)>,
    space_id: SpaceId,
    keys: ArcKeys,
    space: S,
    conn_frame_queue: ArcFrameQueue<ConnFrame>,
    space_frame_queue: ArcFrameQueue<SpaceFrame>,
    need_close_space_frame_queue_at_end: bool,
) where
    S: Receive,
    P: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection,
{
    while let Some((mut packet, path)) = packet_rx.recv().await {
        if let Some(k) = keys.get_remote_keys().await {
            let ok = packet.remove_protection(&k.as_ref().remote.header);
            if !ok {
                // Failed to remove packet header protection, just discard it.
                continue;
            }

            let pn = packet.decode_header().unwrap();
            let pkt_id = pn.decode(space.expected_pn());
            if space.has_rcvd(pkt_id) {
                // Duplicate packet, discard. QUIC does not allow duplicate packets.
                // Is it an error to receive duplicate packets? Definitely not,
                // otherwise it would be too vulnerable to replay attacks.
                continue;
            }

            match packet.decrypt_packet(pkt_id, pn.size(), &k.as_ref().remote.packet) {
                Ok(payload) => {
                    match parse_packet_and_then_dispatch(
                        payload,
                        space_id,
                        &path,
                        &conn_frame_queue,
                        &space_frame_queue,
                    ) {
                        Ok(is_ack_eliciting) => space.record(pkt_id, is_ack_eliciting),
                        Err(_e) => {
                            // 解析包失败，丢弃
                            // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                            continue;
                        }
                    }
                }
                // Decryption failed, just ignore/discard it.
                Err(_) => continue,
            }
        } else {
            break;
        }
    }

    if need_close_space_frame_queue_at_end {
        space_frame_queue.close();
    }
}

pub(crate) async fn loop_read_short_packet_and_then_dispatch_to_space_frame_queue(
    mut packet_rx: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)>,
    keys: ArcOneRttKeys,
    space: impl Receive,
    conn_frame_queue: ArcFrameQueue<ConnFrame>,
    space_frame_queue: ArcFrameQueue<SpaceFrame>,
) {
    while let Some((mut packet, path)) = packet_rx.recv().await {
        // 1rtt空间的header protection key是固定的，packet key则是根据包头中的key_phase_bit变化的
        if let Some((hk, pk)) = keys.get_remote_keys().await {
            let ok = packet.remove_protection(&hk.as_ref());
            if !ok {
                // Failed to remove packet header protection, just discard it.
                continue;
            }

            let (pn, key_phase) = packet.decode_header().unwrap();
            let pkt_id = pn.decode(space.expected_pn());
            // 要根据key_phase_bit来获取packet key
            let pkt_key = pk.lock().unwrap().get_remote(key_phase, pkt_id);
            match packet.decrypt_packet(pkt_id, pn.size(), &pkt_key.as_ref()) {
                Ok(payload) => {
                    match parse_packet_and_then_dispatch(
                        payload,
                        SpaceId::OneRtt,
                        &path,
                        &conn_frame_queue,
                        &space_frame_queue,
                    ) {
                        Ok(is_ack_eliciting) => space.record(pkt_id, is_ack_eliciting),
                        Err(_e) => {
                            // 解析包失败，丢弃
                            // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                            continue;
                        }
                    }
                }
                // Decryption failed, just ignore/discard it.
                Err(_) => continue,
            }
        } else {
            break;
        }
    }
    space_frame_queue.close();
}

/// Continuously read from the frame queue and hand it over to the space for processing.
/// This task will automatically end with the close of space frames, no extra maintenance is needed.
pub(crate) async fn loop_read_space_frame_and_dispatch_to_space(
    mut space_frames_queue: ArcFrameQueue<SpaceFrame>,
    space: impl Receive,
) {
    while let Some(frame) = space_frames_queue.next().await {
        // TODO: 处理连接错误
        // TODO: 0RTT和1RTT公用一个Space
        let _result = space.recv_frame(frame);
    }
}

async fn exchange_hs(
    tls_session: TlsIO,
    (stream_reader, stream_writer): (CryptoStreamReader, CryptoStreamWriter),
) -> std::io::Result<KeyChange> {
    let (tls_reader, tls_writer) = tls_session.split_io();
    let loop_read = tls_reader.loop_read_from(stream_reader);
    let mut poll_writer = tls_writer.write_to(stream_writer);
    let key_change = poll_writer.loop_write().await?;
    loop_read.end().await?;
    Ok(key_change)
}

pub(crate) async fn exchange_initial_crypto_msg_until_getting_handshake_key(
    tls_session: TlsIO,
    handshake_keys: ArcKeys,
    initial_crypto_handler: (CryptoStreamReader, CryptoStreamWriter),
) {
    match exchange_hs(tls_session, initial_crypto_handler).await {
        Ok(key_change) => match key_change {
            KeyChange::Handshake { keys } => {
                handshake_keys.set_keys(keys);
            }
            _ => unreachable!(),
        },
        Err(_) => {
            todo!()
        }
    }
}

pub(crate) async fn exchange_handshake_crypto_msg_until_getting_1rtt_key(
    tls_session: TlsIO,
    one_rtt_keys: ArcOneRttKeys,
    handshake_crypto_handler: (CryptoStreamReader, CryptoStreamWriter),
) {
    match exchange_hs(tls_session, handshake_crypto_handler).await {
        Ok(key_change) => match key_change {
            KeyChange::OneRtt { keys, next } => {
                one_rtt_keys.set_keys(keys, next);
            }
            _ => unreachable!(),
        },
        Err(_) => {
            todo!()
        }
    }
}
