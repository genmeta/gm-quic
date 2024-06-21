use std::ops::Deref;

use qbase::{
    error::{Error, ErrorKind},
    frame::{AckFrame, BeFrame, ConnFrame, Frame, FrameReader, PureFrame},
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
        r#type::Type,
        OneRttPacket, PacketNumber, PacketWrapper,
    },
    util::ArcAsyncQueue,
};
use tokio::sync::mpsc;

use crate::{
    path::ArcPath,
    space::{ArcSpace, DataSpace, Space, SpaceFrame},
};

fn parse_packet_and_then_dispatch(
    payload: bytes::Bytes,
    packet_type: Type,
    _path: &ArcPath,
    conn_frame_queue: &ArcAsyncQueue<ConnFrame>,
    space_frame_queue: &ArcAsyncQueue<SpaceFrame>,
    ack_frames_tx: &mpsc::UnboundedSender<AckFrame>,
    // on_ack_frame_rcvd: impl FnMut(AckFrame, Arc<Mutex<Rtt>>),
) -> Result<bool, Error> {
    let mut space_frame_writer = space_frame_queue.writer();
    let mut conn_frame_writer = conn_frame_queue.writer();
    // let mut path_frame_writer = path.frames().writer();

    FrameReader::new(payload).try_fold(false, |is_ack_eliciting, result| {
        let frame = result.map_err(|e| {
            space_frame_writer.rollback();
            conn_frame_writer.rollback();
            Error::from(e)
        })?;
        match frame {
            Frame::Pure(f) => {
                if !f.belongs_to(packet_type) {
                    space_frame_writer.rollback();
                    conn_frame_writer.rollback();
                    return Err(Error::new(
                        ErrorKind::ProtocolViolation,
                        f.frame_type(),
                        format!("cann't exist in {:?}", packet_type),
                    ));
                }

                match f {
                    PureFrame::Padding(_) => Ok(is_ack_eliciting),
                    PureFrame::Ping(_) => Ok(true),
                    PureFrame::Ack(ack) => {
                        let _ = ack_frames_tx.send(ack);
                        Ok(is_ack_eliciting)
                    }
                    PureFrame::Conn(f) => {
                        conn_frame_writer.push(f);
                        Ok(true)
                    }
                    PureFrame::Stream(f) => {
                        space_frame_writer.push(SpaceFrame::Stream(f));
                        Ok(true)
                    }
                    PureFrame::Path(_f) => {
                        // path_frame_writer.push(f);
                        Ok(true)
                    }
                }
            }
            Frame::Data(f, data) => {
                if !f.belongs_to(packet_type) {
                    space_frame_writer.rollback();
                    conn_frame_writer.rollback();
                    return Err(Error::new(
                        ErrorKind::ProtocolViolation,
                        f.frame_type(),
                        format!("cann't exist in {:?}", packet_type),
                    ));
                }
                space_frame_writer.push(SpaceFrame::Data(f, data));
                Ok(true)
            }
        }
    })
}

pub(crate) async fn loop_read_long_packet_and_then_dispatch_to_space_frame_queue<H, S>(
    mut pkt_rx: mpsc::UnboundedReceiver<(PacketWrapper<H>, ArcPath)>,
    keys: ArcKeys,
    space: ArcSpace<S>,
    conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
) where
    S: Space,
    H: GetType,
    PacketWrapper<H>: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection,
{
    let space_frame_queue = space.space_frame_queue();
    while let Some((mut packet, path)) = pkt_rx.recv().await {
        let Some(k) = keys.get_remote_keys().await else {
            break;
        };

        let protection_removed = packet.remove_protection(k.remote.header.deref());
        if !protection_removed {
            // Failed to remove packet header protection, just discard it.
            continue;
        }

        let encoded_pn = packet.decode_header().unwrap();
        let Ok(pn) = space.decode_pn(encoded_pn) else {
            // Duplicate packet, discard. QUIC does not allow duplicate packets.
            // Is it an error to receive duplicate packets? Definitely not,
            // otherwise it would be too vulnerable to replay attacks.
            continue;
        };

        let packet_type = packet.header.get_type();
        match packet.decrypt_packet(pn, encoded_pn.size(), k.remote.packet.deref()) {
            Ok(payload) => {
                match parse_packet_and_then_dispatch(
                    payload,
                    packet_type,
                    &path,
                    &conn_frame_queue,
                    &space_frame_queue,
                    &ack_frames_tx,
                ) {
                    // TODO: path也要记录收包时间、is_ack_eliciting
                    Ok(_is_ack_eliciting) => space.rcvd_pkt_records().register_pn(pn),
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
    }
    // 0rtt的空间帧队列和0rtt是独立创建的，所以在这里可以直接关闭
    space_frame_queue.close();
}

pub(crate) async fn loop_read_short_packet_and_then_dispatch_to_space_frame_queue(
    mut packet_rx: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)>,
    keys: ArcOneRttKeys,
    space: ArcSpace<DataSpace>,
    conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
) {
    let space_frame_queue = space.space_frame_queue();
    while let Some((mut packet, path)) = packet_rx.recv().await {
        // 1rtt空间的header protection key是固定的，packet key则是根据包头中的key_phase_bit变化的
        let Some((hpk, pk)) = keys.get_remote_keys().await else {
            break;
        };

        let ok = packet.remove_protection(hpk.deref());
        if !ok {
            // Failed to remove packet header protection, just discard it.
            continue;
        }

        let (encoded_pn, key_phase) = packet.decode_header().unwrap();
        let Ok(pn) = space.decode_pn(encoded_pn) else {
            continue;
        };

        // 要根据key_phase_bit来获取packet key
        let packet_type = packet.header.get_type();
        let packet_key = pk.lock().unwrap().get_remote(key_phase, pn);
        match packet.decrypt_packet(pn, encoded_pn.size(), packet_key.deref()) {
            Ok(payload) => {
                match parse_packet_and_then_dispatch(
                    payload,
                    packet_type,
                    &path,
                    &conn_frame_queue,
                    &space_frame_queue,
                    &ack_frames_tx,
                ) {
                    // TODO: path也要登记其收到的包、收包时间、is_ack_eliciting，方便激发AckFrame
                    Ok(_is_ack_eliciting) => space.rcvd_pkt_records().register_pn(pn),
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
    }
    space_frame_queue.close();
}
