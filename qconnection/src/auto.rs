use std::ops::Deref;

use futures::StreamExt;
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
use qrecovery::{
    space::{ArcSpace, SpaceFrame},
    streams::DataStreams,
};
use tokio::sync::mpsc;

use crate::path::ArcPath;

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
    let mut is_ack_eliciting = false;
    for result in FrameReader::new(payload) {
        match result {
            Ok(frame) => match frame {
                Frame::Pure(f) => {
                    if !f.belongs_to(packet_type) {
                        space_frame_writer.rollback();
                        conn_frame_writer.rollback();
                        // path_frame_writer.rollback();
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            f.frame_type(),
                            format!("cann't exist in {:?}", packet_type),
                        ));
                    }

                    match f {
                        PureFrame::Padding(_) => continue,
                        PureFrame::Ping(_) => is_ack_eliciting = true,
                        PureFrame::Ack(ack) => {
                            // TODO: 在此收到AckFrame，ArcPath需先内部处理一番
                            let _ = ack_frames_tx.send(ack);
                        }
                        PureFrame::Conn(f) => {
                            is_ack_eliciting = true;
                            conn_frame_writer.push(f);
                        }
                        PureFrame::Stream(f) => {
                            is_ack_eliciting = true;
                            space_frame_writer.push(SpaceFrame::Stream(f));
                        }
                        PureFrame::Path(_f) => {
                            is_ack_eliciting = true;
                            // path_frame_writer.push(f);
                        }
                    }
                }
                Frame::Data(f, data) => {
                    if !f.belongs_to(packet_type) {
                        space_frame_writer.rollback();
                        conn_frame_writer.rollback();
                        // path_frame_writer.rollback();
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            f.frame_type(),
                            format!("cann't exist in {:?}", packet_type),
                        ));
                    }

                    is_ack_eliciting = true;
                    space_frame_writer.push(SpaceFrame::Data(f, data));
                }
                Frame::Datagram(_, _) => todo!(),
            },
            Err(e) => {
                // If frame parsing fails, discard it and roll back,
                // as if this packet has never been received.
                space_frame_writer.rollback();
                conn_frame_writer.rollback();
                // path_frame_writer.rollback();
                return Err(e.into());
            }
        }
    }
    Ok(is_ack_eliciting)
}

pub(crate) async fn loop_read_long_packet_and_then_dispatch_to_space_frame_queue<H, S>(
    mut packet_rx: mpsc::UnboundedReceiver<(PacketWrapper<H>, ArcPath)>,
    keys: ArcKeys,
    space: ArcSpace<S>,
    conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    space_frame_queue: ArcAsyncQueue<SpaceFrame>,
    ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
    need_close_space_frame_queue_at_end: bool,
) where
    S: AsRef<DataStreams>,
    H: GetType,
    PacketWrapper<H>: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection,
{
    while let Some((mut packet, path)) = packet_rx.recv().await {
        if let Some(k) = keys.get_remote_keys().await {
            let ok = packet.remove_protection(k.remote.header.deref());
            if !ok {
                // Failed to remove packet header protection, just discard it.
                continue;
            }

            let encoded_pn = packet.decode_header().unwrap();
            let result = space.decode_pn(encoded_pn);

            let Ok(pn) = result else {
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
    space: ArcSpace<DataStreams>,
    conn_frame_queue: ArcAsyncQueue<ConnFrame>,
    space_frame_queue: ArcAsyncQueue<SpaceFrame>,
    ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
) {
    while let Some((mut packet, path)) = packet_rx.recv().await {
        // 1rtt空间的header protection key是固定的，packet key则是根据包头中的key_phase_bit变化的
        if let Some((hk, pk)) = keys.get_remote_keys().await {
            let ok = packet.remove_protection(hk.deref());
            if !ok {
                // Failed to remove packet header protection, just discard it.
                continue;
            }

            let (encoded_pn, key_phase) = packet.decode_header().unwrap();
            let pn = match space.decode_pn(encoded_pn) {
                Ok(pn) => pn,
                Err(_e) => continue,
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
        } else {
            break;
        }
    }
    space_frame_queue.close();
}

/// Continuously read from the frame queue and hand it over to the space for processing.
/// This task will automatically end with the close of space frames, no extra maintenance is needed.
pub(crate) async fn loop_read_space_frame_and_dispatch_to_space(
    mut space_frames_queue: ArcAsyncQueue<SpaceFrame>,
    space: impl AsRef<DataStreams>,
) {
    let streams = space.as_ref();
    while let Some(frame) = space_frames_queue.next().await {
        // 闭包模拟try_block feature，写起来方便
        let result = (|| -> Result<(), Error> {
            match frame {
                SpaceFrame::Stream(sctl) => {
                    streams.recv_stream_control(sctl)?;
                }
                SpaceFrame::Data(frame, bytes) => match frame {
                    qbase::frame::DataFrame::Stream(frame) => {
                        streams.recv_data(frame, bytes)?;
                    }

                    // 按说在1rtt是收不到CryptoFrame的
                    qbase::frame::DataFrame::Crypto(_) => unreachable!(),
                },
            }
            Ok(())
        })();

        // 处理连接错误
        if let Err(err) = result {
            streams.on_conn_error(&err);
        }
    }
}
