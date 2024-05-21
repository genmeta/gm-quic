use bytes::Bytes;
use futures::StreamExt;
use path::ArcPath;
use qbase::{
    error::{Error, ErrorKind},
    frame::{BeFrame, ConnFrame, Frame, FrameReader, PureFrame},
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        keys::{ArcKeys, ArcOneRttKeys},
        OneRttPacket, PacketNumber, SpacePacket,
    },
    SpaceId,
};
use qrecovery::space::{Receive, SpaceFrame};

pub mod connection;
pub mod crypto;
pub mod endpoint;
pub mod frame_queue;
pub mod path;

use frame_queue::ArcFrameQueue;
use tokio::sync::mpsc::{self, UnboundedSender};

pub trait ReceiveProtectedPacket {
    fn receive_protected_packet(&mut self, protected_packet: SpacePacket);
}

// 收包队列，就用tokio::sync::mpsc::UnboundedChannel
// 收帧队列，得用VecDeque+is_closed+waker，外加Arc<Mutex>>包装，有close操作
// 之所以要封装VecDeque，为了一个包坏了，全部帧都得回退
// 收帧队列，又分为space的、connection的、path的3个

// 收包解帧任务，就用tokio::task::spawn产生，不同地从收包队列中取出包，取出密钥解帧，再放入对应的收帧队列中
// 包有Arc<Mutex<Path>>信息，收到的Path相关帧写入到
// Connection的收帧队列，只有一个，Arc<Mutex<Connection>>，收到的帧写入到这个队列中

fn parse_packet_and_then_dispatch(
    payload: Bytes,
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
                Frame::Padding => continue,
                Frame::Ping(_) => is_ack_eliciting = true,
                Frame::Ack(ack) => {
                    if !ack.belongs_to(space_id) {
                        space_frame_writer.rollback();
                        conn_frame_writer.rollback();
                        path_frame_writer.rollback();
                        return Err(Error::new(
                            ErrorKind::ProtocolViolation,
                            ack.frame_type(),
                            format!("cann't be received in {}", space_id),
                        ));
                    }
                    space_frame_writer.push(SpaceFrame::Ack(ack, path.rtt()));
                }
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

                    is_ack_eliciting = true;
                    match f {
                        PureFrame::Conn(f) => conn_frame_writer.push(f),
                        PureFrame::Stream(f) => space_frame_writer.push(SpaceFrame::Stream(f)),
                        PureFrame::Path(f) => path_frame_writer.push(f),
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

/// This function concatenates the reading logic of all Spaces except the 1RTT Space. Just pass in the Space and Keys,
/// it will build a packet receiving queue internally, and spawn two detached asynchronous tasks, respectively doing:
/// - *Packet reading and parsing task*: Continuously read packets from the receiving queue, remove header protection,
///   unpack, decode frames, and then write the frames into the corresponding receiving frame queue.
/// - *Frame reading task*: Continuously read frames from the receiving frame queue, hand them over to Space for
///   processing, or handle Path frames with Path when encountered.
/// Finally, it returns the sending end of the packet receiving queue, which can be used to write packets into this
/// queue when receiving packets for this space.
pub fn build_space_reader<S, P>(
    space_id: SpaceId,
    keys: ArcKeys,
    space: S,
    conn_frames: ArcFrameQueue<ConnFrame>,
) -> UnboundedSender<(P, ArcPath)>
where
    S: Clone + Receive + Send + 'static,
    P: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection + Send + 'static,
{
    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<(P, ArcPath)>();
    let space_frames = ArcFrameQueue::new();

    // Continuously read from the frame queue and hand it over to the space for processing.
    // This task will automatically end with the close of space frames, no extra maintenance is needed.
    tokio::task::spawn({
        let mut space_frames = space_frames.clone();
        let space = space.clone();
        async move {
            while let Some(frame) = space_frames.next().await {
                // TODO: 处理连接错误
                // TODO: 0RTT和1RTT公用一个Space
                let result = space.recv_frame(frame);
            }
        }
    });

    // Continuously read packets, decrypt them, parse out frames, and put them into various frame queues.
    // This task will automatically end when the key is discarded or the packet receiving queue is closed, no extra maintenance is needed.
    tokio::task::spawn(async move {
        while let Some((mut packet, path)) = packet_rx.recv().await {
            if let Some(k) = keys.get_remote_keys().await {
                let ok = packet.remove_protection(&k.as_ref().remote.header);
                if !ok {
                    // Failed to remove packet header protection, just discard it.
                    continue;
                }

                let pn = packet.decode_header().unwrap();
                let pkt_id = pn.decode(space.expected_pn());
                match packet.decrypt_packet(pkt_id, pn.size(), &k.as_ref().remote.packet) {
                    Ok(payload) => {
                        match parse_packet_and_then_dispatch(
                            payload,
                            space_id,
                            &path,
                            &conn_frames,
                            &space_frames,
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
        space_frames.close();
    });

    packet_tx
}

pub fn build_1rtt_space_reader(
    keys: ArcOneRttKeys,
    space: impl Receive + Send + 'static,
    conn_frames: ArcFrameQueue<ConnFrame>,
) -> UnboundedSender<(OneRttPacket, ArcPath)> {
    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<(OneRttPacket, ArcPath)>();
    let space_frames = ArcFrameQueue::new();
    // Continuously read packets, decrypt them, parse out frames, and put them into various frame queues.
    // This task will automatically end when the key is discarded or the packet receiving queue is closed, no extra maintenance is needed.
    tokio::task::spawn(async move {
        while let Some((mut packet, path)) = packet_rx.recv().await {
            // 1rtt空间的header protection key是固定的，packet key则是根据包头中的key_phase_bit变化的
            let (hk, pk) = keys.get_remote_keys().await;
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
                        &conn_frames,
                        &space_frames,
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
        }
        space_frames.close();
    });
    packet_tx
}

// 发包的时候，由Path发起，但得先获得包id，若没东西发，包id就没必要获得，或者包id不允许退还，就发一个空包
// 先获取包序号，整理包头，计算剩余空间
// 写入path自己的帧。问题是，这个包丢了，path帧也得重传，怎么告知相应path，它的帧丢了呢？
//  有一张表，记录着那个包id是那个path发送的，当某个包丢的时候，告知path
// 写入Space的帧

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
