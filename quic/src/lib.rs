use futures::StreamExt;
use path::ArcPath;
use qbase::{
    frame::{BeFrame, ConnFrame, Frame, FrameReader, PureFrame},
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        keys::ArcKeys,
        PacketNumber, SpacePacket,
    },
};
use qrecovery::{
    crypto::TransmitCrypto,
    space::{Receive, Space, SpaceFrame},
    streams::TransmitStream,
};
use std::sync::{Arc, Mutex};

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

pub fn build_space_reader<CT, ST, P>(
    keys: ArcKeys,
    space: Arc<Mutex<Space<CT, ST>>>,
    conn_frames: ArcFrameQueue<ConnFrame>,
) -> UnboundedSender<(P, ArcPath)>
where
    CT: TransmitCrypto + Send + 'static,
    ST: TransmitStream + Send + 'static,
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
                let result = space.lock().unwrap().recv_frame(frame);
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
                    // 去除包头保护失败，丢弃
                    continue;
                }

                let pn = packet.decode_header().unwrap();
                let mut s = space.lock().unwrap();
                let space_id = s.space_id();
                let mut space_frame_writer = space_frames.writer();
                let mut conn_frame_writer = conn_frames.writer();
                let mut path_frame_writer = path.frames().writer();
                match packet.decrypt_packet(pn, s.expected_pn(), &k.as_ref().remote.packet) {
                    Ok((pktid, payload)) => {
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
                                            /* 发生错误，这个异步子也要结束，但错误怎么传递给Connection呢？
                                            return Err(Error::new(
                                                ErrorKind::ProtocolViolation,
                                                ack.frame_type(),
                                                format!("cann't be received in {}", space_id),
                                            ));
                                            */
                                        }
                                        space_frame_writer.push(SpaceFrame::Ack(ack, path.rtt()));
                                    }
                                    Frame::Pure(f) => {
                                        if !f.belongs_to(space_id) {
                                            space_frame_writer.rollback();
                                            conn_frame_writer.rollback();
                                            path_frame_writer.rollback();
                                            /*
                                            return Err(Error::new(
                                                ErrorKind::ProtocolViolation,
                                                f.frame_type(),
                                                format!("cann't be received in {}", space_id),
                                            ));
                                            */
                                        }

                                        is_ack_eliciting = true;
                                        match f {
                                            PureFrame::Conn(f) => conn_frame_writer.push(f),
                                            PureFrame::Stream(f) => {
                                                space_frame_writer.push(SpaceFrame::Stream(f))
                                            }
                                            PureFrame::Path(f) => path_frame_writer.push(f),
                                        }
                                    }
                                    Frame::Data(f, data) => {
                                        if !f.belongs_to(space_id) {
                                            space_frame_writer.rollback();
                                            conn_frame_writer.rollback();
                                            path_frame_writer.rollback();
                                            /*
                                            return Err(Error::new(
                                                ErrorKind::ProtocolViolation,
                                                f.frame_type(),
                                                format!("cann't be received in {}", self.space_id),
                                            ));
                                            */
                                        }

                                        is_ack_eliciting = true;
                                        space_frame_writer.push(SpaceFrame::Data(f, data));
                                    }
                                },
                                Err(_) => {
                                    // If frame parsing fails, discard it and roll back,
                                    // as if this packet has never been received.
                                    space_frame_writer.rollback();
                                    conn_frame_writer.rollback();
                                    path_frame_writer.rollback();
                                    break;
                                }
                            }
                        }
                        s.record(pktid, is_ack_eliciting);
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
