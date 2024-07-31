use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::{channel::mpsc, StreamExt};
use qbase::{
    cid::Registry,
    error::Error,
    frame::{ConnectionCloseFrame, Frame, FrameReader},
    packet::{keys::ArcOneRttKeys, SpacePacket},
};
use qrecovery::space::{DataSpace, Epoch};
use qudp::ArcUsc;

use super::raw::{OneRttPacketQueue, Pathway};
use crate::{connection::raw::decode_short_header_packet, error::ConnError, path::ArcPath};

pub struct ClosingConnection {
    pathes: DashMap<Pathway, ArcPath>,
    cid_registry: Registry,
    one_rtt_packet_queue: OneRttPacketQueue,
    recv_record: Vec<Instant>,
    error: ConnError,
}

impl ClosingConnection {
    pub fn new(
        pathes: DashMap<Pathway, ArcPath>,
        cid_registry: Registry,
        data_space: DataSpace,
        one_rtt_keys: ArcOneRttKeys,
        error: Error,
    ) -> Self {
        let conn_error = ConnError::default();
        let (one_rtt_packet_queue, mut one_rtt_packets) = mpsc::unbounded();
        let ccf = ConnectionCloseFrame::from(error);
        let recv_record = Vec::new();

        pathes
            .iter()
            .for_each(|path| path.enter_closing(ccf.clone(), Epoch::Data));

        tokio::spawn({
            let keys = one_rtt_keys.clone();
            let conn_error = conn_error.clone();

            async move {
                let rcvd_packets = data_space.rcvd_packets();
                while let Some((packet, _path)) = one_rtt_packets.next().await {
                    let decode_pn = |pn| rcvd_packets.decode_pn(pn).ok();
                    let payload_opt = decode_short_header_packet(packet, &keys, decode_pn).await;

                    if let Some(payload) = payload_opt {
                        let ccf = FrameReader::new(payload.payload)
                            .filter_map(|frame| frame.ok())
                            .find_map(|frame| {
                                if let Frame::Close(ccf) = frame {
                                    Some(ccf)
                                } else {
                                    None
                                }
                            });

                        if let Some(ccf) = ccf {
                            conn_error.recv_ccf(&ccf);
                            return;
                        }
                    };
                }
            }
        });

        Self {
            pathes,
            cid_registry,
            one_rtt_packet_queue,
            recv_record,
            error: conn_error,
        }
    }

    // 记录收到的包数量，和收包时间，判断是否需要重发CCF；
    pub fn recv_packet_via_path(&mut self, packet: SpacePacket, path: ArcPath) {
        let now = Instant::now();
        self.recv_record.push(now);

        // TODO: 数值从配置中读取, 还是直接固定值?
        // 如果累计收到的包超过一定数量，则发送 ccf
        // 或 如果一定时间内收到的包超过一定数量, 则发送 ccf
        if self.recv_record.len() > 10
            || self.recv_record.len() > 5
                && now - *self.recv_record.get(self.recv_record.len() - 5).unwrap()
                    <= Duration::from_millis(100)
        {
            // TODO: 调用 dying path 直接发送 ccf
            self.recv_record.clear();
        }

        if let SpacePacket::OneRtt(packet) = packet {
            _ = self.one_rtt_packet_queue.unbounded_send((packet, path))
        }
    }

    pub fn get_path(&self, pathway: Pathway, _usc: &ArcUsc) -> Option<ArcPath> {
        self.pathes.get(&pathway).map(|path| path.value().clone())
    }
}
