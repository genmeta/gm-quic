use std::{
    ops::Deref,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Future, Stream, StreamExt};
use qbase::{
    error::{Error, ErrorKind},
    frame::*,
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        header::GetType,
        keys::{ArcKeys, ArcOneRttKeys},
        r#type::Type,
        HandshakeHeader, InitialHeader, OneRttPacket, PacketNumber, PacketWrapper, ZeroRttHeader,
    },
    util::ArcAsyncDeque,
};
use qrecovery::{reliable::rcvdpkt::ArcRcvdPktRecords, space::SpaceFrame};
use tokio::sync::mpsc;

use crate::path::ArcPath;

pub(crate) struct PacketPayload {
    pub pn: u64,
    pub payload: Bytes,
    pub r#type: Type,
    pub path: ArcPath,
}

impl PacketPayload {
    pub fn dispatch(
        self,
        conn_frame_queue: Option<&ArcAsyncDeque<ConnFrame>>,
        space_frame_queue: Option<&ArcAsyncDeque<SpaceFrame>>,
        datagram_frame_queue: Option<&ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        ack_frames_tx: &mpsc::UnboundedSender<AckFrame>,
    ) -> Result<bool, Error> {
        let packet = self;
        let mut space_frame_writer = space_frame_queue.map(ArcAsyncDeque::writer);
        let mut conn_frame_writer = conn_frame_queue.map(ArcAsyncDeque::writer);
        let mut datagram_frame_writer = datagram_frame_queue.map(ArcAsyncDeque::writer);
        // let mut path_frame_writer = path.frames().writer();

        FrameReader::new(packet.payload)
            .try_fold(false, |is_ack_eliciting, frame| {
                let frame = frame.map_err(Error::from)?;
                if !frame.belongs_to(packet.r#type) {
                    return Err(Error::new(
                        ErrorKind::ProtocolViolation,
                        frame.frame_type(),
                        format!("cann't exist in {:?}", packet.r#type),
                    ));
                }
                match frame {
                    Frame::Pure(PureFrame::Padding(_)) => Ok(is_ack_eliciting),
                    Frame::Pure(PureFrame::Ping(_)) => Ok(true),
                    Frame::Pure(PureFrame::Ack(ack)) => {
                        _ = ack_frames_tx.send(ack);
                        Ok(is_ack_eliciting)
                    }
                    Frame::Pure(PureFrame::Conn(conn)) => {
                        let Some(conn_frame_writer) = conn_frame_writer.as_mut() else {
                            unreachable!()
                        };
                        conn_frame_writer.push(conn);
                        Ok(true)
                    }
                    Frame::Pure(PureFrame::Stream(stream)) => {
                        let Some(space_frame_writer) = space_frame_writer.as_mut() else {
                            unreachable!()
                        };
                        space_frame_writer.push(SpaceFrame::Stream(stream));
                        Ok(true)
                    }
                    Frame::Pure(PureFrame::Path(frame)) => {
                        match frame {
                            PathFrame::Challenge(challenge) => {
                                // Save the challenge frame in the path, you need
                                // check whether a response frame needs to be sent
                                // when sending the packet.
                                packet.path.on_recv_path_challenge(challenge)
                            }
                            PathFrame::Response(response) => {
                                // Check whether the path response frame is consistent
                                // with the path challenge frame
                                packet.path.on_recv_path_challenge_response(response);
                            }
                        }
                        Ok(true)
                    }
                    Frame::Data(data_frame, data) => {
                        let Some(space_frame_writer) = space_frame_writer.as_mut() else {
                            unreachable!()
                        };
                        space_frame_writer.push(SpaceFrame::Data(data_frame, data));
                        Ok(true)
                    }
                    Frame::Datagram(datagram, data) => {
                        let Some(datagram_frame_writer) = datagram_frame_writer.as_mut() else {
                            unreachable!()
                        };
                        datagram_frame_writer.push((datagram, data));
                        Ok(true)
                    }
                }
            })
            .inspect_err(|_error| {
                if let Some(mut conn_frame_writer) = conn_frame_writer {
                    conn_frame_writer.rollback();
                };
                if let Some(mut space_frame_writer) = space_frame_writer {
                    space_frame_writer.rollback();
                };
                if let Some(mut datagram_frame_writer) = datagram_frame_writer {
                    datagram_frame_writer.rollback();
                }
            })
    }
}

pub(crate) struct LongHeaderPacketStream<H> {
    packet_rx: mpsc::UnboundedReceiver<(PacketWrapper<H>, ArcPath)>,
    keys: ArcKeys,
    rcvd_pkt_records: ArcRcvdPktRecords,
}

pub(crate) type InitialPacketStream = LongHeaderPacketStream<InitialHeader>;
pub(crate) type HandshakePacketStream = LongHeaderPacketStream<HandshakeHeader>;
pub(crate) type ZeroRttPacketStream = LongHeaderPacketStream<ZeroRttHeader>;

impl<H> Stream for LongHeaderPacketStream<H>
where
    H: GetType,
    PacketWrapper<H>: DecodeHeader<Output = PacketNumber> + DecryptPacket + RemoteProtection,
{
    type Item = PacketPayload;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let f = async {
            let s = self.get_mut();
            let k = s.keys.get_remote_keys().await?;
            loop {
                let (mut packet, path) = s.packet_rx.recv().await?;
                let ok = packet.remove_protection(k.remote.header.deref());

                if !ok {
                    // Failed to remove packet header protection, just discard it.
                    continue;
                }

                let encoded_pn = packet.decode_header().unwrap();

                let Ok(pn) = s.rcvd_pkt_records.decode_pn(encoded_pn) else {
                    // Duplicate packet, discard. QUIC does not allow duplicate packets.
                    // Is it an error to receive duplicate packets? Definitely not,
                    // otherwise it would be too vulnerable to replay attacks.
                    continue;
                };
                let packet_type = packet.header.get_type();
                if let Ok(payload) =
                    packet.decrypt_packet(pn, encoded_pn.size(), k.remote.packet.deref())
                {
                    return Some(PacketPayload {
                        pn,
                        payload,
                        r#type: packet_type,
                        path,
                    });
                }
            }
        };
        pin!(f).poll(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<H> LongHeaderPacketStream<H> {
    pub fn new(
        keys: ArcKeys,
        rcvd_pkt_records: ArcRcvdPktRecords,
    ) -> (mpsc::UnboundedSender<(PacketWrapper<H>, ArcPath)>, Self) {
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        (
            packet_tx,
            Self {
                packet_rx,
                keys,
                rcvd_pkt_records,
            },
        )
    }
}

impl LongHeaderPacketStream<InitialHeader> {
    pub fn spawn_parse_packet_and_then_dispatch(
        mut self,
        conn_frame_queue: Option<ArcAsyncDeque<ConnFrame>>,
        space_frame_queue: Option<ArcAsyncDeque<SpaceFrame>>,
        datagram_frame_queue: Option<ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
        error_tx: mpsc::UnboundedSender<Error>,
    ) {
        tokio::spawn(async move {
            while let Some(payload) = self.next().await {
                let pn = payload.pn;
                match payload.dispatch(
                    conn_frame_queue.as_ref(),
                    space_frame_queue.as_ref(),
                    datagram_frame_queue.as_ref(),
                    &ack_frames_tx,
                ) {
                    // TODO: path也要登记其收到的包、收包时间、is_ack_eliciting，方便激发AckFrame
                    Ok(_is_ack_eliciting) => self.rcvd_pkt_records.register_pn(pn),
                    // 解析包失败，丢弃
                    // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                    Err(error) => {
                        _ = error_tx.send(error);
                    }
                }
            }
        });
    }
}

impl LongHeaderPacketStream<HandshakeHeader> {
    pub fn spawn_parse_packet_and_then_dispatch(
        mut self,
        conn_frame_queue: Option<ArcAsyncDeque<ConnFrame>>,
        space_frame_queue: Option<ArcAsyncDeque<SpaceFrame>>,
        datagram_frame_queue: Option<ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
        error_tx: mpsc::UnboundedSender<Error>,
        mut initial_keys: Option<ArcKeys>,
    ) {
        tokio::spawn(async move {
            while let Some(payload) = self.next().await {
                let pn = payload.pn;
                match payload.dispatch(
                    conn_frame_queue.as_ref(),
                    space_frame_queue.as_ref(),
                    datagram_frame_queue.as_ref(),
                    &ack_frames_tx,
                ) {
                    // TODO: path也要登记其收到的包、收包时间、is_ack_eliciting，方便激发AckFrame
                    Ok(_is_ack_eliciting) => {
                        // a server MUST discard Initial keys when it first successfully processes a
                        // Handshake packet.
                        if let Some(initial_keys) = initial_keys.take() {
                            initial_keys.invalid()
                        }
                        self.rcvd_pkt_records.register_pn(pn)
                    }
                    // 解析包失败，丢弃
                    // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                    Err(error) => {
                        _ = error_tx.send(error);
                    }
                }
            }
        });
    }
}

impl LongHeaderPacketStream<ZeroRttHeader> {
    pub fn spawn_parse_packet_and_then_dispatch(
        mut self,
        conn_frame_queue: Option<ArcAsyncDeque<ConnFrame>>,
        space_frame_queue: Option<ArcAsyncDeque<SpaceFrame>>,
        datagram_frame_queue: Option<ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
        error_tx: mpsc::UnboundedSender<Error>,
    ) {
        tokio::spawn(async move {
            while let Some(payload) = self.next().await {
                let pn = payload.pn;

                // Anti-amplification attack protection, when there is an anti-
                // amplification attack protection, the received data volume
                // will record in the anti-amplification attack protector, if
                // not, no operation will performed
                payload.path.deposit(payload.payload.len());

                match payload.dispatch(
                    conn_frame_queue.as_ref(),
                    space_frame_queue.as_ref(),
                    datagram_frame_queue.as_ref(),
                    &ack_frames_tx,
                ) {
                    // TODO: path也要登记其收到的包、收包时间、is_ack_eliciting，方便激发AckFrame
                    Ok(_is_ack_eliciting) => self.rcvd_pkt_records.register_pn(pn),
                    // 解析包失败，丢弃
                    // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                    Err(error) => {
                        _ = error_tx.send(error);
                    }
                }
            }
        });
    }
}

pub(crate) struct ShortHeaderPacketStream {
    packet_rx: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)>,
    keys: ArcOneRttKeys,
    rcvd_records: ArcRcvdPktRecords,
}

pub(crate) type OneRttPacketStream = ShortHeaderPacketStream;

impl Stream for ShortHeaderPacketStream {
    type Item = PacketPayload;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let f = async {
            let s = self.get_mut();
            let (hk, pk) = s.keys.get_remote_keys().await?;
            loop {
                let (mut packet, path) = s.packet_rx.recv().await?;
                let ok = packet.remove_protection(hk.deref());

                if !ok {
                    // Failed to remove packet header protection, just discard it.
                    continue;
                }

                let (encoded_pn, key_phase) = packet.decode_header().unwrap();
                let pn = match s.rcvd_records.decode_pn(encoded_pn) {
                    Ok(pn) => pn,
                    Err(_) => continue,
                };

                let packet_type = packet.header.get_type();
                let packet_key = pk.lock().unwrap().get_remote(key_phase, pn);
                if let Ok(payload) =
                    packet.decrypt_packet(pn, encoded_pn.size(), packet_key.deref())
                {
                    return Some(PacketPayload {
                        pn,
                        payload,
                        r#type: packet_type,
                        path,
                    });
                }
            }
        };
        pin!(f).poll(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl ShortHeaderPacketStream {
    pub fn new(
        keys: ArcOneRttKeys,
        rcvd_records: ArcRcvdPktRecords,
    ) -> (mpsc::UnboundedSender<(OneRttPacket, ArcPath)>, Self) {
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        (
            packet_tx,
            Self {
                packet_rx,
                keys,
                rcvd_records,
            },
        )
    }

    pub fn spawn_parse_packet_and_then_dispatch(
        mut self,
        conn_frame_queue: Option<ArcAsyncDeque<ConnFrame>>,
        space_frame_queue: Option<ArcAsyncDeque<SpaceFrame>>,
        datagram_frame_queue: Option<ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        ack_frames_tx: mpsc::UnboundedSender<AckFrame>,
        error_tx: mpsc::UnboundedSender<Error>,
    ) {
        tokio::spawn(async move {
            while let Some(payload) = self.next().await {
                let pn = payload.pn;
                match payload.dispatch(
                    conn_frame_queue.as_ref(),
                    space_frame_queue.as_ref(),
                    datagram_frame_queue.as_ref(),
                    &ack_frames_tx,
                ) {
                    // TODO: path也要登记其收到的包、收包时间、is_ack_eliciting，方便激发AckFrame
                    Ok(_is_ack_eliciting) => self.rcvd_records.register_pn(pn),
                    // 解析包失败，丢弃
                    // TODO: 该包要认的话，还得向对方返回错误信息，并终止连接
                    Err(error) => {
                        _ = error_tx.send(error);
                    }
                }
            }
        });
    }
}
