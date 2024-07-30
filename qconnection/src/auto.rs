#![allow(clippy::too_many_arguments)]

use std::{
    ops::Deref,
    pin::{pin, Pin},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{channel::mpsc, Future, Stream, StreamExt};
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
use qrecovery::{reliable::rcvdpkt::ArcRcvdPktRecords, space::Epoch};

use crate::path::ArcPath;

pub(crate) struct PacketPayload {
    pub pn: u64,
    pub payload: Bytes,
    pub r#type: Type,
    pub path: ArcPath,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConnIdFrame {
    NewConnectionId(NewConnectionIdFrame),
    RetireConnectionId(RetireConnectionIdFrame),
}

impl PacketPayload {
    fn generic_dispatch(
        self,
        conn_id_frame_queue: Option<&ArcAsyncDeque<ConnIdFrame>>,
        token_frame_queue: Option<&ArcAsyncDeque<NewTokenFrame>>,
        datagram_frame_queue: Option<&ArcAsyncDeque<(DatagramFrame, Bytes)>>,
        max_data_frame_queue: Option<&ArcAsyncDeque<MaxDataFrame>>,
        hs_done_frame_queue: Option<&ArcAsyncDeque<HandshakeDoneFrame>>,
        stream_frame_queue: Option<&ArcAsyncDeque<(StreamFrame, Bytes)>>,
        stream_ctl_frame_queue: Option<&ArcAsyncDeque<StreamCtlFrame>>,
        crypto_frame_queue: Option<&ArcAsyncDeque<(CryptoFrame, Bytes)>>,
        close_frame_queue: Option<&ArcAsyncDeque<ConnectionCloseFrame>>,
        ack_frame_queue: Option<&ArcAsyncDeque<AckFrame>>,
    ) -> Result<bool, Error> {
        let packet = self;
        let mut conn_id_frame_writer = conn_id_frame_queue.map(ArcAsyncDeque::writer);
        let mut token_frame_writer = token_frame_queue.map(ArcAsyncDeque::writer);
        let mut datagram_frame_writer = datagram_frame_queue.map(ArcAsyncDeque::writer);
        let mut max_data_frame_writer = max_data_frame_queue.map(ArcAsyncDeque::writer);
        let mut hs_done_frame_writer = hs_done_frame_queue.map(ArcAsyncDeque::writer);
        let mut stream_frame_writer = stream_frame_queue.map(ArcAsyncDeque::writer);
        let mut stream_ctl_frame_writer = stream_ctl_frame_queue.map(ArcAsyncDeque::writer);
        let mut crypto_frame_writer = crypto_frame_queue.map(ArcAsyncDeque::writer);
        let mut close_frame_writer = close_frame_queue.map(ArcAsyncDeque::writer);
        let mut ack_frame_writer = ack_frame_queue.map(ArcAsyncDeque::writer);
        // let mut path_frame_writer = path.frames().writer();

        let mut ack_frames = Vec::new();
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
                        let Some(ack_frame_writer) = ack_frame_writer.as_mut() else {
                            return Ok(is_ack_eliciting);
                        };
                        // rollback may occur if an error occurs
                        ack_frames.push(ack.clone());
                        ack_frame_writer.push(ack);
                        Ok(is_ack_eliciting)
                    }
                    Frame::Pure(PureFrame::Conn(conn)) => {
                        match conn {
                            ConnFrame::Close(ccf) => {
                                let Some(close_frame_writer) = close_frame_writer.as_mut() else {
                                    return Ok(true);
                                };
                                close_frame_writer.push(ccf)
                            }
                            ConnFrame::NewToken(token) => {
                                let Some(token_frame_writer) = token_frame_writer.as_mut() else {
                                    return Ok(true);
                                };
                                token_frame_writer.push(token);
                            }
                            ConnFrame::MaxData(max_data) => {
                                let Some(max_data_frame_queue) = max_data_frame_writer.as_mut()
                                else {
                                    return Ok(true);
                                };
                                max_data_frame_queue.push(max_data);
                            }
                            ConnFrame::NewConnectionId(new) => {
                                let Some(conn_id_frame_writer) = conn_id_frame_writer.as_mut()
                                else {
                                    return Ok(true);
                                };
                                conn_id_frame_writer.push(ConnIdFrame::NewConnectionId(new));
                            }
                            ConnFrame::RetireConnectionId(retire) => {
                                let Some(conn_id_frame_writer) = conn_id_frame_writer.as_mut()
                                else {
                                    return Ok(true);
                                };
                                conn_id_frame_writer.push(ConnIdFrame::RetireConnectionId(retire));
                            }
                            ConnFrame::HandshakeDone(done) => {
                                let Some(handshake_done_frame_writer) =
                                    hs_done_frame_writer.as_mut()
                                else {
                                    return Ok(true);
                                };
                                handshake_done_frame_writer.push(done);
                            }
                            ConnFrame::DataBlocked(_) => { /* ignore */ }
                        }
                        Ok(true)
                    }
                    Frame::Pure(PureFrame::Stream(stream)) => {
                        let Some(stream_ctl_frame_writer) = stream_ctl_frame_writer.as_mut() else {
                            return Ok(true);
                        };
                        stream_ctl_frame_writer.push(stream);
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
                    Frame::Data(DataFrame::Stream(stream), data) => {
                        let Some(stream_frame_writer) = stream_frame_writer.as_mut() else {
                            return Ok(true);
                        };
                        stream_frame_writer.push((stream, data));
                        Ok(true)
                    }
                    Frame::Data(DataFrame::Crypto(crypto), data) => {
                        let Some(crypto_frame_writer) = crypto_frame_writer.as_mut() else {
                            return Ok(true);
                        };
                        crypto_frame_writer.push((crypto, data));
                        Ok(true)
                    }
                    Frame::Datagram(datagram, data) => {
                        let Some(datagram_frame_writer) = datagram_frame_writer.as_mut() else {
                            return Ok(true);
                        };
                        datagram_frame_writer.push((datagram, data));
                        Ok(true)
                    }
                }
            })
            .inspect_err(|_error| {
                if let Some(mut writer) = conn_id_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = token_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = datagram_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = max_data_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = hs_done_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = stream_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = stream_ctl_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = crypto_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = close_frame_writer {
                    writer.rollback();
                }
                if let Some(mut writer) = ack_frame_writer {
                    writer.rollback();
                }
            })
            .inspect(|_| {
                use qbase::packet::r#type::long;
                let epoch = match packet.r#type {
                    Type::Long(long::Type::V1(long::Version::INITIAL)) => Epoch::Initial,
                    Type::Long(long::Type::V1(long::Version::HANDSHAKE)) => Epoch::Handshake,
                    Type::Long(long::Type::V1(long::Version::ZERO_RTT)) | Type::Short(_) => {
                        Epoch::Data
                    }
                    _ => unreachable!(),
                };
                for ack in ack_frames {
                    packet.path.on_ack(epoch, &ack);
                }
            })
    }

    pub fn dispatch_initial_space(
        self,
        crypto_frame_queue: &ArcAsyncDeque<(CryptoFrame, Bytes)>,
        close_frame_queue: &ArcAsyncDeque<ConnectionCloseFrame>,
        ack_frame_queue: &ArcAsyncDeque<AckFrame>,
    ) -> Result<bool, Error> {
        self.generic_dispatch(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(crypto_frame_queue),
            Some(close_frame_queue),
            Some(ack_frame_queue),
        )
    }

    pub fn dispatch_handshake_space(
        self,
        crypto_frame_queue: &ArcAsyncDeque<(CryptoFrame, Bytes)>,
        close_frame_queue: &ArcAsyncDeque<ConnectionCloseFrame>,
        ack_frame_queue: &ArcAsyncDeque<AckFrame>,
    ) -> Result<bool, Error> {
        self.dispatch_initial_space(crypto_frame_queue, close_frame_queue, ack_frame_queue)
    }

    pub fn dispatch_zero_rtt(
        self,
        datagram_frame_queue: &ArcAsyncDeque<(DatagramFrame, Bytes)>,
        max_data_frame_queue: &ArcAsyncDeque<MaxDataFrame>,
        stream_frame_queue: &ArcAsyncDeque<(StreamFrame, Bytes)>,
        stream_ctl_frame_queue: &ArcAsyncDeque<StreamCtlFrame>,
        close_frame_queue: &ArcAsyncDeque<ConnectionCloseFrame>,
    ) -> Result<bool, Error> {
        self.generic_dispatch(
            None,
            None,
            Some(datagram_frame_queue),
            Some(max_data_frame_queue),
            None,
            Some(stream_frame_queue),
            Some(stream_ctl_frame_queue),
            None,
            Some(close_frame_queue),
            None,
        )
    }

    pub fn dispatch_one_rtt(
        self,
        conn_id_frame_queue: &ArcAsyncDeque<ConnIdFrame>,
        token_frame_queue: &ArcAsyncDeque<NewTokenFrame>,
        datagram_frame_queue: &ArcAsyncDeque<(DatagramFrame, Bytes)>,
        max_data_frame_queue: &ArcAsyncDeque<MaxDataFrame>,
        hs_done_frame_queue: &ArcAsyncDeque<HandshakeDoneFrame>,
        stream_frame_queue: &ArcAsyncDeque<(StreamFrame, Bytes)>,
        stream_ctl_frame_queue: &ArcAsyncDeque<StreamCtlFrame>,
        crypto_frame_queue: &ArcAsyncDeque<(CryptoFrame, Bytes)>,
        close_frame_queue: &ArcAsyncDeque<ConnectionCloseFrame>,
        ack_frame_queue: &ArcAsyncDeque<AckFrame>,
    ) -> Result<bool, Error> {
        self.generic_dispatch(
            Some(conn_id_frame_queue),
            Some(token_frame_queue),
            Some(datagram_frame_queue),
            Some(max_data_frame_queue),
            Some(hs_done_frame_queue),
            Some(stream_frame_queue),
            Some(stream_ctl_frame_queue),
            Some(crypto_frame_queue),
            Some(close_frame_queue),
            Some(ack_frame_queue),
        )
    }

    pub fn dispatch_closing(
        self,
        close_frame_queue: &ArcAsyncDeque<ConnectionCloseFrame>,
    ) -> Result<bool, Error> {
        self.generic_dispatch(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(close_frame_queue),
            None,
        )
    }
}

pub(crate) struct LongHeaderPacketStream<H> {
    pub packet_rx: mpsc::UnboundedReceiver<(PacketWrapper<H>, ArcPath)>,
    pub keys: ArcKeys,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
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
                let (mut packet, path) = s.packet_rx.next().await?;
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
        packet_rx: mpsc::UnboundedReceiver<(PacketWrapper<H>, ArcPath)>,
        keys: ArcKeys,
        rcvd_pkt_records: ArcRcvdPktRecords,
    ) -> Self {
        Self {
            packet_rx,
            keys,
            rcvd_pkt_records,
        }
    }
}

pub(crate) struct ShortHeaderPacketStream {
    packet_rx: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)>,
    keys: ArcOneRttKeys,
    pub rcvd_pkt_records: ArcRcvdPktRecords,
}

pub(crate) type OneRttPacketStream = ShortHeaderPacketStream;

impl Stream for ShortHeaderPacketStream {
    type Item = PacketPayload;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let f = async {
            let s = self.get_mut();
            let (hk, pk) = s.keys.get_remote_keys().await?;
            loop {
                let (mut packet, path) = s.packet_rx.next().await?;
                let ok = packet.remove_protection(hk.deref());

                if !ok {
                    // Failed to remove packet header protection, just discard it.
                    continue;
                }

                let (encoded_pn, key_phase) = packet.decode_header().unwrap();
                let pn = match s.rcvd_pkt_records.decode_pn(encoded_pn) {
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
        packet_rx: mpsc::UnboundedReceiver<(OneRttPacket, ArcPath)>,
        keys: ArcOneRttKeys,
        rcvd_pkt_records: ArcRcvdPktRecords,
    ) -> Self {
        Self {
            packet_rx,
            keys,
            rcvd_pkt_records,
        }
    }
}
