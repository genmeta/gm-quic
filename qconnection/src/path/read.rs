use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use bytes::BufMut;
use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::ArcSendControler,
    packet::SpinBit,
    util::Constraints,
};
use qcongestion::{congestion::ArcCC, CongestionControl};
use qrecovery::{space::Epoch, streams::data};

use super::{anti_amplifier::ANTI_FACTOR, ArcAntiAmplifier};
use crate::connection::transmit::{
    data::DataSpaceReader, handshake::HandshakeSpaceReader, initial::InitialSpaceReader,
};

pub struct ReadIntoPacket {
    scid: ConnectionId,
    dcid: ArcCidCell,
    spin: Arc<AtomicBool>,
    cc: ArcCC,
    anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    send_flow_ctrl: ArcSendControler,
    initial_space_reader: InitialSpaceReader,
    handshake_space_reader: HandshakeSpaceReader,
    data_space_reader: DataSpaceReader,
}

impl ReadIntoPacket {
    fn read_datagram(
        &self,
        constraints: &mut Constraints,
        datagram: &mut [u8],
        dcid: ConnectionId,
    ) -> usize {
        let datagram_len = datagram.len();
        let mut remain = &mut datagram[..];

        let ack_pkt = self.cc.need_ack(Epoch::Initial);
        // 按顺序发，先发Initial空间的，到Initial数据包
        if let Some((pn, is_ack_eliciting, sent_bytes, in_flight, sent_ack)) = self
            .initial_space_reader
            .try_read(constraints, remain, self.scid, dcid, ack_pkt)
        {
            self.cc.on_pkt_sent(
                Epoch::Initial,
                pn,
                is_ack_eliciting,
                sent_bytes,
                in_flight,
                sent_ack,
            );
            remain = &mut datagram[sent_bytes..];
            // TODO: 还要判定，constraints有没有用完
            if remain.is_empty() {
                return datagram_len;
            }
        }

        // 在发0Rtt数据包，但是0Rtt数据包要看有没有获取到1rtt的密钥o
        let one_rtt_keys = self.data_space_reader.one_rtt_keys();
        if one_rtt_keys.is_none() {
            if let Some((pn, is_ack_eliciting, sent_bytes, in_flight)) = self
                .data_space_reader
                .try_read_0rtt(constraints, remain, self.scid, dcid)
            {
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    pn,
                    is_ack_eliciting,
                    sent_bytes,
                    in_flight,
                    None,
                );
                remain = &mut remain[sent_bytes..];
                // TODO: 还要判定，constraints有没有用完
                if remain.is_empty() {
                    return datagram_len;
                }
            }
        }

        // 再尝试写handshake空间的
        let ack_pkt = self.cc.need_ack(Epoch::Handshake);
        if let Some((pn, is_ack_eliciting, sent_bytes, in_flight, sent_ack)) = self
            .handshake_space_reader
            .try_read(constraints, remain, self.scid, dcid, ack_pkt)
        {
            self.cc.on_pkt_sent(
                Epoch::Handshake,
                pn,
                is_ack_eliciting,
                sent_bytes,
                in_flight,
                sent_ack,
            );
            remain = &mut remain[sent_bytes..];
            // TODO: 还要判定，constraints有没有用完
            if remain.is_empty() {
                return datagram_len;
            }
        }

        // 最后尝试写1rtt数据包
        if let Some(keys) = one_rtt_keys {
            let ack_pkt = self.cc.need_ack(Epoch::Data);
            let spin = self.spin.load(Ordering::Relaxed);
            let spin = SpinBit::from(spin);
            if let Some((pn, is_ack_eliciting, sent_bytes, in_flight, sent_ack)) = self
                .data_space_reader
                .read_1rtt(constraints, remain, dcid, spin, ack_pkt, keys)
            {
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    pn,
                    is_ack_eliciting,
                    sent_bytes,
                    in_flight,
                    sent_ack,
                );
                remain = &mut remain[sent_bytes..];
            }
        }
        datagram_len - remain.len()
    }
}

impl Future for ReadIntoPacket {
    type Output = Option<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let dcid = ready!(self.dcid.poll_get_cid(cx));
        let congestion_ctrl_balance = ready!(self.cc.poll_send(cx));
        let anti_amplification_balance = ready!(self.anti_amplifier.poll_balance(cx));
        let Some(send_flow_credit) = self.send_flow_ctrl.credit().ok() else {
            // 返回None，表示结束
            return Poll::Ready(None);
        };
        let send_flow_balance = send_flow_credit.available();

        let mut constraints = Constraints::new(
            anti_amplification_balance,
            congestion_ctrl_balance,
            send_flow_balance,
        );
        // 可能这次发送，会发送很多包，直到constraints浪费完，或者没什么数据可发
        Poll::Pending
    }
}
