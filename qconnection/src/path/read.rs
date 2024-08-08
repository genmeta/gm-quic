use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::ArcSendControler,
    packet::SpinBit,
    util::{ApplyConstraints, Constraints},
};
use qcongestion::{congestion::ArcCC, CongestionControl};
use qrecovery::space::Epoch;

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
        flow_limit: usize,
        datagram: &mut [u8],
        dcid: ConnectionId,
    ) -> (usize, usize) {
        let datagram_len = datagram.len();
        let mut remain = datagram.apply(constraints);

        let ack_pkt = self.cc.need_ack(Epoch::Initial);
        // 按顺序发，先发Initial空间的，到Initial数据包
        if let Some((pn, is_ack_eliciting, is_just_ack, sent_bytes, in_flight, sent_ack)) = self
            .initial_space_reader
            .try_read(remain, self.scid, dcid, ack_pkt)
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
            constraints.commit(sent_bytes, is_just_ack);
        }

        remain = remain.apply(constraints);
        if remain.is_empty() {
            return (datagram_len, 0);
        }

        // 在发0Rtt数据包，但是0Rtt数据包要看有没有获取到1rtt的密钥o
        let mut fresh_data_len = 0;
        let one_rtt_keys = self.data_space_reader.one_rtt_keys();
        if one_rtt_keys.is_none() {
            if let Some((pn, is_ack_eliciting, sent_bytes, fresh_bytes, in_flight)) = self
                .data_space_reader
                .try_read_0rtt(remain, flow_limit, self.scid, dcid)
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
                // 0Rtt数据包不会发送Ack
                constraints.commit(sent_bytes, false);
                fresh_data_len += fresh_bytes;
            }
        }

        remain = remain.apply(constraints);
        if remain.is_empty() {
            return (datagram_len, fresh_data_len);
        }

        // 再尝试写handshake空间的
        let ack_pkt = self.cc.need_ack(Epoch::Handshake);
        if let Some((pn, is_ack_eliciting, is_just_ack, sent_bytes, in_flight, sent_ack)) = self
            .handshake_space_reader
            .try_read(remain, self.scid, dcid, ack_pkt)
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
            constraints.commit(sent_bytes, is_just_ack);
        }

        remain = remain.apply(constraints);
        if remain.is_empty() {
            return (datagram_len, fresh_data_len);
        }

        // 最后尝试写1rtt数据包
        if let Some(keys) = one_rtt_keys {
            let ack_pkt = self.cc.need_ack(Epoch::Data);
            let spin = self.spin.load(Ordering::Relaxed);
            let spin = SpinBit::from(spin);
            if let Some((
                pn,
                is_ack_eliciting,
                is_just_ack,
                sent_bytes,
                fresh_bytes,
                in_flight,
                sent_ack,
            )) = self
                .data_space_reader
                .try_read_1rtt(remain, flow_limit, dcid, spin, ack_pkt, keys)
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
                constraints.commit(sent_bytes, is_just_ack);
                fresh_data_len += fresh_bytes;
            }
        }
        (datagram_len - remain.len(), fresh_data_len)
    }
}

impl Future for ReadIntoPacket {
    type Output = Option<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let dcid = ready!(self.dcid.poll_get_cid(cx));
        let send_quota = ready!(self.cc.poll_send(cx));
        let credit_limit = ready!(self.anti_amplifier.poll_balance(cx));
        let Some(credit_limit) = credit_limit else {
            return Poll::Pending;
        };
        // 流量控制，受控于对方允许的最大数据，不得超过
        // 作用于新数据，Stream帧中的新数据
        // 当流量限制为0的时候，仍然可以发送Stream中的旧数据，以及其他帧
        // WARN: 流量控制提供指引到最终反馈时，不可解锁，否则其他发送任务会共享流量限制，导致流量限制失效
        let Some(send_flow_credit) = self.send_flow_ctrl.credit().ok() else {
            // 返回None，表示结束
            return Poll::Ready(None);
        };
        let flow_limit = send_flow_credit.available();

        let mut datagram = [0u8; 1500];
        let datagram = &mut datagram[..];
        let mut constraints = Constraints::new(credit_limit, send_quota);
        let (datagram_size, fresh_bytes) =
            self.read_datagram(&mut constraints, flow_limit, datagram, dcid);

        self.anti_amplifier.on_sent(datagram_size);
        send_flow_credit.post_sent(fresh_bytes);
        Poll::Pending
    }
}
