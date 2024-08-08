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
};
use qcongestion::{congestion::ArcCC, CongestionControl};
use qrecovery::space::Epoch;

use super::{
    anti_amplifier::ANTI_FACTOR,
    util::{ApplyConstraints, Constraints},
    ArcAntiAmplifier,
};
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
    fn read_into_datagram(
        &self,
        constraints: &mut Constraints,
        flow_limit: usize,
        datagram: &mut [u8],
        dcid: ConnectionId,
    ) -> (usize, usize) {
        let buffer = datagram.apply(constraints);

        let ack_pkt = self.cc.need_ack(Epoch::Initial);
        // 按顺序发，先发Initial空间的，到Initial数据包
        if let Some((padding, len, is_just_ack)) = self
            .initial_space_reader
            .try_read(buffer, self.scid, dcid, ack_pkt)
        {
            // 若真的只包含ack， 后续只会追加padding，追加的padding也可以看成是新的InitialPacket数据包
            constraints.commit(len, is_just_ack);

            let (wrote, fresh_bytes) = {
                let remain = &mut buffer[len..];
                self.read_other_space(constraints, flow_limit, remain, dcid)
            };

            let padding_len = if wrote == 0 { 1200 } else { 0 };
            let (pn, is_ack_eliciting, is_just_ack, sent_bytes, in_flight, sent_ack) =
                padding(buffer, padding_len);
            self.cc.on_pkt_sent(
                Epoch::Initial,
                pn,
                is_ack_eliciting,
                sent_bytes,
                in_flight,
                sent_ack,
            );
            // 减除initial数据包已经commit的
            constraints.commit(sent_bytes - len, is_just_ack);
            (wrote + sent_bytes, fresh_bytes)
        } else {
            self.read_other_space(constraints, flow_limit, buffer, dcid)
        }
    }

    fn read_other_space(
        &self,
        constraints: &mut Constraints,
        flow_limit: usize,
        mut buffer: &mut [u8],
        dcid: ConnectionId,
    ) -> (usize, usize) {
        // 在发0Rtt数据包，但是0Rtt数据包要看有没有获取到1rtt的密钥o
        let mut written = 0;
        let mut fresh_bytes = 0;
        let one_rtt_keys = self.data_space_reader.one_rtt_keys();
        if one_rtt_keys.is_none() {
            if let Some((pn, is_ack_eliciting, sent_bytes, fresh_len, in_flight)) = self
                .data_space_reader
                .try_read_0rtt(buffer, flow_limit, self.scid, dcid)
            {
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    pn,
                    is_ack_eliciting,
                    sent_bytes,
                    in_flight,
                    None,
                );
                buffer = &mut buffer[sent_bytes..];
                // 0Rtt数据包不会发送Ack
                constraints.commit(sent_bytes, false);
                fresh_bytes += fresh_len;
                written += sent_bytes;
            }
        }

        buffer = buffer.apply(constraints);
        if buffer.is_empty() {
            return (written, fresh_bytes);
        }

        // 再尝试写handshake空间的
        let n = self.read_handshake_space(constraints, buffer, dcid);
        written += n;
        buffer = &mut buffer[n..];
        buffer = buffer.apply(constraints);
        if buffer.is_empty() {
            return (written, fresh_bytes);
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
                fresh_len,
                in_flight,
                sent_ack,
            )) = self
                .data_space_reader
                .try_read_1rtt(buffer, flow_limit, dcid, spin, ack_pkt, keys)
            {
                self.cc.on_pkt_sent(
                    Epoch::Data,
                    pn,
                    is_ack_eliciting,
                    sent_bytes,
                    in_flight,
                    sent_ack,
                );
                constraints.commit(sent_bytes, is_just_ack);
                written += sent_bytes;
                fresh_bytes += fresh_len;
            }
        }

        (written, fresh_bytes)
    }

    fn read_handshake_space(
        &self,
        constraints: &mut Constraints,
        buffer: &mut [u8],
        dcid: ConnectionId,
    ) -> usize {
        // 再尝试写handshake空间的
        let ack_pkt = self.cc.need_ack(Epoch::Handshake);
        if let Some((pn, is_ack_eliciting, is_just_ack, sent_bytes, in_flight, sent_ack)) = self
            .handshake_space_reader
            .try_read(buffer, self.scid, dcid, ack_pkt)
        {
            self.cc.on_pkt_sent(
                Epoch::Handshake,
                pn,
                is_ack_eliciting,
                sent_bytes,
                in_flight,
                sent_ack,
            );
            constraints.commit(sent_bytes, is_just_ack);
            return sent_bytes;
        }
        0
    }
}

impl Future for ReadIntoPacket {
    type Output = Option<Vec<Vec<u8>>>;

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
        let mut constraints = Constraints::new(credit_limit, send_quota);

        // 遍历，填充每一个包
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        let mut total_bytes = 0;
        let mut total_fresh_bytes = 0;
        while constraints.is_available() {
            let mut datagram = Vec::with_capacity(1200);

            let (datagram_size, fresh_bytes) =
                self.read_into_datagram(&mut constraints, flow_limit, datagram.as_mut(), dcid);

            // 啥也没读到，就结束吧
            // TODO: 若因没有数据可发，将waker挂载到数据控制器上一份，包括帧数据、流数据，
            //       一旦有任何数据发送，唤醒该任务发一次
            if datagram_size == 0 {
                break;
            }

            unsafe {
                datagram.set_len(datagram_size);
            }
            datagrams.push(datagram);
            total_bytes += datagram_size;
            total_fresh_bytes += fresh_bytes;
        }

        // 最终将要发送前，反馈给各个限制条件。除了拥塞控制的，在每个Epoch发包后，都已直接反馈给cc过了
        self.anti_amplifier.on_sent(total_bytes);
        send_flow_credit.post_sent(total_fresh_bytes);

        if datagrams.is_empty() {
            // 就算Constraints允许发送，但也不一定真的有数据供发送
            Poll::Pending
        } else {
            // 返回这个后，datagrams肯定等着被发送了
            Poll::Ready(Some(datagrams))
        }
    }
}
