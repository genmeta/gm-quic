use std::{
    io::IoSlice,
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
use qcongestion::{
    congestion::{ArcCC, MSS},
    CongestionControl,
};
use qrecovery::{reliable::ArcReliableFrameDeque, space::Epoch};

use super::{
    anti_amplifier::ANTI_FACTOR,
    util::{ApplyConstraints, Constraints},
    ArcAntiAmplifier,
};
use crate::connection::transmit::{
    data::DataSpaceReader, handshake::HandshakeSpaceReader, initial::InitialSpaceReader,
};

pub struct ReadIntoDatagrams {
    pub(super) scid: ConnectionId,
    pub(super) dcid: ArcCidCell<ArcReliableFrameDeque>,
    pub(super) spin: Arc<AtomicBool>,
    pub(super) cc: ArcCC,
    pub(super) anti_amplifier: ArcAntiAmplifier<ANTI_FACTOR>,
    pub(super) send_flow_ctrl: ArcSendControler,
    pub(super) initial_space_reader: InitialSpaceReader,
    pub(super) handshake_space_reader: HandshakeSpaceReader,
    pub(super) data_space_reader: DataSpaceReader,
}

impl ReadIntoDatagrams {
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

    pub fn poll_read(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut Vec<[u8; MSS]>,
    ) -> Poll<Option<(usize, usize)>> {
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

        let mut total_bytes = 0;
        let mut total_fresh_bytes = 0;

        let mut buffers_used = 0;
        let mut last_buffer_written = 0;

        while constraints.is_available() {
            let datagarm = match buffers.get_mut(buffers_used) {
                Some(buffer) => buffer,
                None => {
                    buffers.push([0; MSS]);
                    &mut buffers[buffers_used]
                }
            };

            let (datagram_size, fresh_bytes) =
                self.read_into_datagram(&mut constraints, flow_limit, datagarm, dcid);
            // 啥也没读到，就结束吧
            // TODO: 若因没有数据可发，将waker挂载到数据控制器上一份，包括帧数据、流数据，
            //       一旦有任何数据发送，唤醒该任务发一次
            if datagram_size == 0 {
                break;
            }

            total_bytes += datagram_size;
            total_fresh_bytes += fresh_bytes;
            buffers_used += 1;
            last_buffer_written = datagram_size;
        }

        if buffers_used == 0 {
            // 就算Constraints允许发送，但也不一定真的有数据供发送
            return Poll::Pending;
        }

        // 最终将要发送前，反馈给各个限制条件。除了拥塞控制的，在每个Epoch发包后，都已直接反馈给cc过了
        self.anti_amplifier.on_sent(total_bytes);
        send_flow_credit.post_sent(total_fresh_bytes);
        // 返回这个后，datagrams肯定等着被发送了
        Poll::Ready(Some((buffers_used, last_buffer_written)))
    }

    pub async fn read<'ds>(&self, buffers: &'ds mut Vec<[u8; MSS]>) -> Option<Vec<IoSlice<'ds>>> {
        // 直接让poll_read_into_packet返回Vec<IoSlice<'ds>>会带来问题
        // 所以这里就让poll返回生成Vec<IoSlice<'ds>>所需要的数据。虽然会导致poll_read_into_packet的返回和这里的返回不一致

        // 如果是别的写法，比如为一个包装了buffer和Reader的结构体实现Future，在poll方法内，通过self.buffer拿到buffer会让'ds周期协变，小于'ds
        // 协变的问题可以通过在buffer上包装一个Option来解决，使用时将buffer take出来，这样buffer的生命周期绕过了Pin<&mut Self>，得到的buffer具有'ds周期
        // 但是，如果poll_read_into_packet返回Vec<IoSlice<'ds>>返回了Pending，此时需要将buffer返还到Option中
        // rust借用检查器不够智能，认为Poll::Pending借用了buffer，所以无法将buffer归还回Option中
        // 这个问题可以通过让poll_read_into_packet_inner返回Result<Vec<IoSlice<'ds>>, &'ds mut Vec<[u8; MSS]>>>来解决，Err对应Pending
        // 但是但是这个是在太过于诡异，太过于不直观，所以这里就不这么做了

        let (buffers_used, last_buffer_written) =
        // 对于这种写法，如果返回Vec<IoSlice<'ds>>，会受制于FnMut的捕获机制，buffer的周期会因为捕获而协变，和上一个方案的第一个问题是一致的     
            core::future::poll_fn(|cx| self.poll_read(cx, buffers)).await?;

        debug_assert!(buffers_used > 0);
        let datagrams = (0..buffers_used - 1)
            .map(|i| IoSlice::new(&buffers[i]))
            .chain(Some(IoSlice::new(
                &buffers[buffers_used - 1][..last_buffer_written],
            )))
            .collect::<Vec<_>>();
        Some(datagrams)
    }
}
