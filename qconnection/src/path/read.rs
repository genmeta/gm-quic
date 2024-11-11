use std::{
    io::IoSlice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use qbase::{
    cid::{ArcCidCell, ConnectionId},
    flow::ArcSendControler,
    packet::SpinBit,
    Epoch,
};
use qcongestion::{ArcCC, CongestionControl, MSS};
use qrecovery::reliable::ArcReliableFrameDeque;

use super::{
    anti_amplifier::ANTI_FACTOR,
    util::{ApplyConstraints, Constraints},
    ArcAntiAmplifier,
};
use crate::conn::transmit::*;

/// The structure that reads data to be sent into datagrams.
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
        let send_quota = buffer.len();

        let ack_pkt = self.cc.need_ack(Epoch::Initial);
        // 按顺序发，先发Initial空间的，到Initial数据包
        if let Some((padding, len, in_flight)) = self
            .initial_space_reader
            .try_read(buffer, self.scid, dcid, ack_pkt)
        {
            // 若真的只包含ack， 后续只会追加padding，追加的padding也可以看成是新的InitialPacket数据包
            constraints.commit(len, in_flight);

            let (wrote, fresh_bytes) = {
                let remain = &mut buffer[len..];
                self.read_other_space(constraints, flow_limit, remain, dcid)
            };

            let padding_len = if wrote == 0 { MSS.min(send_quota) } else { 0 };
            let (pn, is_ack_eliciting, sent_bytes, in_flight, sent_ack) =
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
            constraints.commit(sent_bytes - len, in_flight);
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
            if let Some((pn, is_ack_eliciting, sent_bytes, fresh_len, in_flight, sent_ack)) = self
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
                constraints.commit(sent_bytes, in_flight);
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
        if let Some((pn, is_ack_eliciting, sent_bytes, in_flight, sent_ack)) = self
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
            constraints.commit(sent_bytes, in_flight);
            return sent_bytes;
        }
        0
    }

    fn poll_read_inner(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut Vec<[u8; MSS]>,
    ) -> Poll<Option<(usize, usize)>> {
        let send_quota = core::task::ready!(self.cc.poll_send(cx));
        let Some(dcid) = core::task::ready!(self.dcid.poll_borrow_cid(cx)) else {
            return Poll::Ready(None);
        };
        let Some(credit_limit) = core::task::ready!(self.anti_amplifier.poll_balance(cx)) else {
            return Poll::Ready(None);
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
            let datagram = match buffers.get_mut(buffers_used) {
                Some(buffer) => buffer,
                None => {
                    buffers.push([0; MSS]);
                    &mut buffers[buffers_used]
                }
            };

            let (datagram_size, fresh_bytes) =
                self.read_into_datagram(&mut constraints, flow_limit, datagram, *dcid);
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

            // 本数据报尚未被填满，如果本数据报包含一个1rtt数据包，在“后面填充padding”是不行的，因为那些padding会被认为是1rtt的一部分
            // 就会导致发送出的数据包无法被对端解析，所以这里直接break掉
            if datagram_size < MSS {
                break;
            }
        }

        if buffers_used == 0 {
            // 就算Constraints允许发送，但也不一定真的有数据供发送
            return Poll::Pending;
        }

        // dcid被Drop时自动将dcid的借用归还，可能会触发淘汰dcid
        // self.dcid.return_back();
        // 最终将要发送前，反馈给各个限制条件。除了拥塞控制的，在每个Epoch发包后，都已直接反馈给cc过了
        self.anti_amplifier.on_sent(total_bytes);
        send_flow_credit.post_sent(total_fresh_bytes);
        // 返回这个后，datagrams肯定等着被发送了
        Poll::Ready(Some((buffers_used, last_buffer_written)))
    }

    /// Read data into the given buffers, and return the UDP datagrams that will be sent.
    ///
    /// `buffers` is a vector of buffers, each buffer is a fixed-size([`MSS`]) array of bytes. Each time this function
    /// is called, it will try to read data into these `buffers`, the old data in the buffers will be overwritten.
    ///
    /// This method will read the frame to be sent and assemble the data packet in the order of initial, 0-rtt, handshake,
    /// 1-rtt. It will try to read as much data as possible in one call. If the `buffers` are not enough to hold all the
    /// data, the `buffers` will be automatically extended.     
    ///
    /// Although the data packet to be sent is actually read into the given `buffers`, you should not sent them. You should
    /// sent the returned [`Vec<IoSlice>`], it borrows the `buffers`. The reason for returning a vector is to take advantage
    /// of GSO features. Each [`IoSlice`] in it is a complete datagram contains quic packet(s).
    ///
    /// Returned [`IoSlice`]s can be sent separately, but it is best to use the method provided by [`qudp`] to send in
    /// batches using GSO(if supported).[`ArcUsc`] is a wrapper around the [`qudp::UdpSocketController`]. It also provides
    /// a [`method`] to send all the datagrams.
    ///
    /// In order to take advantage of GSO, the return value is a vector of [`IoSlice`], except for the last [`IoSlice`],
    /// the length of other [`IoSlice`]s must be [`MSS`].
    ///
    /// This is a async method, if there are no data to be sent, the call will be blocked.
    ///
    /// Once the path become inactive, [`None`] will be returned, this means the path will not be used to send data anymore.
    ///
    /// [`ArcUsc`]: crate::usc::ArcUsc
    /// [`method`]: crate::usc::ArcUsc::send_all_via_pathway
    pub async fn read<'ds>(&self, buffers: &'ds mut Vec<[u8; MSS]>) -> Option<Vec<IoSlice<'ds>>> {
        let (buffers_used, last_buffer_written) =
            core::future::poll_fn(|cx| self.poll_read_inner(cx, buffers)).await?;

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
