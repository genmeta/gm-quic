use std::time::Instant;

use qbase::{
    cid::ConnectionId,
    packet::{
        keys::ArcKeys,
        writer::{CompletePacket, HandshakePacketWriter},
        LongHeaderBuilder,
    },
};
use qrecovery::{crypto::CryptoStreamOutgoing, journal::HandshakeJournal};

#[derive(Clone)]
pub struct HandshakeSpaceReader {
    pub(crate) keys: ArcKeys,
    pub(crate) journal: HandshakeJournal,
    pub(crate) crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl HandshakeSpaceReader {
    pub fn try_read(
        &self,
        buf: &mut [u8],
        scid: ConnectionId,
        dcid: ConnectionId,
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(CompletePacket, Option<u64>)> {
        // 1. 判定keys是否有效，无效或者尚未拿到，直接返回
        let k = self.keys.get_local_keys()?;
        let pk = k.local.packet.as_ref();
        let hpk = k.local.header.as_ref();

        // 2. 生成包头，预留2字节len，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).handshake();

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_journal = self.journal.sent();
        let mut journal_guard = sent_journal.send();
        let pn = journal_guard.next_pn();
        let mut writer = HandshakePacketWriter::new(&hdr, buf, pn, pk.tag_len())?;

        // 4. 检查是否需要发送Ack，若是，生成ack
        let mut sent_ack = None;
        if let Some((largest, recv_time)) = ack_pkt {
            let rcvd_pkt_records = self.journal.rcvd();
            rcvd_pkt_records
                .read_ack_frame_util(&mut writer, largest, recv_time)
                .expect("its always have enough space to put a ack frame");
            journal_guard.record_trivial();
            sent_ack = Some(largest);
        }

        // 5. 从CryptoStream提取数据，当前无流控，尽最大努力，提取限制之内的最大数据量
        while let Some(frame) = self.crypto_stream_outgoing.try_read_data(&mut writer) {
            journal_guard.record_frame(frame);
        }

        if writer.is_empty() {
            return None;
        }

        drop(journal_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        let _remain = writer.seal_packet();
        let packet = writer.encrypt(hpk, pk);

        Some((packet, sent_ack))
    }
}
