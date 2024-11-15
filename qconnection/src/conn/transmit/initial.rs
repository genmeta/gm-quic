use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use qbase::{
    cid::ConnectionId,
    packet::{
        keys::ArcKeys,
        writer::{CompletePacket, InitialPacketWriter},
        LongHeaderBuilder,
    },
};
use qrecovery::{crypto::CryptoStreamOutgoing, journal::InitialJournal};

#[derive(Clone)]
pub struct InitialSpaceReader {
    pub(crate) token: Arc<Mutex<Vec<u8>>>,
    pub(crate) keys: ArcKeys,
    pub(crate) journal: InitialJournal,
    pub(crate) crypto_stream_outgoing: CryptoStreamOutgoing,
}

impl InitialSpaceReader {
    #[allow(clippy::complexity)]
    pub fn try_read<'a: 'b, 'b>(
        &'a self,
        buf: &'a mut [u8],
        scid: ConnectionId,
        dcid: ConnectionId,
        ack_pkt: Option<(u64, Instant)>,
    ) -> Option<(
        &'b mut [u8],
        impl FnOnce(Option<&'b mut [u8]>) -> (CompletePacket, Option<u64>) + 'b,
    )> {
        // 1. 判定keys是否有效，无效或者尚未拿到，直接返回
        let k = self.keys.get_local_keys()?;

        // 2. 生成包头，预留2字节len，根据包头大小，配合constraints、剩余空间，检查是否能发送，不能的话，直接返回
        let token = self.token.lock().unwrap();
        let hdr = LongHeaderBuilder::with_cid(dcid, scid).initial(token.clone());
        // length字段预留2字节, 20字节为最小Payload长度，为了保护包头的Sample至少16字节

        // 3. 锁定发送记录器，生成pn，如果pn大小不够，直接返回
        let sent_journal = self.journal.sent();
        let mut journal_guard = sent_journal.send();
        let pn = journal_guard.next_pn();

        let mut writer = InitialPacketWriter::new(&hdr, buf, pn, k.local.packet.tag_len())?;

        // 4. 检查是否需要发送Ack，若是，生成ack
        let sent_ack = ack_pkt.map(|(largest, recv_time)| {
            let rcvd_pkt_records = self.journal.rcvd();

            rcvd_pkt_records
                .read_ack_frame_util(&mut writer, largest, recv_time)
                .expect("its always have enough space to put a ack frame");
            journal_guard.record_trivial();
            largest
        });

        // 5. 从CryptoStream提取数据，当前无流控，仅最大努力，提取限制之内的最大数据量
        while let Some(frame) = self.crypto_stream_outgoing.try_read_data(&mut writer) {
            journal_guard.record_frame(frame);
        }
        drop(journal_guard); // 持有这把锁的时间越短越好，毕竟下面的加密可能会有点耗时

        if writer.is_empty() {
            return None;
        }

        let remain = writer.seal_packet();
        let complete = move |extend| {
            if let Some(extend) = extend {
                writer.extend_packet(extend);
            }
            let hpk = k.local.header.as_ref();
            let pk = k.local.packet.as_ref();
            (writer.encrypt(hpk, pk), sent_ack)
        };
        Some((remain, complete))
    }
}
