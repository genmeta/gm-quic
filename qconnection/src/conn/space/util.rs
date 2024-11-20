use bytes::{Bytes, BytesMut};
use qbase::packet::{
    decrypt::{
        decrypt_packet, remove_protection_of_long_packet, remove_protection_of_short_packet,
    },
    keys::ArcOneRttPacketKeys,
};
use qrecovery::journal::ArcRcvdJournal;
use rustls::quic::{HeaderProtectionKey, PacketKey};

// TODO: use primitive slice instead of BytesMut, Bytes
pub fn parse_long_header_packet(
    mut pkt_buf: BytesMut,
    payload_offset: usize,
    hpk: &dyn HeaderProtectionKey,
    pk: &dyn PacketKey,
    rcvd_pkt_records: &ArcRcvdJournal,
) -> Option<(u64, Bytes)> {
    // faild to remove header protection?
    // invalid reverse bits?
    let undecoded_pn =
        remove_protection_of_long_packet(hpk, &mut pkt_buf, payload_offset).ok()??;
    // faild to decode packet number?
    let pn = rcvd_pkt_records.decode_pn(undecoded_pn).ok()?;

    let body_offset = payload_offset + undecoded_pn.size();
    // faild to decrypt packet?
    let pkt_len = decrypt_packet(pk, pn, &mut pkt_buf, body_offset).ok()?;

    let mut body_buf = pkt_buf.split_off(body_offset);
    body_buf.truncate(pkt_len);

    Some((pn, pkt_buf.freeze()))
}

pub fn parse_short_header_packet(
    mut pkt_buf: BytesMut,
    payload_offset: usize,
    hpk: &dyn HeaderProtectionKey,
    pk: &ArcOneRttPacketKeys,
    rcvd_pkt_records: &ArcRcvdJournal,
) -> Option<(u64, Bytes)> {
    // faild to remove header protection?
    // invalid reverse bits?
    let (undecoded_pn, key_phase) =
        remove_protection_of_short_packet(hpk, &mut pkt_buf, payload_offset).ok()??;
    // faild to decode packet number?
    let pn = rcvd_pkt_records.decode_pn(undecoded_pn).ok()?;

    let body_offset = payload_offset + undecoded_pn.size();
    let pk = pk.lock_guard().get_remote(key_phase, pn);
    // faild to decrypt packet?
    let pkt_len = decrypt_packet(pk.as_ref(), pn, &mut pkt_buf, body_offset).ok()?;

    let mut body_buf = pkt_buf.split_off(body_offset);
    body_buf.truncate(pkt_len);

    Some((pn, pkt_buf.freeze()))
}
