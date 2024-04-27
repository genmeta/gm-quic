use rustls::{
    self,
    quic::{HeaderProtectionKey, Version},
    Side,
};

use crate::quic::cid::ConnectionId;

use super::{CryptoError, HeaderKey, KeyPair, Keys};

impl HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // sample_offset = pn_offset + 4
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

impl super::PacketKey for rustls::quic::PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self.encrypt_in_place(packet, &*header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt<'a>(
        &self,
        packet: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload)
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        Ok(plain_len)
    }

    fn tag_len(&self) -> usize {
        self.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit()
    }
}

pub fn initial_keys(version: Version, dst_cid: &ConnectionId, side: Side) -> Keys {
    let keys = rustls::quic::Keys::initial(version, dst_cid, side.into());
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}
