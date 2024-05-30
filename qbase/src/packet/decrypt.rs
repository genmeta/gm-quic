use super::error::Error;
use super::{
    header::{long::LongHeader, Protect},
    take_pn_len, GetPacketNumberLength, KeyPhaseBit, LongClearBits, OneRttHeader, PacketNumber,
    PacketWrapper, ShortClearBits,
};
use bytes::Bytes;
use rustls::quic::{HeaderProtectionKey, PacketKey};

pub trait RemoteProtection {
    fn remove_protection(&mut self, header_protection_key: &HeaderProtectionKey) -> bool;
}

pub trait DecodeHeader {
    type Output;

    /// Will return Error::InvalidReservedBits if the reserved bits are not 0.
    fn decode_header(&self) -> Result<Self::Output, Error>;
}

pub trait DecryptPacket {
    fn decrypt_packet(
        self,
        pn: u64,
        encoded_pn_size: usize,
        packet_key: &PacketKey,
    ) -> Result<Bytes, Error>;
}

impl<H: Protect> RemoteProtection for PacketWrapper<H> {
    fn remove_protection(&mut self, header_protection_key: &HeaderProtectionKey) -> bool {
        let (header, payload) = self.raw_data.split_at_mut(self.pn_offset);
        let first_byte = &mut header[0];
        let (pn_bytes, sample) = payload.split_at_mut(4);
        // Decryption failure is not a fatal error. When facing a key upgrade,
        // you need to try again with the next key. If it still fails, it may be forged
        // and should be discarded. In any case, it won't cause a connection error!
        header_protection_key
            .decrypt_in_place(sample, first_byte, pn_bytes)
            .map_err(|_| Error::RemoveProtectionFailure)
            .is_ok()
    }
}

impl DecodeHeader for PacketWrapper<OneRttHeader> {
    type Output = (PacketNumber, KeyPhaseBit);

    fn decode_header(&self) -> Result<Self::Output, Error> {
        let clear_bits = ShortClearBits::from(self.raw_data[0]);
        let pn_len = clear_bits.pn_len()?;
        let pn_bytes = &self.raw_data[self.pn_offset..self.pn_offset + pn_len as usize];
        let (_, pn) = take_pn_len(pn_len)(pn_bytes).unwrap();
        Ok((pn, clear_bits.key_phase()))
    }
}

impl<S> DecodeHeader for PacketWrapper<LongHeader<S>> {
    type Output = PacketNumber;

    fn decode_header(&self) -> Result<PacketNumber, Error> {
        let clear_bits = LongClearBits::from(self.raw_data[0]);
        let pn_len = clear_bits.pn_len()?;
        let pn_bytes = &self.raw_data[self.pn_offset..self.pn_offset + pn_len as usize];
        let (_, pn) = take_pn_len(pn_len)(pn_bytes).unwrap();
        Ok(pn)
    }
}

impl<H: Protect> DecryptPacket for PacketWrapper<H> {
    fn decrypt_packet(
        self,
        pn: u64,
        encoded_pn_size: usize,
        remote_keys: &PacketKey,
    ) -> Result<Bytes, Error> {
        // decrypt packet
        let mut raw_data = self.raw_data;
        let header_offset = self.pn_offset + encoded_pn_size;
        let mut body = raw_data.split_off(header_offset);
        let header = raw_data;
        remote_keys
            .decrypt_in_place(pn, &header, &mut body)
            .map_err(|_| Error::DecryptPacketFailure)?;
        Ok(body.freeze())
    }
}
