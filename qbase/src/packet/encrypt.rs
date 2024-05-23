use super::{
    header::{long::LongHeader, GetType, Protect},
    r#type::ext::WritePacketType,
    KeyPhaseBit, LongClearBits, OneRttHeader, PacketNumber, PacketWrapper, ShortClearBits,
    WritePacketNumber,
};
use rustls::quic::{HeaderProtectionKey, PacketKey};
use std::ops::Deref;

/// 有一个Packet了
/// 1. 先填写完整 complete PacketNumber ClearBits
/// 2. 有了头部之后，加密body
/// 3. 添加头部保护

pub trait EncodeHeader {
    type Params;
    fn encode_header(&mut self, params: Self::Params);
}

pub trait EncryptPacket {
    fn encrypt_packet(&mut self, packet_number: u64, pn_len: usize, packet_key: &PacketKey);
}

pub trait ProtectHeader {
    fn protect_header(&mut self, pn_len: usize, header_protection_key: &HeaderProtectionKey);
}

impl EncodeHeader for PacketWrapper<OneRttHeader> {
    type Params = (PacketNumber, KeyPhaseBit);

    fn encode_header(&mut self, (pn, key_phase_bit): Self::Params) {
        let (header, mut payload) = self.raw_data.split_at_mut(self.pn_offset);
        {
            let mut header = &mut header[0..1];
            header.put_packet_type(&self.header.get_type());
        }
        let mut clear_bits = ShortClearBits::from_pn(&pn);
        clear_bits.set_key_phase(key_phase_bit);
        header[0] |= clear_bits.deref();
        payload.put_packet_number(pn);
    }
}

impl<S> EncodeHeader for PacketWrapper<LongHeader<S>>
where
    LongHeader<S>: GetType,
{
    type Params = PacketNumber;

    fn encode_header(&mut self, pn: Self::Params) {
        let (header, mut payload) = self.raw_data.split_at_mut(self.pn_offset);
        {
            let mut header = &mut header[0..5];
            header.put_packet_type(&self.header.get_type());
        }
        let clear_bits = LongClearBits::from_pn(&pn);
        header[0] |= clear_bits.deref();
        payload.put_packet_number(pn);
    }
}

impl<H: Protect> EncryptPacket for PacketWrapper<H> {
    fn encrypt_packet(&mut self, packet_number: u64, pn_len: usize, packet_key: &PacketKey) {
        let header_len = self.pn_offset + pn_len;
        let (header, body) = self.raw_data.split_at_mut(header_len);
        packet_key
            .encrypt_in_place(packet_number, header, body)
            .unwrap();
    }
}

impl<H: Protect> ProtectHeader for PacketWrapper<H> {
    fn protect_header(&mut self, pn_len: usize, header_protection_key: &HeaderProtectionKey) {
        let (header, payload) = self.raw_data.split_at_mut(self.pn_offset);
        let first_byte = &mut header[0];
        let (pn_bytes, sample) = payload.split_at_mut(4);
        let sample_len = header_protection_key.sample_len();
        header_protection_key
            .encrypt_in_place(&sample[..sample_len], first_byte, &mut pn_bytes[..pn_len])
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
