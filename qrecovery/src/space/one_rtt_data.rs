use super::Receive;
/// Application data space, 1-RTT data space
use crate::{crypto_stream::CryptoStream, rtt::Rtt, streams::Streams};
use qbase::{
    error::Error,
    frame::ConnFrame,
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        OneRttHeader, PacketWrapper,
    },
};

pub type OneRttDataSpace = super::Space<CryptoStream, Streams>;

impl super::ReceivePacket for super::ReceiveHalf<OneRttDataSpace> {
    type Packet = PacketWrapper<OneRttHeader>;

    fn receive_packet(
        &self,
        mut packet: Self::Packet,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnFrame>, Error> {
        let mut space = self.space.lock().unwrap();
        let ok = packet.remove_protection(&self.decrypt_keys.header);
        if ok {
            let (pn, _key_phase_bit) = packet.decode_header()?;
            // TODO: 判断key_phase有没有翻转，若有翻转，则需要更新密钥
            let (pktid, payload) = packet
                .decrypt_packet(pn, space.expected_pn(), &self.decrypt_keys.packet)
                .unwrap();
            space.receive(pktid, payload, rtt)
        } else {
            // TODO: 去除保护失败，得用下一个密钥或者旧密钥尝试
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
