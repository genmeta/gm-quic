/// Application data space, 0-RTT data space
use super::{OneRttDataSpace, Receive};
use crate::{
    crypto_stream::{CryptoStream, NoCrypto},
    rtt::Rtt,
    streams::Streams,
};
use qbase::{
    error::Error,
    frame::ConnFrame,
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        PacketWrapper, ZeroRttHeader,
    },
    streamid::StreamIds,
    SpaceId,
};

pub type ZeroRttDataSpace = super::Space<NoCrypto, Streams>;

impl ZeroRttDataSpace {
    pub fn new(stream_ids: StreamIds) -> Self {
        let streams = Streams::new(stream_ids);
        ZeroRttDataSpace::build(SpaceId::ZeroRtt, NoCrypto, streams)
    }

    pub async fn upgrade(self, crypto_stream: CryptoStream) -> OneRttDataSpace {
        OneRttDataSpace::build(SpaceId::OneRtt, crypto_stream, self.stm_trans)
    }
}

impl super::ReceivePacket for super::ReceiveHalf<ZeroRttDataSpace> {
    type Packet = PacketWrapper<ZeroRttHeader>;

    fn receive_packet(
        &self,
        mut packet: Self::Packet,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnFrame>, Error> {
        let mut space = self.space.lock().unwrap();

        let ok = packet.remove_protection(&self.decrypt_keys.header);
        if ok {
            let pn = packet.decode_header()?;
            let (pktid, payload) = packet
                .decrypt_packet(pn, space.expected_pn(), &self.decrypt_keys.packet)
                .unwrap();
            space.receive(pktid, payload, rtt)
        } else {
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
