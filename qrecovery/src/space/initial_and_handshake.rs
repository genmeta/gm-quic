use super::Receive;
use crate::{crypto_stream::CryptoStream, rtt::Rtt, streams::NoStreams};
use deref_derive::{Deref, DerefMut};
use qbase::{
    error::Error,
    frame::ConnFrame,
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        HandshakeHeader, InitialHeader, PacketWrapper,
    },
};

#[derive(Debug, Deref, DerefMut)]
pub struct InitialSpace(#[deref] super::Space<CryptoStream, NoStreams>);
#[derive(Debug, Deref, DerefMut)]
pub struct HandshakeSpace(#[deref] super::Space<CryptoStream, NoStreams>);

impl super::ReceivePacket for super::ReceiveHalf<InitialSpace> {
    type Packet = PacketWrapper<InitialHeader>;

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

impl super::ReceivePacket for super::ReceiveHalf<HandshakeSpace> {
    type Packet = PacketWrapper<HandshakeHeader>;

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
