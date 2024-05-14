use super::{Receive, Transmit};
use crate::{crypto_stream::CryptoStream, rtt::Rtt};
use deref_derive::{Deref, DerefMut};
use qbase::{
    error::Error,
    frame::{ConnectionFrame, CryptoFrame, NoFrame},
    packet::{DecryptPacket, ProtectedHandshakePacket, ProtectedInitialPacket},
};

#[derive(Debug)]
pub struct Transmission {
    crypto_stream: CryptoStream,
}

#[derive(Debug, Deref, DerefMut)]
pub struct InitialSpace(#[deref] super::Space<NoFrame, CryptoFrame, Transmission>);
#[derive(Debug, Deref, DerefMut)]
pub struct HandshakeSpace(#[deref] super::Space<NoFrame, CryptoFrame, Transmission>);

impl Transmit<NoFrame, CryptoFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, buf: &mut Self::Buffer) -> Option<(CryptoFrame, usize)> {
        self.crypto_stream.try_send(buf)
    }

    fn confirm_data(&mut self, data_frame: CryptoFrame) {
        self.crypto_stream.confirm_data(data_frame)
    }

    fn may_loss(&mut self, data_frame: CryptoFrame) {
        self.crypto_stream.may_loss(data_frame)
    }

    fn recv_frame(&mut self, _: NoFrame) -> Result<Option<ConnectionFrame>, Error> {
        unreachable!("no signaling frame in initial or handshake space")
    }

    fn recv_data(&mut self, data_frame: CryptoFrame, data: bytes::Bytes) -> Result<(), Error> {
        self.crypto_stream.recv_data(data_frame, data)
    }
}

impl Transmission {
    pub fn new(crypto_stream: CryptoStream) -> Self {
        Self { crypto_stream }
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        &self.crypto_stream
    }
}

impl super::ReceivePacket for super::ReceiveHalf<InitialSpace> {
    type Packet = ProtectedInitialPacket;

    fn receive_packet(
        &self,
        packet: ProtectedInitialPacket,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnectionFrame>, Error> {
        let mut space = self.space.lock().unwrap();
        let (pktid, payload) = packet.decrypt_packet(space.expected_pn(), &self.decrypt_keys)?;
        space.receive(pktid, payload, rtt)
    }
}

impl super::ReceivePacket for super::ReceiveHalf<HandshakeSpace> {
    type Packet = ProtectedHandshakePacket;

    fn receive_packet(
        &self,
        packet: ProtectedHandshakePacket,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnectionFrame>, Error> {
        let mut space = self.space.lock().unwrap();
        let (pktid, payload) = packet.decrypt_packet(space.expected_pn(), &self.decrypt_keys)?;
        space.receive(pktid, payload, rtt)
    }
}
