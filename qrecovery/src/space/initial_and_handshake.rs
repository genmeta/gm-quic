use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use super::Transmit;
use crate::{
    crypto_stream::{CryptoStream, CryptoStreamReader, CryptoStreamWriter},
    rtt::Rtt,
    space::Receive,
};
use bytes::BytesMut;
use qbase::{
    error::Error,
    frame::{ConnectionFrame, CryptoFrame, NoFrame},
    packet::{ext::decrypt_packet, ProtectedHandshakeHeader, ProtectedInitialHeader},
};
use rustls::quic::Keys;

#[derive(Debug)]
pub struct Transmission {
    crypto_stream: CryptoStream,
}

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

pub struct InitialSpace {
    keys: Keys,
    space: super::Space<NoFrame, CryptoFrame, Transmission>,
}

impl InitialSpace {
    pub fn new(keys: Keys) -> Self {
        let frames = Arc::new(Mutex::new(VecDeque::new()));
        Self {
            keys,
            space: super::Space::build(frames, Transmission::new(CryptoStream::new(1000_000, 0))),
        }
    }

    pub fn crypto_stream(&self) -> &CryptoStream {
        self.space.crypto_stream()
    }

    pub fn receive_packet(
        &mut self,
        header: ProtectedInitialHeader,
        packet: BytesMut,
        pn_offset: usize,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnectionFrame>, Error> {
        let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &self.keys.remote)?;
        self.space.receive(pn, body, rtt)
    }
}

pub enum HandshakeSpace {
    UnknownKeys(Vec<(ProtectedHandshakeHeader, BytesMut, usize)>),
    KnownKeys {
        keys: Keys,
        space: super::Space<NoFrame, CryptoFrame, Transmission>,
    },
}

impl HandshakeSpace {
    pub fn new() -> Self {
        Self::UnknownKeys(Vec::new())
    }

    pub fn update_keys(
        &mut self,
        keys: Keys,
    ) -> Result<
        (
            Vec<ConnectionFrame>,
            (CryptoStreamReader, CryptoStreamWriter),
        ),
        Error,
    > {
        let crypto_stream = CryptoStream::new(1000_000, 0);
        let stream_io = crypto_stream.split_io();
        let mut space = super::Space::build(
            Arc::new(Mutex::new(VecDeque::new())),
            Transmission::new(crypto_stream),
        );
        // TODO: 优化，不必要的内存分配
        let mut connectinon_frames = Vec::new();
        match self {
            HandshakeSpace::UnknownKeys(packets) => {
                for (header, packet, pn_offset) in packets.drain(..) {
                    let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &keys.remote)?;
                    connectinon_frames.extend(space.receive(pn, body, &mut Rtt::default())?);
                }
            }
            HandshakeSpace::KnownKeys { .. } => unreachable!("keys already updated"),
        };
        *self = Self::KnownKeys { keys, space };
        Ok((connectinon_frames, stream_io))
    }

    pub fn receive_packet(
        &mut self,
        header: ProtectedHandshakeHeader,
        packet: BytesMut,
        pn_offset: usize,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnectionFrame>, Error> {
        match self {
            Self::UnknownKeys(packets) => {
                packets.push((header, packet, pn_offset));
                Ok(Vec::new())
            }
            Self::KnownKeys { keys, space } => {
                let (pn, body) = decrypt_packet(header, packet, pn_offset, 0, &keys.remote)?;
                space.receive(pn, body, rtt)
            }
        }
    }
}
