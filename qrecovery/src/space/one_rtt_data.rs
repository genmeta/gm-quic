use super::Receive;
/// Application data space, 1-RTT data space
use crate::{crypto_stream::CryptoStream, rtt::Rtt, streams::Streams};
use qbase::{
    error::Error,
    frame::{ConnectionFrame, DataFrame, OneRttFrame},
    packet::{
        decrypt::{DecodeHeader, DecryptPacket, RemoteProtection},
        OneRttHeader, PacketWrapper,
    },
};

type OneRttDataFrame = DataFrame;

pub type OneRttDataSpace = super::Space<OneRttFrame, OneRttDataFrame, Transmission>;

#[derive(Debug)]
pub struct Transmission {
    streams: Streams,
    crypto_stream: CryptoStream,
}

impl super::Transmit<OneRttFrame, OneRttDataFrame> for Transmission {
    type Buffer = Vec<u8>;

    fn try_send(&mut self, _buf: &mut Self::Buffer) -> Option<(OneRttDataFrame, usize)> {
        todo!()
    }

    fn confirm_data(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => {
                self.streams.confirm_data(stream_frame);
            }
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.confirm_data(crypto_frame);
            }
        }
    }

    fn may_loss(&mut self, data_frame: OneRttDataFrame) {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => {
                self.streams.may_loss(stream_frame);
            }
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.may_loss(crypto_frame);
            }
        }
    }

    fn recv_data(&mut self, data_frame: OneRttDataFrame, body: bytes::Bytes) -> Result<(), Error> {
        match data_frame {
            OneRttDataFrame::Stream(stream_frame) => self.streams.recv_data(stream_frame, body),
            OneRttDataFrame::Crypto(crypto_frame) => {
                self.crypto_stream.recv_data(crypto_frame, body)
            }
        }
    }

    fn recv_frame(&mut self, frame: OneRttFrame) -> Result<Option<ConnectionFrame>, Error> {
        match frame {
            OneRttFrame::Stream(frame) => self.streams.recv_frame(frame),
            OneRttFrame::DataBlocked(frame) => Ok(Some(frame.into())),
            OneRttFrame::MaxData(frame) => Ok(Some(frame.into())),
            OneRttFrame::NewToken(frame) => Ok(Some(frame.into())),
            OneRttFrame::NewConnectionId(frame) => Ok(Some(frame.into())),
            OneRttFrame::RetireConnectionId(frame) => Ok(Some(frame.into())),
            OneRttFrame::PathChallenge(frame) => Ok(Some(frame.into())),
            OneRttFrame::PathResponse(frame) => Ok(Some(frame.into())),
            OneRttFrame::HandshakeDone(frame) => Ok(Some(frame.into())),
            OneRttFrame::Ping(_) => unreachable!("these are handled in space or connection layer"),
        }
    }
}

impl Transmission {
    pub(super) fn new(streams: Streams, crypto_stream: CryptoStream) -> Self {
        Self {
            streams,
            crypto_stream,
        }
    }

    pub fn streams(&mut self) -> &mut Streams {
        &mut self.streams
    }

    pub fn crypto_stream(&mut self) -> &mut CryptoStream {
        &mut self.crypto_stream
    }
}

impl super::ReceivePacket for super::ReceiveHalf<OneRttDataSpace> {
    type Packet = PacketWrapper<OneRttHeader>;

    fn receive_packet(
        &self,
        mut packet: Self::Packet,
        rtt: &mut Rtt,
    ) -> Result<Vec<ConnectionFrame>, Error> {
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
