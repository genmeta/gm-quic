use bytes::BytesMut;
use deref_derive::{Deref, DerefMut};
use thiserror::Error;

pub mod signal;
pub use signal::{KeyPhaseBit, SpinBit};

pub mod r#type;
use r#type::{GetPacketNumberLength, LongClearBits, ShortClearBits};

pub mod header;
pub use header::{
    HandshakeHeader, Header, InitialHeader, LongHeaderBuilder, OneRttHeader, RetryHeader,
    VersionNegotiationHeader, ZeroRttHeader,
};

pub mod number;
pub use number::{take_pn_len, PacketNumber, WritePacketNumber};

use self::header::GetDcid;

pub mod decrypt;
pub mod encrypt;
pub mod keys;

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct PacketWrapper<H> {
    #[deref]
    pub header: H,
    pub raw_data: BytesMut,
    pub pn_offset: usize,
}

pub type InitialPacket = PacketWrapper<InitialHeader>;
pub type HandshakePacket = PacketWrapper<HandshakeHeader>;
pub type ZeroRttPacket = PacketWrapper<ZeroRttHeader>;
pub type OneRttPacket = PacketWrapper<OneRttHeader>;

#[derive(Debug, Clone)]
pub enum SpacePacket {
    Initial(InitialPacket),
    Handshake(HandshakePacket),
    ZeroRtt(ZeroRttPacket),
    OneRtt(OneRttPacket),
}

impl GetDcid for SpacePacket {
    fn get_dcid(&self) -> &crate::cid::ConnectionId {
        match self {
            Self::Initial(packet) => packet.header.get_dcid(),
            Self::Handshake(packet) => packet.header.get_dcid(),
            Self::ZeroRtt(packet) => packet.header.get_dcid(),
            Self::OneRtt(packet) => packet.header.get_dcid(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Packet {
    VN(VersionNegotiationHeader),
    Retry(RetryHeader),
    Space(SpacePacket),
}

#[derive(Debug, Clone, Error)]
#[error("parse packet error")]
pub struct ParsePacketError;

/// 此处解析并不涉及去除头部保护、解密数据包的部分，只是解析出包类型、连接ID等信息，
/// 找到连接ID为进一步向连接交付做准备，去除头部保护、解密数据包的部分则在连接层进行.
/// 收到的一个数据包是BytesMut，是为了做尽量少的Copy，直到应用层读走
#[derive(Debug)]
pub struct PacketReader {
    raw: BytesMut,
    dcid_len: usize,
    // TODO: 添加leve，各种包类型顺序不能错乱，否则失败
}

impl PacketReader {
    pub fn new(raw: BytesMut, dcid_len: usize) -> Self {
        Self { raw, dcid_len }
    }
}

impl Iterator for PacketReader {
    type Item = Result<Packet, ParsePacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        match ext::be_packet(&self.raw, self.dcid_len) {
            Ok((consumed, packet)) => {
                self.raw.truncate(consumed);
                Some(Ok(packet))
            }
            Err(_) => {
                self.raw.clear(); // no longer parsing
                Some(Err(ParsePacketError))
            }
        }
    }
}

pub mod ext {
    use super::{
        header::{ext::be_header, GetLength},
        r#type::ext::be_packet_type,
        *,
    };
    use bytes::BytesMut;

    fn complete(
        length: usize,
        mut raw_data: BytesMut,
        input: &[u8],
    ) -> Result<(&[u8], usize, BytesMut), ParsePacketError> {
        let pn_offset = raw_data.len() - input.len();
        let packet_length = pn_offset + length;
        if length < 20 {
            // payload至少需要20字节，才能有足够的sample采样去除包头保护
            return Err(ParsePacketError);
        }
        if length > input.len() {
            // payload数据不足
            return Err(ParsePacketError);
        }
        raw_data.truncate(packet_length);
        Ok((&input[length..], pn_offset, raw_data))
    }

    pub fn be_packet(
        datagram: &BytesMut,
        dcid_len: usize,
    ) -> Result<(usize, Packet), ParsePacketError> {
        let input = datagram.as_ref();
        let (remain, packet_type) = be_packet_type(input).map_err(|_e| {
            // Fixed bits error or unsupport long header version
            ParsePacketError
        })?;
        let (remain, header) = be_header(packet_type, dcid_len, remain).map_err(|_e| {
            // Parse header error
            ParsePacketError
        })?;
        match header {
            Header::VN(header) => Ok((datagram.len() - remain.len(), Packet::VN(header))),
            Header::Retry(header) => Ok((datagram.len() - remain.len(), Packet::Retry(header))),
            Header::Initial(header) => {
                let (remain, pn_offset, raw_data) =
                    complete(header.get_length(), datagram.clone(), remain)?;
                Ok((
                    datagram.len() - remain.len(),
                    Packet::Space(SpacePacket::Initial(InitialPacket {
                        header,
                        raw_data,
                        pn_offset,
                    })),
                ))
            }
            Header::ZeroRtt(header) => {
                let (remain, pn_offset, raw_data) =
                    complete(header.get_length(), datagram.clone(), remain)?;
                Ok((
                    datagram.len() - remain.len(),
                    Packet::Space(SpacePacket::ZeroRtt(ZeroRttPacket {
                        header,
                        raw_data,
                        pn_offset,
                    })),
                ))
            }
            Header::Handshake(header) => {
                let (remain, pn_offset, raw_data) =
                    complete(header.get_length(), datagram.clone(), remain)?;
                Ok((
                    datagram.len() - remain.len(),
                    Packet::Space(SpacePacket::Handshake(HandshakePacket {
                        header,
                        raw_data,
                        pn_offset,
                    })),
                ))
            }
            Header::OneRtt(header) => {
                let (remain, pn_offset, raw_data) =
                    complete(remain.len(), datagram.clone(), remain)?;
                Ok((
                    datagram.len() - remain.len(),
                    Packet::Space(SpacePacket::OneRtt(OneRttPacket {
                        header,
                        raw_data,
                        pn_offset,
                    })),
                ))
            }
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
