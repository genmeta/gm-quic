use bytes::BytesMut;
use deref_derive::{Deref, DerefMut};

pub mod error;

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

/// The parsing here does not involve removing header protection or decrypting the packet. It only parses information such as packet type and connection ID,
/// and prepares for further delivery to the connection by finding the connection ID. The removal of header protection and decryption of the packet is done at the connection layer.
/// The received packet is a BytesMut, in order to make as few copies as possible until it is read by the application layer.
#[derive(Debug)]
pub struct PacketReader {
    raw: BytesMut,
    dcid_len: usize,
    // TODO: 添加level，各种包类型顺序不能错乱，否则失败
}

impl PacketReader {
    pub fn new(raw: BytesMut, dcid_len: usize) -> Self {
        Self { raw, dcid_len }
    }
}

impl Iterator for PacketReader {
    type Item = Result<Packet, error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }

        match ext::be_packet(&self.raw, self.dcid_len) {
            Ok((consumed, packet)) => {
                self.raw.truncate(consumed);
                Some(Ok(packet))
            }
            Err(e) => {
                self.raw.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

pub mod ext {
    use super::{
        error::Error,
        header::{ext::be_header, GetLength},
        r#type::{ext::be_packet_type, Type},
        *,
    };
    use bytes::BytesMut;

    fn complete(
        packet_type: Type,
        length: usize,
        mut raw_data: BytesMut,
        input: &[u8],
    ) -> Result<(&[u8], usize, BytesMut), Error> {
        let pn_offset = raw_data.len() - input.len();
        let packet_length = pn_offset + length;
        if length < 20 {
            // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
            return Err(Error::UnderSampling(length));
        }
        if length > input.len() {
            // Insufficient payload data
            return Err(Error::IncompletePacket(packet_type, length, input.len()));
        }
        raw_data.truncate(packet_length);
        Ok((&input[length..], pn_offset, raw_data))
    }

    pub fn be_packet(datagram: &BytesMut, dcid_len: usize) -> Result<(usize, Packet), Error> {
        let input = datagram.as_ref();
        let (remain, pkty) = be_packet_type(input).map_err(|e| match e {
            ne @ nom::Err::Incomplete(_) => Error::IncompleteType(ne.to_string()),
            nom::Err::Error(e) => e,
            _ => unreachable!("parsing packet type never generates failure"),
        })?;
        let (remain, header) = be_header(pkty, dcid_len, remain).map_err(|e| match e {
            ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
            _ => unreachable!("parsing packet header never generates error or failure"),
        })?;
        match header {
            Header::VN(header) => Ok((datagram.len() - remain.len(), Packet::VN(header))),
            Header::Retry(header) => Ok((datagram.len() - remain.len(), Packet::Retry(header))),
            Header::Initial(header) => {
                let (remain, pn_offset, raw_data) =
                    complete(pkty, header.get_length(), datagram.clone(), remain)?;
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
                    complete(pkty, header.get_length(), datagram.clone(), remain)?;
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
                    complete(pkty, header.get_length(), datagram.clone(), remain)?;
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
                    complete(pkty, remain.len(), datagram.clone(), remain)?;
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
