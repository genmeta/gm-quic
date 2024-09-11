use bytes::BytesMut;
use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;

use crate::cid::ConnectionId;

/// QUIC packet parse error definitions.
pub mod error;

/// Define signal util, such as key phase bit and spin bit.
pub mod signal;
pub use signal::{KeyPhaseBit, SpinBit};

/// Definitions of QUIC packet types.
pub mod r#type;
pub use r#type::{
    GetPacketNumberLength, LongSpecificBits, ShortSpecificBits, Type, LONG_RESERVED_MASK,
    SHORT_RESERVED_MASK,
};

/// Definitions of QUIC packet headers.
pub mod header;
pub use header::{
    long, EncodeHeader, GetDcid, GetType, HandshakeHeader, Header, InitialHeader,
    LongHeaderBuilder, OneRttHeader, RetryHeader, VersionNegotiationHeader, ZeroRttHeader,
};

/// Encoding and decoding of packet number
pub mod number;
pub use number::{take_pn_len, PacketNumber, WritePacketNumber};

/// Include operations such as decrypting QUIC packets, removing header protection,
/// and parsing the first byte of the packet to get the right packet numbers
pub mod decrypt;

/// Include operations such as encrypting QUIC packets, adding header protection,
/// and encoding the first byte of the packet with pn_len and key_phase optionally.
pub mod encrypt;

/// Encapsulate the crypto keys's logic for long headers and 1-RTT headers.
pub mod keys;

/// The sum type of all QUIC packet headers.
#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid, GetType)]
pub enum DataHeader {
    Long(long::DataHeader),
    Short(OneRttHeader),
}

/// The sum type of all QUIC data packets.
///
/// The long header has the len field, the short header does not have the len field.
/// Remember, the len field is not an attribute of the header, but a attribute of the packet.
///
/// ```text
///                                 +---> payload length in long packet
///                                 |     |<----------- payload --------->|
/// +-----------+---+--------+------+-----+-----------+---......--+-------+
/// |X|1|X X 0 0|0 0| ...hdr | len(0..16) | pn(8..32) | body...   |  tag  |
/// +---+-------+-+-+--------+------------+-----+-----+---......--+-------+
///               |                             |
///               +---> packet number length    +---> actual encoded packet number
/// ```
#[derive(Debug, Clone, Deref, DerefMut)]
pub struct DataPacket {
    #[deref]
    pub header: DataHeader,
    pub bytes: BytesMut,
    // payload_offset
    pub offset: usize,
}

impl GetType for DataPacket {
    fn get_type(&self) -> Type {
        self.header.get_type()
    }
}

/// The sum type of all QUIC packets.
#[derive(Debug, Clone)]
pub enum Packet {
    VN(VersionNegotiationHeader),
    Retry(RetryHeader),
    // Data(header, bytes, payload_offset)
    Data(DataPacket),
}

/// QUIC packet reader, reading packets from the incoming datagrams.
///
/// The parsing here does not involve removing header protection or decrypting the packet.
/// It only parses information such as packet type and connection ID,
/// and prepares for further delivery to the connection by finding the connection ID.
///
/// The received packet is a BytesMut, in order to be decrypted in future, and make as few
/// copies cheaply until it is read by the application layer.
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

        match io::be_packet(&mut self.raw, self.dcid_len) {
            Ok(packet) => Some(Ok(packet)),
            Err(e) => {
                self.raw.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

/// The io module provides the functions to parse the QUIC packet.
///
/// The writing of the QUIC packet is not provided here, they are written in place.
pub mod io {
    use bytes::BytesMut;
    use nom::multi::length_data;

    use super::{
        error::Error,
        header::io::be_header,
        r#type::{io::be_packet_type, Type},
        *,
    };
    use crate::varint::be_varint;

    /// Parse the payload of a packet.
    ///
    /// - For long packets, the payload is a [`nom::multi::length_data`].
    /// - For 1-RTT packet, the payload is the remaining content of the datagram.
    fn be_payload(
        pkty: Type,
        datagram: &mut BytesMut,
        remain_len: usize,
    ) -> Result<(BytesMut, usize), Error> {
        let offset = datagram.len() - remain_len;
        let input = &datagram[offset..];
        let (remain, payload) = length_data(be_varint)(input).map_err(|e| match e {
            ne @ nom::Err::Incomplete(_) => Error::IncompleteHeader(pkty, ne.to_string()),
            _ => unreachable!("parsing packet header never generates error or failure"),
        })?;
        let payload_len = payload.len();
        if payload_len < 20 {
            // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
            return Err(Error::UnderSampling(payload.len()));
        }
        let packet_length = datagram.len() - remain.len();
        let bytes = datagram.split_to(packet_length);
        Ok((bytes, packet_length - payload_len))
    }

    /// Parse the QUIC packet from the datagram, given the length of the DCID.
    /// Returns the parsed packet or an error, and the datagram removed the packet's content.
    pub fn be_packet(datagram: &mut BytesMut, dcid_len: usize) -> Result<Packet, Error> {
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
            Header::VN(header) => Ok(Packet::VN(header)),
            Header::Retry(header) => Ok(Packet::Retry(header)),
            Header::Initial(header) => {
                let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
                Ok(Packet::Data(DataPacket {
                    header: DataHeader::Long(long::DataHeader::Initial(header)),
                    bytes,
                    offset,
                }))
            }
            Header::ZeroRtt(header) => {
                let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
                Ok(Packet::Data(DataPacket {
                    header: DataHeader::Long(long::DataHeader::ZeroRtt(header)),
                    bytes,
                    offset,
                }))
            }
            Header::Handshake(header) => {
                let (bytes, offset) = be_payload(pkty, datagram, remain.len())?;
                Ok(Packet::Data(DataPacket {
                    header: DataHeader::Long(long::DataHeader::Handshake(header)),
                    bytes,
                    offset,
                }))
            }
            Header::OneRtt(header) => {
                if remain.len() < 20 {
                    // The payload needs at least 20 bytes to have enough samples to remove the packet header protection.
                    return Err(Error::UnderSampling(remain.len()));
                }
                let bytes = datagram.clone();
                let offset = bytes.len() - remain.len();
                datagram.clear();
                Ok(Packet::Data(DataPacket {
                    header: DataHeader::Short(header),
                    bytes,
                    offset,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {}
