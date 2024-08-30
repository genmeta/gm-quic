/// A QUIC packet as follows:
/// The long header has the len field, the short header does not have the len field.
/// Remember, the len field is not an attribute of the header, but a attribute of the packet.
/// |--------+-......-+[-------+-------]+--......--+--------+........+--------|
/// |  pkty  |   hdr  |       len       |    pn    |           body           |
/// |--------+-......-+[-------+-------]+--......--+--------+........+--------|
///      ^                              |                                     |
///      |                              |                                     |
/// first byte                          |<--------------payload-------------->|
use bytes::BytesMut;

pub mod error;

pub mod signal;
use deref_derive::{Deref, DerefMut};
use enum_dispatch::enum_dispatch;
use header::GetType;
pub use signal::{KeyPhaseBit, SpinBit};

pub mod r#type;
use r#type::Type;
pub use r#type::{
    GetPacketNumberLength, LongClearBits, ShortClearBits, LONG_RESERVED_MASK, SHORT_RESERVED_MASK,
};

pub mod header;
pub use header::{
    long, Encode, HandshakeHeader, Header, InitialHeader, LongHeaderBuilder, OneRttHeader,
    RetryHeader, VersionNegotiationHeader, ZeroRttHeader,
};

pub mod number;
pub use number::{take_pn_len, PacketNumber, WritePacketNumber};

use self::header::GetDcid;
use crate::cid::ConnectionId;

pub mod decrypt;
pub mod encrypt;
pub mod keys;

#[derive(Debug, Clone)]
#[enum_dispatch(GetDcid, GetType)]
pub enum DataHeader {
    Long(long::DataHeader),
    Short(OneRttHeader),
}

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

#[derive(Debug, Clone)]
pub enum Packet {
    VN(VersionNegotiationHeader),
    Retry(RetryHeader),
    // Data(header, bytes, payload_offset)
    Data(DataPacket),
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

        match ext::be_packet(&mut self.raw, self.dcid_len) {
            Ok(packet) => Some(Ok(packet)),
            Err(e) => {
                self.raw.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

pub mod ext {
    use bytes::BytesMut;
    use nom::multi::length_data;

    use super::{
        error::Error,
        header::ext::be_header,
        r#type::{ext::be_packet_type, Type},
        *,
    };
    use crate::varint::be_varint;

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
