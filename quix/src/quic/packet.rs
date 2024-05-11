use std::io;

use bytes::BufMut;
use nom::{
    error::VerboseError,
    number::complete::{be_u16, be_u24, be_u32, be_u8},
    IResult,
};
use qbase::{
    cid::{be_connection_id, ConnectionId, WriteConnectionId},
    varint::{
        ext::{be_varint, BufMutExt},
        VarInt,
    },
};

use super::crypto;

const FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;

const TYPE_MASK: u8 = 0x30;
const PKT_NUM_MASK: u8 = 0x03;

pub const MAX_CID_LEN: u8 = 20;

pub const MAX_PKT_NUM_LEN: usize = 4;

const SAMPLE_LEN: usize = 16;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SpaceId {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl SpaceId {
    pub fn iter() -> impl Iterator<Item = Self> {
        [Self::Initial, Self::Handshake, Self::Data].iter().cloned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    InvalidPacket,
    UnexpectedEnd,
    NomError,
}

impl From<nom::Err<VerboseError<&[u8]>>> for PacketError {
    fn from(err: nom::Err<VerboseError<&[u8]>>) -> Self {
        PacketError::NomError
    }
}

// QUIC packet number space.
pub enum Space {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

/// QUIC packet type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// Initial packet.
    Initial,

    /// Retry packet.
    Retry,

    /// Handshake packet.
    Handshake,

    /// 0-RTT packet.
    ZeroRTT,

    /// Version negotiation packet.
    VersionNegotiation,

    /// 1-RTT short header packet.
    Short,
}

impl Type {
    pub fn form_space(s: Space) -> Type {
        match s {
            Space::Initial => Type::Initial,
            Space::Handshake => Type::Handshake,
            Space::Application => Type::Short,
        }
    }

    pub fn to_space(self) -> Result<Space, PacketError> {
        match self {
            Type::Initial => Ok(Space::Initial),
            Type::Handshake => Ok(Space::Handshake),
            Type::Short => Ok(Space::Application),
            Type::ZeroRTT => Ok(Space::Application),
            _ => Err(PacketError::InvalidPacket),
        }
    }
}

/// A QUIC packet's header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// The type of the packet.
    pub ty: Type,

    /// The version of the packet.
    pub version: u32,

    /// The destination connection ID of the packet.
    pub dcid: ConnectionId,

    /// The source connection ID of the packet.
    pub scid: ConnectionId,

    /// The packet number. It's only meaningful after the header protection is
    /// removed.
    pub(crate) pkt_num: u64,

    /// The length of the packet number. It's only meaningful after the header
    /// protection is removed.
    pub(crate) pkt_num_len: usize,

    /// The address verification token of the packet. Only present in `Initial`
    /// and `Retry` packets.
    pub token: Option<Vec<u8>>,

    /// The list of versions in the packet. Only present in
    /// `VersionNegotiation` packets.
    pub versions: Option<Vec<u32>>,

    /// The key phase bit of the packet. It's only meaningful after the header
    /// protection is removed.
    pub(crate) key_phase: bool,

    /// The length of the packet. Only present in `Initial` `ZeroRTT` and `Handshake` packets.
    pub len: Option<usize>,
}

impl Header {
    pub(crate) fn decode(input: &[u8], dcid_len: usize) -> nom::IResult<&[u8], Header> {
        let (remain, first) = be_u8(input)?;
        if !Header::is_long(first) {
            let (remain, dcid) = ConnectionId::from_buf(remain, dcid_len)?;

            return Ok((
                remain,
                Header {
                    ty: Type::Short,
                    version: 0,
                    dcid: dcid,
                    scid: ConnectionId::default(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token: None,
                    versions: None,
                    key_phase: false,
                    len: None,
                },
            ));
        }

        let (remain, version) = be_u32(remain)?;
        let ty = if version == 0 {
            Type::VersionNegotiation
        } else {
            // The next two bits (those with a mask of 0x30) of byte 0 contain a packet type
            match (first & TYPE_MASK) >> 4 {
                0x00 => Type::Initial,
                0x01 => Type::ZeroRTT,
                0x02 => Type::Handshake,
                0x03 => Type::Retry,
                _ => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Char,
                    )))
                }
            }
        };
        let (remain, dcid) = be_connection_id(remain)?;
        let (mut remain, scid) = be_connection_id(remain)?;

        let mut token: Option<Vec<u8>> = None;
        let mut versions: Option<Vec<u32>> = None;

        let mut len = None;

        remain = match ty {
            Type::Initial => {
                let (remain, token_len) = be_varint(remain)?;
                let (remain, token_bytes) =
                    nom::bytes::complete::take(token_len.into_inner())(remain)?;
                if token_len.into_inner() == 0 {
                    token = None
                } else {
                    token = Some(token_bytes.to_vec());
                }
                let (remain, length) = be_varint(remain)?;
                len = Some(length.into_inner() as usize);
                remain
            }
            Type::Handshake | Type::ZeroRTT => {
                let (remain, length) = be_varint(input)?;
                len = Some(length.into_inner() as usize);
                remain
            }
            Type::Retry => {
                todo!("retry token")
            }
            Type::VersionNegotiation => {
                let mut list: Vec<u32> = Vec::new();
                while !remain.is_empty() {
                    let (remain, version) = be_u32(remain)?;
                    list.push(version);
                }
                versions = Some(list);
                remain
            }
            _ => remain,
        };
        Ok((
            remain,
            Header {
                ty,
                version,
                dcid,
                scid,
                pkt_num: 0,
                pkt_num_len: 0,
                token,
                versions,
                key_phase: false,
                len: len,
            },
        ))
    }

    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) -> Result<(), PacketError> {
        let mut first = 0;

        first |= self.pkt_num_len.saturating_sub(1) as u8;
        if self.ty == Type::Short {
            first &= !FORM_BIT;
            first |= FIXED_BIT;
            if self.key_phase {
                first |= KEY_PHASE_BIT;
            } else {
                first &= !KEY_PHASE_BIT;
            }

            out.put_u8(first);
            out.put_slice(&self.dcid);
            return Ok(());
        }
        let ty: u8 = match self.ty {
            Type::Initial => 0x00,
            Type::ZeroRTT => 0x01,
            Type::Handshake => 0x02,
            Type::Retry => 0x03,
            _ => return Err(PacketError::InvalidPacket),
        };

        first |= FORM_BIT | FIXED_BIT | (ty << 4);
        out.put_u8(first);
        out.put_u32(self.version);
        out.put_connection_id(&self.dcid);
        out.put_connection_id(&self.scid);

        match self.ty {
            Type::Initial => {
                match self.token {
                    Some(ref v) => {
                        out.put_varint(&VarInt::from_u64(v.len() as u64).unwrap());
                        out.put_slice(v);
                    }
                    None => {
                        out.put_varint(&VarInt::from_u64(0).unwrap());
                    }
                }
                out.put_u16(0);
                let _ = encode_pkt_num(self.pkt_num, out);
            }
            Type::ZeroRTT | Type::Handshake => {
                out.put_u16(0);
                let _ = encode_pkt_num(self.pkt_num, out);
            }
            Type::Retry => {
                todo!("retry token")
            }

            _ => (),
        }
        Ok(())
    }

    fn is_long(b: u8) -> bool {
        b & FORM_BIT != 0
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8], header_crypto: &dyn crypto::HeaderKey) {
        header_crypto.encrypt(pn_offset, packet);
    }

    fn decrypt(
        &mut self,
        pn_offset: usize,
        packet: &mut [u8],
        header_crypto: &dyn crypto::HeaderKey,
    ) -> Result<(), PacketError> {
        header_crypto.decrypt(pn_offset, packet);
        let first = packet[0];

        if self.ty != Type::VersionNegotiation && self.ty != Type::Retry {
            let pn_length = (packet[0] & PKT_NUM_MASK) + 1;
            let (_, pn) = decode_pkt_num(&packet[pn_offset..], pn_length).map_err(|_| {
                dbg!("decode packet number error");
                PacketError::InvalidPacket
            })?;

            self.pkt_num_len = pn_length as usize;
            self.pkt_num = pn;
        }
        if self.ty == Type::Short {
            self.key_phase = (first & KEY_PHASE_BIT) != 0;
        }
        Ok(())
    }
}

pub fn encrypy_packet(
    header: &Header,
    header_len: usize,
    packet: &mut [u8],
    header_crypto: &dyn crypto::HeaderKey,
    packet_crypto: Option<&dyn crypto::PacketKey>,
) -> Result<(), io::Error> {
    let pn_offset = header_len - header.pkt_num_len;

    if header.ty != Type::VersionNegotiation && header.ty != Type::Retry {
        let len = packet.len() - header_len + header.pkt_num_len;
        let mut slice = &mut packet[pn_offset - 2..pn_offset];
        slice.put_u16(len as u16 | 0b01 << 14);
    }

    if let Some(crypto) = packet_crypto {
        crypto.encrypt(header.pkt_num, packet, header_len);
    }
    header.encrypt(pn_offset, packet, header_crypto);
    Ok(())
}

pub fn decrypt_packet<'a>(
    header: &mut Header,
    pn_offset: usize,
    packet: &'a mut [u8],
    packet_crypto: &dyn crypto::PacketKey,
) -> Result<&'a [u8], PacketError> {
    let header_len = pn_offset + header.pkt_num_len;
    let (header_data, payload) = packet.split_at_mut(header_len);
    let len = packet_crypto
        .decrypt(header.pkt_num, &header_data, payload)
        .map_err(|e| {
            dbg!("decrypt error: {:?}", e);
            PacketError::InvalidPacket
        })?;
    return Ok(&payload[..len]);
}

pub fn pkt_num_len(pn: u64) -> Result<usize, PacketError> {
    let len = if pn < u64::from(u8::MAX) {
        1
    } else if pn < u64::from(u16::MAX) {
        2
    } else if pn < 16_777_215u64 {
        3
    } else if pn < u64::from(u32::MAX) {
        4
    } else {
        return Err(PacketError::InvalidPacket);
    };

    Ok(len)
}

pub fn encode_pkt_num<W: BufMut>(pn: u64, b: &mut W) -> Result<(), PacketError> {
    let len = pkt_num_len(pn)?;
    match len {
        1 => b.put_u8(pn as u8),
        2 => b.put_u16(pn as u16),
        3 => b.put_uint(u64::from(pn), 3),
        4 => b.put_u32(pn as u32),
        _ => return Err(PacketError::InvalidPacket),
    };

    Ok(())
}

pub fn decode_pkt_num(input: &[u8], len: u8) -> IResult<&[u8], u64> {
    let pn = match len {
        1 => {
            let (remain, pn) = be_u8(input)?;
            (remain, pn as u64)
        }
        2 => {
            let (remain, pn) = be_u16(input)?;
            (remain, pn as u64)
        }
        3 => {
            let (remain, pn) = be_u24(input)?;
            (remain, pn as u64)
        }
        4 => {
            let (remain, pn) = be_u32(input)?;
            (remain, pn as u64)
        }
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Char,
            )))
        }
    };

    Ok(pn)
}
#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hex_literal::hex;
    use rustls::Side;

    use crate::quic::crypto::key::initial_keys;

    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = Header {
            ty: Type::Initial,
            version: 1,
            dcid: ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]),
            scid: ConnectionId::from_slice(&[0x05, 0x06, 0x07, 0x08]),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
            len: Some(0),
        };
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        let buf = buf.as_slice();
        let (remain, header2) = Header::decode(buf, 4).unwrap();
        // 剩余 提前填充的 packet number
        assert_eq!(remain.len(), 2);
        assert_eq!(header, header2);
    }

    #[test]
    fn init_packet_crypt() {
        use rustls::quic::Version;

        let dcid = ConnectionId::from_slice(&hex!("06b858ec6f80452b"));
        let client = initial_keys(Version::V1, &dcid, Side::Client);
        let mut buf = BytesMut::new();
        let header = Header {
            ty: Type::Initial,
            version: 0x00000001,
            dcid: dcid,
            scid: ConnectionId::from_slice(&[]),
            pkt_num: 0,
            pkt_num_len: pkt_num_len(0).unwrap(),
            token: None,
            versions: None,
            key_phase: false,
            len: None,
        };
        let ret = header.encode(&mut buf);
        assert!(ret.is_ok());

        let header_len = buf.len();
        buf.resize(
            header_len + client.header.local.sample_size() + client.packet.local.tag_len(),
            0,
        );

        let ret = encrypy_packet(
            &header,
            header_len,
            &mut buf,
            &*client.header.local,
            Some(&*client.packet.local),
        );
        assert!(ret.is_ok());
        for byte in &buf {
            print!("{byte:02x}");
        }
        println!();
        assert_eq!(
            buf[..],
            hex!(
                "c8000000010806b858ec6f80452b00004021be
                 3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1"
            )[..]
        );

        let server = initial_keys(Version::V1, &dcid, Side::Server);
        let len = buf.len();
        let (remain, mut decode_header) = Header::decode(&mut buf, dcid.len()).unwrap();
        let pn_offset = len - remain.len();

        let ret = decode_header.decrypt(pn_offset, &mut buf, &*client.header.local);
        assert!(ret.is_ok());
        let ret = decrypt_packet(
            &mut decode_header,
            pn_offset,
            &mut buf,
            &*server.packet.remote,
        );
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), [0; 16]);
        assert_eq!(
            buf[..header_len],
            hex!("c0000000010806b858ec6f80452b0000402100")[..]
        );
    }
}
