use std::io;

use bytes::{BufMut, Bytes};
use nom::number::complete::{be_u32, be_u8};
use qbase::varint::{
    ext::{be_varint, BufMutExt},
    VarInt,
};

use super::cid::ConnectionId;

const FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const KEY_PHASE_BIT: u8 = 0x04;

const TYPE_MASK: u8 = 0x30;
const PKT_NUM_MASK: u8 = 0x03;

pub const MAX_CID_LEN: u8 = 20;

pub const MAX_PKT_NUM_LEN: usize = 4;

const SAMPLE_LEN: usize = 16;

pub enum PackeError {
    InvalidPacket,
    UnexpectedEnd,
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for PackeError {
    fn from(err: nom::Err<(&[u8], nom::error::ErrorKind)>) -> PackeError {
        dbg!("nom parse error {}", err);
        PackeError::UnexpectedEnd
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

    pub fn to_space(self) -> Result<Space, PackeError> {
        match self {
            Type::Initial => Ok(Space::Initial),
            Type::Handshake => Ok(Space::Handshake),
            Type::Short => Ok(Space::Application),
            Type::ZeroRTT => Ok(Space::Application),
            _ => Err(PackeError::InvalidPacket),
        }
    }
}

/// A QUIC packet's header.
#[derive(Clone, PartialEq, Eq)]
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
}

impl Header {
    pub(crate) fn decode(input: &[u8], dcid_len: usize) -> Result<Header, PackeError> {
        let (remain, first) = be_u8(input)?;
        if !Header::is_long(first) {
            let (remian, dcid) =
                ConnectionId::from_buf(remain, dcid_len).map_err(|_| PackeError::InvalidPacket)?;

            return Ok(Header {
                ty: Type::Short,
                version: 0,
                dcid: dcid,
                scid: ConnectionId::default(),
                pkt_num: 0,
                pkt_num_len: 0,
                token: None,
                versions: None,
                key_phase: false,
            });
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
                _ => return Err(PackeError::InvalidPacket),
            }
        };
        let (remain, dcid) =
            ConnectionId::decode_long(remain).map_err(|_| PackeError::InvalidPacket)?;
        let (remain, scid) =
            ConnectionId::decode_long(remain).map_err(|_| PackeError::InvalidPacket)?;

        let mut token: Option<Vec<u8>> = None;
        let mut versions: Option<Vec<u32>> = None;

        match ty {
            Type::Initial => {
                let (remain, token_len) =
                    be_varint(remain).map_err(|_| PackeError::InvalidPacket)?;
                let (remain, token) = nom::bytes::complete::take(token_len.into_inner())(remain)?;
            }
            Type::Retry => {
                todo!("retry token")
            }
            Type::VersionNegotiation => {
                let mut list: Vec<u32> = Vec::new();
                while !remain.is_empty() {
                    let (remian, version) = be_u32(remain)?;
                    list.push(version);
                }
                versions = Some(list);
            }
            _ => (),
        }
        Ok(Header {
            ty,
            version,
            dcid: dcid.into(),
            scid: scid.into(),
            pkt_num: 0,
            pkt_num_len: 0,
            token,
            versions,
            key_phase: false,
        })
    }

    pub(crate) fn encode<W: BufMut>(&self, out: &mut W) -> Result<(), PackeError> {
        let mut first = 0;

        // Encode pkt num length.
        first |= self.pkt_num_len.saturating_sub(1) as u8;
        // Encode short header.
        if self.ty == Type::Short {
            // Unset form bit for short header.
            first &= !FORM_BIT;

            // Set fixed bit.
            first |= FIXED_BIT;

            // Set key phase bit.
            if self.key_phase {
                first |= KEY_PHASE_BIT;
            } else {
                first &= !KEY_PHASE_BIT;
            }

            out.put_u8(first);
            out.put_slice(&self.dcid);
            return Ok(());
        }

        // Encode long header.
        let ty: u8 = match self.ty {
            Type::Initial => 0x00,
            Type::ZeroRTT => 0x01,
            Type::Handshake => 0x02,
            Type::Retry => 0x03,
            _ => return Err(PackeError::InvalidPacket),
        };

        first |= FORM_BIT | FIXED_BIT | (ty << 4);
        out.put_u8(first);
        out.put_u32(self.version);
        self.dcid.encode_long(out);
        self.scid.encode_long(out);

        // Only Initial and Retry packets have a token.
        match self.ty {
            Type::Initial => {
                match self.token {
                    Some(ref v) => {
                        let len = VarInt::from_u64(v.len() as u64).unwrap();
                        out.put_varint(&len);
                        out.put_slice(v);
                    }
                    // No token, so length = 0.
                    None => {
                        out.put_varint(&VarInt::from_u64(0).unwrap());
                    }
                }
            }
            Type::Retry => {
                // Retry packets don't have a token length.
                todo!("retry token")
            }

            _ => (),
        }
        Ok(())
    }

    fn is_long(b: u8) -> bool {
        b & FORM_BIT != 0
    }
}

pub fn pkt_num_len(pn: u64) -> Result<usize, PackeError> {
    let len = if pn < u64::from(u8::MAX) {
        1
    } else if pn < u64::from(u16::MAX) {
        2
    } else if pn < 16_777_215u64 {
        3
    } else if pn < u64::from(u32::MAX) {
        4
    } else {
        return Err(PackeError::InvalidPacket);
    };

    Ok(len)
}
