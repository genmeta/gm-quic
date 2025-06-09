use bytes::{BufMut, BytesMut, buf::UninitSlice};
use derive_more::{Deref, DerefMut};
use encrypt::{encode_long_first_byte, encode_short_first_byte, encrypt_packet, protect_header};
use enum_dispatch::enum_dispatch;
use getset::CopyGetters;
use header::{LongHeader, io::WriteHeader};

use crate::{
    cid::ConnectionId,
    frame::{
        ContainSpec, FrameFeture, FrameType, Spec,
        io::{WriteDataFrame, WriteFrame},
    },
    net::tx::Signals,
    packet::keys::DirectionalKeys,
    util::{DescribeData, WriteData},
    varint::{EncodeBytes, VarInt, WriteVarInt},
};

/// QUIC packet parse error definitions.
pub mod error;

/// Define signal util, such as key phase bit and spin bit.
pub mod signal;
#[doc(hidden)]
pub use signal::{KeyPhaseBit, SpinBit};

/// Definitions of QUIC packet types.
pub mod r#type;
#[doc(hidden)]
pub use r#type::{
    GetPacketNumberLength, LONG_RESERVED_MASK, LongSpecificBits, SHORT_RESERVED_MASK,
    ShortSpecificBits, Type,
};

/// Definitions of QUIC packet headers.
pub mod header;
#[doc(hidden)]
pub use header::{
    EncodeHeader, GetDcid, GetType, HandshakeHeader, Header, InitialHeader, LongHeaderBuilder,
    OneRttHeader, RetryHeader, VersionNegotiationHeader, ZeroRttHeader, long,
};

/// The io module provides the functions to parse the QUIC packet.
///
/// The writing of the QUIC packet is not provided here, they are written in place.
pub mod io;
pub use io::{FinalPacketLayout, PacketLayout, PacketWriter};

/// Encoding and decoding of packet number
pub mod number;
#[doc(hidden)]
pub use number::{InvalidPacketNumber, PacketNumber, WritePacketNumber, take_pn_len};

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
///               +---> encoded pn length       +---> encoded packet number
/// ```
#[derive(Debug, Clone, Deref, DerefMut)]
pub struct DataPacket {
    #[deref]
    #[deref_mut]
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

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum PacketContains {
    #[default]
    NonAckEliciting,
    JustPing,
    EffectivePayload,
}

impl PacketContains {
    pub fn include(self, frame_type: FrameType) -> Self {
        match frame_type {
            FrameType::Ping if self != PacketContains::EffectivePayload => Self::JustPing,
            fty if !fty.specs().contain(Spec::NonAckEliciting) => Self::EffectivePayload,
            _ => self,
        }
    }

    pub fn ack_eliciting(self) -> bool {
        self != Self::NonAckEliciting
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
    raw_bytes: BytesMut,
    dcid_len: usize,
    // TODO: 添加level，各种包类型顺序不能错乱，否则失败
}

impl PacketReader {
    pub fn new(raw_bytes: BytesMut, dcid_len: usize) -> Self {
        Self {
            raw_bytes,
            dcid_len,
        }
    }
}

impl Iterator for PacketReader {
    type Item = Result<Packet, error::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw_bytes.is_empty() {
            return None;
        }

        match io::be_packet(&mut self.raw_bytes, self.dcid_len) {
            Ok(packet) => Some(Ok(packet)),
            Err(e) => {
                tracing::debug!(error = ?e, "dropped unparsed packet");
                self.raw_bytes.clear(); // no longer parsing
                Some(Err(e))
            }
        }
    }
}

/// During the formation of a packet, various frames are arranged into the packet.
pub trait MarshalFrame<F> {
    fn dump_frame(&mut self, frame: F) -> Option<F>;
}

pub trait MarshalDataFrame<F, D> {
    fn dump_frame_with_data(&mut self, frame: F, data: D) -> Option<F>;
}

/// Mainly customized for PathChallengeFrame and PathResponseFrame.
/// These frames are sent in the data space but do not need to be
/// reliably guaranteed in the data space.
pub trait MarshalPathFrame<F> {
    fn dump_path_frame(&mut self, frame: F);
}

enum Keys {
    LongHeaderPacket {
        keys: DirectionalKeys,
    },
    ShortHeaderPacket {
        keys: DirectionalKeys,
        key_phase: KeyPhaseBit,
    },
}

impl Keys {
    fn hpk(&self) -> &dyn rustls::quic::HeaderProtectionKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.header.as_ref()
            }
        }
    }

    fn pk(&self) -> &dyn rustls::quic::PacketKey {
        match self {
            Self::LongHeaderPacket { keys } | Self::ShortHeaderPacket { keys, .. } => {
                keys.packet.as_ref()
            }
        }
    }

    fn key_phase(&self) -> Option<KeyPhaseBit> {
        match self {
            Self::LongHeaderPacket { .. } => None,
            Self::ShortHeaderPacket { key_phase, .. } => Some(*key_phase),
        }
    }
}
