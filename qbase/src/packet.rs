use crate::{
    cid::{be_connection_id, ConnectionId},
    error::Error,
    varint::{ext::be_varint, VarInt},
};
use enum_dispatch::enum_dispatch;
use std::ops::{Deref, DerefMut};

#[enum_dispatch]
pub trait BePacket {
    fn packet_type(&self) -> u8;

    fn packet_type_mut(&mut self) -> &mut u8;
}

#[derive(Debug, Default, Clone)]
pub struct VersionNegotiation {
    pub versions: Vec<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct Retry {
    pub token: Vec<u8>,
    pub integrity: [u8; 16],
}

impl Retry {
    fn from_slice(token: &[u8], integrity: &[u8]) -> Self {
        let mut retry = Retry {
            token: Vec::from(token),
            integrity: [0; 16],
        };
        retry.integrity.copy_from_slice(integrity);
        retry
    }
}

#[derive(Debug, Default, Clone)]
pub struct Initial {
    pub token: Vec<u8>,
    pub length: VarInt,
}

#[derive(Debug, Default, Clone)]
pub struct ZeroRTT {
    pub length: VarInt,
}

#[derive(Debug, Default, Clone)]
pub struct Handshake {
    pub length: VarInt,
}

#[derive(Debug, Default, Clone)]
pub struct LongHeaderWrapper<T> {
    pub ty: u8,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub specific: T,
}

impl<T> BePacket for LongHeaderWrapper<T> {
    fn packet_type(&self) -> u8 {
        self.ty
    }

    fn packet_type_mut(&mut self) -> &mut u8 {
        &mut self.ty
    }
}

impl<T> Deref for LongHeaderWrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.specific
    }
}

impl<T> DerefMut for LongHeaderWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.specific
    }
}

pub type VersionNegotiationHeader = LongHeaderWrapper<VersionNegotiation>;
pub type InitialHeader = LongHeaderWrapper<Initial>;
pub type HandshakeHeader = LongHeaderWrapper<Handshake>;
pub type ZeroRTTHeader = LongHeaderWrapper<ZeroRTT>;
pub type RetryHeader = LongHeaderWrapper<Retry>;

/// header form bit
const HEADER_FORM_MASK: u8 = 0x80;
const LONG_HEADER_BIT: u8 = 0x80;
const SHORT_HEADER_BIT: u8 = 0x00;
/// The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
const FIXED_BIT: u8 = 0x40;
/// The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const INITIAL_PACKET_TYPE: u8 = 0x00;
const ZERO_RTT_PACKET_TYPE: u8 = 0x10;
const HANDSHAKE_PACKET_TYPE: u8 = 0x20;
const RETRY_PACKET_TYPE: u8 = 0x30;
/// The latency spin bit in 1-RTT packets
const SPIN_BIT: u8 = 0x20;
/// The key phase bit in 1-RTT packets
const KEY_PHASE_BIT: u8 = 0x04;
/// The least significant two bits (those with a mask of 0x03)
/// of byte 0 contain the length of the Packet Number field
const PN_LEN_MASK: u8 = 0x03;

impl VersionNegotiationHeader {
    pub fn new(dcid: ConnectionId, scid: ConnectionId, supported_versions: Vec<u32>) -> Self {
        Self {
            ty: LONG_HEADER_BIT,
            version: 0,
            dcid,
            scid,
            specific: VersionNegotiation {
                versions: supported_versions,
            },
        }
    }
}

impl RetryHeader {
    pub fn new(
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
        token: &[u8],
        integrity: &[u8],
    ) -> Self {
        Self {
            ty: LONG_HEADER_BIT | FIXED_BIT | RETRY_PACKET_TYPE,
            version,
            dcid,
            scid,
            specific: Retry::from_slice(token, integrity),
        }
    }
}

impl InitialHeader {
    pub fn new(
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
        token: &[u8],
        length: VarInt,
    ) -> Self {
        Self {
            ty: LONG_HEADER_BIT | FIXED_BIT | INITIAL_PACKET_TYPE,
            version,
            dcid,
            scid,
            specific: Initial {
                token: Vec::from(token),
                length,
            },
        }
    }

    pub fn pn_len(&self) -> u8 {
        self.ty & PN_LEN_MASK
    }
}

impl ZeroRTTHeader {
    pub fn new(version: u32, dcid: ConnectionId, scid: ConnectionId, length: VarInt) -> Self {
        Self {
            ty: LONG_HEADER_BIT | FIXED_BIT | ZERO_RTT_PACKET_TYPE,
            version,
            dcid,
            scid,
            specific: ZeroRTT { length },
        }
    }

    pub fn pn_len(&self) -> u8 {
        self.ty & PN_LEN_MASK
    }
}

impl HandshakeHeader {
    pub fn new(version: u32, dcid: ConnectionId, scid: ConnectionId, length: VarInt) -> Self {
        Self {
            ty: LONG_HEADER_BIT | FIXED_BIT | HANDSHAKE_PACKET_TYPE,
            version,
            dcid,
            scid,
            specific: Handshake { length },
        }
    }

    pub fn pn_len(&self) -> u8 {
        self.ty & PN_LEN_MASK
    }
}

#[derive(Debug, Clone)]
#[enum_dispatch(BePacket)]
pub enum LongHeader {
    VersionNegotiation(VersionNegotiationHeader),
    Retry(RetryHeader),
    Initial(InitialHeader),
    ZeroRTT(ZeroRTTHeader),
    Handshake(HandshakeHeader),
}

#[derive(Debug, Default, Clone)]
pub struct OneRttHeader {
    pub ty: u8,
    pub dcid: ConnectionId,
}

impl BePacket for OneRttHeader {
    fn packet_type(&self) -> u8 {
        self.ty
    }

    fn packet_type_mut(&mut self) -> &mut u8 {
        &mut self.ty
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Toggle<const B: u8> {
    #[default]
    Off,
    On,
}

impl<const B: u8> Toggle<B> {
    pub fn change(&mut self) {
        *self = match self {
            Toggle::Off => Toggle::On,
            Toggle::On => Toggle::Off,
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Toggle::Off => 0,
            Toggle::On => B,
        }
    }
}

impl OneRttHeader {
    pub fn new(
        dcid: ConnectionId,
        spin: Toggle<SPIN_BIT>,
        key_phase: Toggle<KEY_PHASE_BIT>,
    ) -> Self {
        Self {
            ty: SHORT_HEADER_BIT | FIXED_BIT | spin.value() | key_phase.value(),
            dcid,
        }
    }

    pub fn pn_len(&self) -> u8 {
        self.ty & PN_LEN_MASK
    }
}

#[derive(Debug, Clone)]
#[enum_dispatch(BePacket)]
pub enum Header {
    Long(LongHeader),
    Short(OneRttHeader),
}

impl Header {
    /// An endpoint MUST treat receipt of a packet that has a non-zero value for these bits
    /// after removing both packet and header protection as a connection error of type
    /// PROTOCOL_VIOLATION. Discarding such a packet after only removing header protection
    /// can expose the endpoint to attacks.
    ///
    /// see Section 9.5 of [QUIC-TLS].
    ///
    /// Must be called after removing header protection
    pub fn check_if_reserved_bits_zero(&self) -> Result<(), Error> {
        match self {
            Header::Long(long_header) => {
                let reserve_bit = long_header.packet_type() & 0x0c;
                if matches!(
                    long_header,
                    LongHeader::Initial(_) | LongHeader::Handshake(_) | LongHeader::ZeroRTT(_)
                ) && reserve_bit == 0
                {
                    Ok(())
                } else {
                    Err(Error::new_with_default_fty(
                        crate::error::ErrorKind::ProtocolViolation,
                        format!("invalid reserved bits {reserve_bit}"),
                    ))
                }
            }
            Header::Short(one_rtt_header) => {
                if one_rtt_header.ty & 0x18 == 0 {
                    Ok(())
                } else {
                    Err(Error::new_with_default_fty(
                        crate::error::ErrorKind::ProtocolViolation,
                        "invalid reserved bits",
                    ))
                }
            }
        }
    }
}

pub mod ext {
    use super::*;
    use crate::{cid::WriteConnectionId, varint::ext::BufMutExt};
    use bytes::{BufMut, BytesMut};
    use nom::{
        bytes::streaming::take,
        combinator::{eof, map},
        multi::{length_data, many_till},
        number::streaming::{be_u32, be_u8},
        sequence::pair,
        Err,
    };

    fn be_version_negotiation(input: &[u8]) -> nom::IResult<&[u8], VersionNegotiation> {
        let (remain, (versions, _)) = many_till(be_u32, eof)(input)?;
        Ok((remain, VersionNegotiation { versions }))
    }

    fn be_initial(input: &[u8]) -> nom::IResult<&[u8], Initial> {
        map(
            pair(length_data(be_varint), be_varint),
            |(token, length)| Initial {
                token: Vec::from(token),
                length,
            },
        )(input)
    }

    fn be_zero_rtt(input: &[u8]) -> nom::IResult<&[u8], ZeroRTT> {
        map(be_varint, |length| ZeroRTT { length })(input)
    }

    fn be_handshake(input: &[u8]) -> nom::IResult<&[u8], Handshake> {
        map(be_varint, |length| Handshake { length })(input)
    }

    fn be_retry(input: &[u8]) -> nom::IResult<&[u8], Retry> {
        if input.len() < 16 {
            return Err(Err::Incomplete(nom::Needed::new(16)));
        }
        let token_length = input.len() - 16;
        let (integrity, token) = take(token_length)(input)?;
        Ok((&[][..], Retry::from_slice(token, integrity)))
    }

    struct LongHeaderBuilder {
        ty: u8,
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
    }

    impl LongHeaderBuilder {
        fn wrap<T>(self, specific: T) -> LongHeaderWrapper<T> {
            LongHeaderWrapper {
                ty: self.ty,
                version: self.version,
                dcid: self.dcid,
                scid: self.scid,
                specific,
            }
        }

        fn parse(self, ty: u8, input: &[u8]) -> nom::IResult<&[u8], LongHeader> {
            if self.version == 0 {
                let (remain, vn) = be_version_negotiation(input)?;
                Ok((remain, LongHeader::VersionNegotiation(self.wrap(vn))))
            } else {
                // The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation
                // packet. Packets containing a zero value for this bit are not valid packets in this
                // version and MUST be discarded. A value of 1 for this bit allows QUIC to coexist with
                // other protocols; see [RFC7983].
                if ty & FIXED_BIT == 0 {
                    return Err(Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Fix,
                    )));
                }

                match ty & LONG_PACKET_TYPE_MASK {
                    INITIAL_PACKET_TYPE => {
                        let (remain, initial) = be_initial(input)?;
                        Ok((remain, LongHeader::Initial(self.wrap(initial))))
                    }
                    ZERO_RTT_PACKET_TYPE => {
                        let (remain, zero_rtt) = be_zero_rtt(input)?;
                        Ok((remain, LongHeader::ZeroRTT(self.wrap(zero_rtt))))
                    }
                    HANDSHAKE_PACKET_TYPE => {
                        let (remain, handshake) = be_handshake(input)?;
                        Ok((remain, LongHeader::Handshake(self.wrap(handshake))))
                    }
                    RETRY_PACKET_TYPE => {
                        let (remain, retry) = be_retry(input)?;
                        Ok((remain, LongHeader::Retry(self.wrap(retry))))
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    pub fn be_header(input: &[u8], dcid_len: usize) -> nom::IResult<&[u8], Header> {
        let (remain, ty) = be_u8(input)?;
        if ty & HEADER_FORM_MASK == LONG_HEADER_BIT {
            // long header
            let (remain, version) = be_u32(remain)?;
            let (remain, scid) = be_connection_id(remain)?;
            let (remain, dcid) = be_connection_id(remain)?;
            let builder = LongHeaderBuilder {
                ty,
                version,
                dcid,
                scid,
            };
            let (remain, long_header) = builder.parse(ty, remain)?;
            Ok((remain, Header::Long(long_header)))
        } else {
            // short header
            let (remain, dcid) = take(dcid_len)(remain)?;
            let header = OneRttHeader {
                ty,
                dcid: ConnectionId::from_slice(dcid),
            };
            Ok((remain, Header::Short(header)))
        }
    }

    /// 此处解析并不涉及去除头部保护、解密数据包的部分，只是解析出包类型、连接ID等信息，
    /// 找到连接ID为进一步向连接交付做准备，去除头部保护、解密数据包的部分则在连接层进行.
    /// 收到的一个数据包是BytesMut，是为了做尽量少的Copy，直到应用层读走
    pub fn parse_packet(mut datagram: BytesMut, dcid_len: usize) -> Option<(Header, BytesMut)> {
        let datagram_len = datagram.len();
        if let Some((remain, header)) = be_header(&datagram, dcid_len).ok() {
            let offset = datagram_len - remain.len();
            unsafe { datagram.advance_mut(offset) };
            Some((header, datagram))
        } else {
            None
        }
    }

    trait Write<S> {
        fn write_specific(&mut self, specific: &S);
    }

    impl<T: BufMut> Write<VersionNegotiation> for T {
        fn write_specific(&mut self, specific: &VersionNegotiation) {
            for version in &specific.versions {
                self.put_u32(*version);
            }
        }
    }

    impl<T: BufMut> Write<Retry> for T {
        fn write_specific(&mut self, specific: &Retry) {
            self.put_slice(&specific.integrity);
            self.put_slice(&specific.token);
        }
    }

    impl<T: BufMut> Write<Initial> for T {
        fn write_specific(&mut self, specific: &Initial) {
            self.put_varint(&specific.length);
            self.put_slice(&specific.token);
        }
    }

    impl<T: BufMut> Write<ZeroRTT> for T {
        fn write_specific(&mut self, specific: &ZeroRTT) {
            self.put_varint(&specific.length);
        }
    }

    impl<T: BufMut> Write<Handshake> for T {
        fn write_specific(&mut self, specific: &Handshake) {
            self.put_varint(&specific.length);
        }
    }

    pub trait WriteLongHeaderWrapper<T> {
        fn write_long_header_wrapper(&mut self, wrapper: &LongHeaderWrapper<T>);
    }

    impl<T, S> WriteLongHeaderWrapper<S> for T
    where
        T: BufMut + Write<S>,
    {
        fn write_long_header_wrapper(&mut self, wrapper: &LongHeaderWrapper<S>) {
            self.put_u8(wrapper.ty);
            self.put_u32(wrapper.version);
            self.put_connection_id(&wrapper.dcid);
            self.put_connection_id(&wrapper.scid);
            self.write_specific(&wrapper.specific);
        }
    }

    pub trait WriteLongHeader {
        fn write_long_header(&mut self, header: &LongHeader);
    }

    impl<T: BufMut> WriteLongHeader for T {
        fn write_long_header(&mut self, header: &LongHeader) {
            match header {
                LongHeader::Handshake(header) => self.write_long_header_wrapper(header),
                LongHeader::Initial(header) => self.write_long_header_wrapper(header),
                LongHeader::ZeroRTT(header) => self.write_long_header_wrapper(header),
                LongHeader::Retry(header) => self.write_long_header_wrapper(header),
                LongHeader::VersionNegotiation(header) => self.write_long_header_wrapper(header),
            }
        }
    }

    pub trait WriteOneRttHeader {
        fn put_one_rtt_header(&mut self, header: &OneRttHeader);
    }

    impl<T: BufMut> WriteOneRttHeader for T {
        fn put_one_rtt_header(&mut self, header: &OneRttHeader) {
            self.put_u8(header.ty);
            self.put_connection_id(&header.dcid);
        }
    }

    pub trait WriteHeader {
        fn pub_header(&mut self, header: &Header);
    }

    impl<T: BufMut> WriteHeader for T {
        fn pub_header(&mut self, header: &Header) {
            match header {
                Header::Long(header) => self.write_long_header(header),
                Header::Short(header) => self.put_one_rtt_header(header),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::RetryHeader;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);

        let retry_packet = RetryHeader::default();
        let token = &retry_packet.token;
        println!("{:?}", token);
    }
}
