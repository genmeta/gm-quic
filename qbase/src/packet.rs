use crate::{
    cid::{be_connection_id, ConnectionId},
    packet_number::PacketNumber,
    varint::{ext::be_varint, VarInt},
};
use bytes::{Bytes, BytesMut};
use nom::ToUsize;
use std::ops::{Deref, DerefMut};

pub trait GetLength {
    /// The length of the remainder of the packet (that is, the Packet Number and Payload fields) in bytes:
    /// * If the header does not have a length field, return None,
    ///   meaning that the subsequent content of the datagram is the data of this packet.
    /// * If the header has a length field, it is not encrypted and can be read directly,
    ///   return Some(length)
    fn get_length(&self) -> Option<usize>;
}

pub trait BeProtected: GetLength {
    fn first_byte_mut(&mut self) -> &mut u8;
}

pub trait RemoveProtection {
    type Target;
    fn remove_protection_with_pn(self, pn: PacketNumber) -> Self::Target;
}

pub trait Validate {
    /// The value included prior to protection MUST be set to 0.
    /// An endpoint MUST treat receipt of a packet that has a non-zero value for these bits
    /// after removing both packet and header protection as a connection error of type
    /// PROTOCOL_VIOLATION. Discarding such a packet after only removing header protection
    /// can expose the endpoint to attacks.
    ///
    /// see [Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2) and
    /// [Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1-4.8) of QUIC.
    fn check_if_reserved_bits_are_zero(&self) -> Result<(), crate::error::Error>;
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

impl GetLength for Initial {
    fn get_length(&self) -> Option<usize> {
        Some(self.length.to_usize())
    }
}

#[derive(Debug, Default, Clone)]
pub struct ZeroRTT {
    pub length: VarInt,
}

impl GetLength for ZeroRTT {
    fn get_length(&self) -> Option<usize> {
        Some(self.length.to_usize())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Handshake {
    pub length: VarInt,
}

impl GetLength for Handshake {
    fn get_length(&self) -> Option<usize> {
        Some(self.length.to_usize())
    }
}

#[derive(Debug, Default, Clone)]
pub struct LongHeaderWrapper<T> {
    pub ty: u8,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub specific: T,
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
pub type RetryHeader = LongHeaderWrapper<Retry>;

pub type ProtectedInitialHeader = LongHeaderWrapper<Initial>;
pub type ProtectedHandshakeHeader = LongHeaderWrapper<Handshake>;
pub type ProtectedZeroRTTHeader = LongHeaderWrapper<ZeroRTT>;

impl<S: GetLength> GetLength for LongHeaderWrapper<S> {
    fn get_length(&self) -> Option<usize> {
        self.specific.get_length()
    }
}

impl<S: GetLength> BeProtected for LongHeaderWrapper<S> {
    fn first_byte_mut(&mut self) -> &mut u8 {
        &mut self.ty
    }
}

#[derive(Debug, Clone)]
pub struct PlainHeaderWrapper<H: BeProtected> {
    pub header: H,
    pub pn: PacketNumber,
}

impl<H: BeProtected> Deref for PlainHeaderWrapper<H> {
    type Target = H;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<H: BeProtected> DerefMut for PlainHeaderWrapper<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

pub type PlainInitialHeader = PlainHeaderWrapper<ProtectedInitialHeader>;
pub type PlainHandshakeHeader = PlainHeaderWrapper<ProtectedHandshakeHeader>;
pub type PlainZeroRTTHeader = PlainHeaderWrapper<ProtectedZeroRTTHeader>;

impl<T: BeProtected> RemoveProtection for LongHeaderWrapper<T> {
    type Target = PlainHeaderWrapper<Self>;

    fn remove_protection_with_pn(self, pn: PacketNumber) -> Self::Target {
        Self::Target { header: self, pn }
    }
}

impl<S: BeProtected> Validate for PlainHeaderWrapper<LongHeaderWrapper<S>> {
    fn check_if_reserved_bits_are_zero(&self) -> Result<(), crate::error::Error> {
        const RESERVED_MASK: u8 = 0x0c;
        let reserved_bit = self.ty & RESERVED_MASK;
        if reserved_bit == 0 {
            Ok(())
        } else {
            Err(crate::error::Error::new_with_default_fty(
                crate::error::ErrorKind::ProtocolViolation,
                format!("invalid reserved bits {reserved_bit}"),
            ))
        }
    }
}

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

/// A packet with a short header does not include a length,
/// so it can only be the last packet included in a UDP datagram.
#[derive(Debug, Default, Clone)]
pub struct ProtectedOneRttHeader {
    pub ty: u8,
    pub dcid: ConnectionId,
}

pub type PlainOneRttHeader = PlainHeaderWrapper<ProtectedOneRttHeader>;

impl GetLength for ProtectedOneRttHeader {
    fn get_length(&self) -> Option<usize> {
        None
    }
}

impl BeProtected for ProtectedOneRttHeader {
    fn first_byte_mut(&mut self) -> &mut u8 {
        &mut self.ty
    }
}

impl Validate for PlainOneRttHeader {
    fn check_if_reserved_bits_are_zero(&self) -> Result<(), crate::error::Error> {
        const RESERVED_MASK: u8 = 0x18;
        let reserved_bit = self.ty & RESERVED_MASK;
        if reserved_bit == 0 {
            Ok(())
        } else {
            Err(crate::error::Error::new_with_default_fty(
                crate::error::ErrorKind::ProtocolViolation,
                format!("invalid reserved bits {reserved_bit}"),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Toggle<const B: u8> {
    #[default]
    Off,
    On,
}

pub type SpinToggle = Toggle<SPIN_BIT>;
pub type KeyPhaseToggle = Toggle<KEY_PHASE_BIT>;

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

impl PlainOneRttHeader {
    pub fn new(
        dcid: ConnectionId,
        spin: Toggle<SPIN_BIT>,
        key_phase: Toggle<KEY_PHASE_BIT>,
        pn: PacketNumber,
    ) -> Self {
        Self {
            header: ProtectedOneRttHeader {
                ty: SHORT_HEADER_BIT | FIXED_BIT | spin.value() | key_phase.value(),
                dcid,
            },
            pn,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProtectedHeader {
    Initial(ProtectedInitialHeader),
    OneRtt(ProtectedOneRttHeader),
    Handshake(ProtectedHandshakeHeader),
    ZeroRTT(ProtectedZeroRTTHeader),
}

#[derive(Debug, Clone)]
pub enum Packet {
    VersionNegotiation(VersionNegotiationHeader),
    Retry(RetryHeader),
    Protected(ProtectedHeader, BytesMut, usize /* pn offset */),
}

pub mod ext {
    use super::*;
    use crate::{cid::WriteConnectionId, packet_number::take_pn_len, varint::ext::BufMutExt};
    use bytes::{BufMut, BytesMut};
    use nom::{
        bytes::streaming::take,
        combinator::{eof, map},
        multi::{length_data, many_till},
        number::streaming::{be_u32, be_u8},
        sequence::pair,
        Err,
    };
    use rustls::quic::DirectionalKeys;

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

    pub struct LongHeaderBuilder {
        ty: u8,
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
    }

    impl LongHeaderBuilder {
        fn new_plain(ty: u8, version: u32, dcid: ConnectionId, scid: ConnectionId) -> Self {
            Self {
                ty,
                version,
                dcid,
                scid,
            }
        }

        pub fn new_version_neotiation(
            dcid: ConnectionId,
            scid: ConnectionId,
        ) -> impl FnOnce(VersionNegotiation) -> VersionNegotiationHeader {
            move |vg| {
                let ty = LONG_HEADER_BIT;
                Self::new_plain(ty, 0, dcid, scid).wrap(vg)
            }
        }

        pub fn new_retry(
            dcid: ConnectionId,
            scid: ConnectionId,
        ) -> impl FnOnce(Retry) -> RetryHeader {
            move |retry| {
                let ty = LONG_HEADER_BIT | FIXED_BIT | RETRY_PACKET_TYPE;
                Self::new_plain(ty, 1, dcid, scid).wrap(retry)
            }
        }

        pub fn new_plain_initial_v1(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | INITIAL_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn new_plain_zero_rtt_v1(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | ZERO_RTT_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn new_plain_handshake_v1(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | HANDSHAKE_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn build<T: BeProtected>(
            self,
            specific: T,
            pn: PacketNumber,
        ) -> PlainHeaderWrapper<LongHeaderWrapper<T>> {
            PlainHeaderWrapper {
                header: LongHeaderWrapper {
                    ty: self.ty,
                    version: self.version,
                    dcid: self.dcid,
                    scid: self.scid,
                    specific,
                },
                pn,
            }
        }

        fn wrap<T>(self, specific: T) -> LongHeaderWrapper<T> {
            LongHeaderWrapper {
                ty: self.ty,
                version: self.version,
                dcid: self.dcid,
                scid: self.scid,
                specific,
            }
        }

        fn parse(
            self,
            ty: u8,
            input: &[u8],
            mut datagram: BytesMut,
        ) -> nom::IResult<&[u8], Packet> {
            if self.version == 0 {
                let (remain, vn) = be_version_negotiation(input)?;
                Ok((remain, Packet::VersionNegotiation(self.wrap(vn))))
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

                let (remain, length, protected_header) = match ty & LONG_PACKET_TYPE_MASK {
                    INITIAL_PACKET_TYPE => {
                        let (remain, initial) = be_initial(input)?;
                        (
                            remain,
                            initial.length.to_usize(),
                            ProtectedHeader::Initial(self.wrap(initial)),
                        )
                    }
                    ZERO_RTT_PACKET_TYPE => {
                        let (remain, zero_rtt) = be_zero_rtt(input)?;
                        (
                            remain,
                            zero_rtt.length.to_usize(),
                            ProtectedHeader::ZeroRTT(self.wrap(zero_rtt)),
                        )
                    }
                    HANDSHAKE_PACKET_TYPE => {
                        let (remain, handshake) = be_handshake(input)?;
                        (
                            remain,
                            handshake.length.to_usize(),
                            ProtectedHeader::Handshake(self.wrap(handshake)),
                        )
                    }
                    RETRY_PACKET_TYPE => {
                        let (remain, retry) = be_retry(input)?;
                        return Ok((remain, Packet::Retry(self.wrap(retry))));
                    }
                    _ => unreachable!(),
                };
                let pn_offset = datagram.len() - remain.len();
                let packet_length = pn_offset + length;
                if length < 20 {
                    return Err(Err::Incomplete(nom::Needed::new(20)));
                }
                if length > remain.len() {
                    return Err(Err::Incomplete(nom::Needed::new(length)));
                }
                datagram.truncate(packet_length);
                Ok((
                    remain,
                    Packet::Protected(protected_header, datagram, pn_offset),
                ))
            }
        }
    }

    pub fn be_packet(
        datagram: BytesMut,
        dcid_len: usize,
    ) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Packet> {
        move |input| {
            let mut datagram = datagram.clone();
            let start = datagram.len() - input.len();
            let _ = datagram.split_to(start);
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
                builder.parse(ty, remain, datagram)
            } else {
                // short header
                let (remain, dcid) = take(dcid_len)(remain)?;
                if remain.len() < 20 {
                    return Err(Err::Incomplete(nom::Needed::new(20)));
                }
                let header = ProtectedOneRttHeader {
                    ty,
                    dcid: ConnectionId::from_slice(dcid),
                };
                let pn_offset = datagram.len() - remain.len();
                Ok((
                    remain,
                    Packet::Protected(ProtectedHeader::OneRtt(header), datagram, pn_offset),
                ))
            }
        }
    }

    /// 此处解析并不涉及去除头部保护、解密数据包的部分，只是解析出包类型、连接ID等信息，
    /// 找到连接ID为进一步向连接交付做准备，去除头部保护、解密数据包的部分则在连接层进行.
    /// 收到的一个数据包是BytesMut，是为了做尽量少的Copy，直到应用层读走
    pub fn parse_packet_from_datagram(datagram: BytesMut) -> Result<Vec<Packet>, ()> {
        let raw = datagram.clone();
        let input = datagram.as_ref();
        let (_, (packets, _)) = many_till(be_packet(raw, 16), eof)(input).map_err(|_ne| ())?;
        Ok(packets)
    }

    pub fn decrypt<H, T>(
        mut protected: H,
        mut packet: BytesMut,
        pn_offset: usize,
        expected_pn: u64,
        remote_keys: &DirectionalKeys,
    ) -> Result<(u64, Bytes), rustls::Error>
    where
        H: BeProtected + RemoveProtection<Target = T>,
        T: Validate,
    {
        use nom::error::Error as NomError;
        let first_byte = protected.first_byte_mut();
        let (_, payload) = packet.split_at_mut(pn_offset);
        let (pn_bytes, sample) = payload.split_at_mut(4);
        remote_keys
            .header
            .decrypt_in_place(sample, first_byte, pn_bytes)?;

        let pn_len = *first_byte & PN_LEN_MASK + 1;
        let header_offset = pn_offset + pn_len as usize;
        let pn_bytes = &payload[pn_offset..header_offset];
        let (_, pn) = take_pn_len(pn_len)(pn_bytes).map_err(|_ne: nom::Err<NomError<&[u8]>>| {
            rustls::Error::General(format!("parse pn error: {:?}", _ne))
        })?;

        let target = protected.remove_protection_with_pn(pn);
        target
            .check_if_reserved_bits_are_zero()
            .map_err(|e| rustls::Error::General(format!("validate reserve bit error: {:?}", e)))?;

        let mut body = packet.split_off(header_offset);
        let header = packet.freeze();
        let pn = pn.decode(expected_pn);
        remote_keys
            .packet
            .decrypt_in_place(pn, &header, &mut body)?;
        Ok((pn, body.freeze()))
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

    pub trait WriteOneRttHeader {
        fn put_one_rtt_header(&mut self, header: &ProtectedOneRttHeader);
    }

    impl<T: BufMut> WriteOneRttHeader for T {
        fn put_one_rtt_header(&mut self, header: &ProtectedOneRttHeader) {
            self.put_u8(header.ty);
            self.put_connection_id(&header.dcid);
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
