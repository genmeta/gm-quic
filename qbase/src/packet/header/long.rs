use super::*;
use crate::{
    cid::ConnectionId,
    error::{Error as QuicError, ErrorKind},
    varint::VarInt,
};
use deref_derive::{Deref, DerefMut};
use nom::ToUsize;

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

macro_rules! protect {
    ($($type:ty),*) => {
        $(
            impl super::Protect for $type {}

            impl super::GetLength for $type {
                fn get_length(&self) -> usize {
                    self.length.to_usize()
                }
            }
        )*
    };
}

protect!(Initial, ZeroRTT, Handshake);

#[derive(Debug, Default, Clone, Deref, DerefMut)]
pub struct LongHeaderWrapper<T> {
    pub ty: u8,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    #[deref]
    pub specific: T,
}

impl<T> super::GetVersion for LongHeaderWrapper<T> {
    fn get_version(&self) -> u32 {
        self.version
    }
}

impl<T> super::GetDcid for LongHeaderWrapper<T> {
    fn get_dcid(&self) -> &ConnectionId {
        &self.dcid
    }
}

pub type VersionNegotiationHeader = LongHeaderWrapper<VersionNegotiation>;
pub type RetryHeader = LongHeaderWrapper<Retry>;

pub type ProtectedInitialHeader = LongHeaderWrapper<Initial>;
pub type ProtectedHandshakeHeader = LongHeaderWrapper<Handshake>;
pub type ProtectedZeroRTTHeader = LongHeaderWrapper<ZeroRTT>;

impl<S: super::Protect> super::BeProtected for LongHeaderWrapper<S> {
    fn cipher_packet_type(&self) -> u8 {
        self.ty
    }
}

impl<S: super::Protect> super::RemoveProtection for LongHeaderWrapper<S> {
    fn remove_protection(mut self, plain_packet_type: u8) -> Result<u8, QuicError> {
        self.ty = plain_packet_type;
        let plain_header = PlainHeaderWrapper(self);
        plain_header.pn_len()
    }
}

impl<S: super::GetLength> super::GetLength for LongHeaderWrapper<S> {
    fn get_length(&self) -> usize {
        self.specific.get_length()
    }
}

pub type PlainInitialHeader = PlainHeaderWrapper<ProtectedInitialHeader>;
pub type PlainHandshakeHeader = PlainHeaderWrapper<ProtectedHandshakeHeader>;
pub type PlainZeroRTTHeader = PlainHeaderWrapper<ProtectedZeroRTTHeader>;

impl<S: super::Protect> super::BePlain for PlainHeaderWrapper<LongHeaderWrapper<S>> {
    fn pn_len(&self) -> Result<u8, QuicError> {
        const RESERVED_MASK: u8 = 0x0c;
        let reserved_bit = self.ty & RESERVED_MASK;
        if reserved_bit == 0 {
            Ok((self.ty & super::PN_LEN_MASK) + 1)
        } else {
            Err(QuicError::new_with_default_fty(
                ErrorKind::ProtocolViolation,
                format!("invalid reserved bits {reserved_bit}"),
            ))
        }
    }
}

pub mod ext {
    use super::*;
    use crate::{
        cid::WriteConnectionId,
        packet::{self, Packet, ProtectedPacket},
        varint::ext::{be_varint, BufMutExt},
    };
    use bytes::{BufMut, BytesMut};
    use nom::{
        bytes::streaming::take,
        combinator::{eof, map},
        multi::{length_data, many_till},
        number::streaming::be_u32,
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

    pub struct LongHeaderBuilder {
        pub(crate) ty: u8,
        pub(crate) version: u32,
        pub(crate) dcid: ConnectionId,
        pub(crate) scid: ConnectionId,
    }

    impl LongHeaderBuilder {
        pub fn new_plain(ty: u8, version: u32, dcid: ConnectionId, scid: ConnectionId) -> Self {
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
                let ty = super::LONG_HEADER_BIT;
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

        pub fn new_plain_initial(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | INITIAL_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn new_plain_zero_rtt(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | ZERO_RTT_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn new_plain_handshake(dcid: ConnectionId, scid: ConnectionId) -> Self {
            let ty = LONG_HEADER_BIT | FIXED_BIT | HANDSHAKE_PACKET_TYPE;
            Self::new_plain(ty, 1, dcid, scid)
        }

        pub fn build<T: Protect>(self, specific: T) -> PlainHeaderWrapper<LongHeaderWrapper<T>> {
            PlainHeaderWrapper(LongHeaderWrapper {
                ty: self.ty,
                version: self.version,
                dcid: self.dcid,
                scid: self.scid,
                specific,
            })
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

        pub fn parse(
            self,
            ty: u8,
            input: &[u8],
            raw_data: BytesMut,
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

                match ty & LONG_PACKET_TYPE_MASK {
                    INITIAL_PACKET_TYPE => {
                        let (remain, initial) = be_initial(input)?;
                        let (remain, packet) =
                            packet::ext::complete(self.wrap(initial), raw_data, remain)?;
                        Ok((remain, Packet::Protected(ProtectedPacket::Initial(packet))))
                    }
                    ZERO_RTT_PACKET_TYPE => {
                        let (remain, zero_rtt) = be_zero_rtt(input)?;
                        let (remain, packet) =
                            packet::ext::complete(self.wrap(zero_rtt), raw_data, remain)?;
                        Ok((remain, Packet::Protected(ProtectedPacket::ZeroRtt(packet))))
                    }
                    HANDSHAKE_PACKET_TYPE => {
                        let (remain, handshake) = be_handshake(input)?;
                        let (remain, packet) =
                            packet::ext::complete(self.wrap(handshake), raw_data, remain)?;
                        Ok((
                            remain,
                            Packet::Protected(ProtectedPacket::Handshake(packet)),
                        ))
                    }
                    RETRY_PACKET_TYPE => {
                        let (remain, retry) = be_retry(input)?;
                        Ok((remain, Packet::Retry(self.wrap(retry))))
                    }
                    _ => unreachable!(),
                }
            }
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

    pub trait WriteLongHeader<T> {
        fn write_long_header(&mut self, wrapper: &LongHeaderWrapper<T>);
    }

    impl<T, S> WriteLongHeader<S> for T
    where
        T: BufMut + Write<S>,
    {
        fn write_long_header(&mut self, long_header: &LongHeaderWrapper<S>) {
            self.put_u8(long_header.ty);
            self.put_u32(long_header.version);
            self.put_connection_id(&long_header.dcid);
            self.put_connection_id(&long_header.scid);
            self.write_specific(&long_header.specific);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4)
    }
}
