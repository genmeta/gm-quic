use deref_derive::Deref;

/// Supports IQuic version 1, if other versions are supported in the future, add them here.
pub mod v1;

/// The long packet header contains version information, so the packet type of a certain
/// version is considered as one type.
#[derive(Debug, Clone, Copy, Deref, PartialEq, Eq)]
pub struct Version<const N: u32, Ty>(#[deref] pub(crate) Ty);

pub trait GetVersion {
    fn get_version(&self) -> u32;
}

impl<const N: u32, Ty> GetVersion for Version<N, Ty> {
    fn get_version(&self) -> u32 {
        N
    }
}

impl Version<1, v1::Type> {
    pub const RETRY: Self = Self(v1::Type::Retry);
    pub const INITIAL: Self = Self(v1::Type::Initial);
    pub const HANDSHAKE: Self = Self(v1::Type::Handshake);
    pub const ZERO_RTT: Self = Self(v1::Type::ZeroRtt);
}

pub type Ver1 = Version<1, v1::Type>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    VersionNegotiation,
    V1(Version<1, v1::Type>),
    // V2(v2::HeaderType),
}

const LONG_HEADER_BIT: u8 = 0x80;
use super::FIXED_BIT;

pub mod ext {
    use super::*;
    use crate::packet::error::Error;
    use bytes::BufMut;
    use nom::number::streaming::be_u32;

    pub fn parse_long_type(ty: u8) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Type, Error> {
        move |input| {
            // The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation
            // packet. Packets containing a zero value for this bit are not valid packets in this
            // version and MUST be discarded. A value of 1 for this bit allows QUIC to coexist with
            // other protocols; see [RFC7983].
            if ty & super::FIXED_BIT == 0 {
                return Err(nom::Err::Error(Error::InvalidFixedBit));
            }

            let (remain, version) = be_u32(input)?;
            /*
            let (remain, version) = be_u32::<_, ()>(input).map_err(|e| match e {
                ne @ nom::Err::Incomplete(_) => {
                    nom::Err::Error(Error::IncompleteType(ne.to_string()))
                }
                _ => unreachable!("parsing packet type never generates error or failure"),
            })?;
            */
            match version {
                0 => Ok((remain, Type::VersionNegotiation)),
                1 => Ok((remain, Type::V1(Version::<1, v1::Type>(ty.into())))),
                v => Err(nom::Err::Error(Error::UnsupportedVersion(v))),
            }
        }
    }

    pub trait WriteLongType {
        fn put_long_type(&mut self, value: &Type);
    }

    impl<B: BufMut> WriteLongType for B {
        fn put_long_type(&mut self, value: &Type) {
            match value {
                Type::VersionNegotiation => {
                    self.put_u8(LONG_HEADER_BIT);
                    self.put_u32(0);
                }
                Type::V1(Version::<1, _>(ty)) => {
                    let ty: u8 = (*ty).into();
                    self.put_u8(LONG_HEADER_BIT | FIXED_BIT | ty);
                    self.put_u32(1);
                }
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
