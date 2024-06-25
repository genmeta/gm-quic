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
    use bytes::BufMut;
    use nom::number::streaming::be_u32;

    use super::*;
    use crate::packet::error::Error;

    pub fn parse_long_type(ty: u8) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], Type, Error> {
        move |input| {
            let (remain, version) = be_u32(input)?;
            match version {
                0 => Ok((remain, Type::VersionNegotiation)),
                1 => Ok((
                    remain,
                    Type::V1(Version::<1, v1::Type>(
                        ty.try_into().map_err(nom::Err::Error)?,
                    )),
                )),
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
    use crate::packet::r#type::long::Ver1;

    #[test]
    fn test_read_long_type() {
        use super::{ext::parse_long_type, Type};

        let buf = vec![0x00, 0x00, 0x00, 0x01];
        let (remain, ty) = parse_long_type(0xc0)(&buf).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(ty, Type::V1(Ver1::INITIAL));

        let buf = vec![0x00, 0x00, 0x00, 0x00];
        let (remain, ty) = parse_long_type(0x80)(&buf).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(ty, Type::VersionNegotiation);
    }

    #[test]
    #[should_panic]
    fn test_read_long_type_with_wrong_version() {
        use super::{ext::parse_long_type, Type};

        let buf = vec![0x00, 0x00, 0x00, 0x03];
        let (remain, ty) = parse_long_type(0xc0)(&buf).unwrap();
        assert_eq!(remain.len(), 0);
        assert_eq!(ty, Type::V1(Ver1::INITIAL));
    }

    #[test]
    fn test_write_long_type() {
        use super::Type;
        use crate::packet::r#type::long::ext::WriteLongType;

        let mut buf = vec![];
        let ty = Type::V1(Ver1::INITIAL);
        buf.put_long_type(&ty);
        assert_eq!(buf, vec![0xc0, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_write_version_negotiation_long_type() {
        use super::Type;
        use crate::packet::r#type::long::ext::WriteLongType;

        let mut buf = vec![];
        let ty = Type::VersionNegotiation;
        buf.put_long_type(&ty);
        assert_eq!(buf, vec![0x80, 0x00, 0x00, 0x00, 0x00]);
    }
}
