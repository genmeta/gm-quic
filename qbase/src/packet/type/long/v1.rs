use crate::packet::{error::Error, r#type::FIXED_BIT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Retry,
    Initial,
    ZeroRtt,
    Handshake,
}

/// The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const INITIAL_PACKET_TYPE: u8 = 0x00;
const ZERO_RTT_PACKET_TYPE: u8 = 0x10;
const HANDSHAKE_PACKET_TYPE: u8 = 0x20;
const RETRY_PACKET_TYPE: u8 = 0x30;

impl From<Type> for u8 {
    fn from(value: Type) -> u8 {
        match value {
            Type::Retry => RETRY_PACKET_TYPE,
            Type::Initial => INITIAL_PACKET_TYPE,
            Type::ZeroRtt => ZERO_RTT_PACKET_TYPE,
            Type::Handshake => HANDSHAKE_PACKET_TYPE,
        }
    }
}

impl TryFrom<u8> for Type {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value & FIXED_BIT == 0 {
            return Err(Error::InvalidFixedBit);
        }
        match value & LONG_PACKET_TYPE_MASK {
            INITIAL_PACKET_TYPE => Ok(Type::Initial),
            ZERO_RTT_PACKET_TYPE => Ok(Type::ZeroRtt),
            HANDSHAKE_PACKET_TYPE => Ok(Type::Handshake),
            RETRY_PACKET_TYPE => Ok(Type::Retry),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_try_from() {
        use super::Type;
        use crate::packet::error::Error;

        assert_eq!(Type::try_from(0xc0), Ok(Type::Initial));
        assert_eq!(Type::try_from(0xd0), Ok(Type::ZeroRtt));
        assert_eq!(Type::try_from(0xe0), Ok(Type::Handshake));
        assert_eq!(Type::try_from(0xf0), Ok(Type::Retry));
        assert_eq!(Type::try_from(0x00), Err(Error::InvalidFixedBit));
    }
}
