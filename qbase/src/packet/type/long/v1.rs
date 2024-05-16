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

impl From<u8> for Type {
    fn from(value: u8) -> Self {
        match value & LONG_PACKET_TYPE_MASK {
            INITIAL_PACKET_TYPE => Type::Initial,
            ZERO_RTT_PACKET_TYPE => Type::ZeroRtt,
            HANDSHAKE_PACKET_TYPE => Type::Handshake,
            RETRY_PACKET_TYPE => Type::Retry,
            _ => unreachable!(),
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
