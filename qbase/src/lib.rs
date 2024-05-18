pub mod cid;
pub mod config;
pub mod error;
pub mod frame;
pub mod packet;
pub mod streamid;
pub mod varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceId {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

impl std::fmt::Display for SpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaceId::Initial => write!(f, "Initial space"),
            SpaceId::Handshake => write!(f, "Handshake space"),
            SpaceId::ZeroRtt => write!(f, "0-RTT space"),
            SpaceId::OneRtt => write!(f, "1-RTT space"),
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
