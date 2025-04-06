use bytes::BufMut;
use derive_more::Deref;

use crate::packet::SpinBit;

const SHORT_HEADER_BIT: u8 = 0x00;

/// The type of the 1-Rtt packet.
/// For simplicity, the spin bit is also one part of the 1-Rtt packet type.
#[derive(Debug, Clone, Copy, Deref, PartialEq, Eq)]
pub struct OneRtt(#[deref] pub SpinBit);

impl From<u8> for OneRtt {
    fn from(value: u8) -> Self {
        OneRtt(SpinBit::from(value))
    }
}

impl From<OneRtt> for u8 {
    fn from(one_rtt: OneRtt) -> Self {
        SHORT_HEADER_BIT | super::FIXED_BIT | one_rtt.0.value()
    }
}

/// A [`bytes::BufMut`] extension trait, makes buffer more friendly to write the short packet type.
pub trait WriteShortType: BufMut {
    /// Write the short packet type to the buffer.
    fn put_short_type(&mut self, ty: &OneRtt);
}

impl<B: BufMut> WriteShortType for B {
    fn put_short_type(&mut self, ty: &OneRtt) {
        self.put_u8((*ty).into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_short_type() {
        use super::OneRtt;

        let mut buf = vec![];
        let ty = OneRtt::from(0x00);
        buf.put_short_type(&ty);
        // Note: 0x40 == SHORT_HEADER_BIT | super::FIXED_BIT | 0x00
        assert_eq!(buf, vec![0x40]);

        let mut buf = vec![];
        let ty = OneRtt::from(0x20);
        buf.put_short_type(&ty);
        // Note: 0x60 == SHORT_HEADER_BIT | super::FIXED_BIT | 0x20
        assert_eq!(buf, vec![0x60]);
    }
}
