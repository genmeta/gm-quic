use bytes::BufMut;

/// An encoded packet number
///
/// The packet number is an integer in the range 0 to 2^62  - 1 and encoded in 1 to 4 bytes.
///
/// See [Section 12.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3) and
/// [Section 17.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

pub trait WritePacketNumber {
    fn put_packet_number(&mut self, pn: PacketNumber);
}

impl<T: BufMut> WritePacketNumber for T {
    fn put_packet_number(&mut self, pn: PacketNumber) {
        use self::PacketNumber::*;
        match pn {
            U8(x) => self.put_u8(x),
            U16(x) => self.put_u16(x),
            U24(x) => {
                self.put_u8((x >> 16) as u8);
                self.put_u16(x as u16);
            }
            U32(x) => self.put_u32(x),
        }
    }
}

pub fn take_pn_len(pn_len: u8) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], PacketNumber> {
    use nom::{
        combinator::map,
        number::complete::{be_u16, be_u24, be_u32, be_u8},
    };
    move |input: &[u8]| match pn_len {
        1 => map(be_u8, PacketNumber::U8)(input),
        2 => map(be_u16, PacketNumber::U16)(input),
        3 => map(be_u24, PacketNumber::U24)(input),
        4 => map(be_u32, PacketNumber::U32)(input),
        _ => unreachable!(),
    }
}

impl PacketNumber {
    /// The size of the packet number encoding is at least one bit more than the
    /// base-2 logarithm of the number of contiguous unacknowledged packet numbers
    ///
    /// See [Section 17.1-5](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1-5) and
    /// [Section A.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2)
    pub fn encode(pn: u64, largest_acked: u64) -> Self {
        let range = (pn - largest_acked) * 2;
        if range < 1 << 8 {
            Self::U8(pn as u8)
        } else if range < 1 << 16 {
            Self::U16(pn as u16)
        } else if range < 1 << 24 {
            Self::U24(pn as u32)
        } else if range < 1 << 32 {
            Self::U32(pn as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    pub fn size(self) -> usize {
        use self::PacketNumber::*;
        match self {
            U8(_) => 1,
            U16(_) => 2,
            U24(_) => 3,
            U32(_) => 4,
        }
    }

    /// For decoding packet numbers after header protection has been removed.
    /// the packet number is decoded by finding the packet number value that
    /// is closest to the next expected packet. The next expected packet is
    /// the highest received packet number plus one.
    ///
    /// See [Section 17.1-7](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1-7) and
    /// [Section A.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3)
    pub fn decode(self, expected: u64) -> u64 {
        use self::PacketNumber::*;

        let (truncated, nbits) = match self {
            U8(x) => (u64::from(x), 8),
            U16(x) => (u64::from(x), 16),
            U24(x) => (u64::from(x), 24),
            U32(x) => (u64::from(x), 32),
        };
        let win = 1 << nbits;
        let hwin = win / 2;
        let mask = win - 1;
        // The incoming packet number should be greater than expected - hwin and less than or equal
        // to expected + hwin
        //
        // This means we can't just strip the trailing bits from expected and add the truncated
        // because that might yield a value outside the window.
        //
        // The following code calculates a candidate value and makes sure it's within the packet
        // number window.
        let candidate = (expected & !mask) | truncated;
        if expected.checked_sub(hwin).map_or(false, |x| candidate <= x) {
            candidate + win
        } else if candidate > expected + hwin && candidate > win {
            candidate - win
        } else {
            candidate
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_read_packet_number() {
        let buf = [0x00];
        assert_eq!(
            (&[][..], super::PacketNumber::U8(0)),
            super::take_pn_len(1)(&buf).unwrap()
        );

        let buf = [0x01, 0x00];
        assert_eq!(
            (&[][..], super::PacketNumber::U16(1 << 8)),
            super::take_pn_len(2)(&buf).unwrap()
        );

        let buf = [0x01, 0x00, 0x00];
        assert_eq!(
            (&[][..], super::PacketNumber::U24(1 << 16)),
            super::take_pn_len(3)(&buf).unwrap()
        );

        let buf = [0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            (&[][..], super::PacketNumber::U32(1 << 24)),
            super::take_pn_len(4)(&buf).unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn test_read_packet_number_too_large() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x00];
        super::take_pn_len(5)(&buf).unwrap();
    }

    #[test]
    fn test_write_packet_number() {
        use super::WritePacketNumber;
        use crate::packet::PacketNumber;

        let mut buf = vec![];
        buf.put_packet_number(PacketNumber::encode(0, 0));
        assert_eq!(buf, [0x00]);

        buf.clear();
        buf.put_packet_number(PacketNumber::encode(1 << 8, 0));
        assert_eq!(buf, [0x01, 0x00]);

        buf.clear();
        buf.put_packet_number(PacketNumber::encode(1 << 16, 0));
        assert_eq!(buf, [0x01, 0x00, 0x00]);

        buf.clear();
        buf.put_packet_number(PacketNumber::encode(1 << 24, 0));
        assert_eq!(buf, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_packet_number() {
        let pn = super::PacketNumber::encode((1 << 31) - 1, 0);
        assert_eq!(pn.decode(0), (1 << 31) - 1);

        let pn = super::PacketNumber::encode(0, 0);
        assert_eq!(pn.decode(0), 0);
    }

    #[test]
    #[should_panic]
    fn test_encode_packet_number_overflow() {
        super::PacketNumber::encode(1 << 31, 0);
    }
}
