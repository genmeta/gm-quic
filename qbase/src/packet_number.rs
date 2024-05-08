use bytes::BufMut;

// An encoded packet number
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketNumber {
    U8(u8),
    U16(u16),
    U24(u32),
    U32(u32),
}

pub trait WritePacketNumber {
    fn write_packet_number(&mut self, pn: PacketNumber);
}

impl<T: BufMut> WritePacketNumber for T {
    fn write_packet_number(&mut self, pn: PacketNumber) {
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
    pub fn encode(n: u64, largest_acked: u64) -> Self {
        let range = (n - largest_acked) * 2;
        if range < 1 << 8 {
            Self::U8(n as u8)
        } else if range < 1 << 16 {
            Self::U16(n as u16)
        } else if range < 1 << 24 {
            Self::U24(n as u32)
        } else if range < 1 << 32 {
            Self::U32(n as u32)
        } else {
            panic!("packet number too large to encode")
        }
    }

    pub fn pn_len(self) -> u8 {
        use self::PacketNumber::*;
        match self {
            U8(_) => 0b00,
            U16(_) => 0b01,
            U24(_) => 0b10,
            U32(_) => 0b11,
        }
    }

    pub fn decode(self, expected: u64) -> u64 {
        // From Appendix A
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
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
