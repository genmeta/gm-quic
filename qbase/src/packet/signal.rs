/// The latency spin bit in 1-RTT packets
const SPIN_BIT: u8 = 0x20;
/// The key phase bit in 1-RTT packets
const KEY_PHASE_BIT: u8 = 0x04;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Toggle<const B: u8> {
    #[default]
    Zero,
    One,
}

pub type SpinBit = Toggle<SPIN_BIT>;
pub type KeyPhaseBit = Toggle<KEY_PHASE_BIT>;

impl<const B: u8> Toggle<B> {
    pub fn toggle(&mut self) {
        *self = match self {
            Toggle::Zero => Toggle::One,
            Toggle::One => Toggle::Zero,
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Toggle::Zero => 0,
            Toggle::One => B,
        }
    }

    pub fn imply(&self, byte: &mut u8) {
        match self {
            Toggle::Zero => *byte &= !B,
            Toggle::One => *byte |= B,
        }
    }

    pub(crate) fn as_index(&self) -> usize {
        match self {
            Toggle::Zero => 0,
            Toggle::One => 1,
        }
    }
}

impl<const B: u8> std::ops::Not for Toggle<B> {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Toggle::Zero => Toggle::One,
            Toggle::One => Toggle::Zero,
        }
    }
}

impl<const B: u8> From<u8> for Toggle<B> {
    fn from(value: u8) -> Self {
        if value & B == 0 {
            Toggle::Zero
        } else {
            Toggle::One
        }
    }
}

impl<const B: u8> From<Toggle<B>> for u8 {
    fn from(value: Toggle<B>) -> Self {
        value.value()
    }
}

impl<const B: u8> From<bool> for Toggle<B> {
    fn from(value: bool) -> Self {
        if value {
            Toggle::One
        } else {
            Toggle::Zero
        }
    }
}

impl<const B: u8> From<Toggle<B>> for bool {
    fn from(value: Toggle<B>) -> Self {
        match value {
            Toggle::Zero => false,
            Toggle::One => true,
        }
    }
}
