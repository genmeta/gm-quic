/// The latency spin bit in 1-RTT packets
const SPIN_BIT: u8 = 0x20;
/// The key phase bit in 1-RTT packets
const KEY_PHASE_BIT: u8 = 0x04;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Toggle<const B: u8> {
    #[default]
    Off,
    On,
}

pub type SpinBit = Toggle<SPIN_BIT>;
pub type KeyPhaseBit = Toggle<KEY_PHASE_BIT>;

impl<const B: u8> Toggle<B> {
    pub fn toggle(&mut self) {
        *self = match self {
            Toggle::Off => Toggle::On,
            Toggle::On => Toggle::Off,
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Toggle::Off => 0,
            Toggle::On => B,
        }
    }

    pub(crate) fn index(&self) -> usize {
        match self {
            Toggle::Off => 0,
            Toggle::On => 1,
        }
    }
}

impl<const B: u8> std::ops::Not for Toggle<B> {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Toggle::Off => Toggle::On,
            Toggle::On => Toggle::Off,
        }
    }
}

impl<const B: u8> From<u8> for Toggle<B> {
    fn from(value: u8) -> Self {
        if value & B == 0 {
            Toggle::Off
        } else {
            Toggle::On
        }
    }
}
