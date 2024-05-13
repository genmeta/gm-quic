/// The latency spin bit in 1-RTT packets
const SPIN_BIT: u8 = 0x20;
/// The key phase bit in 1-RTT packets
const KEY_PHASE_BIT: u8 = 0x04;

#[derive(Debug, Clone, Copy, Default)]
pub enum Toggle<const B: u8> {
    #[default]
    Off,
    On,
}

pub type SpinToggle = Toggle<SPIN_BIT>;
pub type KeyPhaseToggle = Toggle<KEY_PHASE_BIT>;

impl<const B: u8> Toggle<B> {
    pub fn change(&mut self) {
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
}
