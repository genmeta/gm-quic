use std::ops::{Deref, DerefMut};

/// Manages state that exists in both 0-RTT and 1-RTT phases.
/// This allows sending tasks to use the appropriate state value based on the packet type
/// while both states can be updated independently.
#[derive(Debug, Clone, Copy)]
pub struct DualRttState<T> {
    /// State value used for 0-RTT packets
    zero_rtt_value: T,
    /// State value used for 1-RTT packets  
    one_rtt_value: T,
    /// Flag to determine which state should be used for current operations
    in_zero_rtt: bool,
    zero_rtt_accepted: Option<bool>,
}

impl<T> Deref for DualRttState<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        if self.in_zero_rtt {
            self.zero_rtt()
        } else {
            self.one_rtt()
        }
    }
}

impl<T> DerefMut for DualRttState<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.in_zero_rtt {
            self.zero_rtt_mut()
        } else {
            self.one_rtt_mut()
        }
    }
}

impl<T> DualRttState<T> {
    /// Creates a new [`DualRttState`] with the given 0-RTT value and a default 1-RTT value.
    pub fn new(value: T, zero_rtt: bool) -> Self
    where
        T: Default,
    {
        match zero_rtt {
            true => Self {
                zero_rtt_value: value,
                one_rtt_value: T::default(),
                in_zero_rtt: true,
                zero_rtt_accepted: None,
            },
            false => Self {
                zero_rtt_value: T::default(),
                one_rtt_value: value,
                in_zero_rtt: false,
                zero_rtt_accepted: Some(false),
            },
        }
    }

    /// Gets the 0-RTT state value
    pub fn zero_rtt(&self) -> &T {
        &self.zero_rtt_value
    }

    /// Gets a mutable reference to the 0-RTT state value
    pub fn zero_rtt_mut(&mut self) -> &mut T {
        &mut self.zero_rtt_value
    }

    /// Gets the 1-RTT state value
    pub fn one_rtt(&self) -> &T {
        &self.one_rtt_value
    }

    /// Gets a mutable reference to the 1-RTT state value
    pub fn one_rtt_mut(&mut self) -> &mut T {
        &mut self.one_rtt_value
    }

    /// Checks if currently in 0-RTT phase
    pub fn in_zero_rtt(&self) -> bool {
        self.in_zero_rtt
    }

    /// Switches to 1-RTT phase
    pub fn switch_to_one_rtt(&mut self, zero_rtt_accepted: bool, tf: impl FnOnce(&mut T, &mut T)) {
        if self.zero_rtt_accepted.is_some() {
            return;
        }
        self.in_zero_rtt = false;
        self.zero_rtt_accepted = Some(zero_rtt_accepted);
        tf(&mut self.zero_rtt_value, &mut self.one_rtt_value);
    }

    pub fn zero_rtt_accepted(&self) -> Option<bool> {
        self.zero_rtt_accepted
    }
}
