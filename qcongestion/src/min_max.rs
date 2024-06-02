use std::time::{Duration, Instant};

#[derive(Copy, Clone)]
struct MinmaxSample<T> {
    time: Instant,
    value: T,
}

pub struct Minmax<T> {
    estimate: [MinmaxSample<T>; 3],
}

impl<T: PartialOrd + Copy> Minmax<T> {
    pub fn new(val: T) -> Self {
        Minmax {
            estimate: [MinmaxSample {
                time: Instant::now(),
                value: val,
            }; 3],
        }
    }

    /// Resets the estimates to the given value.
    pub fn reset(&mut self, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        for i in self.estimate.iter_mut() {
            *i = val;
        }

        self.estimate[0].value
    }

    /// Updates the min estimate based on the given measurement, and returns it.
    pub fn _running_min(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[2].time);

        // Reset if there's nothing in the window or a new min value is found.
        if val.value <= self.estimate[0].value || delta_time > win {
            return self.reset(time, meas);
        }

        if val.value <= self.estimate[1].value {
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if val.value <= self.estimate[2].value {
            self.estimate[2] = val;
        }

        self.subwin_update(win, time, meas)
    }

    /// Updates the max estimate based on the given measurement, and returns it.
    pub fn running_max(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[2].time);

        // Reset if there's nothing in the window or a new max value is found.
        if val.value >= self.estimate[0].value || delta_time > win {
            return self.reset(time, meas);
        }

        if val.value >= self.estimate[1].value {
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if val.value >= self.estimate[2].value {
            self.estimate[2] = val
        }

        self.subwin_update(win, time, meas)
    }

    /// As time advances, update the 1st, 2nd and 3rd estimates.
    fn subwin_update(&mut self, win: Duration, time: Instant, meas: T) -> T {
        let val = MinmaxSample { time, value: meas };

        let delta_time = time.duration_since(self.estimate[0].time);

        if delta_time > win {
            // Passed entire window without a new val so make 2nd estimate the
            // new val & 3rd estimate the new 2nd choice. we may have to iterate
            // this since our 2nd estimate may also be outside the window (we
            // checked on entry that the third estimate was in the window).
            self.estimate[0] = self.estimate[1];
            self.estimate[1] = self.estimate[2];
            self.estimate[2] = val;

            if time.duration_since(self.estimate[0].time) > win {
                self.estimate[0] = self.estimate[1];
                self.estimate[1] = self.estimate[2];
                self.estimate[2] = val;
            }
        } else if self.estimate[1].time == self.estimate[0].time && delta_time > win.div_f32(4.0) {
            // We've passed a quarter of the window without a new val so take a
            // 2nd estimate from the 2nd quarter of the window.
            self.estimate[2] = val;
            self.estimate[1] = val;
        } else if self.estimate[2].time == self.estimate[1].time && delta_time > win.div_f32(2.0) {
            // We've passed half the window without finding a new val so take a
            // 3rd estimate from the last half of the window.
            self.estimate[2] = val;
        }

        self.estimate[0].value
    }
}
