use std::fmt::Debug;

#[derive(Copy, Clone, Debug)]
pub(super) struct MinMax {
    /// round count, not a timestamp
    window: u64,
    samples: [MinMaxSample; 3],
}

impl MinMax {
    fn fill(&mut self, sample: MinMaxSample) {
        self.samples.fill(sample);
    }

    pub(super) fn update_max(&mut self, current_round: u64, measurement: u64) -> u64 {
        let sample = MinMaxSample {
            time: current_round,
            value: measurement,
        };

        if self.samples[0].value == 0  /* uninitialised */
            || /* found new max? */ sample.value >= self.samples[0].value
            || /* nothing left in window? */ sample.time - self.samples[2].time > self.window
        {
            self.fill(sample); /* forget earlier samples */
            return self.samples[0].value;
        }

        if sample.value >= self.samples[1].value {
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if sample.value >= self.samples[2].value {
            self.samples[2] = sample;
        }

        self.subwin_update(sample);
        self.samples[0].value
    }

    /* As time advances, update the 1st, 2nd, and 3rd choices. */
    fn subwin_update(&mut self, sample: MinMaxSample) {
        let dt = sample.time - self.samples[0].time;
        if dt > self.window {
            /*
             * Passed entire window without a new sample so make 2nd
             * choice the new sample & 3rd choice the new 2nd choice.
             * we may have to iterate this since our 2nd choice
             * may also be outside the window (we checked on entry
             * that the third choice was in the window).
             */
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.time - self.samples[0].time > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].time == self.samples[0].time && dt > self.window / 4 {
            /*
             * We've passed a quarter of the window without a new sample
             * so take a 2nd choice from the 2nd quarter of the window.
             */
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if self.samples[2].time == self.samples[1].time && dt > self.window / 2 {
            /*
             * We've passed half the window without finding a new sample
             * so take a 3rd choice from the last half of the window
             */
            self.samples[2] = sample;
        }
    }
}

impl Default for MinMax {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [Default::default(); 3],
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct MinMaxSample {
    /// round number, not a timestamp
    time: u64,
    value: u64,
}
