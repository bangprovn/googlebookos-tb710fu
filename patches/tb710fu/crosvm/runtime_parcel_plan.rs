// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bounded adaptive parcel scheduling. No firmware or memory ownership operations.
const UNIT: u64 = 2 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    InvalidWindow,
    TooManyParcels,
}

pub struct ParcelPlan {
    total: u64,
    offset: u64,
    preferred: u64,
    current: u64,
    count: usize,
    slots: usize,
}

impl ParcelPlan {
    pub fn new(total: u64, preferred: u64, slots: usize) -> Result<Self, PlanError> {
        if total == 0 || total > (2 << 30) || total % UNIT != 0
            || preferred < UNIT || preferred > (2 << 30) || preferred % UNIT != 0
            || slots == 0
        {
            return Err(PlanError::InvalidWindow);
        }
        Ok(Self { total, offset: 0, preferred, current: preferred, count: 0, slots })
    }

    pub fn request(&self) -> Result<Option<(u64, u64)>, PlanError> {
        if self.offset == self.total {
            return Ok(None);
        }
        if self.count == self.slots {
            return Err(PlanError::TooManyParcels);
        }
        Ok(Some((self.offset, self.current.min(self.total - self.offset))))
    }

    /// Retry only a kernel refusal that occurred before SCM/RM transfer.
    /// False means the minimum-sized request was refused; do not retry it.
    pub fn split_refused(&mut self) -> Result<bool, PlanError> {
        let Some((_, length)) = self.request()? else {
            return Err(PlanError::InvalidWindow);
        };
        if length <= UNIT {
            return Ok(false);
        }
        self.current = (length / 2).div_ceil(UNIT) * UNIT;
        Ok(true)
    }

    pub fn accepted(&mut self) -> Result<(), PlanError> {
        let Some((offset, length)) = self.request()? else {
            return Err(PlanError::InvalidWindow);
        };
        self.offset = offset + length;
        self.count += 1;
        self.current = self.preferred;
        Ok(())
    }

    pub fn count(&self) -> usize { self.count }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_two_gib_window_fits_and_covers_every_byte_once() {
        let mut plan = ParcelPlan::new(2042 << 20, 16 << 20, 1024).unwrap();
        let mut covered = 0;
        while let Some((offset, length)) = plan.request().unwrap() {
            assert_eq!(offset, covered);
            if length > UNIT {
                assert!(plan.split_refused().unwrap());
            } else {
                assert!(length / 4096 <= 512);
                covered += length;
                plan.accepted().unwrap();
            }
        }
        assert_eq!(covered, 2042 << 20);
        assert_eq!(plan.count(), 1021);
    }

    #[test]
    fn mixed_backing_retries_same_offset_without_losing_completed_parcels() {
        let mut plan = ParcelPlan::new(506 << 20, 16 << 20, 1024).unwrap();
        let mut covered = 0;
        while let Some((offset, length)) = plan.request().unwrap() {
            assert_eq!(offset, covered);
            let limit = if offset < 480 << 20 { 16 << 20 } else { UNIT };
            if length > limit {
                let count = plan.count();
                assert!(plan.split_refused().unwrap());
                assert_eq!(plan.count(), count);
            } else {
                covered += length;
                plan.accepted().unwrap();
            }
        }
        assert_eq!(covered, 506 << 20);
        assert_eq!(plan.count(), 43);
    }

    #[test]
    fn exhausted_slots_and_minimum_refusal_are_terminal() {
        let mut plan = ParcelPlan::new(4 << 20, UNIT, 1).unwrap();
        assert!(!plan.split_refused().unwrap());
        plan.accepted().unwrap();
        assert_eq!(plan.request(), Err(PlanError::TooManyParcels));
        assert_eq!(plan.split_refused(), Err(PlanError::TooManyParcels));
        for (size, preferred, slots) in [(0, UNIT, 1), (1, UNIT, 1), (UNIT, 1, 1), (UNIT, UNIT, 0), ((2 << 30) + UNIT, UNIT, 1024)] {
            assert!(matches!(ParcelPlan::new(size, preferred, slots), Err(PlanError::InvalidWindow)));
        }
    }
}
