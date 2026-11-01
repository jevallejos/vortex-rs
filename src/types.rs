//! Compile-time dimensional safety (Newtype pattern) and microeconomic friction guards.

use core::fmt;

/// Discrete price expressed in integer multiples of the instrument's tick_size.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PriceTicks(pub i64);

/// Discrete quantity expressed in integer multiples of the instrument's lot_step.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LotQty(pub i64);

/// Monotonic timestamp in nanoseconds.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampNs(pub i64);

/// Basis points scaled by 100 (1 bps = 100 units; 1.50 bps = 150 units; 35.00 bps = 3500 units).
/// Eliminates IEEE-754 floating-point drift in fee and threshold comparisons.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScaledBps(pub i64);

impl ScaledBps {
    /// Maximum allowed relative tick size: 1.50 bps (0.015%).
    pub const MAX_ALLOWED_TICK_BPS: Self = Self(150);
    /// Minimum structural excursion target: 35.00 bps (0.35%).
    pub const MIN_STRUCTURAL_EXCURSION_BPS: Self = Self(3_500);
    /// Maximum structural excursion cap: 80.00 bps (0.80%).
    pub const MAX_STRUCTURAL_EXCURSION_BPS: Self = Self(8_000);
    /// Bybit UTA V5 VIP-0 Maker fee: 2.00 bps (0.020%).
    pub const BYBIT_VIP0_MAKER_FEE_BPS: Self = Self(200);
    /// Bybit UTA V5 VIP-0 Taker fee: 5.50 bps (0.055%).
    pub const BYBIT_VIP0_TAKER_FEE_BPS: Self = Self(550);

    #[inline]
    #[must_use]
    pub const fn from_whole_bps(bps: i64) -> Self {
        Self(bps * 100)
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> i64 {
        self.0
    }
}

/// Bounded microstructural flow score in the closed interval [-1.0, +1.0].
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct BoundedScore(f64);

impl BoundedScore {
    /// Compile-time neutral score (0.0).
    pub const ZERO: Self = Self(0.0);

    /// Creates a bounded score in compile-time or runtime contexts, clamping non-finite values
    /// to 0.0 and bounding to [-1.0, +1.0].
    #[inline]
    #[must_use]
    #[allow(clippy::manual_clamp)]
    pub const fn new_clamped(val: f64) -> Self {
        if val.is_nan() || val.is_infinite() {
            return Self(0.0);
        }
        if val > 1.0 {
            Self(1.0)
        } else if val < -1.0 {
            Self(-1.0)
        } else {
            Self(val)
        }
    }

    #[inline]
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// Converts score in [-1.0, +1.0] to integer basis points [-10_000, +10_000] for binary storage.
    #[inline]
    #[must_use]
    pub fn to_bps_i32(self) -> i32 {
        (self.0 * 10_000.0) as i32
    }
}

/// Compact static identifier for a trading pair in the shared-memory ring.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub u16);

/// Trade and book side.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Bid = 0,
    Ask = 1,
}

/// Domain-level deterministic error catalog (zero panics).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VortexError {
    InvalidPriceOrTickSpec,
    TickBpsExceedsInstitutionalCap {
        observed_scaled_bps: ScaledBps,
        max_allowed_scaled_bps: ScaledBps,
    },
    RealizedVolBelowStructuralFloor {
        observed_vol_5m_scaled_bps: ScaledBps,
        min_required_scaled_bps: ScaledBps,
    },
    FrictionBarrierRejected {
        expected_excursion_scaled_bps: ScaledBps,
        required_3x_barrier_scaled_bps: ScaledBps,
    },
    StopLossGeometryViolation {
        side: Side,
        proposed_sl_ticks: PriceTicks,
        reference_mark_ticks: PriceTicks,
    },
    SharedMemorySeqConflict,
    InvalidSymbolSlot,
    BatchCapacityExceeded,
    ColumnarIoFailure,
    ColumnarFormatCorrupted,
    AccountingParityDrift {
        internal_balance_1e8: i64,
        exchange_balance_1e8: i64,
        drift_1e8: i64,
    },
}

impl fmt::Display for VortexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Static specification and microeconomic eligibility guard for a perpetual contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PairSpec {
    pub symbol_id: SymbolId,
    /// Price of 1 tick scaled by 1e8 (e.g., 0.0001 USDT -> 10_000).
    pub tick_size_1e8: i64,
    /// Quantity step scaled by 1e8.
    pub lot_step_1e8: i64,
    /// Empirical probability of Taker exit in percent (0..=100, default 20 for 20%).
    pub empirical_taker_exit_prob_pct: i64,
}

impl PairSpec {
    /// Computes relative tick size in ScaledBps (1 bps = 100 units) at a given mid price in ticks.
    #[inline]
    pub const fn compute_tick_scaled_bps(&self, mid_price_ticks: PriceTicks) -> Result<ScaledBps, VortexError> {
        if mid_price_ticks.0 <= 0 || self.tick_size_1e8 <= 0 || self.lot_step_1e8 <= 0 {
            return Err(VortexError::InvalidPriceOrTickSpec);
        }
        let scaled = 1_000_000_i64 / mid_price_ticks.0;
        Ok(ScaledBps(scaled))
    }

    /// Evaluates the Tick-to-Price Guard (<= 1.50 bps) and 5-minute realized volatility capability (>= 35.00 bps).
    #[inline]
    pub const fn validate_eligibility(
        &self,
        mid_price_ticks: PriceTicks,
        realized_vol_5m_scaled_bps: ScaledBps,
    ) -> Result<ScaledBps, VortexError> {
        let tick_bps = match self.compute_tick_scaled_bps(mid_price_ticks) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if tick_bps.0 > ScaledBps::MAX_ALLOWED_TICK_BPS.0 {
            return Err(VortexError::TickBpsExceedsInstitutionalCap {
                observed_scaled_bps: tick_bps,
                max_allowed_scaled_bps: ScaledBps::MAX_ALLOWED_TICK_BPS,
            });
        }
        if realized_vol_5m_scaled_bps.0 < ScaledBps::MIN_STRUCTURAL_EXCURSION_BPS.0 {
            return Err(VortexError::RealizedVolBelowStructuralFloor {
                observed_vol_5m_scaled_bps: realized_vol_5m_scaled_bps,
                min_required_scaled_bps: ScaledBps::MIN_STRUCTURAL_EXCURSION_BPS,
            });
        }
        Ok(tick_bps)
    }

    /// Computes expected round-trip friction cost in ScaledBps and enforces the 3x Friction Barrier.
    #[inline]
    #[allow(clippy::manual_clamp)]
    pub const fn passes_3x_friction_barrier(
        &self,
        mid_price_ticks: PriceTicks,
        expected_excursion_scaled_bps: ScaledBps,
    ) -> Result<ScaledBps, VortexError> {
        let tick_bps = match self.compute_tick_scaled_bps(mid_price_ticks) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_taker = if self.empirical_taker_exit_prob_pct < 0 {
            0
        } else if self.empirical_taker_exit_prob_pct > 100 {
            100
        } else {
            self.empirical_taker_exit_prob_pct
        };
        let exit_fee_expected = (p_taker * ScaledBps::BYBIT_VIP0_TAKER_FEE_BPS.0
            + (100 - p_taker) * ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.0)
            / 100;
        let round_trip_cost = ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.0 + exit_fee_expected + tick_bps.0;
        let required_3x = round_trip_cost * 3;
        let effective_floor = if required_3x > ScaledBps::MIN_STRUCTURAL_EXCURSION_BPS.0 {
            required_3x
        } else {
            ScaledBps::MIN_STRUCTURAL_EXCURSION_BPS.0
        };

        if expected_excursion_scaled_bps.0 < effective_floor {
            return Err(VortexError::FrictionBarrierRejected {
                expected_excursion_scaled_bps,
                required_3x_barrier_scaled_bps: ScaledBps(effective_floor),
            });
        }
        Ok(ScaledBps(round_trip_cost))
    }

    /// Pre-validates Bybit UTA V5 server-side Stop-Loss geometry against LastPrice and MarkPrice
    /// to prevent `retCode 10001` rejections.
    #[inline]
    pub const fn validate_stop_loss_geometry(
        side: Side,
        proposed_sl: PriceTicks,
        last_price: PriceTicks,
        mark_price: PriceTicks,
    ) -> Result<(), VortexError> {
        match side {
            Side::Bid => {
                let ref_floor = if last_price.0 < mark_price.0 {
                    last_price.0
                } else {
                    mark_price.0
                };
                if proposed_sl.0 >= ref_floor - 2 {
                    return Err(VortexError::StopLossGeometryViolation {
                        side,
                        proposed_sl_ticks: proposed_sl,
                        reference_mark_ticks: PriceTicks(ref_floor),
                    });
                }
                Ok(())
            }
            Side::Ask => {
                let ref_ceil = if last_price.0 > mark_price.0 {
                    last_price.0
                } else {
                    mark_price.0
                };
                if proposed_sl.0 <= ref_ceil + 2 {
                    return Err(VortexError::StopLossGeometryViolation {
                        side,
                        proposed_sl_ticks: proposed_sl,
                        reference_mark_ticks: PriceTicks(ref_ceil),
                    });
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tick_to_price_guard_rejects_wide_tick_altcoin() {
        let spec = PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 1_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let res = spec.validate_eligibility(PriceTicks(500), ScaledBps::from_whole_bps(45));
        assert!(matches!(
            res,
            Err(VortexError::TickBpsExceedsInstitutionalCap { .. })
        ));
    }

    #[test]
    fn test_tick_to_price_and_3x_friction_barrier_passes_institutional_pair() {
        let spec = PairSpec {
            symbol_id: SymbolId(2),
            tick_size_1e8: 10_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let elig = spec.validate_eligibility(PriceTicks(20_000), ScaledBps::from_whole_bps(50));
        assert_eq!(elig, Ok(ScaledBps(50)));

        let rejected = spec.passes_3x_friction_barrier(PriceTicks(20_000), ScaledBps::from_whole_bps(12));
        assert!(matches!(
            rejected,
            Err(VortexError::FrictionBarrierRejected { .. })
        ));

        let passed = spec.passes_3x_friction_barrier(PriceTicks(20_000), ScaledBps::from_whole_bps(42));
        assert_eq!(passed, Ok(ScaledBps(520)));
    }

    #[test]
    fn test_stop_loss_geometry_validation() {
        assert_eq!(
            PairSpec::validate_stop_loss_geometry(
                Side::Bid,
                PriceTicks(9_990),
                PriceTicks(10_000),
                PriceTicks(9_995)
            ),
            Ok(())
        );
        assert!(matches!(
            PairSpec::validate_stop_loss_geometry(
                Side::Bid,
                PriceTicks(9_994),
                PriceTicks(10_000),
                PriceTicks(9_995)
            ),
            Err(VortexError::StopLossGeometryViolation { .. })
        ));
    }
}