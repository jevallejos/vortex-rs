//! Compile-time dimensional safety (Newtype pattern), fixed-point ASCII parsers,
//! and microeconomic friction guards.

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

impl SymbolId {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "BTCUSDT",
            2 => "ETHUSDT",
            3 => "SOLUSDT",
            4 => "AVAXUSDT",
            5 => "TAOUSDT",
            6 => "SUIUSDT",
            7 => "XRPUSDT",
            8 => "ZEREBROUSDT",
            9 => "WALUSDT",
            _ => "UNKNOWN",
        }
    }
}

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
    AsciiDecimalParseError,
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
    /// Price of 1 tick scaled by 1e8 (e.g., 0.10 USDT -> 10_000_000).
    pub tick_size_1e8: i64,
    /// Quantity step scaled by 1e8.
    pub lot_step_1e8: i64,
    /// Empirical probability of Taker exit in percent (0..=100, default 20 for 20%).
    pub empirical_taker_exit_prob_pct: i64,
}

impl PairSpec {
    /// Parses a decimal ASCII string (e.g., `"77670.50"`) directly into an integer scaled by `1e8`
    /// with zero floating-point intermediate representation and zero heap allocation.
    #[inline]
    pub fn parse_decimal_1e8(raw: &str) -> Result<i64, VortexError> {
        let bytes = raw.trim().as_bytes();
        if bytes.is_empty() {
            return Err(VortexError::AsciiDecimalParseError);
        }
        let mut int_part: i64 = 0;
        let mut frac_part: i64 = 0;
        let mut frac_scale: i64 = 100_000_000;
        let mut in_frac = false;
        let mut seen_digit = false;

        for &b in bytes {
            if b == b'.' {
                if in_frac {
                    return Err(VortexError::AsciiDecimalParseError);
                }
                in_frac = true;
                continue;
            }
            if !b.is_ascii_digit() {
                return Err(VortexError::AsciiDecimalParseError);
            }
            seen_digit = true;
            let digit = i64::from(b - b'0');
            if !in_frac {
                int_part = int_part
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(VortexError::AsciiDecimalParseError)?;
            } else if frac_scale >= 10 {
                frac_scale /= 10;
                frac_part += digit * frac_scale;
            }
        }
        if !seen_digit {
            return Err(VortexError::AsciiDecimalParseError);
        }
        int_part
            .checked_mul(100_000_000)
            .and_then(|v| v.checked_add(frac_part))
            .ok_or(VortexError::AsciiDecimalParseError)
    }

    /// Converts an ASCII price string from Bybit into exact `PriceTicks`.
    #[inline]
    pub fn parse_price_ticks(&self, raw: &str) -> Result<PriceTicks, VortexError> {
        if self.tick_size_1e8 <= 0 {
            return Err(VortexError::InvalidPriceOrTickSpec);
        }
        let val_1e8 = Self::parse_decimal_1e8(raw)?;
        let ticks = (val_1e8 + (self.tick_size_1e8 / 2)) / self.tick_size_1e8;
        Ok(PriceTicks(ticks))
    }

    /// Converts an ASCII quantity string from Bybit into exact `LotQty`.
    #[inline]
    pub fn parse_lot_qty(&self, raw: &str) -> Result<LotQty, VortexError> {
        if self.lot_step_1e8 <= 0 {
            return Err(VortexError::InvalidPriceOrTickSpec);
        }
        let val_1e8 = Self::parse_decimal_1e8(raw)?;
        let lots = (val_1e8 + (self.lot_step_1e8 / 2)) / self.lot_step_1e8;
        Ok(LotQty(lots))
    }

    /// Formats `PriceTicks` back into `(whole_usdt, frac_4digits)` for human HUD display.
    #[inline]
    #[must_use]
    pub const fn format_price_usdt_parts(&self, ticks: PriceTicks) -> (i64, i64) {
        let total_1e8 = ticks.0.saturating_mul(self.tick_size_1e8);
        let whole = total_1e8 / 100_000_000;
        let frac4 = (total_1e8.abs() % 100_000_000) / 10_000;
        (whole, frac4)
    }

    #[inline]
    pub const fn compute_tick_scaled_bps(&self, mid_price_ticks: PriceTicks) -> Result<ScaledBps, VortexError> {
        if mid_price_ticks.0 <= 0 || self.tick_size_1e8 <= 0 || self.lot_step_1e8 <= 0 {
            return Err(VortexError::InvalidPriceOrTickSpec);
        }
        let scaled = 1_000_000_i64 / mid_price_ticks.0;
        Ok(ScaledBps(scaled))
    }

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
        let effective_floor = round_trip_cost * 3;

        if expected_excursion_scaled_bps.0 < effective_floor {
            return Err(VortexError::FrictionBarrierRejected {
                expected_excursion_scaled_bps,
                required_3x_barrier_scaled_bps: ScaledBps(effective_floor),
            });
        }
        Ok(ScaledBps(round_trip_cost))
    }

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

/// ANSI terminal color and badge constants shared across CLI binaries.
pub const ANSI_GREEN: &str = "\x1b[1;32m";
pub const ANSI_ORANGE: &str = "\x1b[38;5;208m";
pub const ANSI_RED: &str = "\x1b[1;31m";
pub const ANSI_YELLOW: &str = "\x1b[1;33m";
pub const ANSI_GRAY: &str = "\x1b[90m";
pub const ANSI_RESET: &str = "\x1b[0m";

/// Canonical PnL badge classifier (`WIN` >= +1.00 bps, `SCRATCH` in [-0.50, +1.00) bps, `LOSS` < -0.50 bps).
#[inline]
#[must_use]
pub fn classify_pnl_badge(net_bps: f64) -> (&'static str, &'static str, &'static str) {
    if net_bps >= 1.00 {
        (ANSI_GREEN, "\u{1F7E2}", "WIN")
    } else if net_bps >= -0.50 {
        (ANSI_ORANGE, "\u{1F7E0}", "SCRATCH")
    } else {
        (ANSI_RED, "\u{1F534}", "LOSS")
    }
}

/// Canonical 6 approved institutional perpetual contracts (`Tick_bps <= 1.50 bps`).
pub const APPROVED_SPECS: [PairSpec; 6] = [
    PairSpec {
        symbol_id: SymbolId(1),
        tick_size_1e8: 10_000_000,
        lot_step_1e8: 100_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(2),
        tick_size_1e8: 1_000_000,
        lot_step_1e8: 1_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(3),
        tick_size_1e8: 1_000_000,
        lot_step_1e8: 10_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(4),
        tick_size_1e8: 100_000,
        lot_step_1e8: 10_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(5),
        tick_size_1e8: 1_000_000,
        lot_step_1e8: 1_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(6),
        tick_size_1e8: 10_000,
        lot_step_1e8: 100_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
];

/// Looks up `(slot_idx, PairSpec)` for an approved `SymbolId`.
#[inline]
#[must_use]
pub const fn spec_for_symbol(sym: SymbolId) -> Option<(usize, PairSpec)> {
    let mut i = 0;
    while i < APPROVED_SPECS.len() {
        if APPROVED_SPECS[i].symbol_id.0 == sym.0 {
            return Some((i, APPROVED_SPECS[i]));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_point_decimal_parser_exact_ticks_and_lots() {
        let btc_spec = PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 10_000_000, // 0.10 USDT
            lot_step_1e8: 100_000,     // 0.001 BTC
            empirical_taker_exit_prob_pct: 20,
        };
        assert_eq!(btc_spec.parse_price_ticks("77670.50"), Ok(PriceTicks(776_705)));
        assert_eq!(btc_spec.parse_lot_qty("0.254"), Ok(LotQty(254)));
        assert_eq!(btc_spec.parse_lot_qty("0"), Ok(LotQty(0)));
    }

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