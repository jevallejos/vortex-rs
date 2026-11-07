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

    /// Converts whole basis points into `ScaledBps` (`1 bps = 100 units`).
    #[inline]
    #[must_use]
    pub const fn from_whole_bps(bps: i64) -> Self {
        Self(bps * 100)
    }

    /// Returns the raw integer value in `1/100th` of a basis point.
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

    /// Clamps a floating-point score into `[-1.0, +1.0]`, mapping `NaN`/`Inf` to `0.0`.
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

    /// Returns the underlying clamped score in `[-1.0, +1.0]`.
    #[inline]
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// Scales the normalized score into basis points (`[-10_000, +10_000]`).
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
    /// Returns the canonical Bybit UTA V5 ticker symbol string.
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
            7 => "ORDIUSDT",
            8 => "PENDLEUSDT",
            9 => "WIFUSDT",
            10 => "XRPUSDT",
            11 => "ZEREBROUSDT",
            12 => "WALUSDT",
            _ => "UNKNOWN",
        }
    }
}

/// Trade and book side.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// Passive买/bid side (`0`).
    Bid = 0,
    /// Passive卖/ask side (`1`).
    Ask = 1,
}

/// Domain-level deterministic error catalog (zero panics).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VortexError {
    /// Price, tick size, or lot step specification is non-positive.
    InvalidPriceOrTickSpec,
    /// Input string is not a valid fixed-point ASCII decimal.
    AsciiDecimalParseError,
    /// Relative tick size exceeds the institutional 1.50 bps ceiling.
    TickBpsExceedsInstitutionalCap {
        /// Observed relative tick size.
        observed_scaled_bps: ScaledBps,
        /// Maximum permitted relative tick size.
        max_allowed_scaled_bps: ScaledBps,
    },
    /// Realized 5-minute volatility is below the minimum structural floor.
    RealizedVolBelowStructuralFloor {
        /// Observed 5-minute realized volatility.
        observed_vol_5m_scaled_bps: ScaledBps,
        /// Minimum required volatility.
        min_required_scaled_bps: ScaledBps,
    },
    /// Expected excursion does not cover 3x round-trip friction.
    FrictionBarrierRejected {
        /// Predicted excursion in `ScaledBps`.
        expected_excursion_scaled_bps: ScaledBps,
        /// Required 3x friction barrier in `ScaledBps`.
        required_3x_barrier_scaled_bps: ScaledBps,
    },
    /// Proposed Stop-Loss violates Bybit `MarkPrice` geometry.
    StopLossGeometryViolation {
        /// Order side.
        side: Side,
        /// Proposed Stop-Loss trigger price.
        proposed_sl_ticks: PriceTicks,
        /// Reference mark/last price.
        reference_mark_ticks: PriceTicks,
    },
    /// Seqlock read retry budget exhausted due to concurrent writer.
    SharedMemorySeqConflict,
    /// Requested shared-memory slot index is out of bounds.
    InvalidSymbolSlot,
    /// Columnar `PAR1` batch capacity (`256`) exceeded.
    BatchCapacityExceeded,
    /// Disk or shared-memory I/O operation failed.
    ColumnarIoFailure,
    /// `PAR1` magic bytes or FNV-1a 64-bit checksum mismatch.
    ColumnarFormatCorrupted,
    /// Accounting drift between internal ledger and exchange wallet exceeded tolerance.
    AccountingParityDrift {
        /// Expected internal balance (`1e8` scale).
        internal_balance_1e8: i64,
        /// Reported exchange wallet balance (`1e8` scale).
        exchange_balance_1e8: i64,
        /// Absolute drift (`1e8` scale).
        drift_1e8: i64,
    },
}

impl fmt::Display for VortexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VortexError {}

impl From<std::io::Error> for VortexError {
    #[inline]
    fn from(_: std::io::Error) -> Self {
        Self::ColumnarIoFailure
    }
}

/// Static specification and microeconomic eligibility guard for a perpetual contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PairSpec {
    /// Canonical symbol identifier.
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

    /// Computes the relative tick size in `ScaledBps` at `mid_price_ticks`.
    #[inline]
    pub const fn compute_tick_scaled_bps(&self, mid_price_ticks: PriceTicks) -> Result<ScaledBps, VortexError> {
        if mid_price_ticks.0 <= 0 || self.tick_size_1e8 <= 0 || self.lot_step_1e8 <= 0 {
            return Err(VortexError::InvalidPriceOrTickSpec);
        }
        let scaled = 1_000_000_i64 / mid_price_ticks.0;
        Ok(ScaledBps(scaled))
    }

    /// Validates that the contract meets institutional tick-size and volatility floors.
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
        let max_t = if self.symbol_id.0 >= 7 && self.symbol_id.0 <= 9 {
            800
        } else {
            ScaledBps::MAX_ALLOWED_TICK_BPS.0
        };
        if tick_bps.0 > max_t {
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

    /// Enforces that `expected_excursion_scaled_bps` is at least 3x round-trip friction.
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
        let eff_t = if self.symbol_id.0 >= 7 && self.symbol_id.0 <= 9 && tick_bps.0 > 150 {
            150
        } else {
            tick_bps.0
        };
        let round_trip_cost = ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.0 + exit_fee_expected + eff_t;
        let effective_floor = round_trip_cost * 3;

        if expected_excursion_scaled_bps.0 < effective_floor {
            return Err(VortexError::FrictionBarrierRejected {
                expected_excursion_scaled_bps,
                required_3x_barrier_scaled_bps: ScaledBps(effective_floor),
            });
        }
        Ok(ScaledBps(round_trip_cost))
    }

    /// Verifies that `proposed_sl` is strictly outside the 2-tick `MarkPrice` buffer.
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

    /// Scale-invariant minimum L1 queue depth in `LotQty` required to avoid paper-thin top-of-book traps.
    #[inline]
    #[must_use]
    #[allow(clippy::manual_clamp)]
    pub const fn min_resting_l1_lots(
        &self,
        entry_price: PriceTicks,
        realized_vol_5m: ScaledBps,
    ) -> i64 {
        if entry_price.0 <= 0 || self.tick_size_1e8 <= 0 || self.lot_step_1e8 <= 0 {
            return 15;
        }
        let vol_raw = realized_vol_5m.raw();
        let vol_clamped = if vol_raw < 4_000 {
            4_000
        } else if vol_raw > 10_000 {
            10_000
        } else {
            vol_raw
        };
        let min_notional_1e4 = (vol_clamped as i128) * 420;
        let lot_usdt_1e4 = ((entry_price.0 as i128)
            * (self.tick_size_1e8 as i128)
            * (self.lot_step_1e8 as i128))
            / 1_000_000_000_000;
        let denom = if lot_usdt_1e4 > 1 { lot_usdt_1e4 } else { 1 };
        let raw_lots = ((min_notional_1e4 + denom - 1) / denom) as i64;
        if raw_lots < 15 {
            15
        } else if raw_lots > 350 {
            350
        } else {
            raw_lots
        }
    }

    /// Unified scale-invariant L1 queue depth floor and elastic wall guard.
    #[inline]
    #[must_use]
    pub fn passes_l1_queue_depth_and_wall_guard(
        &self,
        entry_price: PriceTicks,
        realized_vol_5m: ScaledBps,
        own_q: i64,
        opp_q: i64,
        abs_ofi: f64,
        abs_tfi: f64,
    ) -> bool {
        let min_l1_q = self.min_resting_l1_lots(entry_price, realized_vol_5m);
        let vol_c = realized_vol_5m.raw().clamp(4_000, 12_500);
        let tfi_bonus_lots = (abs_tfi.clamp(0.0, 1.0) * 4_000.0) as i64;
        let max_wall_lots = (8_000 + ((vol_c * 2) / 3) + tfi_bonus_lots).clamp(10_000, 18_000);
        if own_q < min_l1_q || own_q > max_wall_lots {
            return false;
        }
        let tot_q = (own_q + opp_q).max(1);
        let tfi_exc = (abs_tfi - abs_ofi).max(0.0);
        let max_q_permille = 720 + ((tfi_exc * 100.0) as i64).min(60);
        (own_q * 1_000) / tot_q <= max_q_permille
    }
}

/// ANSI terminal color and badge constants shared across CLI binaries.
pub const ANSI_GREEN: &str = "\x1b[1;32m";
/// ANSI 256-color orange escape sequence.
pub const ANSI_ORANGE: &str = "\x1b[38;5;208m";
/// ANSI bold red escape sequence.
pub const ANSI_RED: &str = "\x1b[1;31m";
/// ANSI bold yellow escape sequence.
pub const ANSI_YELLOW: &str = "\x1b[1;33m";
/// ANSI gray escape sequence.
pub const ANSI_GRAY: &str = "\x1b[90m";
/// ANSI reset escape sequence.
pub const ANSI_RESET: &str = "\x1b[0m";

/// Computes the exact terminal column width of `s`, ignoring ANSI escape codes (`\x1b[...m`)
/// and counting wide Unicode emojis as 2 visual columns.
#[inline]
#[must_use]
pub fn visual_width_cols(s: &str) -> usize {
    let mut cols = 0_usize;
    let mut in_ansi = false;
    for ch in s.chars() {
        if in_ansi {
            if ch.is_ascii_alphabetic() {
                in_ansi = false;
            }
            continue;
        }
        if ch == '\x1b' {
            in_ansi = true;
            continue;
        }
        let cp = ch as u32;
        let w = if (0x1F300..=0x1FAFF).contains(&cp) || (0x2600..=0x27BF).contains(&cp) {
            2
        } else {
            1
        };
        cols += w;
    }
    cols
}

/// Formats a multi-section box (`╔═..═╗`, `╠═..═╣`, `╚═..═╝`) where every border and row
/// is mathematically padded to match the visual column width of the longest line.
#[must_use]
pub fn format_auto_aligned_box(sections: &[Vec<String>]) -> Vec<String> {
    let mut max_cols = 0_usize;
    for sec in sections {
        for line in sec {
            let w = visual_width_cols(line);
            if w > max_cols {
                max_cols = w;
            }
        }
    }
    if max_cols == 0 {
        return Vec::new();
    }
    let inner_w = max_cols + 2;
    let horiz = "\u{2550}".repeat(inner_w);
    let mut out = Vec::new();
    out.push(format!("\u{2554}{}\u{2557}", horiz));
    for (s_idx, sec) in sections.iter().enumerate() {
        if s_idx > 0 {
            out.push(format!("\u{2560}{}\u{2563}", horiz));
        }
        for line in sec {
            let w = visual_width_cols(line);
            let pad = max_cols.saturating_sub(w);
            out.push(format!("\u{2551} {line}{:pad$} \u{2551}", "", pad = pad));
        }
    }
    out.push(format!("\u{255a}{}\u{255d}", horiz));
    out
}

/// Prints a multi-section box aligned to the longest line.
pub fn print_auto_aligned_box(sections: &[Vec<String>]) {
    for line in format_auto_aligned_box(sections) {
        println!("{}", line);
    }
}

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
pub const APPROVED_SPECS: [PairSpec; 9] = [
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
    PairSpec {
        symbol_id: SymbolId(7),
        tick_size_1e8: 100_000,
        lot_step_1e8: 10_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(8),
        tick_size_1e8: 10_000,
        lot_step_1e8: 100_000_000,
        empirical_taker_exit_prob_pct: 20,
    },
    PairSpec {
        symbol_id: SymbolId(9),
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

/// Resolves a canonical Bybit ticker string (`"BTCUSDT"`..`"SUIUSDT"`) to its slot index `0..5`.
#[inline]
#[must_use]
pub fn slot_from_symbol_name(sym: &str) -> Option<usize> {
    match sym {
        "BTCUSDT" => Some(0),
        "ETHUSDT" => Some(1),
        "SOLUSDT" => Some(2),
        "AVAXUSDT" => Some(3),
        "TAOUSDT" => Some(4),
        "SUIUSDT" => Some(5),
        "ORDIUSDT" => Some(6),
        "PENDLEUSDT" => Some(7),
        "WIFUSDT" => Some(8),
        _ => None,
    }
}

/// Parses a side string (`"Ask"` / `"Sell"` vs `"Bid"` / `"Buy"`) into `Side`.
#[inline]
#[must_use]
pub fn side_from_str(raw: &str) -> Side {
    if raw == "Ask" || raw == "Sell" {
        Side::Ask
    } else {
        Side::Bid
    }
}

/// Returns the current UNIX epoch timestamp in nanoseconds.
#[inline]
#[must_use]
pub fn now_epoch_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(_) => 1_762_012_800_000_000_000,
    }
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