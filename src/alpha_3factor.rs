//! Orthogonal 3-factor microstructural alpha model (`X_OFI`, `X_TFI`, `X_Geom`)
//! with scale-invariant directional flow accumulators, anti-spoofing confirmation,
//! and 3x round-trip friction barrier enforcement.

use crate::lob_shm::{BookLevel, SymbolLobSnapshot};
use crate::types::{BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, VortexError};

/// Number of top L2 levels used for multi-scale Order Flow Imbalance (`X_OFI`).
pub const OFI_DEPTH: usize = 5;
/// Number of L2 levels used for Liquidity Geometry & Vacuum Ratio (`X_Geom`).
pub const GEOM_DEPTH: usize = 10;

/// Decision emitted by the orthogonal 3-factor evaluator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignalVerdict {
    /// Market conditions do not exhibit sufficient directional edge.
    NeutralNoAction,
    /// L2 book imbalance (`X_OFI`) is contradicted by aggressive trade flow (`X_TFI`), indicating passive spoofing.
    SpoofingVeto,
    /// Authorized passive `Limit PostOnly` entry at the BBO.
    AuthorizeMakerEntry {
        side: Side,
        target_excursion_scaled_bps: ScaledBps,
        estimated_cost_rt_scaled_bps: ScaledBps,
    },
}

/// Zero-allocation per-symbol rolling state for the 3 orthogonal factors.
#[derive(Copy, Clone, Debug)]
pub struct OrthogonalFactorState {
    initialized: bool,
    prev_bids: [BookLevel; OFI_DEPTH],
    prev_asks: [BookLevel; OFI_DEPTH],
    ofi_pos_fast: f64,
    ofi_neg_fast: f64,
    ofi_pos_med: f64,
    ofi_neg_med: f64,
    ofi_pos_slow: f64,
    ofi_neg_slow: f64,
    tfi_buy_accum: f64,
    tfi_sell_accum: f64,
    last_ofi: BoundedScore,
    last_tfi: BoundedScore,
    last_geom: BoundedScore,
}

impl Default for OrthogonalFactorState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl OrthogonalFactorState {
    /// Creates a zeroed factor state on the stack.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            prev_bids: [BookLevel {
                price: PriceTicks(0),
                qty: LotQty(0),
            }; OFI_DEPTH],
            prev_asks: [BookLevel {
                price: PriceTicks(0),
                qty: LotQty(0),
            }; OFI_DEPTH],
            ofi_pos_fast: 0.0,
            ofi_neg_fast: 0.0,
            ofi_pos_med: 0.0,
            ofi_neg_med: 0.0,
            ofi_pos_slow: 0.0,
            ofi_neg_slow: 0.0,
            tfi_buy_accum: 0.0,
            tfi_sell_accum: 0.0,
            last_ofi: BoundedScore::ZERO,
            last_tfi: BoundedScore::ZERO,
            last_geom: BoundedScore::ZERO,
        }
    }

    /// Wipes any prior or synthetic state when a fresh L2 snapshot arrives from the exchange.
    #[inline]
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Updates Factor 2 (`X_TFI`) from a real executed `publicTrade` event.
    #[inline]
    pub fn on_public_trade(&mut self, aggressor_side: Side, qty: LotQty) -> BoundedScore {
        let q = (qty.0.max(0)) as f64;
        self.tfi_buy_accum *= 0.92;
        self.tfi_sell_accum *= 0.92;
        match aggressor_side {
            Side::Bid => self.tfi_buy_accum += q,
            Side::Ask => self.tfi_sell_accum += q,
        }
        let total = self.tfi_buy_accum + self.tfi_sell_accum;
        if total <= 1e-9 {
            self.last_tfi = BoundedScore::ZERO;
        } else {
            let raw_tfi = (self.tfi_buy_accum - self.tfi_sell_accum) / total;
            self.last_tfi = BoundedScore::new_clamped(raw_tfi);
        }
        self.last_tfi
    }

    /// Updates Factor 1 (`X_OFI`) using scale-invariant directional pressure accumulators
    /// and Factor 3 (`X_Geom`) from a new L2 book snapshot.
    #[inline]
    pub fn on_l2_snapshot(&mut self, snap: &mut SymbolLobSnapshot) {
        let level_weights: [f64; OFI_DEPTH] = [1.0, 0.70, 0.45, 0.25, 0.12];
        let mut cur_bids = [BookLevel::default(); OFI_DEPTH];
        let mut cur_asks = [BookLevel::default(); OFI_DEPTH];

        let mut i = 0;
        while i < OFI_DEPTH {
            cur_bids[i] = snap.bids[i];
            cur_asks[i] = snap.asks[i];
            i += 1;
        }

        if !self.initialized {
            self.prev_bids = cur_bids;
            self.prev_asks = cur_asks;
            self.initialized = true;
        } else {
            let mut pos_pressure = 0.0;
            let mut neg_pressure = 0.0;

            let mut lvl = 0;
            while lvl < OFI_DEPTH {
                let w = level_weights[lvl];
                let b_cur = cur_bids[lvl];
                let b_prv = self.prev_bids[lvl];
                let a_cur = cur_asks[lvl];
                let a_prv = self.prev_asks[lvl];

                let bid_delta = if b_cur.price.0 > b_prv.price.0 {
                    b_cur.qty.0 as f64
                } else if b_cur.price.0 < b_prv.price.0 {
                    -(b_prv.qty.0 as f64)
                } else {
                    (b_cur.qty.0 - b_prv.qty.0) as f64
                };

                let ask_delta = if a_cur.price.0 < a_prv.price.0 {
                    a_cur.qty.0 as f64
                } else if a_cur.price.0 > a_prv.price.0 {
                    -(a_prv.qty.0 as f64)
                } else {
                    (a_cur.qty.0 - a_prv.qty.0) as f64
                };

                let net_level_impulse = w * (bid_delta - ask_delta);
                if net_level_impulse > 0.0 {
                    pos_pressure += net_level_impulse;
                } else if net_level_impulse < 0.0 {
                    neg_pressure += -net_level_impulse;
                }
                lvl += 1;
            }

            // Multi-scale directional accumulators: Fast (~500ms), Medium (~3s), Slow (~15s)
            self.ofi_pos_fast = 0.80 * self.ofi_pos_fast + pos_pressure;
            self.ofi_neg_fast = 0.80 * self.ofi_neg_fast + neg_pressure;

            self.ofi_pos_med = 0.94 * self.ofi_pos_med + pos_pressure;
            self.ofi_neg_med = 0.94 * self.ofi_neg_med + neg_pressure;

            self.ofi_pos_slow = 0.985 * self.ofi_pos_slow + pos_pressure;
            self.ofi_neg_slow = 0.985 * self.ofi_neg_slow + neg_pressure;

            let fast_ratio = Self::directional_ratio(self.ofi_pos_fast, self.ofi_neg_fast);
            let med_ratio = Self::directional_ratio(self.ofi_pos_med, self.ofi_neg_med);
            let slow_ratio = Self::directional_ratio(self.ofi_pos_slow, self.ofi_neg_slow);

            let blended_ofi = 0.50 * fast_ratio + 0.35 * med_ratio + 0.15 * slow_ratio;
            self.last_ofi = BoundedScore::new_clamped(blended_ofi);
            self.prev_bids = cur_bids;
            self.prev_asks = cur_asks;
        }

        // Factor 3: Liquidity Geometry & Vacuum Ratio across L1..L10 penalized by spread in ticks
        let mut bid_depth_10 = 0_i64;
        let mut ask_depth_10 = 0_i64;
        let mut k = 0;
        while k < GEOM_DEPTH {
            bid_depth_10 += snap.bids[k].qty.0.max(0);
            ask_depth_10 += snap.asks[k].qty.0.max(0);
            k += 1;
        }
        let spread_ticks = match snap.bbo_and_spread_ticks() {
            Some((_, _, s)) => s.max(1) as f64,
            None => 10.0,
        };
        let total_depth = ((bid_depth_10 + ask_depth_10).max(1)) as f64;
        let depth_imbalance = ((bid_depth_10 - ask_depth_10) as f64) / total_depth;
        let spread_penalty = 1.0 / (1.0 + 0.25 * (spread_ticks - 1.0));
        self.last_geom = BoundedScore::new_clamped(depth_imbalance * spread_penalty);

        snap.factor_ofi = self.last_ofi;
        snap.factor_tfi = self.last_tfi;
        snap.factor_geom = self.last_geom;
    }

    #[inline]
    fn directional_ratio(pos: f64, neg: f64) -> f64 {
        let total = pos + neg;
        if total <= 1e-9 {
            0.0
        } else {
            (pos - neg) / total
        }
    }

    /// Evaluates whether the 3 orthogonal factors authorize a passive Maker entry
    /// after enforcing the Anti-Spoofing check and the 3x Round-Trip Friction Barrier.
    #[inline]
    pub fn evaluate_entry_signal(
        &self,
        spec: &PairSpec,
        snap: &SymbolLobSnapshot,
    ) -> Result<SignalVerdict, VortexError> {
        let (best_bid, best_ask, _) = match snap.bbo_and_spread_ticks() {
            Some(bbo) => bbo,
            None => return Err(VortexError::InvalidPriceOrTickSpec),
        };
        let mid_ticks = PriceTicks((best_bid.price.0 + best_ask.price.0) / 2);

        let _tick_bps = spec.validate_eligibility(mid_ticks, snap.realized_vol_5m)?;

        let x_ofi = snap.factor_ofi.get();
        let x_tfi = snap.factor_tfi.get();
        let x_geom = snap.factor_geom.get();

        if (x_ofi >= 0.35 && x_tfi <= -0.05) || (x_ofi <= -0.35 && x_tfi >= 0.05) {
            return Ok(SignalVerdict::SpoofingVeto);
        }

        let composite = 0.45 * x_ofi + 0.35 * x_tfi + 0.20 * x_geom;
        let abs_comp = composite.abs();
        if abs_comp < 0.42 {
            return Ok(SignalVerdict::NeutralNoAction);
        }

        let long_aligned = x_ofi > 0.25 && x_tfi > 0.20 && x_geom > 0.10;
        let short_aligned = x_ofi < -0.25 && x_tfi < -0.20 && x_geom < -0.10;
        if !long_aligned && !short_aligned {
            return Ok(SignalVerdict::NeutralNoAction);
        }

        let vol_bps = snap.realized_vol_5m.raw() as f64;
        let predicted_scaled = ((vol_bps * abs_comp * 1.15) as i64)
            .clamp(0, ScaledBps::MAX_STRUCTURAL_EXCURSION_BPS.raw());
        let expected_excursion = ScaledBps(predicted_scaled);

        let cost_rt = spec.passes_3x_friction_barrier(mid_ticks, expected_excursion)?;

        let side = if long_aligned { Side::Bid } else { Side::Ask };
        Ok(SignalVerdict::AuthorizeMakerEntry {
            side,
            target_excursion_scaled_bps: expected_excursion,
            estimated_cost_rt_scaled_bps: cost_rt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SymbolId, TimestampNs};

    #[test]
    fn test_anti_spoofing_veto_when_trade_tape_contradicts_book_ofi() {
        let spec = PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 10_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let state = OrthogonalFactorState::new();
        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            is_eligible: true,
            sequence_id: 10,
            ts_exchange_ns: TimestampNs(1_000),
            ts_local_ns: TimestampNs(1_005),
            mark_price: PriceTicks(20_000),
            last_trade_price: PriceTicks(20_000),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.65),
            factor_tfi: BoundedScore::new_clamped(-0.30),
            factor_geom: BoundedScore::new_clamped(0.40),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(20_000),
            qty: LotQty(500),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(20_001),
            qty: LotQty(200),
        };

        let verdict = state.evaluate_entry_signal(&spec, &snap);
        assert_eq!(verdict, Ok(SignalVerdict::SpoofingVeto));
    }

    #[test]
    fn test_orthogonal_alignment_and_3x_friction_authorization() {
        let spec = PairSpec {
            symbol_id: SymbolId(2),
            tick_size_1e8: 10_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let mut state = OrthogonalFactorState::new();
        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(2),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(1_000),
            ts_local_ns: TimestampNs(1_005),
            mark_price: PriceTicks(25_000),
            last_trade_price: PriceTicks(25_000),
            realized_vol_5m: ScaledBps::from_whole_bps(65),
            ..SymbolLobSnapshot::default()
        };
        for i in 0..10 {
            snap.bids[i] = BookLevel {
                price: PriceTicks(25_000 - (i as i64)),
                qty: LotQty(100),
            };
            snap.asks[i] = BookLevel {
                price: PriceTicks(25_001 + (i as i64)),
                qty: LotQty(100),
            };
        }
        state.on_l2_snapshot(&mut snap);

        for _ in 0..6 {
            let _ = state.on_public_trade(Side::Bid, LotQty(5));
            snap.bids[0].qty.0 += 2;
            state.on_l2_snapshot(&mut snap);
        }

        assert!(snap.factor_ofi.get() > 0.80);
        let verdict = state.evaluate_entry_signal(&spec, &snap);
        assert!(matches!(
            verdict,
            Ok(SignalVerdict::AuthorizeMakerEntry {
                side: Side::Bid,
                ..
            })
        ));
    }
}