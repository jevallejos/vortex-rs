//! Orthogonal 3-factor microstructural alpha model (`X_OFI`, `X_TFI`, `X_Geom`)
//! with anti-spoofing confirmation and 3x round-trip friction barrier enforcement.

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
    ema_reference_depth: f64,
    ofi_fast_500ms: f64,
    ofi_med_3s: f64,
    ofi_slow_15s: f64,
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
            ema_reference_depth: 1.0,
            ofi_fast_500ms: 0.0,
            ofi_med_3s: 0.0,
            ofi_slow_15s: 0.0,
            tfi_buy_accum: 0.0,
            tfi_sell_accum: 0.0,
            last_ofi: BoundedScore::ZERO,
            last_tfi: BoundedScore::ZERO,
            last_geom: BoundedScore::ZERO,
        }
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
        let total = (self.tfi_buy_accum + self.tfi_sell_accum).max(1e-9);
        let raw_tfi = (self.tfi_buy_accum - self.tfi_sell_accum) / total;
        self.last_tfi = BoundedScore::new_clamped(raw_tfi);
        self.last_tfi
    }

    /// Updates Factor 1 (`X_OFI`) and Factor 3 (`X_Geom`) from a new L2 book snapshot
    /// and writes the 3 pre-warmed orthogonal factors into `snap`.
    #[inline]
    pub fn on_l2_snapshot(&mut self, snap: &mut SymbolLobSnapshot) {
        let level_weights: [f64; OFI_DEPTH] = [1.0, 0.70, 0.45, 0.25, 0.12];
        let mut cur_bids = [BookLevel::default(); OFI_DEPTH];
        let mut cur_asks = [BookLevel::default(); OFI_DEPTH];
        let mut cur_weighted_depth = 0.0;

        let mut i = 0;
        while i < OFI_DEPTH {
            cur_bids[i] = snap.bids[i];
            cur_asks[i] = snap.asks[i];
            cur_weighted_depth +=
                level_weights[i] * ((cur_bids[i].qty.0.max(1) + cur_asks[i].qty.0.max(1)) as f64);
            i += 1;
        }

        if !self.initialized {
            self.prev_bids = cur_bids;
            self.prev_asks = cur_asks;
            self.ema_reference_depth = cur_weighted_depth.max(1.0);
            self.initialized = true;
        } else {
            let mut net_flow = 0.0;
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

                net_flow += w * (bid_delta - ask_delta);
                lvl += 1;
            }

            // Normalize against pre-impact smoothed reference depth to prevent self-dilution
            let step_ofi = (net_flow / self.ema_reference_depth.max(1.0)).clamp(-1.0, 1.0);
            self.ema_reference_depth =
                0.95 * self.ema_reference_depth + 0.05 * cur_weighted_depth.max(1.0);

            self.ofi_fast_500ms = 0.65 * self.ofi_fast_500ms + 0.35 * step_ofi;
            self.ofi_med_3s = 0.90 * self.ofi_med_3s + 0.10 * step_ofi;
            self.ofi_slow_15s = 0.975 * self.ofi_slow_15s + 0.025 * step_ofi;

            let blended_ofi =
                0.50 * self.ofi_fast_500ms + 0.35 * self.ofi_med_3s + 0.15 * self.ofi_slow_15s;
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
            let _ = state.on_public_trade(Side::Bid, LotQty(450));
            for i in 0..5 {
                snap.bids[i].qty.0 += 350;
            }
            state.on_l2_snapshot(&mut snap);
        }

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