//! Exhaustive Finite-State Machine (`OrderLifecycleState`) for Bybit UTA V5 execution:
//! 100% `Limit PostOnly` normal exits, geometric `MarkPrice` Stop-Loss protection,
//! deterministic `110017` win reconciliation (zero false quarantine), and `110007` margin guard.

use crate::alpha_3factor::SignalVerdict;
use crate::forensic_parquet::ParitySyncLedger;
use crate::lob_shm::SymbolLobSnapshot;
use crate::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, TimestampNs, VortexError};

/// Cooldown applied ONLY after a real server-side Stop-Loss trigger (60 seconds in nanoseconds).
pub const STOP_LOSS_COOLDOWN_NS: i64 = 60_000_000_000;

/// Canonical Bybit UTA V5 return codes handled deterministically by the execution FSM.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BybitRetCode {
    /// `retCode = 0`: Request accepted.
    OkZero,
    /// `retCode = 10001`: Parameter or Stop-Loss MarkPrice geometry violation.
    SlGeometryError10001,
    /// `retCode = 110007`: Insufficient available margin in UTA wallet.
    InsufficientMargin110007,
    /// `retCode = 110017`: Order does not exist or position was already closed.
    OrderNotExistsOrAlreadyClosed110017,
}

/// Terminal halt reason when the risk guard locks the execution engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HaltReason {
    InsufficientMargin110007,
    AccountingParityDrift,
    MaxDailyDrawdownBreached,
}

/// Classification of a completed trade for forensic and OOS attribution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClosedTradeKind {
    /// Passive `Limit PostOnly` Take-Profit at structural target (`35..80 bps`).
    MakerStructuralTp,
    /// Passive `Limit PostOnly` BBO unwind when flow exhausts in profit.
    MakerPassiveUnwind,
    /// Catastrophic server-side `MarkPrice` Stop-Loss (`Taker` fee + `1 tick` slippage).
    ServerMarkPriceStopLoss,
}

/// Exhaustive algebraic state machine governing a single concurrent slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OrderLifecycleState {
    Idle,
    PlacingEntryMaker {
        side: Side,
        entry_price: PriceTicks,
        qty: LotQty,
        target_excursion: ScaledBps,
        sl_trigger_price: PriceTicks,
        submitted_ts: TimestampNs,
    },
    RestingEntryQueue {
        side: Side,
        entry_price: PriceTicks,
        qty: LotQty,
        target_excursion: ScaledBps,
        sl_trigger_price: PriceTicks,
        resting_since_ts: TimestampNs,
    },
    PositionOpenMakerExit {
        side: Side,
        entry_price: PriceTicks,
        qty: LotQty,
        tp_maker_price: PriceTicks,
        sl_trigger_price: PriceTicks,
        opened_ts: TimestampNs,
    },
    EmergencyStopTriggered {
        side: Side,
        entry_price: PriceTicks,
        exit_price: PriceTicks,
        qty: LotQty,
        triggered_ts: TimestampNs,
    },
    HaltedByRiskGuard {
        reason: HaltReason,
    },
}

/// Summary record returned whenever a position closes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClosedTradeSummary {
    pub kind: ClosedTradeKind,
    pub side: Side,
    pub entry_price: PriceTicks,
    pub exit_price: PriceTicks,
    pub gross_scaled_bps: ScaledBps,
    pub fee_scaled_bps: ScaledBps,
    pub net_scaled_bps: ScaledBps,
    pub net_pnl_1e8: i64,
    pub is_maker_exit: bool,
}

/// Deterministic Execution State Machine coupled to `ParitySyncLedger`.
#[derive(Copy, Clone, Debug)]
pub struct ExecutionFsm {
    pub state: OrderLifecycleState,
    pub notional_per_trade_1e8: i64,
    pub max_daily_drawdown_1e8: i64,
    pub cooldown_until_ns: TimestampNs,
    pub maker_exits_count: u64,
    pub taker_sl_exits_count: u64,
    pub gross_profit_accum_1e8: i64,
    pub gross_loss_accum_1e8: i64,
}

impl Default for ExecutionFsm {
    #[inline]
    fn default() -> Self {
        Self::new(10_000_000_000, 1_500_000_000)
    }
}

impl ExecutionFsm {
    /// Creates a new Execution FSM with fixed notional (`1e8` scale) and daily drawdown limit.
    #[inline]
    #[must_use]
    pub const fn new(notional_per_trade_1e8: i64, max_daily_drawdown_1e8: i64) -> Self {
        Self {
            state: OrderLifecycleState::Idle,
            notional_per_trade_1e8,
            max_daily_drawdown_1e8,
            cooldown_until_ns: TimestampNs(0),
            maker_exits_count: 0,
            taker_sl_exits_count: 0,
            gross_profit_accum_1e8: 0,
            gross_loss_accum_1e8: 0,
        }
    }

    /// Evaluates transition from `Idle` to `PlacingEntryMaker` using a validated `SignalVerdict`.
    #[inline]
    pub fn try_arm_maker_entry(
        &mut self,
        spec: &PairSpec,
        snap: &SymbolLobSnapshot,
        verdict: SignalVerdict,
        order_qty: LotQty,
    ) -> Result<bool, VortexError> {
        if !matches!(self.state, OrderLifecycleState::Idle) {
            return Ok(false);
        }
        if snap.ts_local_ns.0 < self.cooldown_until_ns.0 {
            return Ok(false);
        }

        let (side, target_excursion) = match verdict {
            SignalVerdict::AuthorizeMakerEntry {
                side,
                target_excursion_scaled_bps,
                ..
            } => (side, target_excursion_scaled_bps),
            SignalVerdict::NeutralNoAction | SignalVerdict::SpoofingVeto => return Ok(false),
        };

        let (best_bid, best_ask, _) = match snap.bbo_and_spread_ticks() {
            Some(bbo) => bbo,
            None => return Err(VortexError::InvalidPriceOrTickSpec),
        };

        let entry_price = match side {
            Side::Bid => best_bid.price,
            Side::Ask => best_ask.price,
        };

        // Structural Stop-Loss distance: 52.00 bps (scaled 5_200), minimum 4 ticks away
        let sl_distance_ticks = ((entry_price.0 * 5_200) / 1_000_000).max(4);
        let proposed_sl = match side {
            Side::Bid => PriceTicks(entry_price.0 - sl_distance_ticks),
            Side::Ask => PriceTicks(entry_price.0 + sl_distance_ticks),
        };

        let _ = spec;
        PairSpec::validate_stop_loss_geometry(
            side,
            proposed_sl,
            snap.last_trade_price,
            snap.mark_price,
        )?;

        self.state = OrderLifecycleState::PlacingEntryMaker {
            side,
            entry_price,
            qty: order_qty,
            target_excursion,
            sl_trigger_price: proposed_sl,
            submitted_ts: snap.ts_local_ns,
        };
        Ok(true)
    }

    /// Confirms that the `Limit PostOnly` entry order is resting on the L1 queue without crossing.
    #[inline]
    pub fn on_entry_order_resting(&mut self, ts_ns: TimestampNs) -> bool {
        if let OrderLifecycleState::PlacingEntryMaker {
            side,
            entry_price,
            qty,
            target_excursion,
            sl_trigger_price,
            ..
        } = self.state
        {
            self.state = OrderLifecycleState::RestingEntryQueue {
                side,
                entry_price,
                qty,
                target_excursion,
                sl_trigger_price,
                resting_since_ts: ts_ns,
            };
            return true;
        }
        false
    }

    /// Aborts a resting entry order if executed trade flow (`X_TFI`) flips against the order before fill.
    #[inline]
    pub fn check_resting_queue_abort(&mut self, snap: &SymbolLobSnapshot) -> bool {
        if let OrderLifecycleState::RestingEntryQueue { side, .. } = self.state {
            let tfi = snap.factor_tfi.get();
            let adverse_flip = match side {
                Side::Bid => tfi <= -0.15,
                Side::Ask => tfi >= 0.15,
            };
            if adverse_flip {
                self.state = OrderLifecycleState::Idle;
                return true;
            }
        }
        false
    }

    /// Transitions from `RestingEntryQueue` to `PositionOpenMakerExit` upon passive L1 fill.
    #[inline]
    pub fn on_entry_filled_maker(&mut self, fill_ts_ns: TimestampNs) -> bool {
        if let OrderLifecycleState::RestingEntryQueue {
            side,
            entry_price,
            qty,
            target_excursion,
            sl_trigger_price,
            ..
        } = self.state
        {
            let tp_delta_ticks =
                ((entry_price.0 * target_excursion.raw()) / 1_000_000).max(2);
            let tp_maker_price = match side {
                Side::Bid => PriceTicks(entry_price.0 + tp_delta_ticks),
                Side::Ask => PriceTicks((entry_price.0 - tp_delta_ticks).max(1)),
            };
            self.state = OrderLifecycleState::PositionOpenMakerExit {
                side,
                entry_price,
                qty,
                tp_maker_price,
                sl_trigger_price,
                opened_ts: fill_ts_ns,
            };
            return true;
        }
        false
    }

    /// Evaluates open position against current L2 + `MarkPrice` state.
    /// Executes 100% passive Maker exits (`MakerStructuralTp` or `MakerPassiveUnwind`)
    /// or triggers catastrophic server-side `MarkPrice` Stop-Loss.
    #[inline]
    pub fn step_open_position(
        &mut self,
        snap: &SymbolLobSnapshot,
        ledger: &mut ParitySyncLedger,
    ) -> Option<ClosedTradeSummary> {
        let (side, entry_price, qty, tp_maker_price, sl_trigger_price) = match self.state {
            OrderLifecycleState::PositionOpenMakerExit {
                side,
                entry_price,
                qty,
                tp_maker_price,
                sl_trigger_price,
                ..
            } => (side, entry_price, qty, tp_maker_price, sl_trigger_price),
            _ => return None,
        };

        // 1. Check catastrophic server-side MarkPrice Stop-Loss first
        let sl_hit = match side {
            Side::Bid => snap.mark_price.0 <= sl_trigger_price.0,
            Side::Ask => snap.mark_price.0 >= sl_trigger_price.0,
        };
        if sl_hit {
            // Apply 1 tick adverse Taker slippage on emergency SL
            let sl_fill_price = match side {
                Side::Bid => PriceTicks((sl_trigger_price.0 - 1).max(1)),
                Side::Ask => PriceTicks(sl_trigger_price.0 + 1),
            };
            self.state = OrderLifecycleState::EmergencyStopTriggered {
                side,
                entry_price,
                exit_price: sl_fill_price,
                qty,
                triggered_ts: snap.ts_local_ns,
            };
            return Some(self.finalize_close(
                ClosedTradeKind::ServerMarkPriceStopLoss,
                side,
                entry_price,
                sl_fill_price,
                snap.ts_local_ns,
                ledger,
            ));
        }

        // 2. Check passive Limit PostOnly structural Take-Profit fill
        let tp_hit = match side {
            Side::Bid => snap.last_trade_price.0 >= tp_maker_price.0,
            Side::Ask => snap.last_trade_price.0 <= tp_maker_price.0,
        };
        if tp_hit {
            return Some(self.finalize_close(
                ClosedTradeKind::MakerStructuralTp,
                side,
                entry_price,
                tp_maker_price,
                snap.ts_local_ns,
                ledger,
            ));
        }

        // 3. Check passive Maker Unwind at BBO (only when net profitable >= 8.00 bps gross and flow reverses)
        if let Some((best_bid, best_ask, _)) = snap.bbo_and_spread_ticks() {
            let bbo_exit_price = match side {
                Side::Bid => best_bid.price,
                Side::Ask => best_ask.price,
            };
            let current_gross_bps = Self::compute_gross_scaled_bps(side, entry_price, bbo_exit_price);
            let flow_exhausted = match side {
                Side::Bid => snap.factor_ofi.get() < -0.10 && snap.factor_tfi.get() < -0.10,
                Side::Ask => snap.factor_ofi.get() > 0.10 && snap.factor_tfi.get() > 0.10,
            };
            if current_gross_bps.raw() >= 800 && flow_exhausted {
                return Some(self.finalize_close(
                    ClosedTradeKind::MakerPassiveUnwind,
                    side,
                    entry_price,
                    bbo_exit_price,
                    snap.ts_local_ns,
                    ledger,
                ));
            }
        }

        None
    }

    /// Handles Bybit UTA V5 return codes deterministically, including `110017` without
    /// penalizing winning trades with quarantine, and `110007` immediate margin halt.
    #[inline]
    pub fn on_exchange_retcode(
        &mut self,
        ret_code: BybitRetCode,
        snap: &SymbolLobSnapshot,
        ledger: &mut ParitySyncLedger,
    ) -> Option<ClosedTradeSummary> {
        match ret_code {
            BybitRetCode::OkZero => None,
            BybitRetCode::SlGeometryError10001 => {
                if matches!(self.state, OrderLifecycleState::PlacingEntryMaker { .. }) {
                    self.state = OrderLifecycleState::Idle;
                }
                None
            }
            BybitRetCode::InsufficientMargin110007 => {
                self.state = OrderLifecycleState::HaltedByRiskGuard {
                    reason: HaltReason::InsufficientMargin110007,
                };
                None
            }
            BybitRetCode::OrderNotExistsOrAlreadyClosed110017 => {
                if let OrderLifecycleState::PositionOpenMakerExit {
                    side,
                    entry_price,
                    tp_maker_price,
                    sl_trigger_price,
                    ..
                } = self.state
                {
                    let is_win = match side {
                        Side::Bid => snap.last_trade_price.0 >= entry_price.0,
                        Side::Ask => snap.last_trade_price.0 <= entry_price.0,
                    };
                    if is_win {
                        return Some(self.finalize_close(
                            ClosedTradeKind::MakerStructuralTp,
                            side,
                            entry_price,
                            tp_maker_price,
                            snap.ts_local_ns,
                            ledger,
                        ));
                    }
                    return Some(self.finalize_close(
                        ClosedTradeKind::ServerMarkPriceStopLoss,
                        side,
                        entry_price,
                        sl_trigger_price,
                        snap.ts_local_ns,
                        ledger,
                    ));
                }
                None
            }
        }
    }

    #[inline]
    const fn compute_gross_scaled_bps(
        side: Side,
        entry_price: PriceTicks,
        exit_price: PriceTicks,
    ) -> ScaledBps {
        if entry_price.0 <= 0 {
            return ScaledBps(0);
        }
        let diff = match side {
            Side::Bid => exit_price.0 - entry_price.0,
            Side::Ask => entry_price.0 - exit_price.0,
        };
        ScaledBps((diff * 1_000_000) / entry_price.0)
    }

    #[inline]
    fn finalize_close(
        &mut self,
        kind: ClosedTradeKind,
        side: Side,
        entry_price: PriceTicks,
        exit_price: PriceTicks,
        close_ts_ns: TimestampNs,
        ledger: &mut ParitySyncLedger,
    ) -> ClosedTradeSummary {
        let gross_scaled_bps = Self::compute_gross_scaled_bps(side, entry_price, exit_price);
        let is_maker_exit = match kind {
            ClosedTradeKind::MakerStructuralTp | ClosedTradeKind::MakerPassiveUnwind => true,
            ClosedTradeKind::ServerMarkPriceStopLoss => false,
        };

        let fee_scaled_bps = if is_maker_exit {
            // Maker entry (2.00 bps) + Maker exit (2.00 bps) = 4.00 bps (400 ScaledBps)
            ScaledBps(
                ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw()
                    + ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw(),
            )
        } else {
            // Maker entry (2.00 bps) + Taker SL exit (5.50 bps) = 7.50 bps (750 ScaledBps)
            ScaledBps(
                ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw()
                    + ScaledBps::BYBIT_VIP0_TAKER_FEE_BPS.raw(),
            )
        };

        let net_scaled_bps = ScaledBps(gross_scaled_bps.raw() - fee_scaled_bps.raw());
        let gross_pnl_1e8 = (self.notional_per_trade_1e8 * gross_scaled_bps.raw()) / 1_000_000;
        let fee_1e8 = (self.notional_per_trade_1e8 * fee_scaled_bps.raw()) / 1_000_000;
        let net_pnl_1e8 = gross_pnl_1e8 - fee_1e8;

        ledger.record_closed_trade(gross_pnl_1e8, fee_1e8);

        if is_maker_exit {
            self.maker_exits_count += 1;
            // Zero quarantine on winning Maker exits
            self.cooldown_until_ns = TimestampNs(0);
        } else {
            self.taker_sl_exits_count += 1;
            self.cooldown_until_ns = TimestampNs(close_ts_ns.0 + STOP_LOSS_COOLDOWN_NS);
        }

        if net_pnl_1e8 >= 0 {
            self.gross_profit_accum_1e8 += net_pnl_1e8;
        } else {
            self.gross_loss_accum_1e8 += -net_pnl_1e8;
        }

        if ledger.cumulative_net_pnl_1e8 <= -self.max_daily_drawdown_1e8 {
            self.state = OrderLifecycleState::HaltedByRiskGuard {
                reason: HaltReason::MaxDailyDrawdownBreached,
            };
        } else {
            self.state = OrderLifecycleState::Idle;
        }

        ClosedTradeSummary {
            kind,
            side,
            entry_price,
            exit_price,
            gross_scaled_bps,
            fee_scaled_bps,
            net_scaled_bps,
            net_pnl_1e8,
            is_maker_exit,
        }
    }

    /// Computes Net Profit Factor scaled by 100 (e.g., 241 = 2.41 Profit Factor).
    #[inline]
    #[must_use]
    pub const fn net_profit_factor_x100(&self) -> i64 {
        if self.gross_loss_accum_1e8 <= 0 {
            return 999;
        }
        (self.gross_profit_accum_1e8 * 100) / self.gross_loss_accum_1e8
    }

    /// Computes percentage of all closed trades exited passively as Maker (scaled by 100, e.g., 8230 = 82.30%).
    #[inline]
    #[must_use]
    pub const fn maker_exit_ratio_bps(&self) -> u64 {
        let total = self.maker_exits_count + self.taker_sl_exits_count;
        if total == 0 {
            return 0;
        }
        (self.maker_exits_count * 10_000) / total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lob_shm::BookLevel;
    use crate::types::SymbolId;

    #[test]
    fn test_fsm_100pct_maker_lifecycle_and_zero_quarantine_on_win_110017() {
        let spec = PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 10_000_000,
            lot_step_1e8: 100_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let mut fsm = ExecutionFsm::new(10_000_000_000, 1_500_000_000);
        let mut ledger = ParitySyncLedger::new(5_000_000_000);

        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(1_000_000_000),
            ts_local_ns: TimestampNs(1_000_000_000),
            mark_price: PriceTicks(100_000),
            last_trade_price: PriceTicks(100_000),
            realized_vol_5m: ScaledBps::from_whole_bps(55),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(100_000),
            qty: LotQty(200),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(100_001),
            qty: LotQty(200),
        };

        let verdict = SignalVerdict::AuthorizeMakerEntry {
            side: Side::Bid,
            target_excursion_scaled_bps: ScaledBps::from_whole_bps(42),
            estimated_cost_rt_scaled_bps: ScaledBps(480),
        };

        assert_eq!(
            fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10)),
            Ok(true)
        );
        assert!(fsm.on_entry_order_resting(TimestampNs(1_025_000_000)));
        assert!(fsm.on_entry_filled_maker(TimestampNs(1_050_000_000)));

        // Simulate price reaching +42 bps (100_420 ticks) and Bybit returning 110017 on order check
        snap.last_trade_price = PriceTicks(100_420);
        snap.mark_price = PriceTicks(100_420);
        snap.ts_local_ns = TimestampNs(5_000_000_000);

        let closed = fsm.on_exchange_retcode(
            BybitRetCode::OrderNotExistsOrAlreadyClosed110017,
            &snap,
            &mut ledger,
        );
        assert!(closed.is_some());
        if let Some(summary) = closed {
            assert_eq!(summary.kind, ClosedTradeKind::MakerStructuralTp);
            assert!(summary.is_maker_exit);
            assert_eq!(summary.net_scaled_bps, ScaledBps(3_800)); // +42.00 bps gross - 4.00 bps Maker fees = +38.00 bps
        }
        // Winning 110017 must NEVER trigger pair cooldown quarantine
        assert_eq!(fsm.cooldown_until_ns, TimestampNs(0));
        assert_eq!(fsm.state, OrderLifecycleState::Idle);
    }

    #[test]
    fn test_fsm_mark_price_stop_loss_and_110007_margin_halt() {
        let spec = PairSpec {
            symbol_id: SymbolId(2),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let mut fsm = ExecutionFsm::new(10_000_000_000, 1_500_000_000);
        let mut ledger = ParitySyncLedger::new(5_000_000_000);

        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(2),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(2_000_000_000),
            ts_local_ns: TimestampNs(2_000_000_000),
            mark_price: PriceTicks(100_000),
            last_trade_price: PriceTicks(100_000),
            realized_vol_5m: ScaledBps::from_whole_bps(50),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(100_000),
            qty: LotQty(200),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(100_001),
            qty: LotQty(200),
        };

        let verdict = SignalVerdict::AuthorizeMakerEntry {
            side: Side::Bid,
            target_excursion_scaled_bps: ScaledBps::from_whole_bps(40),
            estimated_cost_rt_scaled_bps: ScaledBps(480),
        };

        assert_eq!(
            fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10)),
            Ok(true)
        );
        assert!(fsm.on_entry_order_resting(TimestampNs(2_025_000_000)));
        assert!(fsm.on_entry_filled_maker(TimestampNs(2_050_000_000)));

        // Breach server-side MarkPrice Stop-Loss (99_480 ticks)
        snap.mark_price = PriceTicks(99_480);
        snap.last_trade_price = PriceTicks(99_480);
        snap.ts_local_ns = TimestampNs(10_000_000_000);

        let sl_summary = fsm.step_open_position(&snap, &mut ledger);
        assert!(sl_summary.is_some());
        if let Some(s) = sl_summary {
            assert_eq!(s.kind, ClosedTradeKind::ServerMarkPriceStopLoss);
            assert!(!s.is_maker_exit);
            assert!(s.net_pnl_1e8 < 0);
        }
        assert_eq!(
            fsm.cooldown_until_ns,
            TimestampNs(10_000_000_000 + STOP_LOSS_COOLDOWN_NS)
        );

        // Verify retCode 110007 immediately halts the engine
        let _ = fsm.on_exchange_retcode(BybitRetCode::InsufficientMargin110007, &snap, &mut ledger);
        assert_eq!(
            fsm.state,
            OrderLifecycleState::HaltedByRiskGuard {
                reason: HaltReason::InsufficientMargin110007
            }
        );
    }
}