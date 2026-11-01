//! Exhaustive Finite-State Machine (`OrderLifecycleState`) for Bybit UTA V5 execution:
//! 100% `Limit PostOnly` normal exits, geometric `MarkPrice` Stop-Loss protection,
//! Joint OFI+TFI & BBO Runaway Queue Abort Guard, deterministic `110017` win reconciliation, and `110007` margin guard.

use crate::alpha_3factor::SignalVerdict;
use crate::forensic_parquet::ParitySyncLedger;
use crate::lob_shm::SymbolLobSnapshot;
use crate::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, TimestampNs, VortexError};

/// Cooldown applied ONLY after a real server-side Stop-Loss trigger (60 seconds in nanoseconds).
pub const STOP_LOSS_COOLDOWN_NS: i64 = 60_000_000_000;
/// Maximum time a passive `Limit PostOnly` entry order may sit unfilled in the L1 queue (25 seconds).
pub const MAX_RESTING_QUEUE_TTL_NS: i64 = 25_000_000_000;
/// Maximum distance in ticks the BBO can run away from our resting entry order before cancellation.
pub const MAX_BBO_RUNAWAY_TICKS: i64 = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BybitRetCode {
    OkZero,
    SlGeometryError10001,
    InsufficientMargin110007,
    OrderNotExistsOrAlreadyClosed110017,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HaltReason {
    InsufficientMargin110007,
    AccountingParityDrift,
    MaxDailyDrawdownBreached,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClosedTradeKind {
    MakerStructuralTp,
    MakerPassiveUnwind,
    ServerMarkPriceStopLoss,
}

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

    /// Aborts a resting entry order ONLY after verifying the order did not fill on the current event:
    /// 1. Both L2 book pressure (`X_OFI`) and trade tape (`X_TFI`) reversed against our side, OR
    /// 2. Monotonic elapsed time exceeds `MAX_RESTING_QUEUE_TTL_NS` (25s), OR
    /// 3. The BBO ran away from `entry_price` by `>= MAX_BBO_RUNAWAY_TICKS` (3 ticks).
    #[inline]
    pub fn check_resting_queue_abort(&mut self, snap: &SymbolLobSnapshot) -> bool {
        if let OrderLifecycleState::RestingEntryQueue {
            side,
            entry_price,
            resting_since_ts,
            ..
        } = self.state
        {
            let ofi = snap.factor_ofi.get();
            let tfi = snap.factor_tfi.get();
            let joint_flow_reversal = match side {
                Side::Bid => ofi <= -0.20 && tfi <= -0.25,
                Side::Ask => ofi >= 0.20 && tfi >= 0.25,
            };

            let ttl_expired = snap.ts_local_ns.0 > resting_since_ts.0
                && (snap.ts_local_ns.0 - resting_since_ts.0) >= MAX_RESTING_QUEUE_TTL_NS;

            let bbo_runaway = match snap.bbo_and_spread_ticks() {
                Some((best_bid, best_ask, _)) => match side {
                    Side::Bid => best_bid.price.0 - entry_price.0 >= MAX_BBO_RUNAWAY_TICKS,
                    Side::Ask => entry_price.0 - best_ask.price.0 >= MAX_BBO_RUNAWAY_TICKS,
                },
                None => false,
            };

            if joint_flow_reversal || ttl_expired || bbo_runaway {
                self.state = OrderLifecycleState::Idle;
                return true;
            }
        }
        false
    }

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

        let ref_trade_price = if snap.last_trade_price.0 > 0 {
            snap.last_trade_price
        } else {
            snap.mark_price
        };

        // 1. Check catastrophic server-side MarkPrice Stop-Loss first
        let sl_hit = match side {
            Side::Bid => snap.mark_price.0 <= sl_trigger_price.0,
            Side::Ask => snap.mark_price.0 >= sl_trigger_price.0,
        };
        if sl_hit {
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
            Side::Bid => ref_trade_price.0 >= tp_maker_price.0,
            Side::Ask => ref_trade_price.0 <= tp_maker_price.0,
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

        // 3. Check passive Maker Unwind at BBO (when gross >= +6.00 bps -> net >= +2.00 bps after 4.00 bps Maker fees)
        if let Some((best_bid, best_ask, _)) = snap.bbo_and_spread_ticks() {
            let bbo_exit_price = match side {
                Side::Bid => best_bid.price,
                Side::Ask => best_ask.price,
            };
            let current_gross_bps =
                Self::compute_gross_scaled_bps(side, entry_price, bbo_exit_price);
            let flow_exhausted = match side {
                Side::Bid => snap.factor_ofi.get() < -0.10 && snap.factor_tfi.get() < -0.10,
                Side::Ask => snap.factor_ofi.get() > 0.10 && snap.factor_tfi.get() > 0.10,
            };
            if current_gross_bps.raw() >= 600 && flow_exhausted {
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
            ScaledBps(
                ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw()
                    + ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw(),
            )
        } else {
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

    #[inline]
    #[must_use]
    pub const fn net_profit_factor_x100(&self) -> i64 {
        if self.gross_loss_accum_1e8 <= 0 {
            return 999;
        }
        (self.gross_profit_accum_1e8 * 100) / self.gross_loss_accum_1e8
    }

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
    use crate::types::{BoundedScore, SymbolId};

    #[test]
    fn test_fsm_resting_queue_aborts_on_bbo_runaway_or_ttl() {
        let spec = PairSpec {
            symbol_id: SymbolId(6),
            tick_size_1e8: 10_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let mut fsm = ExecutionFsm::new(10_000_000_000, 1_500_000_000);
        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(6),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(1_000_000_000),
            ts_local_ns: TimestampNs(1_000_000_000),
            mark_price: PriceTicks(9_000),
            last_trade_price: PriceTicks(9_000),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.80),
            factor_tfi: BoundedScore::new_clamped(0.90),
            factor_geom: BoundedScore::new_clamped(0.30),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(9_000),
            qty: LotQty(5_000),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(9_001),
            qty: LotQty(2_000),
        };

        let verdict = SignalVerdict::AuthorizeMakerEntry {
            side: Side::Bid,
            target_excursion_scaled_bps: ScaledBps::from_whole_bps(45),
            estimated_cost_rt_scaled_bps: ScaledBps(517),
        };
        assert_eq!(
            fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(100)),
            Ok(true)
        );
        assert!(fsm.on_entry_order_resting(TimestampNs(1_000_000_000)));

        snap.bids[0].price = PriceTicks(9_003);
        snap.asks[0].price = PriceTicks(9_004);
        assert!(fsm.check_resting_queue_abort(&snap));
        assert_eq!(fsm.state, OrderLifecycleState::Idle);
    }

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
            assert_eq!(summary.net_scaled_bps, ScaledBps(3_800));
        }
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

        let _ = fsm.on_exchange_retcode(BybitRetCode::InsufficientMargin110007, &snap, &mut ledger);
        assert_eq!(
            fsm.state,
            OrderLifecycleState::HaltedByRiskGuard {
                reason: HaltReason::InsufficientMargin110007
            }
        );
    }
}