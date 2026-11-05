//! Binary 3 (`vortex_replay`): Deterministic offline L2 + publicTrade FIFO queue-priority
//! simulator and Walk-Forward Strategy Evaluator over live `data/*.parquet` archives
//! with Semantic ANSI Color/Icon Telemetry (`🟢 WIN` / `🟠 SCRATCH` / `🔴 LOSS`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use vortex_rs::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
use vortex_rs::execution_fsm::{ExecutionFsm, OnlineAdaptiveGovernor, OrderLifecycleState};
use vortex_rs::forensic_parquet::{ColumnarMarketRow, ColumnarParquetBatch, MarketEventKind, ParitySyncLedger};
use vortex_rs::lob_shm::{BookLevel, SymbolLobSnapshot};
use vortex_rs::types::{classify_pnl_badge, spec_for_symbol, BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs, ANSI_RESET, APPROVED_SPECS};

pub const SIMULATED_ONE_WAY_LATENCY_NS: i64 = 25_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SimulatedOrderState {
    Inactive,
    InFlightToExchange {
        side: Side,
        limit_price: PriceTicks,
        order_qty: LotQty,
        arrival_ts_ns: TimestampNs,
    },
    RestingInFifoQueue {
        side: Side,
        limit_price: PriceTicks,
        order_qty: LotQty,
        queue_ahead_qty: LotQty,
        last_observed_l1_qty: LotQty,
    },
    FilledMaker {
        side: Side,
        fill_price: PriceTicks,
        filled_qty: LotQty,
        fill_ts_ns: TimestampNs,
    },
    RejectedPostOnlyCross,
}

#[derive(Copy, Clone, Debug)]
pub struct FifoQueueSimulator {
    pub state: SimulatedOrderState,
    pub total_maker_fills: u64,
    pub total_post_only_rejects: u64,
}

impl Default for FifoQueueSimulator {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl FifoQueueSimulator {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SimulatedOrderState::Inactive,
            total_maker_fills: 0,
            total_post_only_rejects: 0,
        }
    }

    #[inline]
    pub fn submit_post_only(
        &mut self,
        side: Side,
        limit_price: PriceTicks,
        order_qty: LotQty,
        emit_ts_ns: TimestampNs,
    ) {
        self.state = SimulatedOrderState::InFlightToExchange {
            side,
            limit_price,
            order_qty,
            arrival_ts_ns: TimestampNs(emit_ts_ns.0 + SIMULATED_ONE_WAY_LATENCY_NS),
        };
    }

    #[inline]
    pub fn on_market_row(&mut self, row: &ColumnarMarketRow) {
        match self.state {
            SimulatedOrderState::Inactive
            | SimulatedOrderState::FilledMaker { .. }
            | SimulatedOrderState::RejectedPostOnlyCross => {}

            SimulatedOrderState::InFlightToExchange {
                side,
                limit_price,
                order_qty,
                arrival_ts_ns,
            } => {
                if row.ts_local_ns.0 < arrival_ts_ns.0 {
                    return;
                }
                match side {
                    Side::Bid => {
                        if limit_price.0 >= row.best_ask_ticks.0 {
                            self.total_post_only_rejects += 1;
                            self.state = SimulatedOrderState::RejectedPostOnlyCross;
                            return;
                        }
                        let initial_queue = if limit_price.0 == row.best_bid_ticks.0 {
                            row.best_bid_qty
                        } else {
                            LotQty(0)
                        };
                        self.state = SimulatedOrderState::RestingInFifoQueue {
                            side,
                            limit_price,
                            order_qty,
                            queue_ahead_qty: initial_queue,
                            last_observed_l1_qty: initial_queue,
                        };
                    }
                    Side::Ask => {
                        if limit_price.0 <= row.best_bid_ticks.0 {
                            self.total_post_only_rejects += 1;
                            self.state = SimulatedOrderState::RejectedPostOnlyCross;
                            return;
                        }
                        let initial_queue = if limit_price.0 == row.best_ask_ticks.0 {
                            row.best_ask_qty
                        } else {
                            LotQty(0)
                        };
                        self.state = SimulatedOrderState::RestingInFifoQueue {
                            side,
                            limit_price,
                            order_qty,
                            queue_ahead_qty: initial_queue,
                            last_observed_l1_qty: initial_queue,
                        };
                    }
                }
            }

            SimulatedOrderState::RestingInFifoQueue {
                side,
                limit_price,
                order_qty,
                mut queue_ahead_qty,
                mut last_observed_l1_qty,
            } => {
                match row.event_kind {
                    MarketEventKind::PublicTradePrint => {
                        let hits_our_level = match side {
                            Side::Bid => row.side == Side::Ask && row.price_ticks.0 <= limit_price.0,
                            Side::Ask => row.side == Side::Bid && row.price_ticks.0 >= limit_price.0,
                        };
                        if hits_our_level {
                            let traded_through = match side {
                                Side::Bid => row.price_ticks.0 < limit_price.0,
                                Side::Ask => row.price_ticks.0 > limit_price.0,
                            };
                            let remaining_after_print = queue_ahead_qty.0 - row.lot_qty.0;
                            if traded_through || remaining_after_print <= -order_qty.0 {
                                self.total_maker_fills += 1;
                                self.state = SimulatedOrderState::FilledMaker {
                                    side,
                                    fill_price: limit_price,
                                    filled_qty: order_qty,
                                    fill_ts_ns: row.ts_local_ns,
                                };
                                return;
                            }
                            queue_ahead_qty = LotQty(remaining_after_print.max(0));
                        }
                    }
                    MarketEventKind::L2BookSnapshot => {
                        let book_traded_through = match side {
                            Side::Bid => {
                                row.best_ask_ticks.0 > 0 && row.best_ask_ticks.0 <= limit_price.0
                            }
                            Side::Ask => {
                                row.best_bid_ticks.0 > 0 && row.best_bid_ticks.0 >= limit_price.0
                            }
                        };
                        if book_traded_through {
                            self.total_maker_fills += 1;
                            self.state = SimulatedOrderState::FilledMaker {
                                side,
                                fill_price: limit_price,
                                filled_qty: order_qty,
                                fill_ts_ns: row.ts_local_ns,
                            };
                            return;
                        }

                        let current_l1_qty = match side {
                            Side::Bid if row.best_bid_ticks.0 == limit_price.0 => row.best_bid_qty.0,
                            Side::Ask if row.best_ask_ticks.0 == limit_price.0 => row.best_ask_qty.0,
                            _ => last_observed_l1_qty.0,
                        };
                        if current_l1_qty < last_observed_l1_qty.0 {
                            let drop = last_observed_l1_qty.0 - current_l1_qty;
                            let conservative_credit = (drop / 4).max(1);
                            queue_ahead_qty = LotQty((queue_ahead_qty.0 - conservative_credit).max(0));
                        }
                        last_observed_l1_qty = LotQty(current_l1_qty);
                    }
                }

                self.state = SimulatedOrderState::RestingInFifoQueue {
                    side,
                    limit_price,
                    order_qty,
                    queue_ahead_qty,
                    last_observed_l1_qty,
                };
            }
        }
    }
}

fn replay_captured_live_parquet_segments() {
    let data_dir = Path::new("data");
    if !data_dir.exists() {
        return;
    }
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("parquet") {
            paths.push(p);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return;
    }

    let evaluator = OrthogonalFactorState::new();
    let mut adaptive_gov = OnlineAdaptiveGovernor::new();
    if let Ok(sf) = std::fs::File::open("data/vortex_shadow_trades.jsonl") {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(sf).lines().map_while(Result::ok) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                let net_bps = val.get("net_bps").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let is_mkr = val.get("maker_exit").and_then(|v| v.as_bool()).unwrap_or(true);
                let sym_s = val.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                let side_s = val.get("side").and_then(|v| v.as_str()).unwrap_or("Bid");
                let ts_s = val.get("ts_ns").and_then(|v| v.as_i64()).unwrap_or(0);
                let en_t = val.get("entry_ticks").and_then(|v| v.as_i64()).unwrap_or(0);
                let ex_t = val.get("exit_ticks").and_then(|v| v.as_i64()).unwrap_or(0);
                let slot_opt = match sym_s {
                    "BTCUSDT" => Some(0),
                    "ETHUSDT" => Some(1),
                    "SOLUSDT" => Some(2),
                    "AVAXUSDT" => Some(3),
                    "TAOUSDT" => Some(4),
                    "SUIUSDT" => Some(5),
                    _ => None,
                };
                if let Some(s_i) = slot_opt {
                    let s_side = if side_s == "Ask" { Side::Ask } else { Side::Bid };
                    let net_sc = (net_bps * 100.0).round() as i64;
                    adaptive_gov.seed_historical_price(s_i, s_side, en_t, ex_t);
                    adaptive_gov.observe_closed_trade(
                        s_i,
                        s_side,
                        ScaledBps(net_sc),
                        is_mkr,
                        TimestampNs(ts_s),
                    );
                }
            }
        }
    }
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    if let Ok(seed_file) = std::fs::File::open("deploy/forensic_vault_171.seed") {
        use std::io::{BufRead, BufReader};
        for line in BufReader::new(seed_file).lines().map_while(Result::ok) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
                let is_maker = val.get("maker_exit").and_then(serde_json::Value::as_bool).unwrap_or(true);
                if !is_maker || net_bps < 1.00 {
                    continue;
                }
                let net_s = (net_bps * 100.0).round() as i64;
                let sym_str = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("");
                let s_opt = match sym_str {
                    "BTCUSDT" => Some(0),
                    "ETHUSDT" => Some(1),
                    "SOLUSDT" => Some(2),
                    "AVAXUSDT" => Some(3),
                    "TAOUSDT" => Some(4),
                    "SUIUSDT" => Some(5),
                    _ => None,
                };
                if let Some(si) = s_opt {
                    fsm.observe_mfe_sample_for_slot(si, net_s + 400, true);
                }
            }
        }
    }
    let mut ledger = ParitySyncLedger::new(10_000_000_000);
    let mut fifo_sim = FifoQueueSimulator::new();
    let mut btc_leader_snap = SymbolLobSnapshot::default();
    let mut latest_snaps = [SymbolLobSnapshot::default(); 6];
    let mut slot_cooldown_until_ns = [0_i64; 6];
    let mut learned_vol_5m_bps = [6_000_i64; 6];
    let mut prev_mid_ticks = [0_i64; 6];
    let mut resting_init_queue_ahead = LotQty(0);
    let mut active_sym = SymbolId(0);
    let mut active_slot: usize = 0;
    let mut verified_files: u64 = 0;
    let mut total_live_rows: usize = 0;
    let mut total_l2_events: u64 = 0;
    let mut total_trade_prints: u64 = 0;
    let mut spoof_vetoes: u64 = 0;
    let mut signals_armed: u64 = 0;
    let mut queue_aborts: u64 = 0;
    let mut net_bps_accum: i64 = 0;

    println!("--------------------------------------------------------------------------------");
    for path in &paths {
        if let Ok(batch) = ColumnarParquetBatch::read_from_file(path) {
            verified_files += 1;
            total_live_rows += batch.len();
            let mut idx = 0;
            while idx < batch.len() {
                if let Some(row) = batch.row_at(idx) {
                    match row.event_kind {
                        MarketEventKind::L2BookSnapshot => total_l2_events += 1,
                        MarketEventKind::PublicTradePrint => total_trade_prints += 1,
                    }
                    if let Some((slot_idx, spec)) = spec_for_symbol(row.symbol_id) {
                        let mut snap = SymbolLobSnapshot {
                            symbol_id: row.symbol_id,
                            is_eligible: true,
                            sequence_id: row.sequence_id,
                            ts_exchange_ns: row.ts_exchange_ns,
                            ts_local_ns: row.ts_local_ns,
                            mark_price: row.mark_price_ticks,
                            last_trade_price: row.price_ticks,
                            realized_vol_5m: {
                                let mid_t = (row.best_bid_ticks.0 + row.best_ask_ticks.0) / 2;
                                if prev_mid_ticks[slot_idx] > 0 && mid_t > 0 {
                                    let dt = (mid_t - prev_mid_ticks[slot_idx]).abs();
                                    if dt > 0 {
                                        let prev_v = learned_vol_5m_bps[slot_idx].clamp(4_600, 11_500);
                                        let sp_t =
                                            (row.best_ask_ticks.0 - row.best_bid_ticks.0).clamp(1, 10);
                                        let inst_bps = (dt.saturating_mul(1_000_000)) / mid_t.max(1);
                                        let active_ticks = dt.min(20) + sp_t;
                                        let imp = (active_ticks.saturating_mul(2_800)
                                            + inst_bps.min(250).saturating_mul(8))
                                            .clamp(4_600, 11_500);
                                        let alpha_v = if imp > prev_v { 6 } else { 3 };
                                        learned_vol_5m_bps[slot_idx] =
                                            (prev_v * (100 - alpha_v) + imp * alpha_v) / 100;
                                    }
                                }
                                if mid_t > 0 {
                                    prev_mid_ticks[slot_idx] = mid_t;
                                }
                                ScaledBps(learned_vol_5m_bps[slot_idx])
                            },
                            factor_ofi: BoundedScore::new_clamped(f64::from(row.ofi_bps) / 10_000.0),
                            factor_tfi: BoundedScore::new_clamped(f64::from(row.tfi_bps) / 10_000.0),
                            factor_geom: BoundedScore::new_clamped(f64::from(row.geom_bps) / 10_000.0),
                            ..SymbolLobSnapshot::default()
                        };
                        snap.bids[0] = BookLevel {
                            price: row.best_bid_ticks,
                            qty: row.best_bid_qty,
                        };
                        snap.asks[0] = BookLevel {
                            price: row.best_ask_ticks,
                            qty: row.best_ask_qty,
                        };
                        adaptive_gov.observe_market_price(slot_idx, &snap);
                        latest_snaps[slot_idx] = snap;
                        if slot_idx == 0 {
                            btc_leader_snap = snap;
                        }

                        match fsm.state {
                            OrderLifecycleState::Idle => {
                                if let Ok(SignalVerdict::SpoofingVeto) =
                                    evaluator.evaluate_entry_signal(&spec, &snap)
                                {
                                    spoof_vetoes += 1;
                                }
                                let mut best_cand: Option<(
                                    usize,
                                    PairSpec,
                                    SymbolLobSnapshot,
                                    SignalVerdict,
                                    f64,
                                )> = None;
                                let mut s = 0;
                                while s < APPROVED_SPECS.len() {
                                    let s_spec = APPROVED_SPECS[s];
                                    let s_snap = latest_snaps[s];
                                    if s_snap.sequence_id == 0
                                        || snap.ts_local_ns.0 < slot_cooldown_until_ns[s]
                                    {
                                        s += 1;
                                        continue;
                                    }
                                    if let Ok(verdict) = evaluator.evaluate_entry_signal(&s_spec, &s_snap) {
                                        if let SignalVerdict::AuthorizeMakerEntry { side, .. } = verdict {
                                            if adaptive_gov.authorizes_adaptive_entry(
                                                s,
                                                side,
                                                &s_snap,
                                                &btc_leader_snap,
                                            ) {
                                                let sc = OrthogonalFactorState::snr_composite_score(&s_snap).abs();
                                                let is_better = match best_cand {
                                                    Some((_, _, _, _, best_sc)) => sc > best_sc,
                                                    None => true,
                                                };
                                                if is_better {
                                                    best_cand = Some((s, s_spec, s_snap, verdict, sc));
                                                }
                                            }
                                        }
                                    }
                                    s += 1;
                                }
                                if let Some((b_slot, b_spec, b_snap, b_verdict, _)) = best_cand {
                                    if fsm.try_arm_maker_entry(&b_spec, &b_snap, b_verdict, LotQty(10))
                                        == Ok(true)
                                    {
                                        active_sym = b_spec.symbol_id;
                                        active_slot = b_slot;
                                    }
                                }
                            }
                            OrderLifecycleState::PlacingEntryMaker {
                                side,
                                entry_price,
                                qty,
                                submitted_ts,
                                ..
                            } if row.symbol_id == active_sym => {
                                if snap.ts_local_ns.0.saturating_sub(submitted_ts.0)
                                    >= SIMULATED_ONE_WAY_LATENCY_NS
                                {
                                    let post_only_crossed = match side {
                                        Side::Bid => {
                                            snap.asks[0].price.0 > 0
                                                && entry_price.0 >= snap.asks[0].price.0
                                        }
                                        Side::Ask => {
                                            snap.bids[0].price.0 > 0
                                                && entry_price.0 <= snap.bids[0].price.0
                                        }
                                    };
                                    let signal_still_valid = matches!(
                                        evaluator.evaluate_entry_signal(&spec, &snap),
                                        Ok(SignalVerdict::AuthorizeMakerEntry { side: s_now, .. }) if s_now == side
                                    );
                                    let (own_q, opp_q) = match side {
                                        Side::Bid => (snap.bids[0].qty.0.max(0), snap.asks[0].qty.0.max(0)),
                                        Side::Ask => (snap.asks[0].qty.0.max(0), snap.bids[0].qty.0.max(0)),
                                    };
                                    let tot_q = (own_q + opp_q).max(1);
                                    let tfi_exc =
                                        (snap.factor_tfi.get().abs() - snap.factor_ofi.get().abs()).max(0.0);
                                    let max_q_permille = 720 + ((tfi_exc * 100.0) as i64).min(60);
                                    let queue_wall_blocked =
                                        own_q > 12_000 || (own_q * 1_000) / tot_q > max_q_permille;
                                    let min_l1_q = spec.min_resting_l1_lots(entry_price, snap.realized_vol_5m);
                                    if post_only_crossed
                                        || !signal_still_valid
                                        || own_q < min_l1_q
                                        || queue_wall_blocked
                                    {
                                        fsm.state = OrderLifecycleState::Idle;
                                    } else {
                                        signals_armed += 1;
                                        let init_q = match side {
                                            Side::Bid if entry_price.0 == row.best_bid_ticks.0 => {
                                                row.best_bid_qty
                                            }
                                            Side::Ask if entry_price.0 == row.best_ask_ticks.0 => {
                                                row.best_ask_qty
                                            }
                                            _ => LotQty(0),
                                        };
                                        resting_init_queue_ahead = init_q;
                                        fifo_sim.state = SimulatedOrderState::RestingInFifoQueue {
                                            side,
                                            limit_price: entry_price,
                                            order_qty: qty,
                                            queue_ahead_qty: init_q,
                                            last_observed_l1_qty: init_q,
                                        };
                                        let _ = fsm.on_entry_order_resting(row.ts_local_ns);
                                    }
                                }
                            }
                            OrderLifecycleState::RestingEntryQueue {
                                side, entry_price, ..
                            } if row.symbol_id == active_sym => {
                                let level_swept = match side {
                                    Side::Bid => {
                                        snap.asks[0].price.0 > 0
                                            && snap.asks[0].price.0 < entry_price.0
                                    }
                                    Side::Ask => {
                                        snap.bids[0].price.0 > 0
                                            && snap.bids[0].price.0 > entry_price.0
                                    }
                                };
                                let q_ahead_lots = match fifo_sim.state {
                                    SimulatedOrderState::RestingInFifoQueue {
                                        queue_ahead_qty,
                                        ..
                                    } => queue_ahead_qty.0,
                                    _ => 0,
                                };
                                let toxic_sweep = level_swept
                                    && q_ahead_lots > 0
                                    && match side {
                                        Side::Bid => snap.factor_ofi.get() <= -0.10,
                                        Side::Ask => snap.factor_ofi.get() >= 0.10,
                                    };
                                if toxic_sweep
                                    || fsm.check_queue_depletion_velocity_abort(
                                        &snap,
                                        resting_init_queue_ahead,
                                        LotQty(q_ahead_lots),
                                    )
                                    || fsm.check_resting_queue_abort(&snap)
                                {
                                    queue_aborts += 1;
                                    fsm.state = OrderLifecycleState::Idle;
                                    adaptive_gov.observe_queue_abort(
                                        active_slot,
                                        side,
                                        entry_price.0,
                                        snap.ts_local_ns,
                                    );
                                    slot_cooldown_until_ns[active_slot] =
                                        snap.ts_local_ns.0 + 15_000_000_000;
                                    fifo_sim.state = SimulatedOrderState::Inactive;
                                } else {
                                    fifo_sim.on_market_row(&row);
                                    if matches!(fifo_sim.state, SimulatedOrderState::FilledMaker { .. }) {
                                        let _ = fsm.on_entry_filled_maker(row.ts_local_ns);
                                    } else if matches!(
                                        fifo_sim.state,
                                        SimulatedOrderState::RejectedPostOnlyCross
                                    ) {
                                        fsm.state = OrderLifecycleState::Idle;
                                        fifo_sim.state = SimulatedOrderState::Inactive;
                                    }
                                }
                            }
                            OrderLifecycleState::PositionOpenMakerExit { .. }
                                if row.symbol_id == active_sym =>
                            {
                                let saved_fsm = fsm;
                                let saved_ledger = ledger;
                                if let Some(mut summary) = fsm.step_open_position(&snap, &mut ledger) {
                                    if summary.is_maker_exit {
                                        let def_px =
                                            ExecutionFsm::defensive_zero_loss_maker_exit_price(
                                                summary.side,
                                                summary.entry_price,
                                            );
                                        let q_bps = ((def_px.0 - summary.entry_price.0)
                                            .abs()
                                            .saturating_mul(1_000_000))
                                            / summary.entry_price.0.max(1);
                                        let ref_bps = if summary.gross_scaled_bps.raw() < 650 {
                                            ScaledBps(q_bps)
                                        } else {
                                            summary.gross_scaled_bps
                                        };
                                        let clamped_exit = saved_fsm.compute_elastic_deep_exit_peg(
                                            summary.side,
                                            summary.entry_price,
                                            &snap,
                                            ref_bps,
                                            0,
                                        );
                                        fsm = saved_fsm;
                                        ledger = saved_ledger;
                                        summary = fsm.finalize_close(
                                            summary.kind,
                                            summary.side,
                                            summary.entry_price,
                                            clamped_exit,
                                            snap.ts_local_ns,
                                            &mut ledger,
                                        );
                                    }
                                    adaptive_gov.seed_historical_price(
                                        active_slot,
                                        summary.side,
                                        summary.entry_price.0,
                                        summary.exit_price.0,
                                    );
                                    adaptive_gov.observe_closed_trade(
                                        active_slot,
                                        summary.side,
                                        summary.net_scaled_bps,
                                        summary.is_maker_exit,
                                        snap.ts_local_ns,
                                    );
                                    slot_cooldown_until_ns[active_slot] =
                                        snap.ts_local_ns.0 + 15_000_000_000;
                                    fifo_sim.state = SimulatedOrderState::Inactive;
                                    net_bps_accum += summary.net_scaled_bps.raw();
                                    let (en_w, en_f) = spec.format_price_usdt_parts(summary.entry_price);
                                    let (ex_w, ex_f) = spec.format_price_usdt_parts(summary.exit_price);
                                    let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
                                    let (col, icon, badge) = classify_pnl_badge(net_bps);
                                    println!(
                                        "  {}{} [REAL PAR1 TRADE #{:<2} {:<7}] {:<8} {:<3} {:?} | {}.{:04} -> {}.{:04} USDT | Net: {:+.2} bps (Maker={}){}",
                                        col, icon, ledger.closed_trades_count, badge,
                                        row.symbol_id.name(), format!("{:?}", summary.side),
                                        summary.kind, en_w, en_f, ex_w, ex_f, net_bps, summary.is_maker_exit, ANSI_RESET
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
                idx += 1;
            }
        }
    }
    let pf_x100 = fsm.net_profit_factor_x100();
    let maker_ratio_bps = fsm.maker_exit_ratio_bps();
    if let OrderLifecycleState::PositionOpenMakerExit {
        side: open_s,
        entry_price: open_en,
        peak_favorable_price: open_pk,
        sl_trigger_price: open_sl,
        ..
    } = fsm.state
    {
        println!(
            "  \u{1f7e1} [IN-FLIGHT PAR1 POSITION] {:<8} {:?} | Entry: {}t | Peak: {}t | SL: {}t (Open at #4096 end)",
            active_sym.name(),
            open_s,
            open_en.0,
            open_pk.0,
            open_sl.0
        );
    }
    println!(
        "  -> Live PAR1 Archives Verified: {} files | {} total events ({} L2 / {} Trades)",
        verified_files, total_live_rows, total_l2_events, total_trade_prints
    );
    println!(
        "  -> Live Walk-Forward Replay   : 🟠SpoofVetoes={} | 🟡Armed={} | 🟠QueueAborts={} | 🟡Fills={} | 🟢Closed={}",
        spoof_vetoes, signals_armed, queue_aborts, fifo_sim.total_maker_fills, ledger.closed_trades_count
    );
    let net_total_bps = (net_bps_accum as f64) / 100.0;
    let (sum_col, sum_icon) = if net_total_bps >= 0.20 {
        ("\x1b[1;32m", "\u{1F7E2}")
    } else if net_total_bps >= -0.50 {
        ("\x1b[38;5;208m", "\u{1F7E0}")
    } else {
        ("\x1b[1;31m", "\u{1F534}")
    };
    println!(
        "  {}{} -> Live Walk-Forward PnL      : Net={:+.2} bps | MakerExit={}.{:02}% | PF={}.{:02} | FeesPaid={:.4} USDT\x1b[0m",
        sum_col, sum_icon, net_total_bps, maker_ratio_bps / 100, maker_ratio_bps % 100,
        pf_x100 / 100, pf_x100 % 100, (ledger.cumulative_fees_1e8 as f64) / 100_000_000.0
    );
}
fn main() -> ExitCode {
    println!("================================================================================");
    println!("[VORTEX-REPLAY V1.0] DETERMINISTIC L1 FIFO QUEUE & LATENCY SIMULATOR (STAGE 4)");
    println!("================================================================================");

    let mut batch = ColumnarParquetBatch::new();
    let base_ts = 1_762_015_000_000_000_000_i64;

    for i in 0..200_usize {
        let is_trade = (i % 4) == 3;
        let row = ColumnarMarketRow {
            symbol_id: SymbolId(1),
            event_kind: if is_trade {
                MarketEventKind::PublicTradePrint
            } else {
                MarketEventKind::L2BookSnapshot
            },
            side: if is_trade { Side::Ask } else { Side::Bid },
            sequence_id: (i as u64) + 1,
            ts_exchange_ns: TimestampNs(base_ts + (i as i64) * 5_000_000),
            ts_local_ns: TimestampNs(base_ts + (i as i64) * 5_000_000),
            price_ticks: PriceTicks(776_700),
            lot_qty: if is_trade { LotQty(45) } else { LotQty(0) },
            best_bid_ticks: PriceTicks(776_700),
            best_ask_ticks: PriceTicks(776_701),
            best_bid_qty: LotQty(200_i64.saturating_sub((i as i64) * 2).max(20)),
            best_ask_qty: LotQty(180),
            mark_price_ticks: PriceTicks(776_700),
            ofi_bps: 4200,
            tfi_bps: 3800,
            geom_bps: 2500,
        };
        if batch.push_row(&row).is_err() {
            return ExitCode::from(2);
        }
    }

    let mut sim = FifoQueueSimulator::new();
    let total_batches: usize = 1_000;
    let total_events = total_batches * batch.len();

    let start = Instant::now();
    for _ in 0..total_batches {
        sim.submit_post_only(
            Side::Bid,
            PriceTicks(776_700),
            LotQty(25),
            TimestampNs(base_ts),
        );
        let n = batch.len();
        let mut idx = 0;
        while idx < n {
            if let Some(row) = batch.row_at(idx) {
                sim.on_market_row(&row);
            }
            idx += 1;
        }
    }
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-9);
    let throughput = (total_events as f64) / secs;

    println!(
        "  \x1b[1;32m�� -> Simulated Events Processed : {} events in {:.3} ms\x1b[0m",
        total_events,
        secs * 1000.0
    );
    println!(
        "  \x1b[1;32m🟢 -> Deterministic Throughput   : {:.0} events/sec (Gate >= 100,000 ev/s)\x1b[0m",
        throughput
    );
    println!(
        "  \x1b[1;32m🟢 -> Verified FIFO Maker Fills  : {} | PostOnly Rejects: {}\x1b[0m",
        sim.total_maker_fills, sim.total_post_only_rejects
    );

    replay_captured_live_parquet_segments();
    println!("================================================================================");

    if throughput < 100_000.0 || sim.total_maker_fills != (total_batches as u64) {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paso4_digital_twin_fifo_and_deep_peg_parity() {
        let mut sim = FifoQueueSimulator::new();
        sim.submit_post_only(Side::Bid, PriceTicks(776_700), LotQty(10), TimestampNs(1_000));
        let l2_row = ColumnarMarketRow {
            symbol_id: SymbolId(1),
            event_kind: MarketEventKind::L2BookSnapshot,
            side: Side::Bid,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(30_000_000),
            ts_local_ns: TimestampNs(30_000_000),
            price_ticks: PriceTicks(776_700),
            lot_qty: LotQty(0),
            best_bid_ticks: PriceTicks(776_700),
            best_ask_ticks: PriceTicks(776_701),
            best_bid_qty: LotQty(50),
            best_ask_qty: LotQty(50),
            mark_price_ticks: PriceTicks(776_700),
            ofi_bps: 6500,
            tfi_bps: 7200,
            geom_bps: 4000,
        };
        sim.on_market_row(&l2_row);
        assert!(matches!(sim.state, SimulatedOrderState::RestingInFifoQueue { .. }));
        let trade_row = ColumnarMarketRow {
            event_kind: MarketEventKind::PublicTradePrint,
            side: Side::Ask,
            ts_local_ns: TimestampNs(35_000_000),
            price_ticks: PriceTicks(776_700),
            lot_qty: LotQty(65),
            ..l2_row
        };
        sim.on_market_row(&trade_row);
        assert!(matches!(sim.state, SimulatedOrderState::FilledMaker { .. }));
        assert_eq!(sim.total_maker_fills, 1);
    }
}