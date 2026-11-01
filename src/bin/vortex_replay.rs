//! Binary 3 (`vortex_replay`): Deterministic offline L2 + publicTrade FIFO queue-priority
//! simulator and Walk-Forward Strategy Evaluator over live `data/*.parquet` archives.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use vortex_rs::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
use vortex_rs::execution_fsm::{ExecutionFsm, OrderLifecycleState};
use vortex_rs::forensic_parquet::{ColumnarMarketRow, ColumnarParquetBatch, MarketEventKind, ParitySyncLedger};
use vortex_rs::lob_shm::{BookLevel, SymbolLobSnapshot};
use vortex_rs::types::{BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

pub const SIMULATED_ONE_WAY_LATENCY_NS: i64 = 25_000_000;

const APPROVED_SPECS: [PairSpec; 6] = [
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
                            let remaining_after_print = queue_ahead_qty.0 - row.lot_qty.0;
                            if remaining_after_print <= -order_qty.0 {
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
                        let current_l1_qty = match side {
                            Side::Bid if row.best_bid_ticks.0 == limit_price.0 => row.best_bid_qty.0,
                            Side::Ask if row.best_ask_ticks.0 == limit_price.0 => row.best_ask_qty.0,
                            _ => last_observed_l1_qty.0,
                        };
                        if current_l1_qty < last_observed_l1_qty.0 {
                            let drop = last_observed_l1_qty.0 - current_l1_qty;
                            let conservative_credit = drop / 4;
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

fn spec_for_symbol(sym: SymbolId) -> Option<(usize, PairSpec)> {
    let mut i = 0;
    while i < APPROVED_SPECS.len() {
        if APPROVED_SPECS[i].symbol_id == sym {
            return Some((i, APPROVED_SPECS[i]));
        }
        i += 1;
    }
    None
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
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    let mut ledger = ParitySyncLedger::new(10_000_000_000);
    let mut fifo_sim = FifoQueueSimulator::new();
    let mut active_sym = SymbolId(0);

    let mut verified_files: u64 = 0;
    let mut total_live_rows: usize = 0;
    let mut total_l2_events: u64 = 0;
    let mut total_trade_prints: u64 = 0;
    let mut spoof_vetoes: u64 = 0;
    let mut signals_armed: u64 = 0;
    let mut queue_aborts: u64 = 0;

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

                    if let Some((_, spec)) = spec_for_symbol(row.symbol_id) {
                        let mut snap = SymbolLobSnapshot {
                            symbol_id: row.symbol_id,
                            is_eligible: true,
                            sequence_id: row.sequence_id,
                            ts_exchange_ns: row.ts_exchange_ns,
                            ts_local_ns: row.ts_local_ns,
                            mark_price: row.mark_price_ticks,
                            last_trade_price: row.price_ticks,
                            realized_vol_5m: ScaledBps::from_whole_bps(58),
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

                        match fsm.state {
                            OrderLifecycleState::Idle => {
                                if let Ok(verdict) = evaluator.evaluate_entry_signal(&spec, &snap) {
                                    if matches!(verdict, SignalVerdict::SpoofingVeto) {
                                        spoof_vetoes += 1;
                                    } else if let Ok(true) =
                                        fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10))
                                    {
                                        if let OrderLifecycleState::PlacingEntryMaker {
                                            side,
                                            entry_price,
                                            qty,
                                            ..
                                        } = fsm.state
                                        {
                                            active_sym = row.symbol_id;
                                            signals_armed += 1;
                                            fifo_sim.submit_post_only(
                                                side,
                                                entry_price,
                                                qty,
                                                row.ts_local_ns,
                                            );
                                            let _ = fsm.on_entry_order_resting(row.ts_local_ns);
                                        }
                                    }
                                }
                            }
                            OrderLifecycleState::RestingEntryQueue { .. }
                                if row.symbol_id == active_sym =>
                            {
                                if fsm.check_resting_queue_abort(&snap) {
                                    queue_aborts += 1;
                                    fifo_sim.state = SimulatedOrderState::Inactive;
                                } else {
                                    fifo_sim.on_market_row(&row);
                                    if matches!(
                                        fifo_sim.state,
                                        SimulatedOrderState::FilledMaker { .. }
                                    ) {
                                        let _ = fsm.on_entry_filled_maker(row.ts_local_ns);
                                    } else if matches!(
                                        fifo_sim.state,
                                        SimulatedOrderState::RejectedPostOnlyCross
                                    ) {
                                        fsm.state = OrderLifecycleState::Idle;
                                    }
                                }
                            }
                            OrderLifecycleState::PositionOpenMakerExit { .. }
                                if row.symbol_id == active_sym =>
                            {
                                let _ = fsm.step_open_position(&snap, &mut ledger);
                            }
                            _ => {}
                        }
                    }
                }
                idx += 1;
            }
        }
    }

    println!("--------------------------------------------------------------------------------");
    println!(
        "  -> Live PAR1 Archives Verified: {} files | {} total events ({} L2 / {} Trades)",
        verified_files, total_live_rows, total_l2_events, total_trade_prints
    );
    println!(
        "  -> Live Walk-Forward Replay   : SpoofVetoes={} | Armed={} | QueueAborts={} | Fills={} | Closed={}",
        spoof_vetoes,
        signals_armed,
        queue_aborts,
        fifo_sim.total_maker_fills,
        ledger.closed_trades_count
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
        "  -> Simulated Events Processed : {} events in {:.3} ms",
        total_events,
        secs * 1000.0
    );
    println!(
        "  -> Deterministic Throughput   : {:.0} events/sec (Gate >= 100,000 ev/s)",
        throughput
    );
    println!(
        "  -> Verified FIFO Maker Fills  : {} | PostOnly Rejects: {}",
        sim.total_maker_fills, sim.total_post_only_rejects
    );

    replay_captured_live_parquet_segments();
    println!("================================================================================");

    if throughput < 100_000.0 || sim.total_maker_fills != (total_batches as u64) {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}