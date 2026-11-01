//! Binary 3 (`vortex_replay`): Deterministic offline L2 + publicTrade FIFO queue-priority
//! simulator with 25ms network RTT latency and conservative 25% cancellation credit.

use std::process::ExitCode;
use std::time::Instant;

use vortex_rs::forensic_parquet::{ColumnarMarketRow, ColumnarParquetBatch, MarketEventKind};
use vortex_rs::types::{LotQty, PriceTicks, Side, SymbolId, TimestampNs};

/// Simulated one-way network latency from `sniper-singapur` to Bybit matching engine (25 ms).
pub const SIMULATED_ONE_WAY_LATENCY_NS: i64 = 25_000_000;

/// Lifecycle state of a simulated `Limit PostOnly` order inside `vortex_replay`.
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

/// Deterministic L1 FIFO queue simulator for a single passive `Limit PostOnly` order.
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

    /// Submits a new passive `Limit PostOnly` order at `emit_ts_ns`.
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

    /// Advances the FIFO state machine using a single `ColumnarMarketRow`.
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
                // Check PostOnly crossing rule upon arrival at matching engine
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
                        // Aggressive trade hitting our resting limit price drains 100% from queue_ahead_qty
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
                        // Conservative 25% queue reduction credit on L2 size drops at our level
                        let current_l1_qty = match side {
                            Side::Bid if row.best_bid_ticks.0 == limit_price.0 => row.best_bid_qty.0,
                            Side::Ask if row.best_ask_ticks.0 == limit_price.0 => row.best_ask_qty.0,
                            _ => last_observed_l1_qty.0,
                        };
                        if current_l1_qty < last_observed_l1_qty.0 {
                            let drop = last_observed_l1_qty.0 - current_l1_qty;
                            let conservative_credit = drop / 4; // 25% credit
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

fn main() -> ExitCode {
    println!("================================================================================");
    println!("[VORTEX-REPLAY V1.0] DETERMINISTIC L1 FIFO QUEUE & LATENCY SIMULATOR (STAGE 4)");
    println!("================================================================================");

    // Construct a deterministic columnar batch representing L2 updates + aggressive trade prints
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

    // Run 1,000 batch replays (200,000 events) to certify vectorized single-thread throughput
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
    println!("================================================================================");

    if throughput < 100_000.0 || sim.total_maker_fills != (total_batches as u64) {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}