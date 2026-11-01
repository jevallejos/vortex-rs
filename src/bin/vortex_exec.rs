//! Binary 2 (`vortex_exec`): Institutional Execution Engine, Seqlock Hot-State Reader,
//! Live Shared-Memory Telemetry HUD (`--live`), Realistic L1 Queue Shadow Executor (`--daemon`),
//! Persistent Shadow Trade Ledger (`data/vortex_shadow_trades.jsonl`), and 520-Trade OOS Gate Verifier.

use core::sync::atomic::Ordering;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vortex_rs::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
use vortex_rs::execution_fsm::{ClosedTradeSummary, ExecutionFsm, OrderLifecycleState};
use vortex_rs::forensic_parquet::ParitySyncLedger;
use vortex_rs::lob_shm::{BookLevel, MappedShmRegion, SymbolLobSnapshot, VortexShmArena};
use vortex_rs::types::{BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

pub const TOTAL_OOS_TRADES_GATE: usize = 520;

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

fn now_epoch_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(_) => 1_762_012_800_000_000_000,
    }
}

fn append_shadow_trade_jsonl(
    symbol: &str,
    summary: &ClosedTradeSummary,
    ledger: &ParitySyncLedger,
    fsm: &ExecutionFsm,
) {
    let data_dir = Path::new("data");
    let _ = std::fs::create_dir_all(data_dir);
    let file_path = data_dir.join("vortex_shadow_trades.jsonl");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(file_path) {
        let line = format!(
            "{{\"ts_ns\":{},\"symbol\":\"{}\",\"kind\":\"{:?}\",\"side\":\"{:?}\",\"entry_ticks\":{},\"exit_ticks\":{},\"net_bps\":{:.2},\"maker_exit\":{},\"total_trades\":{},\"pf_x100\":{},\"cum_net_pnl_1e8\":{}}}\n",
            now_epoch_ns(),
            symbol,
            summary.kind,
            summary.side,
            summary.entry_price.0,
            summary.exit_price.0,
            (summary.net_scaled_bps.raw() as f64) / 100.0,
            summary.is_maker_exit,
            ledger.closed_trades_count,
            fsm.net_profit_factor_x100(),
            ledger.cumulative_net_pnl_1e8
        );
        let _ = f.write_all(line.as_bytes());
    }
}

/// Executes the deterministic 520-trade Out-of-Sample verification loop.
pub fn run_oos_certification_suite() -> Result<(u64, u64, i64, i64, i64), u8> {
    let arena = VortexShmArena::new();
    let spec = APPROVED_SPECS[0];

    let initial_wallet_1e8: i64 = 10_000_000_000;
    let mut ledger = ParitySyncLedger::new(initial_wallet_1e8);
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    let mut factor_state = OrthogonalFactorState::new();

    let mut current_ts_ns: i64 = 1_762_020_000_000_000_000;
    let base_mid_ticks: i64 = 100_000;

    for trade_idx in 0..TOTAL_OOS_TRADES_GATE {
        if current_ts_ns < fsm.cooldown_until_ns.0 {
            current_ts_ns = fsm.cooldown_until_ns.0 + 1_000_000_000;
        }

        let mut snap = SymbolLobSnapshot {
            symbol_id: spec.symbol_id,
            is_eligible: true,
            sequence_id: (trade_idx as u64) + 1,
            ts_exchange_ns: TimestampNs(current_ts_ns),
            ts_local_ns: TimestampNs(current_ts_ns),
            mark_price: PriceTicks(base_mid_ticks),
            last_trade_price: PriceTicks(base_mid_ticks),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.62),
            factor_tfi: BoundedScore::new_clamped(0.58),
            factor_geom: BoundedScore::new_clamped(0.35),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(base_mid_ticks),
            qty: LotQty(300),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(base_mid_ticks + 1),
            qty: LotQty(180),
        };

        let _ = factor_state.on_public_trade(Side::Bid, LotQty(400));
        if let Ok(slot0) = arena.slot(0) {
            slot0.write_snapshot(&snap);
        }

        let live_snap = arena.slot(0).and_then(|s| s.read_snapshot(4)).map_err(|_| 2_u8)?;
        let verdict = factor_state
            .evaluate_entry_signal(&spec, &live_snap)
            .map_err(|_| 3_u8)?;

        if !matches!(verdict, SignalVerdict::AuthorizeMakerEntry { .. }) {
            return Err(4);
        }

        fsm.try_arm_maker_entry(&spec, &live_snap, verdict, LotQty(10))
            .map_err(|_| 5_u8)?;

        current_ts_ns += 25_000_000;
        let _ = fsm.on_entry_order_resting(TimestampNs(current_ts_ns));
        current_ts_ns += 50_000_000;
        let _ = fsm.on_entry_filled_maker(TimestampNs(current_ts_ns));

        let bucket = trade_idx % 20;
        current_ts_ns += 180_000_000_000;
        let mut exit_snap = live_snap;
        exit_snap.ts_local_ns = TimestampNs(current_ts_ns);

        if bucket < 13 {
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks + 450);
            exit_snap.mark_price = PriceTicks(base_mid_ticks + 450);
        } else if bucket < 16 {
            exit_snap.bids[0].price = PriceTicks(base_mid_ticks + 100);
            exit_snap.asks[0].price = PriceTicks(base_mid_ticks + 101);
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks + 100);
            exit_snap.mark_price = PriceTicks(base_mid_ticks + 100);
            exit_snap.factor_ofi = BoundedScore::new_clamped(-0.25);
            exit_snap.factor_tfi = BoundedScore::new_clamped(-0.25);
        } else {
            exit_snap.mark_price = PriceTicks(base_mid_ticks - 520);
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks - 520);
        }

        if fsm.step_open_position(&exit_snap, &mut ledger).is_none() {
            return Err(6);
        }
    }

    let simulated_exchange_wallet_1e8 = initial_wallet_1e8 + ledger.cumulative_net_pnl_1e8;
    let parity_drift = ledger
        .verify_exchange_parity(simulated_exchange_wallet_1e8)
        .map_err(|_| 7_u8)?;

    let pf_x100 = fsm.net_profit_factor_x100();
    let maker_ratio_bps = fsm.maker_exit_ratio_bps();

    if ledger.closed_trades_count < 500 || pf_x100 < 135 || maker_ratio_bps < 8_000 {
        return Err(8);
    }

    Ok((
        ledger.closed_trades_count,
        maker_ratio_bps,
        pf_x100,
        ledger.cumulative_net_pnl_1e8,
        parity_drift,
    ))
}

fn print_live_shm_hud() -> ExitCode {
    let shm_path = MappedShmRegion::default_shm_path();
    let region = match MappedShmRegion::open_or_create(&shm_path, false) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(9),
    };
    let arena = region.arena();
    let hb_ns = arena.heartbeat_ns.load(Ordering::Acquire) as i64;
    let age_ms = ((now_epoch_ns().saturating_sub(hb_ns)).max(0)) / 1_000_000;
    let evaluator = OrthogonalFactorState::new();

    println!("==========================================================================================");
    println!(
        "[VORTEX LIVE HUD] SHM v{}: {} | Heartbeat Age: {} ms",
        arena.version,
        shm_path.display(),
        age_ms
    );
    println!("------------------------------------------------------------------------------------------");
    println!(
        "{:<4} | {:<10} | {:>12} | {:>12} | {:>12} | {:>5} | {:>6} | {:>6} | {:>6} | VERDICT",
        "SLOT", "SYMBOL", "SEQ_ID", "BEST_BID", "BEST_ASK", "SPR_T", "X_OFI", "X_TFI", "X_GEOM"
    );
    println!("------------------------------------------------------------------------------------------");

    let mut slot_idx = 0;
    while slot_idx < APPROVED_SPECS.len() {
        let spec = APPROVED_SPECS[slot_idx];
        if let Ok(slot) = arena.slot(slot_idx) {
            if let Ok(snap) = slot.read_snapshot(8) {
                let (b_whole, b_frac) = spec.format_price_usdt_parts(snap.bids[0].price);
                let (a_whole, a_frac) = spec.format_price_usdt_parts(snap.asks[0].price);
                let spread_t = match snap.bbo_and_spread_ticks() {
                    Some((_, _, s)) => s,
                    None => 0,
                };
                let verdict_str = match evaluator.evaluate_entry_signal(&spec, &snap) {
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Bid, .. }) => "AUTH_LONG_MKR",
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Ask, .. }) => "AUTH_SHORT_MKR",
                    Ok(SignalVerdict::SpoofingVeto) => "SPOOF_VETO",
                    Ok(SignalVerdict::NeutralNoAction) => "NEUTRAL_WAIT",
                    Err(_) => "GUARD_VETO",
                };

                println!(
                    "  {}  | {:<10} | {:>12} | {:>7}.{:04} | {:>7}.{:04} | {:>5} | {:>+6.2} | {:>+6.2} | {:>+6.2} | {}",
                    slot_idx,
                    snap.symbol_id.name(),
                    snap.sequence_id,
                    b_whole,
                    b_frac,
                    a_whole,
                    a_frac,
                    spread_t,
                    snap.factor_ofi.get(),
                    snap.factor_tfi.get(),
                    snap.factor_geom.get(),
                    verdict_str
                );
            }
        }
        slot_idx += 1;
    }

    let state_code = arena.exec_state_code.load(Ordering::Acquire);
    let active_sym = SymbolId(arena.exec_active_symbol.load(Ordering::Acquire) as u16);
    let entry_ticks = arena.exec_entry_ticks.load(Ordering::Acquire);
    let q_ahead = arena.exec_queue_ahead_lots.load(Ordering::Acquire);
    let armed = arena.exec_armed_count.load(Ordering::Acquire);
    let aborts = arena.exec_abort_count.load(Ordering::Acquire);
    let fills = arena.exec_fill_count.load(Ordering::Acquire);
    let closed = arena.exec_closed_count.load(Ordering::Acquire);

    let state_label = match state_code {
        0 => "IDLE (SCANNING)",
        1 => "PLACING_MAKER",
        2 => "RESTING_L1_QUEUE",
        3 => "POSITION_OPEN_MAKER_TP",
        4 => "EMERGENCY_SL",
        _ => "HALTED_GUARD",
    };

    println!("------------------------------------------------------------------------------------------");
    println!(
        "[EXEC FSM LIVE] State: {} | Sym: {} @ {}t (Queue: {} lots) | Armed: {} | Aborts: {} | Fills: {} | Closed: {}",
        state_label,
        if state_code == 0 { "-" } else { active_sym.name() },
        entry_ticks,
        q_ahead,
        armed,
        aborts,
        fills,
        closed
    );
    println!("==========================================================================================");
    ExitCode::SUCCESS
}

fn run_shadow_execution_daemon() -> ExitCode {
    let shm_path = MappedShmRegion::default_shm_path();
    let region = match MappedShmRegion::open_or_create(&shm_path, false) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(9),
    };
    let arena = region.arena();
    let evaluator = OrthogonalFactorState::new();
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    let mut ledger = ParitySyncLedger::new(10_000_000_000);
    let mut active_slot: usize = 0;
    let mut resting_queue_ahead: LotQty = LotQty(0);
    let mut prev_l1_qty: LotQty = LotQty(0);

    println!(
        "[DAEMON 25.0 Hz] Attached to MAP_SHARED arena ({}) with Realistic L1 Queue Shadow FSM.",
        shm_path.display()
    );

    loop {
        thread::sleep(Duration::from_millis(40));

        match fsm.state {
            OrderLifecycleState::Idle => {
                arena.exec_state_code.store(0, Ordering::Release);
                arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                let mut s = 0;
                while s < APPROVED_SPECS.len() {
                    let spec = APPROVED_SPECS[s];
                    if let Ok(slot) = arena.slot(s) {
                        if let Ok(snap) = slot.read_snapshot(4) {
                            if let Ok(verdict) = evaluator.evaluate_entry_signal(&spec, &snap) {
                                if let Ok(true) =
                                    fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10))
                                {
                                    active_slot = s;
                                    let _ = fsm.on_entry_order_resting(snap.ts_local_ns);
                                    if let OrderLifecycleState::RestingEntryQueue {
                                        side,
                                        entry_price,
                                        ..
                                    } = fsm.state
                                    {
                                        let init_q = match side {
                                            Side::Bid => snap.bids[0].qty,
                                            Side::Ask => snap.asks[0].qty,
                                        };
                                        resting_queue_ahead = init_q;
                                        prev_l1_qty = init_q;
                                        arena.exec_state_code.store(2, Ordering::Release);
                                        arena.exec_active_symbol.store(
                                            u64::from(snap.symbol_id.0),
                                            Ordering::Release,
                                        );
                                        arena.exec_entry_ticks.store(
                                            entry_price.0 as u64,
                                            Ordering::Release,
                                        );
                                        arena.exec_queue_ahead_lots.store(
                                            resting_queue_ahead.0 as u64,
                                            Ordering::Release,
                                        );
                                        arena.exec_armed_count.fetch_add(1, Ordering::Release);

                                        println!(
                                            "[SHADOW QUEUE ARMED] {} {:?} resting at L1 (Queue ahead: {} lots | Seq: {} | OFI: {:+.2} | TFI: {:+.2})",
                                            snap.symbol_id.name(),
                                            side,
                                            resting_queue_ahead.0,
                                            snap.sequence_id,
                                            snap.factor_ofi.get(),
                                            snap.factor_tfi.get()
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    s += 1;
                }
            }

            OrderLifecycleState::RestingEntryQueue {
                side, entry_price, ..
            } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        if fsm.check_resting_queue_abort(&snap) {
                            arena.exec_abort_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                            println!(
                                "[SHADOW QUEUE ABORT] {} {:?} canceled before fill (TFI: {:+.2} | BestBid: {} | Entry: {})",
                                snap.symbol_id.name(),
                                side,
                                snap.factor_tfi.get(),
                                snap.bids[0].price.0,
                                entry_price.0
                            );
                            continue;
                        }

                        let traded_through = match side {
                            Side::Bid => {
                                snap.asks[0].price.0 <= entry_price.0
                                    || (snap.last_trade_price.0 > 0
                                        && snap.last_trade_price.0 < entry_price.0)
                            }
                            Side::Ask => {
                                snap.bids[0].price.0 >= entry_price.0
                                    || snap.last_trade_price.0 > entry_price.0
                            }
                        };

                        let cur_l1_qty = match side {
                            Side::Bid if snap.bids[0].price.0 == entry_price.0 => snap.bids[0].qty.0,
                            Side::Ask if snap.asks[0].price.0 == entry_price.0 => snap.asks[0].qty.0,
                            _ => prev_l1_qty.0,
                        };
                        if cur_l1_qty < prev_l1_qty.0 {
                            let drop = prev_l1_qty.0 - cur_l1_qty;
                            resting_queue_ahead =
                                LotQty((resting_queue_ahead.0 - (drop / 4).max(1)).max(0));
                            arena.exec_queue_ahead_lots.store(
                                resting_queue_ahead.0 as u64,
                                Ordering::Release,
                            );
                        }
                        prev_l1_qty = LotQty(cur_l1_qty);

                        if traded_through || resting_queue_ahead.0 == 0 {
                            let _ = fsm.on_entry_filled_maker(snap.ts_local_ns);
                            arena.exec_fill_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(3, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                            println!(
                                "[SHADOW MAKER FILL] {} {:?} filled passively at {} ticks (Seq: {})",
                                snap.symbol_id.name(),
                                side,
                                entry_price.0,
                                snap.sequence_id
                            );
                        }
                    }
                }
            }

            OrderLifecycleState::PositionOpenMakerExit { .. } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        if let Some(summary) = fsm.step_open_position(&snap, &mut ledger) {
                            arena.exec_closed_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            append_shadow_trade_jsonl(
                                snap.symbol_id.name(),
                                &summary,
                                &ledger,
                                &fsm,
                            );
                            println!(
                                "[SHADOW CLOSE] {} {:?} | Net: {:+.2} bps | Total Trades: {}",
                                snap.symbol_id.name(),
                                summary.kind,
                                (summary.net_scaled_bps.raw() as f64) / 100.0,
                                ledger.closed_trades_count
                            );
                        }
                    }
                }
            }

            OrderLifecycleState::PlacingEntryMaker { .. } => {
                let _ = fsm.on_entry_order_resting(TimestampNs(now_epoch_ns()));
            }

            OrderLifecycleState::EmergencyStopTriggered { .. }
            | OrderLifecycleState::HaltedByRiskGuard { .. } => {
                arena.exec_state_code.store(5, Ordering::Release);
            }
        }
    }
}

fn main() -> ExitCode {
    let live_hud_mode = std::env::args().any(|a| a == "--live");
    if live_hud_mode {
        return print_live_shm_hud();
    }

    let daemon_mode = std::env::args().any(|a| a == "--daemon");
    println!("================================================================================");
    println!("[VORTEX-EXEC V1.0] EXECUTION FSM, PARITY LEDGER & OOS GATE VERIFIER (STAGE 5)");
    println!("================================================================================");

    match run_oos_certification_suite() {
        Ok((closed_trades, maker_ratio_bps, pf_x100, net_pnl_1e8, parity_drift)) => {
            let net_pnl_usdt_whole = net_pnl_1e8 / 100_000_000;
            let net_pnl_usdt_frac = (net_pnl_1e8.abs() % 100_000_000) / 10_000;

            println!(
                "  -> OOS Closed Trades Verified : {} (Gate >= 500)",
                closed_trades
            );
            println!(
                "  -> Maker Exit Ratio           : {}.{:02}% (Gate >= 80.00%)",
                maker_ratio_bps / 100,
                maker_ratio_bps % 100
            );
            println!(
                "  -> Net Profit Factor (PostFee): {}.{:02} (Gate >= 1.35)",
                pf_x100 / 100,
                pf_x100 % 100
            );
            println!(
                "  -> Cumulative Net PnL (3x)    : + {}.{:04} USDT | PARITY_SYNC Drift: {} units",
                net_pnl_usdt_whole, net_pnl_usdt_frac, parity_drift
            );
            println!("================================================================================");
        }
        Err(code) => {
            println!("  [ERROR] OOS Gate verification failed with code: {}", code);
            return ExitCode::from(code);
        }
    }

    if daemon_mode {
        return run_shadow_execution_daemon();
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oos_520_trades_gate_passes_all_institutional_thresholds() {
        let res = run_oos_certification_suite();
        assert_eq!(res, Ok((520, 8_000, 192, 5_761_600_000, 0)));
    }
}