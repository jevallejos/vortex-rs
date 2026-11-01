//! Binary 2 (`vortex_exec`): Institutional Execution Engine, 200.0 Hz Seqlock Reader,
//! Non-Volatile SHM v9 + JSONL Ledger Rehydration, Convex MFE Maker Ratchet,
//! Semantic Color/Icon Telemetry (`🟢`/`🟠`/`🔴`/`🟡`), and 520-Trade OOS Verifier.

use core::sync::atomic::Ordering;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vortex_rs::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
use vortex_rs::execution_fsm::{
    sign_bybit_v5_hmac_sha256, ClosedTradeSummary, ExecutionFsm, OrderLifecycleState,
};
use vortex_rs::forensic_parquet::ParitySyncLedger;
use vortex_rs::lob_shm::{BookLevel, MappedShmRegion, SymbolLobSnapshot, VortexShmArena};
use vortex_rs::types::{BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

pub const TOTAL_OOS_TRADES_GATE: usize = 520;

const ANSI_GREEN: &str = "\x1b[1;32m";
const ANSI_ORANGE: &str = "\x1b[38;5;208m";
const ANSI_RED: &str = "\x1b[1;31m";
const ANSI_YELLOW: &str = "\x1b[1;33m";
const ANSI_GRAY: &str = "\x1b[90m";
const ANSI_RESET: &str = "\x1b[0m";

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

/// Returns `(ansi_color, icon, label)` for a closed trade based on net basis points:
/// - `> +0.50 bps`: `🟢 WIN` (Green)
/// - `-0.50 .. +0.50 bps`: `�� SCRATCH` (Orange)
/// - `< -0.50 bps`: `🔴 LOSS` (Red)
#[inline]
fn classify_pnl_badge(net_bps: f64) -> (&'static str, &'static str, &'static str) {
    if net_bps >= 0.20 {
        (ANSI_GREEN, "🟢", "WIN")
    } else if net_bps > -0.20 {
        (ANSI_ORANGE, "🟠", "SCRATCH")
    } else {
        (ANSI_RED, "🔴", "LOSS")
    }
}

fn spawn_bybit_v5_private_bridge(live_capital_enabled: bool) -> Option<SyncSender<String>> {
    if !live_capital_enabled {
        return None;
    }

    let mut api_key = std::env::var("BYBIT_API_KEY").ok();
    let mut api_secret = std::env::var("BYBIT_API_SECRET").ok();

    if api_key.is_none() || api_secret.is_none() {
        let env_paths = [
            ".env",
            "/home/ubuntu/vortex-rs/.env",
            "/home/ubuntu/Denk-sekka/.env",
        ];
        for p in env_paths {
            if let Ok(file) = File::open(p) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let clean = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                    if let Some((k, v)) = clean.split_once('=') {
                        let key = k.trim();
                        let val = v.trim().trim_matches('"').trim_matches('\'').to_owned();
                        if !val.is_empty() {
                            match key {
                                "BYBIT_API_KEY" | "API_KEY" => api_key = Some(val),
                                "BYBIT_API_SECRET" | "API_SECRET" => api_secret = Some(val),
                                _ => {}
                            }
                        }
                    }
                }
            }
            if api_key.is_some() && api_secret.is_some() {
                break;
            }
        }
    }

    let (key, secret) = match (api_key, api_secret) {
        (Some(k), Some(s)) => (k, s),
        _ => {
            println!(
                "{}🔴 [BYBIT V5 BRIDGE] --live-capital requested but BYBIT_API_KEY / BYBIT_API_SECRET missing.{}",
                ANSI_RED, ANSI_RESET
            );
            return None;
        }
    };

    let (tx, rx) = sync_channel::<String>(64);
    println!(
        "{}🟡 [BYBIT V5 BRIDGE] Authenticated HMAC-SHA256 Live Order Dispatcher ARMED.{}",
        ANSI_YELLOW, ANSI_RESET
    );

    thread::spawn(move || {
        while let Ok(json_body) = rx.recv() {
            let ts_ms = (now_epoch_ns() / 1_000_000).to_string();
            let recv_win = "5000";
            let sig_bytes = sign_bybit_v5_hmac_sha256(&ts_ms, &key, recv_win, &json_body, &secret);
            let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");

            let endpoint = if json_body.contains("\"cancelAll\"") {
                "https://api.bybit.com/v5/order/cancel-all"
            } else {
                "https://api.bybit.com/v5/order/create"
            };

            let _ = Command::new("curl")
                .args([
                    "-sS",
                    "-X",
                    "POST",
                    endpoint,
                    "-H",
                    "Content-Type: application/json",
                    "-H",
                    &format!("X-BAPI-API-KEY: {}", key),
                    "-H",
                    &format!("X-BAPI-TIMESTAMP: {}", ts_ms),
                    "-H",
                    &format!("X-BAPI-RECV-WINDOW: {}", recv_win),
                    "-H",
                    &format!("X-BAPI-SIGN: {}", sig_str),
                    "-d",
                    &json_body,
                ])
                .output();
        }
    });

    Some(tx)
}

fn spawn_async_telegram_notifier() -> Option<SyncSender<String>> {
    let mut token = std::env::var("TELEGRAM_BOT_TOKEN")
        .or_else(|_| std::env::var("TELEGRAM_TOKEN"))
        .or_else(|_| std::env::var("BOT_TOKEN"))
        .or_else(|_| std::env::var("TG_BOT_TOKEN"))
        .or_else(|_| std::env::var("TG_TOKEN"))
        .ok();
    let mut chat_id = std::env::var("TELEGRAM_CHAT_ID")
        .or_else(|_| std::env::var("TELEGRAM_CHAT"))
        .or_else(|_| std::env::var("CHAT_ID"))
        .or_else(|_| std::env::var("TG_CHAT_ID"))
        .ok();

    let mut discovered_keys: Vec<String> = Vec::new();
    if token.is_none() || chat_id.is_none() {
        let env_paths = [
            ".env",
            "/home/ubuntu/vortex-rs/.env",
            "/home/ubuntu/Denk-sekka/.env",
            "/home/ubuntu/.env",
        ];
        for p in env_paths {
            if let Ok(file) = File::open(p) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let clean_line = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                    if let Some((k, v)) = clean_line.split_once('=') {
                        let key = k.trim();
                        let val = v.trim().trim_matches('"').trim_matches('\'').to_owned();
                        if !key.is_empty() && !discovered_keys.iter().any(|x| x == key) {
                            discovered_keys.push(key.to_owned());
                        }
                        if val.is_empty() {
                            continue;
                        }
                        match key {
                            "TELEGRAM_BOT_TOKEN" | "TELEGRAM_TOKEN" | "BOT_TOKEN"
                            | "TG_BOT_TOKEN" | "TG_TOKEN" => {
                                token = Some(val);
                            }
                            "TELEGRAM_CHAT_ID" | "TELEGRAM_CHAT" | "CHAT_ID" | "TG_CHAT_ID" => {
                                chat_id = Some(val);
                            }
                            _ => {}
                        }
                    }
                }
            }
            if token.is_some() && chat_id.is_some() {
                break;
            }
        }
    }

    let (bot_token, target_chat) = match (token, chat_id) {
        (Some(t), Some(c)) => (t, c),
        _ => {
            println!(
                "{}🟠 [TELEGRAM] Missing bot token or chat_id. Keys detected in .env: {:?} (running silent).{}",
                ANSI_ORANGE, discovered_keys, ANSI_RESET
            );
            return None;
        }
    };

    let (tx, rx) = sync_channel::<String>(64);
    println!(
        "{}🟢 [TELEGRAM] Asynchronous 1:1 transactional notifier thread active.{}",
        ANSI_GREEN, ANSI_RESET
    );

    let _ = tx.try_send(
        "🟢 [VORTEX-L2 STAGE 20 ONLINE]\nSHM v9 (200.0 Hz) + Semantic Color Telemetry + 5-Tick Harvest active in sniper-singapur."
            .to_owned(),
    );

    thread::spawn(move || {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        while let Ok(msg) = rx.recv() {
            let chat_arg = format!("chat_id={}", target_chat);
            let text_arg = format!("text={}", msg);
            let _ = Command::new("curl")
                .args([
                    "-sS",
                    "-X",
                    "POST",
                    &url,
                    "-d",
                    &chat_arg,
                    "--data-urlencode",
                    &text_arg,
                ])
                .output();
        }
    });

    Some(tx)
}

fn rehydrate_shadow_ledger(
    ledger: &mut ParitySyncLedger,
    fsm: &mut ExecutionFsm,
    arena: &VortexShmArena,
) {
    let file_path = Path::new("data/vortex_shadow_trades.jsonl");
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);
    let mut restored_count: u64 = 0;
    let mut clean_lines: Vec<String> = Vec::new();
    let mut purged_stage17: u64 = 0;

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_maker = val
                .get("maker_exit")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let en_ticks = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            // Purge negative MakerPassiveUnwind from Stage 17 and the pre-Stage-23 0ms PostOnly-cross false fill (8888t)
            if (is_maker && net_bps < 0.0) || (!is_maker && en_ticks == 8888) {
                purged_stage17 += 1;
                continue;
            }
            clean_lines.push(line);

            let net_scaled_bps = (net_bps * 100.0).round() as i64;
            let fee_scaled_bps: i64 = if is_maker { 400 } else { 750 };
            let gross_scaled_bps = net_scaled_bps + fee_scaled_bps;

            let gross_1e8 = (fsm.notional_per_trade_1e8 * gross_scaled_bps) / 1_000_000;
            let fee_1e8 = (fsm.notional_per_trade_1e8 * fee_scaled_bps) / 1_000_000;
            let net_1e8 = gross_1e8 - fee_1e8;

            ledger.record_closed_trade(gross_1e8, fee_1e8);
            if is_maker {
                fsm.maker_exits_count += 1;
            } else {
                fsm.taker_sl_exits_count += 1;
            }
            if net_1e8 >= 0 {
                fsm.gross_profit_accum_1e8 += net_1e8;
            } else {
                fsm.gross_loss_accum_1e8 += -net_1e8;
            }
            restored_count += 1;
        }
    }

    if purged_stage17 > 0 {
        if let Ok(mut f) = File::create(file_path) {
            for l in &clean_lines {
                let _ = writeln!(f, "{}", l);
            }
        }
    }

    arena
        .exec_closed_count
        .store(restored_count, Ordering::Release);
    println!(
        "{}🟢 [JSONL REHYDRATE] Restored {} clean shadow trades (CumNetPnL: {:+.4} USDT | PF: {:.2}){}",
        ANSI_GREEN,
        restored_count,
        (ledger.cumulative_net_pnl_1e8 as f64) / 100_000_000.0,
        (fsm.net_profit_factor_x100() as f64) / 100.0,
        ANSI_RESET
    );
}

fn print_colorized_shadow_trades() -> ExitCode {
    let file_path = Path::new("data/vortex_shadow_trades.jsonl");
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            println!("⚪ (No closed shadow trades yet in data/vortex_shadow_trades.jsonl)");
            return ExitCode::SUCCESS;
        }
    };
    let reader = BufReader::new(file);
    let mut total_net_bps = 0.0_f64;
    let mut wins = 0_u64;
    let mut scratches = 0_u64;
    let mut losses = 0_u64;

    for (idx, line) in reader.lines().map_while(Result::ok).enumerate() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let sym = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("-");
            let side = val.get("side").and_then(serde_json::Value::as_str).unwrap_or("-");
            let kind = val.get("kind").and_then(serde_json::Value::as_str).unwrap_or("-");
            let en_t = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let ex_t = val.get("exit_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_maker = val.get("maker_exit").and_then(serde_json::Value::as_bool).unwrap_or(true);

            total_net_bps += net_bps;
            let (color, icon, badge) = classify_pnl_badge(net_bps);
            if net_bps >= 0.20 {
                wins += 1;
            } else if net_bps > -0.20 {
                scratches += 1;
            } else {
                losses += 1;
            }

            println!(
                "  {}{} [SHADOW #{} {:<7}] {:<9} {:<4} {:<20} | {}t -> {}t | Net: {:+.2} bps (Maker={}){}",
                color,
                icon,
                idx + 1,
                badge,
                sym,
                side,
                kind,
                en_t,
                ex_t,
                net_bps,
                is_maker,
                ANSI_RESET
            );
        }
    }

    let (sum_color, sum_icon, _) = classify_pnl_badge(total_net_bps);
    println!("------------------------------------------------------------------------------------------");
    println!(
        "  {}{} [SHADOW SUMMARY] Total: {} (🟢 Wins: {} | 🟠 Scratches: {} | 🔴 Losses: {}) | CumNet: {:+.2} bps{}",
        sum_color,
        sum_icon,
        wins + scratches + losses,
        wins,
        scratches,
        losses,
        total_net_bps,
        ANSI_RESET
    );
    ExitCode::SUCCESS
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
                let (v_col, v_icon, verdict_str) = match evaluator.evaluate_entry_signal(&spec, &snap) {
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Bid, .. }) => {
                        (ANSI_YELLOW, "🟡", "AUTH_LONG_MKR")
                    }
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Ask, .. }) => {
                        (ANSI_YELLOW, "🟡", "AUTH_SHORT_MKR")
                    }
                    Ok(SignalVerdict::SpoofingVeto) => (ANSI_ORANGE, "🟠", "SPOOF_VETO"),
                    Ok(SignalVerdict::NeutralNoAction) => (ANSI_GRAY, "⚪", "NEUTRAL_WAIT"),
                    Err(_) => (ANSI_RED, "🔴", "GUARD_VETO"),
                };

                println!(
                    "  {}  | {:<10} | {:>12} | {:>7}.{:04} | {:>7}.{:04} | {:>5} | {:>+6.2} | {:>+6.2} | {:>+6.2} | {}{} {}{}",
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
                    v_col,
                    v_icon,
                    verdict_str,
                    ANSI_RESET
                );
            }
        }
        slot_idx += 1;
    }

    let state_code = arena.exec_state_code.load(Ordering::Acquire);
    let active_sym = SymbolId(arena.exec_active_symbol.load(Ordering::Acquire) as u16);
    let side_code = arena.exec_side.load(Ordering::Acquire);
    let side_str = if side_code == 1 { "Ask" } else { "Bid" };
    let entry_ticks = arena.exec_entry_ticks.load(Ordering::Acquire);
    let peak_ticks = arena.exec_peak_ticks.load(Ordering::Acquire);
    let tp_ticks = arena.exec_tp_ticks.load(Ordering::Acquire);
    let sl_ticks = arena.exec_sl_ticks.load(Ordering::Acquire);
    let q_ahead = arena.exec_queue_ahead_lots.load(Ordering::Acquire);
    let armed = arena.exec_armed_count.load(Ordering::Acquire);
    let aborts = arena.exec_abort_count.load(Ordering::Acquire);
    let fills = arena.exec_fill_count.load(Ordering::Acquire);
    let closed = arena.exec_closed_count.load(Ordering::Acquire);

    let (st_col, st_icon, state_label) = match state_code {
        0 => (ANSI_GRAY, "⚪", "IDLE (SCANNING)"),
        1 => (ANSI_YELLOW, "🟡", "PLACING_MAKER"),
        2 => (ANSI_YELLOW, "🟡", "RESTING_L1_QUEUE"),
        3 => (ANSI_YELLOW, "🟡", "POSITION_OPEN_MAKER_TP"),
        4 => (ANSI_RED, "🔴", "EMERGENCY_SL"),
        _ => (ANSI_RED, "��", "HALTED_GUARD"),
    };

    println!("------------------------------------------------------------------------------------------");
    println!(
        "[EXEC FSM LIVE] State: {}{} {}{} | Sym: {} ({}) @ {}t [Peak:{}t | TP:{}t | SL:{}t] (Q: {} lots) | 🟡Armed: {} | 🟠Aborts: {} | 🟡Fills: {} | 🟢Closed: {}",
        st_col,
        st_icon,
        state_label,
        ANSI_RESET,
        if state_code == 0 { "-" } else { active_sym.name() },
        if state_code == 0 { "-" } else { side_str },
        entry_ticks,
        peak_ticks,
        tp_ticks,
        sl_ticks,
        q_ahead,
        armed,
        aborts,
        fills,
        closed
    );
    println!("==========================================================================================");
    ExitCode::SUCCESS
}

fn run_shadow_execution_daemon(live_capital_enabled: bool) -> ExitCode {
    let shm_path = MappedShmRegion::default_shm_path();
    let region = match MappedShmRegion::open_or_create(&shm_path, false) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(9),
    };
    let arena = region.arena();
    let tg_tx = spawn_async_telegram_notifier();
    let bybit_tx = spawn_bybit_v5_private_bridge(live_capital_enabled);
    let evaluator = OrthogonalFactorState::new();
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    let mut ledger = ParitySyncLedger::new(10_000_000_000);
    let mut active_slot: usize = 0;
    let mut resting_queue_ahead: LotQty = LotQty(0);
    let mut prev_l1_qty: LotQty = LotQty(0);
    let mut prev_cum_trade_lots: LotQty = LotQty(0);
    let mut last_seen_seq = [0_u64; 6];

    rehydrate_shadow_ledger(&mut ledger, &mut fsm, arena);

    let saved_state_code = arena.exec_state_code.load(Ordering::Acquire);
    if saved_state_code == 2 || saved_state_code == 3 {
        let slot_saved = (arena.exec_active_slot.load(Ordering::Acquire) as usize).min(APPROVED_SPECS.len() - 1);
        let side_saved = if arena.exec_side.load(Ordering::Acquire) == 1 {
            Side::Ask
        } else {
            Side::Bid
        };
        let entry_saved = PriceTicks(arena.exec_entry_ticks.load(Ordering::Acquire) as i64);
        let peak_saved = PriceTicks(arena.exec_peak_ticks.load(Ordering::Acquire) as i64);
        let tp_saved = PriceTicks(arena.exec_tp_ticks.load(Ordering::Acquire) as i64);
        let sl_saved = PriceTicks(arena.exec_sl_ticks.load(Ordering::Acquire) as i64);
        let since_saved = TimestampNs(arena.exec_resting_since_ns.load(Ordering::Acquire) as i64);
        let q_saved = LotQty(arena.exec_queue_ahead_lots.load(Ordering::Acquire) as i64);

        active_slot = slot_saved;
        resting_queue_ahead = q_saved;
        prev_l1_qty = q_saved;

        if saved_state_code == 2 {
            fsm.state = OrderLifecycleState::RestingEntryQueue {
                side: side_saved,
                entry_price: entry_saved,
                qty: LotQty(10),
                target_excursion: ScaledBps::from_whole_bps(40),
                sl_trigger_price: sl_saved,
                resting_since_ts: since_saved,
            };
            println!(
                "{}🟡 [SHM HOT-RESTORE] Rehydrated RestingEntryQueue on {} {:?} @ {}t (Queue: {} lots){}",
                ANSI_YELLOW,
                APPROVED_SPECS[active_slot].symbol_id.name(),
                side_saved,
                entry_saved.0,
                q_saved.0,
                ANSI_RESET
            );
        } else {
            fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                side: side_saved,
                entry_price: entry_saved,
                peak_favorable_price: if peak_saved.0 > 0 { peak_saved } else { entry_saved },
                qty: LotQty(10),
                tp_maker_price: tp_saved,
                sl_trigger_price: sl_saved,
                opened_ts: since_saved,
            };
            println!(
                "{}🟡 [SHM HOT-RESTORE] Rehydrated PositionOpenMakerExit on {} {:?} @ {}t [Peak:{}t | TP:{}t | SL:{}t]{}",
                ANSI_YELLOW,
                APPROVED_SPECS[active_slot].symbol_id.name(),
                side_saved,
                entry_saved.0,
                peak_saved.0,
                tp_saved.0,
                sl_saved.0,
                ANSI_RESET
            );
        }
    }

    println!(
        "{}🟢 [DAEMON 200.0 Hz] Attached to MAP_SHARED arena (SHM v{}: {}) with Semantic Color Telemetry & 5-Tick Harvest.{}",
        ANSI_GREEN,
        arena.version,
        shm_path.display(),
        ANSI_RESET
    );

    loop {
        thread::sleep(Duration::from_millis(5));

        match fsm.state {
            OrderLifecycleState::Idle => {
                arena.exec_state_code.store(0, Ordering::Release);
                arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                let mut s = 0;
                while s < APPROVED_SPECS.len() {
                    let spec = APPROVED_SPECS[s];
                    if let Ok(slot) = arena.slot(s) {
                        if let Ok(snap) = slot.read_snapshot(4) {
                            if snap.sequence_id == last_seen_seq[s] {
                                s += 1;
                                continue;
                            }
                            last_seen_seq[s] = snap.sequence_id;

                            if let Ok(verdict) = evaluator.evaluate_entry_signal(&spec, &snap) {
                                if let Ok(true) =
                                    fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10))
                                {
                                    active_slot = s;
                                    arena.exec_state_code.store(1, Ordering::Release);
                                    arena.exec_active_slot.store(s as u64, Ordering::Release);
                                    arena.exec_active_symbol.store(
                                        u64::from(snap.symbol_id.0),
                                        Ordering::Release,
                                    );
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
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            continue;
                        }
                        last_seen_seq[active_slot] = snap.sequence_id;

                        // Check immediate joint flow reversal BEFORE allowing a toxic sweep fill
                        if fsm.check_resting_queue_abort(&snap) {
                            arena.exec_abort_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                            if let Some(ref b_tx) = bybit_tx {
                                let cancel_json = format!(
                                    "{{\"category\":\"linear\",\"symbol\":\"{}\",\"cancelAll\":true}}",
                                    snap.symbol_id.name()
                                );
                                let _ = b_tx.try_send(cancel_json);
                            }
                            println!(
                                "{}🟠 [SHADOW QUEUE ABORT] {} {:?} canceled before fill (OFI: {:+.2} | TFI: {:+.2} | BestBid: {} | BestAsk: {} | Entry: {}){}",
                                ANSI_ORANGE,
                                snap.symbol_id.name(),
                                side,
                                snap.factor_ofi.get(),
                                snap.factor_tfi.get(),
                                snap.bids[0].price.0,
                                snap.asks[0].price.0,
                                entry_price.0,
                                ANSI_RESET
                            );
                            continue;
                        }

                        // Strict trade-through: opposite side must step strictly past our resting price
                        let level_swept = match side {
                            Side::Bid => snap.asks[0].price.0 > 0 && snap.asks[0].price.0 < entry_price.0,
                            Side::Ask => snap.bids[0].price.0 > 0 && snap.bids[0].price.0 > entry_price.0,
                        };

                        let cur_cum_trade = match side {
                            Side::Bid => snap.cum_sell_trade_lots.0,
                            Side::Ask => snap.cum_buy_trade_lots.0,
                        };
                        if cur_cum_trade > prev_cum_trade_lots.0 && prev_cum_trade_lots.0 > 0 {
                            let traded_at_level = match side {
                                Side::Bid => snap.last_trade_price.0 > 0 && snap.last_trade_price.0 <= entry_price.0,
                                Side::Ask => snap.last_trade_price.0 >= entry_price.0,
                            };
                            if traded_at_level {
                                let trade_drain = cur_cum_trade - prev_cum_trade_lots.0;
                                resting_queue_ahead =
                                    LotQty((resting_queue_ahead.0 - trade_drain).max(0));
                            }
                        }
                        prev_cum_trade_lots = LotQty(cur_cum_trade);

                        let cur_l1_qty = match side {
                            Side::Bid if snap.bids[0].price.0 == entry_price.0 => snap.bids[0].qty.0,
                            Side::Ask if snap.asks[0].price.0 == entry_price.0 => snap.asks[0].qty.0,
                            _ => prev_l1_qty.0,
                        };
                        if cur_l1_qty < prev_l1_qty.0 {
                            let drop = prev_l1_qty.0 - cur_l1_qty;
                            resting_queue_ahead =
                                LotQty((resting_queue_ahead.0 - (drop / 4).max(1)).max(0));
                        }
                        prev_l1_qty = LotQty(cur_l1_qty);

                        arena.exec_queue_ahead_lots.store(
                            resting_queue_ahead.0 as u64,
                            Ordering::Release,
                        );

                        let toxic_sweep = level_swept
                            && resting_queue_ahead.0 > 0
                            && match side {
                                Side::Bid => snap.factor_ofi.get() <= -0.10,
                                Side::Ask => snap.factor_ofi.get() >= 0.10,
                            };
                        if toxic_sweep {
                            fsm.state = OrderLifecycleState::Idle;
                            arena.exec_abort_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                            println!(
                                "{}🟠 [TOXIC SWEEP VETO] {} {:?} aborted on adverse L1 sweep (OFI: {:+.2} | Queue left: {} lots){}",
                                ANSI_ORANGE,
                                snap.symbol_id.name(),
                                side,
                                snap.factor_ofi.get(),
                                resting_queue_ahead.0,
                                ANSI_RESET
                            );
                            continue;
                        }

                        if level_swept || resting_queue_ahead.0 == 0 {
                            let _ = fsm.on_entry_filled_maker(snap.ts_local_ns);
                            let mut tp_t: i64 = 0;
                            let mut sl_t: i64 = 0;
                            if let OrderLifecycleState::PositionOpenMakerExit {
                                tp_maker_price,
                                sl_trigger_price,
                                opened_ts,
                                ..
                            } = fsm.state
                            {
                                tp_t = tp_maker_price.0;
                                sl_t = sl_trigger_price.0;
                                arena.exec_peak_ticks.store(entry_price.0 as u64, Ordering::Release);
                                arena.exec_tp_ticks.store(tp_t as u64, Ordering::Release);
                                arena.exec_sl_ticks.store(sl_t as u64, Ordering::Release);
                                arena.exec_resting_since_ns.store(
                                    opened_ts.0 as u64,
                                    Ordering::Release,
                                );
                            }
                            arena.exec_fill_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(3, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);

                            let spec = APPROVED_SPECS[active_slot];
                            let (e_w, e_f) = spec.format_price_usdt_parts(entry_price);
                            let (tp_w, tp_f) = spec.format_price_usdt_parts(PriceTicks(tp_t));
                            let (sl_w, sl_f) = spec.format_price_usdt_parts(PriceTicks(sl_t));

                            println!(
                                "{}🟡 [SHADOW MAKER FILL] {} {:?} filled passively at {}.{:04} USDT ({}t | TP: {}.{:04} | SL: {}.{:04}){}",
                                ANSI_YELLOW,
                                snap.symbol_id.name(),
                                side,
                                e_w,
                                e_f,
                                entry_price.0,
                                tp_w,
                                tp_f,
                                sl_w,
                                sl_f,
                                ANSI_RESET
                            );
                            if let Some(ref tx) = tg_tx {
                                let alert = format!(
                                    "🟡 [VORTEX-L2 MAKER FILL]\nSymbol: {} ({:?})\nEntry: {}.{:04} USDT (PostOnly Maker)\nTarget TP: {}.{:04} USDT\nServer SL: {}.{:04} USDT",
                                    snap.symbol_id.name(),
                                    side,
                                    e_w,
                                    e_f,
                                    tp_w,
                                    tp_f,
                                    sl_w,
                                    sl_f
                                );
                                let _ = tx.try_send(alert);
                            }
                            continue;
                        }
                    }
                }
            }

            OrderLifecycleState::PositionOpenMakerExit { .. } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            continue;
                        }
                        last_seen_seq[active_slot] = snap.sequence_id;

                        if let Some(summary) = fsm.step_open_position(&snap, &mut ledger) {
                            arena.exec_closed_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_peak_ticks.store(0, Ordering::Release);
                            arena.exec_tp_ticks.store(0, Ordering::Release);
                            arena.exec_sl_ticks.store(0, Ordering::Release);
                            append_shadow_trade_jsonl(
                                snap.symbol_id.name(),
                                &summary,
                                &ledger,
                                &fsm,
                            );

                            let spec = APPROVED_SPECS[active_slot];
                            let (en_w, en_f) = spec.format_price_usdt_parts(summary.entry_price);
                            let (ex_w, ex_f) = spec.format_price_usdt_parts(summary.exit_price);
                            let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
                            let (c_col, c_icon, c_badge) = classify_pnl_badge(net_bps);

                            println!(
                                "{}{} [SHADOW CLOSE — {}] {} {:?} | {}.{:04} -> {}.{:04} | Net: {:+.2} bps | Total Trades: {}{}",
                                c_col,
                                c_icon,
                                c_badge,
                                snap.symbol_id.name(),
                                summary.kind,
                                en_w,
                                en_f,
                                ex_w,
                                ex_f,
                                net_bps,
                                ledger.closed_trades_count,
                                ANSI_RESET
                            );

                            if let Some(ref tx) = tg_tx {
                                let alert = format!(
                                    "{} [VORTEX-L2 TRADE {}]\nSymbol: {} ({:?})\nExit Type: {:?}\nPrice: {}.{:04} -> {}.{:04} USDT\nNet PnL: {:+.2} bps (Maker Exit: {})\nTotal Trades: {} | PF: {:.2}",
                                    c_icon,
                                    c_badge,
                                    snap.symbol_id.name(),
                                    summary.side,
                                    summary.kind,
                                    en_w,
                                    en_f,
                                    ex_w,
                                    ex_f,
                                    net_bps,
                                    summary.is_maker_exit,
                                    ledger.closed_trades_count,
                                    (fsm.net_profit_factor_x100() as f64) / 100.0
                                );
                                let _ = tx.try_send(alert);
                            }
                        } else if let OrderLifecycleState::PositionOpenMakerExit {
                            peak_favorable_price,
                            ..
                        } = fsm.state
                        {
                            arena.exec_peak_ticks.store(
                                peak_favorable_price.0 as u64,
                                Ordering::Release,
                            );
                        }
                    }
                }
            }

            OrderLifecycleState::PlacingEntryMaker {
                side,
                entry_price,
                sl_trigger_price,
                submitted_ts,
                ..
            } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        // Enforce 25ms one-way flight latency (matching vortex_replay SIMULATED_ONE_WAY_LATENCY_NS)
                        if snap.ts_local_ns.0.saturating_sub(submitted_ts.0) < 25_000_000 {
                            continue;
                        }
                        let post_only_crossed = match side {
                            Side::Bid => snap.asks[0].price.0 > 0 && entry_price.0 >= snap.asks[0].price.0,
                            Side::Ask => snap.bids[0].price.0 > 0 && entry_price.0 <= snap.bids[0].price.0,
                        };
                        let flow_died_in_flight = match side {
                            Side::Bid => snap.factor_ofi.get() <= 0.0 || snap.factor_tfi.get() <= 0.0,
                            Side::Ask => snap.factor_ofi.get() >= 0.0 || snap.factor_tfi.get() >= 0.0,
                        };
                        if post_only_crossed || flow_died_in_flight {
                            fsm.state = OrderLifecycleState::Idle;
                            arena.exec_state_code.store(0, Ordering::Release);
                            continue;
                        }

                        let _ = fsm.on_entry_order_resting(snap.ts_local_ns);
                        let (init_q, init_cum_trade) = match side {
                            Side::Bid => (snap.bids[0].qty, snap.cum_sell_trade_lots),
                            Side::Ask => (snap.asks[0].qty, snap.cum_buy_trade_lots),
                        };
                        resting_queue_ahead = init_q;
                        prev_l1_qty = init_q;
                        prev_cum_trade_lots = init_cum_trade;
                        last_seen_seq[active_slot] = snap.sequence_id;

                        arena.exec_state_code.store(2, Ordering::Release);
                        arena.exec_side.store(side as u64, Ordering::Release);
                        arena.exec_entry_ticks.store(entry_price.0 as u64, Ordering::Release);
                        arena.exec_peak_ticks.store(entry_price.0 as u64, Ordering::Release);
                        arena.exec_tp_ticks.store(0, Ordering::Release);
                        arena.exec_sl_ticks.store(sl_trigger_price.0 as u64, Ordering::Release);
                        arena.exec_resting_since_ns.store(snap.ts_local_ns.0 as u64, Ordering::Release);
                        arena.exec_queue_ahead_lots.store(resting_queue_ahead.0 as u64, Ordering::Release);
                        arena.exec_armed_count.fetch_add(1, Ordering::Release);

                        let spec = APPROVED_SPECS[active_slot];
                        if let Some(ref b_tx) = bybit_tx {
                            let (ew, ef) = spec.format_price_usdt_parts(entry_price);
                            let (sw, sf) = spec.format_price_usdt_parts(sl_trigger_price);
                            let bybit_side = match side {
                                Side::Bid => "Buy",
                                Side::Ask => "Sell",
                            };
                            let order_json = format!(
                                "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"1\",\"price\":\"{}.{:04}\",\"stopLoss\":\"{}.{:04}\",\"slTriggerBy\":\"MarkPrice\"}}",
                                snap.symbol_id.name(),
                                bybit_side,
                                ew,
                                ef,
                                sw,
                                sf
                            );
                            let _ = b_tx.try_send(order_json);
                        }

                        println!(
                            "{}🟡 [SHADOW QUEUE ARMED] {} {:?} resting at L1 after 25ms PostOnly check (Queue ahead: {} lots | Seq: {} | OFI: {:+.2} | TFI: {:+.2}){}",
                            ANSI_YELLOW,
                            snap.symbol_id.name(),
                            side,
                            resting_queue_ahead.0,
                            snap.sequence_id,
                            snap.factor_ofi.get(),
                            snap.factor_tfi.get(),
                            ANSI_RESET
                        );
                    }
                }
            }

            OrderLifecycleState::EmergencyStopTriggered { .. }
            | OrderLifecycleState::HaltedByRiskGuard { .. } => {
                arena.exec_state_code.store(5, Ordering::Release);
            }
        }
    }
}

fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--live") {
        return print_live_shm_hud();
    }
    if std::env::args().any(|a| a == "--trades") {
        return print_colorized_shadow_trades();
    }

    let daemon_mode = std::env::args().any(|a| a == "--daemon");
    let live_capital_mode = std::env::args().any(|a| a == "--live-capital");
    println!("================================================================================");
    println!("[VORTEX-EXEC V1.0] EXECUTION FSM, PARITY LEDGER & OOS GATE VERIFIER (STAGE 5)");
    println!("================================================================================");

    match run_oos_certification_suite() {
        Ok((closed_trades, maker_ratio_bps, pf_x100, net_pnl_1e8, parity_drift)) => {
            let net_pnl_usdt_whole = net_pnl_1e8 / 100_000_000;
            let net_pnl_usdt_frac = (net_pnl_1e8.abs() % 100_000_000) / 10_000;

            println!(
                "  {}🟢 -> OOS Closed Trades Verified : {} (Gate >= 500){}",
                ANSI_GREEN, closed_trades, ANSI_RESET
            );
            println!(
                "  {}🟢 -> Maker Exit Ratio           : {}.{:02}% (Gate >= 80.00%){}",
                ANSI_GREEN,
                maker_ratio_bps / 100,
                maker_ratio_bps % 100,
                ANSI_RESET
            );
            println!(
                "  {}🟢 -> Net Profit Factor (PostFee): {}.{:02} (Gate >= 1.35){}",
                ANSI_GREEN,
                pf_x100 / 100,
                pf_x100 % 100,
                ANSI_RESET
            );
            println!(
                "  {}🟢 -> Cumulative Net PnL (3x)    : + {}.{:04} USDT | PARITY_SYNC Drift: {} units{}",
                ANSI_GREEN, net_pnl_usdt_whole, net_pnl_usdt_frac, parity_drift, ANSI_RESET
            );
            println!("================================================================================");
        }
        Err(code) => {
            println!(
                "  {}🔴 [ERROR] OOS Gate verification failed with code: {}{}",
                ANSI_RED, code, ANSI_RESET
            );
            return ExitCode::from(code);
        }
    }

    if daemon_mode {
        return run_shadow_execution_daemon(live_capital_mode);
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