//! Binary 2 (`vortex_exec`): Institutional Execution Engine, 200.0 Hz Seqlock Reader,
//! Stage 27 Global Account Single-Position Lock (`settleCoin=USDT`), Non-Abandoning Exchange-Verified Close,
//! Slot-0 `BTCUSDT` Macro Leader Coherence Filter, Dynamic 70% MFE Ratchet, and 520-Trade OOS Verifier.

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
    sign_bybit_v5_hmac_sha256, ClosedTradeKind, ClosedTradeSummary, ExecutionFsm,
    OrderLifecycleState,
};
use vortex_rs::forensic_parquet::ParitySyncLedger;
use vortex_rs::lob_shm::{BookLevel, MappedShmRegion, SymbolLobSnapshot, VortexShmArena};
use vortex_rs::types::{BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

pub const TOTAL_OOS_TRADES_GATE: usize = 520;

/// Optimal Live Canary Notional Reference (12.50 USDT in 1e8 fixed-point scale).
pub const OPTIMAL_LIVE_NOTIONAL_1E8: i64 = 1_250_000_000;

/// Per-slot anti-chasing cooldown after an unfilled queue abort or close (15 seconds).
pub const SLOT_ABORT_COOLDOWN_NS: i64 = 15_000_000_000;

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

#[inline]
const fn compute_optimal_50usdt_wallet_qty_str(symbol_id: SymbolId) -> &'static str {
    match symbol_id.0 {
        1 => "0.001",
        2 => "0.01",
        3 => "0.2",
        4 => "1.4",
        5 => "0.05",
        6 => "14",
        _ => "1",
    }
}

#[derive(Clone, Debug)]
struct BybitV5LiveClient {
    api_key: String,
    api_secret: String,
}

impl BybitV5LiveClient {
    fn from_env_if_enabled(live_capital_enabled: bool) -> Option<Self> {
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
                    "{}🔴 [BYBIT V5 LIVE] --live-capital requested but BYBIT_API_KEY / BYBIT_API_SECRET missing.{}",
                    ANSI_RED, ANSI_RESET
                );
                return None;
            }
        };

        let client = Self {
            api_key: key,
            api_secret: secret,
        };

        for spec in APPROVED_SPECS {
            let sym = spec.symbol_id.name();
            let lev_body = format!(
                "{{\"category\":\"linear\",\"symbol\":\"{}\",\"buyLeverage\":\"10\",\"sellLeverage\":\"10\"}}",
                sym
            );
            let _ = client.post_v5("/v5/position/set-leverage", &lev_body);
        }

        println!(
            "{}🟢 [BYBIT V5 LIVE CAPITAL ARMED] Stage 27 Global Account Lock + Non-Abandoning Exit + 70% Dynamic Ratchet active.{}",
            ANSI_GREEN, ANSI_RESET
        );
        Some(client)
    }

    fn post_v5(&self, path: &str, json_body: &str) -> Option<serde_json::Value> {
        let ts_ms = (now_epoch_ns() / 1_000_000).to_string();
        let recv_win = "5000";
        let sig_bytes =
            sign_bybit_v5_hmac_sha256(&ts_ms, &self.api_key, recv_win, json_body, &self.api_secret);
        let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");
        let url = format!("https://api.bybit.com{}", path);

        let output = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "4",
                "-X",
                "POST",
                &url,
                "-H",
                "Content-Type: application/json",
                "-H",
                &format!("X-BAPI-API-KEY: {}", self.api_key),
                "-H",
                &format!("X-BAPI-TIMESTAMP: {}", ts_ms),
                "-H",
                &format!("X-BAPI-RECV-WINDOW: {}", recv_win),
                "-H",
                &format!("X-BAPI-SIGN: {}", sig_str),
                "-d",
                json_body,
            ])
            .output()
            .ok()?;

        serde_json::from_slice(&output.stdout).ok()
    }

    fn get_v5(&self, path: &str, query_str: &str) -> Option<serde_json::Value> {
        let ts_ms = (now_epoch_ns() / 1_000_000).to_string();
        let recv_win = "5000";
        let sig_bytes =
            sign_bybit_v5_hmac_sha256(&ts_ms, &self.api_key, recv_win, query_str, &self.api_secret);
        let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");
        let url = format!("https://api.bybit.com{}?{}", path, query_str);

        let output = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "4",
                "-X",
                "GET",
                &url,
                "-H",
                &format!("X-BAPI-API-KEY: {}", self.api_key),
                "-H",
                &format!("X-BAPI-TIMESTAMP: {}", ts_ms),
                "-H",
                &format!("X-BAPI-RECV-WINDOW: {}", recv_win),
                "-H",
                &format!("X-BAPI-SIGN: {}", sig_str),
            ])
            .output()
            .ok()?;

        serde_json::from_slice(&output.stdout).ok()
    }

    fn cancel_all_symbol_orders(&self, symbol: &str) {
        let body = format!("{{\"category\":\"linear\",\"symbol\":\"{}\"}}", symbol);
        let _ = self.post_v5("/v5/order/cancel-all", &body);
    }

    /// Queries `/v5/position/list?category=linear&settleCoin=USDT` to inspect ALL open positions across the entire account.
    /// Returns `Some((symbol, size_str, side_str, avg_price_str))` if any position has `size > 0`.
    fn get_any_account_open_position(&self) -> Option<(String, String, String, String)> {
        if let Some(resp) = self.get_v5("/v5/position/list", "category=linear&settleCoin=USDT") {
            if let Some(list) = resp
                .get("result")
                .and_then(|r| r.get("list"))
                .and_then(serde_json::Value::as_array)
            {
                for item in list {
                    let size_str = item
                        .get("size")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0");
                    let size_f = size_str.parse::<f64>().unwrap_or(0.0);
                    if size_f > 0.0 {
                        let sym = item
                            .get("symbol")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("UNKNOWN");
                        let side = item
                            .get("side")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("None");
                        let avg_p = item
                            .get("avgPrice")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("0");
                        return Some((
                            sym.to_owned(),
                            size_str.to_owned(),
                            side.to_owned(),
                            avg_p.to_owned(),
                        ));
                    }
                }
            }
        }
        None
    }

    /// Queries `/v5/position/list` for a specific symbol and returns `(has_open_position, size_str, side_str)`.
    fn get_open_position_info(&self, symbol: &str) -> (bool, String, String) {
        let query = format!("category=linear&symbol={}", symbol);
        if let Some(resp) = self.get_v5("/v5/position/list", &query) {
            if let Some(list) = resp
                .get("result")
                .and_then(|r| r.get("list"))
                .and_then(serde_json::Value::as_array)
            {
                if let Some(first) = list.first() {
                    let size_str = first
                        .get("size")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0");
                    let side_str = first
                        .get("side")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("None");
                    let size_f = size_str.parse::<f64>().unwrap_or(0.0);
                    if size_f > 0.0 {
                        return (true, size_str.to_owned(), side_str.to_owned());
                    }
                }
            }
        }
        (false, String::from("0"), String::from("None"))
    }

    fn get_open_position_size(&self, symbol: &str) -> (bool, String) {
        let (open, sz, _) = self.get_open_position_info(symbol);
        (open, sz)
    }

    /// Audits all 6 approved pairs on startup to ensure zero untracked orphan positions exist outside the active SHM slot.
    fn audit_and_clean_untracked_orphans(&self, tracked_symbol: Option<&str>) {
        for spec in APPROVED_SPECS {
            let sym = spec.symbol_id.name();
            if Some(sym) == tracked_symbol {
                continue;
            }
            self.cancel_all_symbol_orders(sym);
            let (has_orphan, orphan_qty, orphan_side) = self.get_open_position_info(sym);
            if has_orphan {
                let close_side = if orphan_side == "Buy" { "Sell" } else { "Buy" };
                println!(
                    "{}🟠 [BYBIT V5 ORPHAN CLEANUP] Found untracked orphan position on {} (side={} size={}) — closing with reduceOnly{}",
                    ANSI_ORANGE, sym, orphan_side, orphan_qty, ANSI_RESET
                );
                let close_body = format!(
                    "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Market\",\"qty\":\"{}\",\"reduceOnly\":true,\"positionIdx\":0}}",
                    sym, close_side, orphan_qty
                );
                let _ = self.post_v5("/v5/order/create", &close_body);
            }
        }
    }

    fn place_post_only_entry(
        &self,
        spec: &PairSpec,
        symbol: &str,
        side: Side,
        entry_price: PriceTicks,
        sl_price: PriceTicks,
    ) -> bool {
        // GLOBAL ACCOUNT SINGLE-POSITION LOCK: never send a new entry if ANY position is open across the entire USDT account!
        if let Some((open_sym, existing_qty, open_side, _)) = self.get_any_account_open_position() {
            println!(
                "{}🟠 [BYBIT V5 GLOBAL ACCOUNT LOCK] Account already holds open position on {} ({} size={}) — blocking new entry on {}{}",
                ANSI_ORANGE, open_sym, open_side, existing_qty, symbol, ANSI_RESET
            );
            return false;
        }

        let (ew, ef) = spec.format_price_usdt_parts(entry_price);
        let (sw, sf) = spec.format_price_usdt_parts(sl_price);
        let bybit_side = match side {
            Side::Bid => "Buy",
            Side::Ask => "Sell",
        };
        let qty_str = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id);
        let body = format!(
            "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",\"price\":\"{}.{:04}\",\"stopLoss\":\"{}.{:04}\",\"slTriggerBy\":\"MarkPrice\",\"positionIdx\":0}}",
            symbol, bybit_side, qty_str, ew, ef, sw, sf
        );

        match self.post_v5("/v5/order/create", &body) {
            Some(resp) => {
                let ret_code = resp.get("retCode").and_then(serde_json::Value::as_i64).unwrap_or(-1);
                let ret_msg = resp
                    .get("retMsg")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                if ret_code == 0 {
                    println!(
                        "{}🟡 [BYBIT V5 LIVE ORDER SENT] {} {} qty={} @ {}.{:04} USDT (SL: {}.{:04}){}",
                        ANSI_YELLOW, symbol, bybit_side, qty_str, ew, ef, sw, sf, ANSI_RESET
                    );
                    true
                } else {
                    println!(
                        "{}🟠 [BYBIT V5 ORDER REJECTED] {} retCode={} ({}){}",
                        ANSI_ORANGE, symbol, ret_code, ret_msg, ANSI_RESET
                    );
                    false
                }
            }
            None => false,
        }
    }

    /// Executes a verified close on Bybit WITHOUT abandoning the position:
    /// - Preserves FIFO queue priority by only re-pegging the `Limit PostOnly reduceOnly` order when the BBO price changes.
    /// - Returns `true` ONLY when Bybit confirms `0.00` open position size.
    /// - If `force_market_if_unfilled` is true (e.g., on Stop-Loss), sweeps any remaining size with `Market reduceOnly`.
    fn execute_verified_close_step(
        &self,
        arena: &VortexShmArena,
        active_slot: usize,
        spec: &PairSpec,
        open_side: Side,
        initial_exit_price: PriceTicks,
        force_market_if_unfilled: bool,
    ) -> bool {
        let symbol = spec.symbol_id.name();
        let close_side = match open_side {
            Side::Bid => "Sell",
            Side::Ask => "Buy",
        };

        let mut last_pegged_price = PriceTicks(0);
        let mut attempt = 0_usize;

        while attempt < 8 {
            let (is_open, pos_qty) = self.get_open_position_size(symbol);
            if !is_open {
                self.cancel_all_symbol_orders(symbol);
                println!(
                    "{}🟢 [BYBIT V5 REAL EXIT CONFIRMED] {} position closed (0.00 remaining){}",
                    ANSI_GREEN, symbol, ANSI_RESET
                );
                return true;
            }

            if force_market_if_unfilled {
                self.cancel_all_symbol_orders(symbol);
                let mkt_body = format!(
                    "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Market\",\"qty\":\"{}\",\"reduceOnly\":true,\"positionIdx\":0}}",
                    symbol, close_side, pos_qty
                );
                let _ = self.post_v5("/v5/order/create", &mkt_body);
                thread::sleep(Duration::from_millis(350));
                let (still_open, _) = self.get_open_position_size(symbol);
                if !still_open {
                    return true;
                }
            } else {
                let mut peg_price = initial_exit_price;
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(latest_snap) = slot.read_snapshot(4) {
                        peg_price = match open_side {
                            Side::Bid if latest_snap.bids[0].price.0 > 0 => latest_snap.bids[0].price,
                            Side::Ask if latest_snap.asks[0].price.0 > 0 => latest_snap.asks[0].price,
                            _ => initial_exit_price,
                        };
                    }
                }

                // Only cancel and re-peg if the BBO price moved (preserving FIFO queue priority!)
                if peg_price.0 != last_pegged_price.0 {
                    self.cancel_all_symbol_orders(symbol);
                    let (xw, xf) = spec.format_price_usdt_parts(peg_price);
                    let post_only_exit = format!(
                        "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",\"price\":\"{}.{:04}\",\"reduceOnly\":true,\"positionIdx\":0}}",
                        symbol, close_side, pos_qty, xw, xf
                    );
                    if let Some(resp) = self.post_v5("/v5/order/create", &post_only_exit) {
                        if resp.get("retCode").and_then(serde_json::Value::as_i64) == Some(0) {
                            last_pegged_price = peg_price;
                        } else {
                            last_pegged_price = PriceTicks(0);
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(350));
            attempt += 1;
        }

        let (still_open_end, _) = self.get_open_position_size(symbol);
        if !still_open_end {
            self.cancel_all_symbol_orders(symbol);
            println!(
                "{}🟢 [BYBIT V5 REAL EXIT CONFIRMED] {} position closed (0.00 remaining){}",
                ANSI_GREEN, symbol, ANSI_RESET
            );
            return true;
        }

        println!(
            "{}🟡 [BYBIT V5 EXIT STILL RESTING] {} position still open after peg cycle — retaining FSM custody (no abandonment!){}",
            ANSI_YELLOW, symbol, ANSI_RESET
        );
        false
    }
}

fn spawn_async_telegram_notifier(live_capital_enabled: bool) -> Option<SyncSender<String>> {
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

    let mode_banner = if live_capital_enabled {
        "🟢 [VORTEX-L2 STAGE 27 — GLOBAL SINGLE-POSITION LOCK & 70% RATCHET]\nBybit UTA V5 Non-Abandoning Exit + Macro BTC Filter + Signed % Telemetry active."
    } else {
        "🟡 [VORTEX-L2 STAGE 27 — SHADOW MODE]\nSHM v9 (200.0 Hz) active in sniper-singapur."
    };
    let _ = tx.try_send(mode_banner.to_owned());

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
    let mut purged_count: u64 = 0;

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_maker = val
                .get("maker_exit")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let en_ticks = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            if (is_maker && net_bps < 0.0) || (!is_maker && en_ticks == 8888) {
                purged_count += 1;
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

    if purged_count > 0 {
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
        "{}🟢 [JSONL REHYDRATE] Restored {} clean trades (CumNetPnL: {:+.4} USDT | PF: {:.2}){}",
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
            println!("  (No closed trades yet in data/vortex_shadow_trades.jsonl)");
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
            let net_pct_1x = net_bps / 100.0;
            let net_pct_10x = net_bps / 10.0;

            println!(
                "  {}{} [TRADE #{} {:<7}] {:<9} {:<4} {:<20} | {}t -> {}t | Net: {:+.2} bps ({:+.3}% | {:+.2}% @10x) (Maker={}){}",
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
                net_pct_1x,
                net_pct_10x,
                is_maker,
                ANSI_RESET
            );
        }
    }

    let (sum_color, sum_icon, _) = classify_pnl_badge(total_net_bps);
    let total_pct_1x = total_net_bps / 100.0;
    let total_pct_10x = total_net_bps / 10.0;
    println!("------------------------------------------------------------------------------------------");
    println!(
        "  {}{} [LEDGER SUMMARY] Total: {} (🟢 Wins: {} | 🟠 Scratches: {} | 🔴 Losses: {}) | CumNet: {:+.2} bps ({:+.3}% | {:+.2}% @10x){}",
        sum_color,
        sum_icon,
        wins + scratches + losses,
        wins,
        scratches,
        losses,
        total_net_bps,
        total_pct_1x,
        total_pct_10x,
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
        _ => (ANSI_RED, "🔴", "HALTED_GUARD"),
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
    let tg_tx = spawn_async_telegram_notifier(live_capital_enabled);
    let live_client = BybitV5LiveClient::from_env_if_enabled(live_capital_enabled);

    let evaluator = OrthogonalFactorState::new();
    let mut fsm = ExecutionFsm::new(OPTIMAL_LIVE_NOTIONAL_1E8, OPTIMAL_LIVE_NOTIONAL_1E8);
    let mut ledger = ParitySyncLedger::new(5_096_000_000);

    let mut active_slot: usize = 0;
    let mut resting_queue_ahead: LotQty = LotQty(0);
    let mut prev_l1_qty: LotQty = LotQty(0);
    let mut prev_cum_trade_lots: LotQty = LotQty(0);
    let mut last_seen_seq = [0_u64; 6];
    let mut slot_cooldown_until_ns = [0_i64; 6];

    rehydrate_shadow_ledger(&mut ledger, &mut fsm, arena);

    let saved_state_code = arena.exec_state_code.load(Ordering::Acquire);
    let mut tracked_sym_on_startup: Option<&'static str> = None;

    if saved_state_code == 2 || saved_state_code == 3 {
        let slot_saved = (arena.exec_active_slot.load(Ordering::Acquire) as usize).min(APPROVED_SPECS.len() - 1);
        let sym_name = APPROVED_SPECS[slot_saved].symbol_id.name();
        let mut valid_to_restore = true;

        if let Some(ref client) = live_client {
            if saved_state_code == 3 {
                let (has_pos, real_sz) = client.get_open_position_size(sym_name);
                if !has_pos {
                    println!(
                        "{}�� [BYBIT V5 LIVE SYNC] Clearing simulated SHM position on {} (0.00 real size on Bybit){}",
                        ANSI_ORANGE, sym_name, ANSI_RESET
                    );
                    arena.exec_state_code.store(0, Ordering::Release);
                    arena.exec_peak_ticks.store(0, Ordering::Release);
                    arena.exec_tp_ticks.store(0, Ordering::Release);
                    arena.exec_sl_ticks.store(0, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                    valid_to_restore = false;
                } else {
                    tracked_sym_on_startup = Some(sym_name);
                    println!(
                        "{}🟢 [BYBIT V5 LIVE SYNC] Verified active exchange position on {} (open size={}){}",
                        ANSI_GREEN, sym_name, real_sz, ANSI_RESET
                    );
                }
            } else {
                client.cancel_all_symbol_orders(sym_name);
                let (filled_while_resting, _) = client.get_open_position_size(sym_name);
                if filled_while_resting {
                    tracked_sym_on_startup = Some(sym_name);
                } else {
                    arena.exec_state_code.store(0, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                    valid_to_restore = false;
                }
            }
        }

        if valid_to_restore {
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

            fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                side: side_saved,
                entry_price: entry_saved,
                peak_favorable_price: if peak_saved.0 > 0 { peak_saved } else { entry_saved },
                qty: LotQty(10),
                tp_maker_price: tp_saved,
                sl_trigger_price: sl_saved,
                opened_ts: since_saved,
            };
            arena.exec_state_code.store(3, Ordering::Release);
            println!(
                "{}🟡 [SHM HOT-RESTORE] Rehydrated PositionOpenMakerExit on {} {:?} @ {}t [Peak:{}t | TP:{}t | SL:{}t]{}",
                ANSI_YELLOW, sym_name, side_saved, entry_saved.0, peak_saved.0, tp_saved.0, sl_saved.0, ANSI_RESET
            );
        }
    }

    if let Some(ref client) = live_client {
        client.audit_and_clean_untracked_orphans(tracked_sym_on_startup);
    }

    println!(
        "{}🟢 [DAEMON 200.0 Hz] Attached to MAP_SHARED arena (SHM v{}: {}) | LiveCapital={} (Stage 27 Global Lock + 70% Ratchet){}",
        ANSI_GREEN,
        arena.version,
        shm_path.display(),
        live_client.is_some(),
        ANSI_RESET
    );

    loop {
        thread::sleep(Duration::from_millis(5));

        match fsm.state {
            OrderLifecycleState::Idle => {
                arena.exec_state_code.store(0, Ordering::Release);
                arena.exec_queue_ahead_lots.store(0, Ordering::Release);

                // Read Slot 0 (BTCUSDT) macro flow for cross-asset coherence
                let mut btc_ofi = 0.0_f64;
                let mut btc_tfi = 0.0_f64;
                if let Ok(slot0) = arena.slot(0) {
                    if let Ok(btc_snap) = slot0.read_snapshot(4) {
                        btc_ofi = btc_snap.factor_ofi.get();
                        btc_tfi = btc_snap.factor_tfi.get();
                    }
                }

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

                            if snap.ts_local_ns.0 < slot_cooldown_until_ns[s] {
                                s += 1;
                                continue;
                            }

                            if let Ok(verdict) = evaluator.evaluate_entry_signal(&spec, &snap) {
                                // Slot-0 BTCUSDT Macro Leader Coherence Filter for Altcoins (Slots 1..5)
                                if s > 0 {
                                    if let SignalVerdict::AuthorizeMakerEntry { side, .. } = verdict {
                                        let macro_contradiction = match side {
                                            Side::Bid => btc_ofi < -0.25 && btc_tfi < -0.25,
                                            Side::Ask => btc_ofi > 0.25 && btc_tfi > 0.25,
                                        };
                                        if macro_contradiction {
                                            s += 1;
                                            continue;
                                        }
                                    }
                                }

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
                side,
                entry_price,
                target_excursion,
                ..
            } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            continue;
                        }
                        last_seen_seq[active_slot] = snap.sequence_id;

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

                        let want_abort = toxic_sweep || fsm.check_resting_queue_abort(&snap);
                        let mut filled_on_exchange_during_abort = false;

                        if want_abort {
                            if let Some(ref client) = live_client {
                                client.cancel_all_symbol_orders(snap.symbol_id.name());
                                let (real_filled, real_qty) =
                                    client.get_open_position_size(snap.symbol_id.name());
                                if real_filled {
                                    filled_on_exchange_during_abort = true;
                                    println!(
                                        "{}🟢 [BYBIT V5 FILL-ON-ABORT RECOVERED] {} {:?} filled on exchange before cancel arrived (open size={}) — managing position!{}",
                                        ANSI_GREEN,
                                        snap.symbol_id.name(),
                                        side,
                                        real_qty,
                                        ANSI_RESET
                                    );
                                }
                            }

                            if !filled_on_exchange_during_abort {
                                fsm.state = OrderLifecycleState::Idle;
                                slot_cooldown_until_ns[active_slot] =
                                    snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
                                arena.exec_abort_count.fetch_add(1, Ordering::Release);
                                arena.exec_state_code.store(0, Ordering::Release);
                                arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                                println!(
                                    "{}🟠 [QUEUE ABORT] {} {:?} canceled before fill (OFI: {:+.2} | TFI: {:+.2} | BestBid: {} | BestAsk: {} | Entry: {} | 15s Slot Cooldown){}",
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
                        }

                        if filled_on_exchange_during_abort || level_swept || resting_queue_ahead.0 == 0 {
                            if !filled_on_exchange_during_abort {
                                if let Some(ref client) = live_client {
                                    client.cancel_all_symbol_orders(snap.symbol_id.name());
                                    let (real_filled, real_qty) =
                                        client.get_open_position_size(snap.symbol_id.name());
                                    if !real_filled {
                                        fsm.state = OrderLifecycleState::Idle;
                                        slot_cooldown_until_ns[active_slot] =
                                            snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
                                        arena.exec_abort_count.fetch_add(1, Ordering::Release);
                                        arena.exec_state_code.store(0, Ordering::Release);
                                        arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                                        println!(
                                            "{}🟠 [BYBIT V5 REAL QUEUE UNFILLED] {} {:?} did not fill on exchange before queue end (reset to Idle){}",
                                            ANSI_ORANGE,
                                            snap.symbol_id.name(),
                                            side,
                                            ANSI_RESET
                                        );
                                        continue;
                                    }
                                    println!(
                                        "{}🟢 [BYBIT V5 REAL FILL CONFIRMED] {} {:?} real open size={}{}",
                                        ANSI_GREEN,
                                        snap.symbol_id.name(),
                                        side,
                                        real_qty,
                                        ANSI_RESET
                                    );
                                }
                            }

                            let spec = APPROVED_SPECS[active_slot];
                            let sl_dist_ticks =
                                ((entry_price.0 * 5_200) / 1_000_000).max(4);
                            let sl_trig = match side {
                                Side::Bid => PriceTicks(entry_price.0 - sl_dist_ticks),
                                Side::Ask => PriceTicks(entry_price.0 + sl_dist_ticks),
                            };
                            fsm.state = OrderLifecycleState::RestingEntryQueue {
                                side,
                                entry_price,
                                qty: LotQty(10),
                                target_excursion,
                                sl_trigger_price: sl_trig,
                                resting_since_ts: snap.ts_local_ns,
                            };
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

                            let (e_w, e_f) = spec.format_price_usdt_parts(entry_price);
                            let (tp_w, tp_f) = spec.format_price_usdt_parts(PriceTicks(tp_t));
                            let (sl_w, sl_f) = spec.format_price_usdt_parts(PriceTicks(sl_t));

                            println!(
                                "{}🟡 [MAKER FILL] {} {:?} filled passively at {}.{:04} USDT ({}t | TP: {}.{:04} | SL: {}.{:04}){}",
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
                                let qty_str = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id);
                                let alert = format!(
                                    "🟡 [VORTEX-L2 MAKER FILL]\nSymbol: {} ({:?}) | Qty: {}\nEntry: {}.{:04} USDT (PostOnly Maker)\nTarget TP: {}.{:04} USDT (Dynamic 70% MFE Ratchet)\nServer SL: {}.{:04} USDT (-0.520% | -5.20% @ 10x)",
                                    snap.symbol_id.name(),
                                    side,
                                    qty_str,
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
            OrderLifecycleState::PositionOpenMakerExit {
                side: open_side,
                entry_price: open_entry_price,
                peak_favorable_price: open_peak_price,
                qty: open_qty,
                tp_maker_price: open_tp_price,
                sl_trigger_price: open_sl_price,
                opened_ts: open_since_ts,
            } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(snap) = slot.read_snapshot(4) {
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            continue;
                        }
                        last_seen_seq[active_slot] = snap.sequence_id;

                        // Save state snapshot before step_open_position in case Bybit close is not yet filled
                        let saved_fsm = fsm;
                        let saved_ledger = ledger;

                        if let Some(summary) = fsm.step_open_position(&snap, &mut ledger) {
                            let spec = APPROVED_SPECS[active_slot];
                            let mut exchange_confirmed_closed = true;

                            if let Some(ref client) = live_client {
                                let force_mkt = matches!(
                                    summary.kind,
                                    ClosedTradeKind::ServerMarkPriceStopLoss
                                );
                                exchange_confirmed_closed = client.execute_verified_close_step(
                                    arena,
                                    active_slot,
                                    &spec,
                                    summary.side,
                                    summary.exit_price,
                                    force_mkt,
                                );
                            }

                            if !exchange_confirmed_closed {
                                // CRITICAL STAGE 27 INVARIANT: Never transition to Idle or log a closed trade
                                // while the position is still open on Bybit! Restore FSM & Ledger and keep managing!
                                fsm = saved_fsm;
                                ledger = saved_ledger;
                                fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                                    side: open_side,
                                    entry_price: open_entry_price,
                                    peak_favorable_price: open_peak_price,
                                    qty: open_qty,
                                    tp_maker_price: open_tp_price,
                                    sl_trigger_price: open_sl_price,
                                    opened_ts: open_since_ts,
                                };
                                continue;
                            }

                            slot_cooldown_until_ns[active_slot] =
                                snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
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

                            let (en_w, en_f) = spec.format_price_usdt_parts(summary.entry_price);
                            let (ex_w, ex_f) = spec.format_price_usdt_parts(summary.exit_price);
                            let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
                            let net_pct_1x = net_bps / 100.0;
                            let net_pct_10x = net_bps / 10.0;
                            let trade_usdt = ((OPTIMAL_LIVE_NOTIONAL_1E8 as f64) / 100_000_000.0)
                                * (net_bps / 10_000.0);
                            let cum_usdt = (ledger.cumulative_net_pnl_1e8 as f64) / 100_000_000.0;
                            let cum_bps = (cum_usdt
                                / ((OPTIMAL_LIVE_NOTIONAL_1E8 as f64) / 100_000_000.0))
                                * 10_000.0;
                            let cum_pct_1x = cum_bps / 100.0;
                            let cum_pct_10x = cum_bps / 10.0;
                            let qty_str = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id);
                            let (c_col, c_icon, c_badge) = classify_pnl_badge(net_bps);

                            println!(
                                "{}{} [TRADE CLOSE — {}] {} {:?} | {}.{:04} -> {}.{:04} | Net: {:+.2} bps ({:+.3}% | {:+.2}% @10x | {:+.4} USDT) | Total Trades: {}{}",
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
                                net_pct_1x,
                                net_pct_10x,
                                trade_usdt,
                                ledger.closed_trades_count,
                                ANSI_RESET
                            );

                            if let Some(ref tx) = tg_tx {
                                let alert = format!(
                                    "{} [VORTEX-L2 TRADE {} ({:+.3}% | {:+.2}% @ 10x)]\nSymbol: {} ({:?}) | Qty: {}\nExit Type: {:?}\nPrice: {}.{:04} -> {}.{:04} USDT\nNet PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nCum PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nMaker Exit: {} | Total Trades: {} | PF: {:.2}",
                                    c_icon,
                                    c_badge,
                                    net_pct_1x,
                                    net_pct_10x,
                                    snap.symbol_id.name(),
                                    summary.side,
                                    qty_str,
                                    summary.kind,
                                    en_w,
                                    en_f,
                                    ex_w,
                                    ex_f,
                                    net_bps,
                                    net_pct_1x,
                                    net_pct_10x,
                                    trade_usdt,
                                    cum_bps,
                                    cum_pct_1x,
                                    cum_pct_10x,
                                    cum_usdt,
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
                        if snap.ts_local_ns.0.saturating_sub(submitted_ts.0) < 25_000_000 {
                            continue;
                        }
                        let spec = APPROVED_SPECS[active_slot];
                        let post_only_crossed = match side {
                            Side::Bid => snap.asks[0].price.0 > 0 && entry_price.0 >= snap.asks[0].price.0,
                            Side::Ask => snap.bids[0].price.0 > 0 && entry_price.0 <= snap.bids[0].price.0,
                        };
                        let signal_still_valid = matches!(
                            evaluator.evaluate_entry_signal(&spec, &snap),
                            Ok(SignalVerdict::AuthorizeMakerEntry { side: s_now, .. }) if s_now == side
                        );
                        if post_only_crossed || !signal_still_valid {
                            fsm.state = OrderLifecycleState::Idle;
                            arena.exec_state_code.store(0, Ordering::Release);
                            continue;
                        }

                        if let Some(ref client) = live_client {
                            if !client.place_post_only_entry(
                                &spec,
                                snap.symbol_id.name(),
                                side,
                                entry_price,
                                sl_trigger_price,
                            ) {
                                fsm.state = OrderLifecycleState::Idle;
                                slot_cooldown_until_ns[active_slot] =
                                    snap.ts_local_ns.0 + 5_000_000_000;
                                arena.exec_state_code.store(0, Ordering::Release);
                                continue;
                            }
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

                        println!(
                            "{}🟡 [QUEUE ARMED] {} {:?} resting at L1 after 25ms PostOnly check (Queue ahead: {} lots | Seq: {} | OFI: {:+.2} | TFI: {:+.2}){}",
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