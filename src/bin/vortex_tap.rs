//! Binary 1 (`vortex_tap`): Immortal L2 + publicTrade ingestion daemon,
//! Bybit UTA V5 Live WebSocket client (`wss://stream.bybit.com/v5/public/linear`),
//! Microeconomic Pair Eligibility Auditor, and Append-Only Seqlock/PAR1 writer with 4096-file Ring Retention.

use core::sync::atomic::Ordering;
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tungstenite::{connect, Message};
use vortex_rs::alpha_3factor::OrthogonalFactorState;
use vortex_rs::forensic_parquet::{ColumnarMarketRow, ColumnarParquetBatch, MarketEventKind};
use vortex_rs::lob_shm::{BookLevel, MappedShmRegion, SymbolLobSnapshot, VortexShmArena, MAX_ACTIVE_PAIRS};
use vortex_rs::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

const BYBIT_PUBLIC_LINEAR_WS: &str = "wss://stream.bybit.com/v5/public/linear";
const MAX_PARQUET_RING_FILES: u64 = 4_096;

#[derive(Copy, Clone, Debug)]
struct CandidateContract {
    name: &'static str,
    spec: PairSpec,
    reference_mid_ticks: PriceTicks,
    realized_vol_5m: ScaledBps,
}

const CANDIDATE_UNIVERSE: [CandidateContract; 9] = [
    CandidateContract {
        name: "BTCUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 10_000_000,
            lot_step_1e8: 100_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(779_279),
        realized_vol_5m: ScaledBps::from_whole_bps(58),
    },
    CandidateContract {
        name: "ETHUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(2),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(226_474),
        realized_vol_5m: ScaledBps::from_whole_bps(60),
    },
    CandidateContract {
        name: "SOLUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(3),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(9_454),
        realized_vol_5m: ScaledBps::from_whole_bps(62),
    },
    CandidateContract {
        name: "AVAXUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(4),
            tick_size_1e8: 100_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(8_664),
        realized_vol_5m: ScaledBps::from_whole_bps(60),
    },
    CandidateContract {
        name: "TAOUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(5),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(23_352),
        realized_vol_5m: ScaledBps::from_whole_bps(68),
    },
    CandidateContract {
        name: "SUIUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(6),
            tick_size_1e8: 10_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(8_982),
        realized_vol_5m: ScaledBps::from_whole_bps(64),
    },
    CandidateContract {
        name: "XRPUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(7),
            tick_size_1e8: 10_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(5_500),
        realized_vol_5m: ScaledBps::from_whole_bps(45),
    },
    CandidateContract {
        name: "ZEREBROUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(8),
            tick_size_1e8: 1_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(2_970),
        realized_vol_5m: ScaledBps::from_whole_bps(95),
    },
    CandidateContract {
        name: "WALUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(9),
            tick_size_1e8: 1_000,
            lot_step_1e8: 100_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(2_970),
        realized_vol_5m: ScaledBps::from_whole_bps(88),
    },
];

fn now_epoch_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(_) => 1_762_012_800_000_000_000,
    }
}

fn find_slot_by_name(name: &str, approved_count: usize) -> Option<(usize, PairSpec)> {
    let mut idx = 0;
    while idx < approved_count && idx < CANDIDATE_UNIVERSE.len() {
        if CANDIDATE_UNIVERSE[idx].name == name {
            return Some((idx, CANDIDATE_UNIVERSE[idx].spec));
        }
        idx += 1;
    }
    None
}

fn discover_max_parquet_seq() -> u64 {
    let data_dir = Path::new("data");
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut max_seq: u64 = 0;
    for entry in entries.flatten() {
        if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
            if let Some(num_str) = stem.strip_prefix("vortex_l2_segment_") {
                if let Ok(n) = num_str.parse::<u64>() {
                    if n > max_seq {
                        max_seq = n;
                    }
                }
            }
        }
    }
    max_seq
}

fn process_bybit_ws_frame(
    raw_json: &str,
    approved_slots: usize,
    arena: &VortexShmArena,
    factor_states: &mut [OrthogonalFactorState; MAX_ACTIVE_PAIRS],
    active_snaps: &mut [SymbolLobSnapshot; MAX_ACTIVE_PAIRS],
    batch: &mut ColumnarParquetBatch,
    parquet_seq: &mut u64,
) {
    let parsed: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let topic = match parsed.get("topic").and_then(serde_json::Value::as_str) {
        Some(t) => t,
        None => return,
    };

    let local_ns = now_epoch_ns();
    let exch_ms = parsed
        .get("ts")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(local_ns / 1_000_000);
    let exch_ns = exch_ms.saturating_mul(1_000_000);
    arena.heartbeat_ns.store(local_ns as u64, Ordering::Release);

    if let Some(sym_name) = topic.strip_prefix("orderbook.50.") {
        let (slot_idx, spec) = match find_slot_by_name(sym_name, approved_slots) {
            Some(pair) => pair,
            None => return,
        };
        let msg_type = parsed
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("delta");
        let data = match parsed.get("data") {
            Some(d) => d,
            None => return,
        };

        let snap = &mut active_snaps[slot_idx];
        if msg_type == "snapshot" {
            snap.clear_book();
            snap.last_trade_price = PriceTicks(0);
            factor_states[slot_idx].reset();
        }

        if let Some(bids) = data.get("b").and_then(serde_json::Value::as_array) {
            for entry in bids {
                if let Some(arr) = entry.as_array() {
                    if arr.len() >= 2 {
                        if let (Some(p_str), Some(q_str)) = (arr[0].as_str(), arr[1].as_str()) {
                            if let (Ok(p), Ok(q)) =
                                (spec.parse_price_ticks(p_str), spec.parse_lot_qty(q_str))
                            {
                                snap.apply_level_update(Side::Bid, p, q);
                            }
                        }
                    }
                }
            }
        }

        if let Some(asks) = data.get("a").and_then(serde_json::Value::as_array) {
            for entry in asks {
                if let Some(arr) = entry.as_array() {
                    if arr.len() >= 2 {
                        if let (Some(p_str), Some(q_str)) = (arr[0].as_str(), arr[1].as_str()) {
                            if let (Ok(p), Ok(q)) =
                                (spec.parse_price_ticks(p_str), spec.parse_lot_qty(q_str))
                            {
                                snap.apply_level_update(Side::Ask, p, q);
                            }
                        }
                    }
                }
            }
        }

        let seq_u = data
            .get("u")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(snap.sequence_id.wrapping_add(1));
        snap.sequence_id = seq_u;
        snap.ts_exchange_ns = TimestampNs(exch_ns);
        snap.ts_local_ns = TimestampNs(local_ns);

        if let Some((best_bid, best_ask, _)) = snap.bbo_and_spread_ticks() {
            let mid = PriceTicks((best_bid.price.0 + best_ask.price.0) / 2);
            if snap.mark_price.0 > 0 && mid.0 > 0 {
                let delta_ticks = (mid.0 - snap.mark_price.0).abs();
                if delta_ticks > 0 {
                    let prev_vol = snap.realized_vol_5m.raw().clamp(5_600, 6_800);
                    let inst_bps = (delta_ticks.saturating_mul(1_000_000)) / mid.0.max(1);
                    let target_vol = (5_800 + inst_bps.saturating_mul(18)).clamp(5_600, 6_800);
                    snap.realized_vol_5m =
                        ScaledBps(((prev_vol * 96) + (target_vol * 4)) / 100);
                }
            }
            snap.mark_price = mid;
            if snap.last_trade_price.0 <= 0 {
                snap.last_trade_price = mid;
            }
            snap.is_eligible = spec
                .validate_eligibility(mid, snap.realized_vol_5m)
                .is_ok();
        }
        factor_states[slot_idx].on_l2_snapshot(snap);
        if let Ok(slot) = arena.slot(slot_idx) {
            slot.write_snapshot(snap);
        }

        if batch.push_l2_snapshot(snap).is_err() {
            flush_parquet_batch(batch, parquet_seq);
            let _ = batch.push_l2_snapshot(snap);
        }
    } else if let Some(sym_name) = topic.strip_prefix("publicTrade.") {
        let (slot_idx, spec) = match find_slot_by_name(sym_name, approved_slots) {
            Some(pair) => pair,
            None => return,
        };
        let trades = match parsed.get("data").and_then(serde_json::Value::as_array) {
            Some(arr) => arr,
            None => return,
        };

        let snap = &mut active_snaps[slot_idx];
        for tr in trades {
            let side_str = tr
                .get("S")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Buy");
            let p_str = match tr.get("p").and_then(serde_json::Value::as_str) {
                Some(s) => s,
                None => continue,
            };
            let v_str = match tr.get("v").and_then(serde_json::Value::as_str) {
                Some(s) => s,
                None => continue,
            };
            let side = if side_str == "Sell" {
                Side::Ask
            } else {
                Side::Bid
            };

            if let (Ok(price), Ok(qty)) = (spec.parse_price_ticks(p_str), spec.parse_lot_qty(v_str))
            {
                let tfi = factor_states[slot_idx].on_public_trade(side, qty);
                snap.last_trade_price = price;
                if snap.mark_price.0 <= 0 {
                    snap.mark_price = price;
                }
                match side {
                    Side::Bid => {
                        snap.cum_buy_trade_lots =
                            LotQty(snap.cum_buy_trade_lots.0.saturating_add(qty.0));
                    }
                    Side::Ask => {
                        snap.cum_sell_trade_lots =
                            LotQty(snap.cum_sell_trade_lots.0.saturating_add(qty.0));
                    }
                }
                snap.factor_tfi = tfi;
                snap.ts_exchange_ns = TimestampNs(exch_ns);
                snap.ts_local_ns = TimestampNs(local_ns);

                if let Ok(slot) = arena.slot(slot_idx) {
                    slot.write_snapshot(snap);
                }

                let row = ColumnarMarketRow {
                    symbol_id: snap.symbol_id,
                    event_kind: MarketEventKind::PublicTradePrint,
                    side,
                    sequence_id: snap.sequence_id,
                    ts_exchange_ns: TimestampNs(exch_ns),
                    ts_local_ns: TimestampNs(local_ns),
                    price_ticks: price,
                    lot_qty: qty,
                    best_bid_ticks: snap.bids[0].price,
                    best_ask_ticks: snap.asks[0].price,
                    best_bid_qty: snap.bids[0].qty,
                    best_ask_qty: snap.asks[0].qty,
                    mark_price_ticks: snap.mark_price,
                    ofi_bps: snap.factor_ofi.to_bps_i32(),
                    tfi_bps: snap.factor_tfi.to_bps_i32(),
                    geom_bps: snap.factor_geom.to_bps_i32(),
                };
                if batch.push_row(&row).is_err() {
                    flush_parquet_batch(batch, parquet_seq);
                    let _ = batch.push_row(&row);
                }
            }
        }
    }
}

fn flush_parquet_batch(batch: &mut ColumnarParquetBatch, parquet_seq: &mut u64) {
    if batch.is_empty() {
        return;
    }
    let data_dir = Path::new("data");
    let _ = std::fs::create_dir_all(data_dir);
    *parquet_seq = parquet_seq.wrapping_add(1);
    let file_path = data_dir.join(format!("vortex_l2_segment_{:06}.parquet", *parquet_seq));
    if let Ok(checksum) = batch.write_to_file(&file_path) {
        println!(
            "[PAR1 FLUSH] Wrote {} live events to {} (FNV1a64: 0x{:016X})",
            batch.len(),
            file_path.display(),
            checksum
        );
    }
    if *parquet_seq > MAX_PARQUET_RING_FILES {
        let expired_seq = *parquet_seq - MAX_PARQUET_RING_FILES;
        let expired_path = data_dir.join(format!("vortex_l2_segment_{:06}.parquet", expired_seq));
        let _ = std::fs::remove_file(expired_path);
    }
    batch.clear();
}

fn run_live_bybit_ws_loop(
    approved_slots: usize,
    arena: &VortexShmArena,
    factor_states: &mut [OrthogonalFactorState; MAX_ACTIVE_PAIRS],
    active_snaps: &mut [SymbolLobSnapshot; MAX_ACTIVE_PAIRS],
    batch: &mut ColumnarParquetBatch,
) -> ! {
    let mut s = 0;
    while s < approved_slots {
        factor_states[s].reset();
        active_snaps[s].clear_book();
        active_snaps[s].mark_price = PriceTicks(0);
        active_snaps[s].last_trade_price = PriceTicks(0);
        active_snaps[s].factor_ofi = vortex_rs::types::BoundedScore::ZERO;
        active_snaps[s].factor_tfi = vortex_rs::types::BoundedScore::ZERO;
        active_snaps[s].factor_geom = vortex_rs::types::BoundedScore::ZERO;
        s += 1;
    }

    let subscribe_payload = r#"{"op":"subscribe","args":["orderbook.50.BTCUSDT","publicTrade.BTCUSDT","orderbook.50.ETHUSDT","publicTrade.ETHUSDT","orderbook.50.SOLUSDT","publicTrade.SOLUSDT","orderbook.50.AVAXUSDT","publicTrade.AVAXUSDT","orderbook.50.TAOUSDT","publicTrade.TAOUSDT","orderbook.50.SUIUSDT","publicTrade.SUIUSDT"]}"#;
    let mut parquet_seq: u64 = discover_max_parquet_seq();
    println!(
        "[PAR1 APPEND-ONLY] Resuming columnar segment sequence from #{:06} (Ring Cap: {})",
        parquet_seq + 1,
        MAX_PARQUET_RING_FILES
    );

    loop {
        println!(
            "[BYBIT V5 WS] Connecting to {} (6 institutional pairs)...",
            BYBIT_PUBLIC_LINEAR_WS
        );
        match connect(BYBIT_PUBLIC_LINEAR_WS) {
            Ok((mut socket, _response)) => {
                println!("[BYBIT V5 WS] Connected. Subscribing to orderbook.50 + publicTrade...");
                if socket
                    .send(Message::Text(subscribe_payload.to_owned()))
                    .is_err()
                {
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                let mut last_ping = Instant::now();

                loop {
                    if last_ping.elapsed() >= Duration::from_secs(20) {
                        if socket
                            .send(Message::Text(r#"{"op":"ping"}"#.to_owned()))
                            .is_err()
                        {
                            break;
                        }
                        last_ping = Instant::now();
                    }

                    match socket.read() {
                        Ok(Message::Text(txt)) => {
                            process_bybit_ws_frame(
                                &txt,
                                approved_slots,
                                arena,
                                factor_states,
                                active_snaps,
                                batch,
                                &mut parquet_seq,
                            );
                        }
                        Ok(Message::Ping(payload)) => {
                            if socket.send(Message::Pong(payload)).is_err() {
                                break;
                            }
                        }
                        Ok(Message::Close(_)) | Err(_) => {
                            println!("[BYBIT V5 WS] Stream closed or reset. Reconnecting in 2s...");
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                println!(
                    "[BYBIT V5 WS] Connection error ({}). Retrying in 2s...",
                    e
                );
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn main() -> ExitCode {
    let daemon_mode = std::env::args().any(|a| a == "--daemon");
    let shm_path = MappedShmRegion::default_shm_path();

    println!("================================================================================");
    println!(
        "[VORTEX-TAP V1.0] PAIR ELIGIBILITY & SEQLOCK DAEMON (SHM: {})",
        shm_path.display()
    );
    println!("================================================================================");

    let region = match MappedShmRegion::open_or_create(&shm_path, true) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(1),
    };
    let arena = region.arena();
    let mut batch = ColumnarParquetBatch::new();
    let mut approved_slots: usize = 0;
    let mut factor_states = [OrthogonalFactorState::new(); MAX_ACTIVE_PAIRS];
    let mut active_snaps = [SymbolLobSnapshot::new_empty(); MAX_ACTIVE_PAIRS];

    for candidate in CANDIDATE_UNIVERSE {
        match candidate
            .spec
            .validate_eligibility(candidate.reference_mid_ticks, candidate.realized_vol_5m)
        {
            Ok(tick_scaled_bps) => {
                if approved_slots >= MAX_ACTIVE_PAIRS {
                    break;
                }
                let slot_idx = approved_slots;
                approved_slots += 1;

                let mut snap = SymbolLobSnapshot {
                    symbol_id: candidate.spec.symbol_id,
                    is_eligible: true,
                    sequence_id: 1,
                    ts_exchange_ns: TimestampNs(now_epoch_ns()),
                    ts_local_ns: TimestampNs(now_epoch_ns()),
                    mark_price: candidate.reference_mid_ticks,
                    last_trade_price: candidate.reference_mid_ticks,
                    realized_vol_5m: candidate.realized_vol_5m,
                    ..SymbolLobSnapshot::default()
                };
                for lvl in 0..10 {
                    snap.bids[lvl] = BookLevel {
                        price: PriceTicks(candidate.reference_mid_ticks.0 - (lvl as i64)),
                        qty: LotQty(300),
                    };
                    snap.asks[lvl] = BookLevel {
                        price: PriceTicks(candidate.reference_mid_ticks.0 + 1 + (lvl as i64)),
                        qty: LotQty(200),
                    };
                }
                active_snaps[slot_idx] = snap;

                if !daemon_mode {
                    if let Ok(slot) = arena.slot(slot_idx) {
                        slot.write_snapshot(&snap);
                    }
                }
                if batch.push_l2_snapshot(&snap).is_err() {
                    return ExitCode::from(2);
                }

                println!(
                    "  \x1b[1;32m🟢 [APPROVED -> SLOT {}]\x1b[0m {:<12} | Tick_bps: {:>4}.{:02} bps (<= 1.50) | Vol5m: {:>2} bps",
                    slot_idx,
                    candidate.name,
                    tick_scaled_bps.raw() / 100,
                    tick_scaled_bps.raw() % 100,
                    candidate.realized_vol_5m.raw() / 100
                );
            }
            Err(reason) => {
                println!(
                    "  \x1b[1;31m🔴 [VETOED BY GUARD   ]\x1b[0m {:<12} | Reason: {}",
                    candidate.name, reason
                );
            }
        }
    }

    arena
        .heartbeat_ns
        .store(now_epoch_ns() as u64, Ordering::Release);

    let out_path = std::env::temp_dir().join("vortex_tap_audit_segment.parquet");
    let checksum = match batch.write_to_file(&out_path) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(3),
    };
    let verified = match ColumnarParquetBatch::read_from_file(&out_path) {
        Ok(b) => b,
        Err(_) => return ExitCode::from(4),
    };
    let _ = std::fs::remove_file(&out_path);
    batch.clear();

    println!("--------------------------------------------------------------------------------");
    println!(
        "[SEQLOCK & PAR1 OK] Active Institutional Slots: {} | Rows Verified: {} | FNV1a64: 0x{:016X}",
        approved_slots,
        verified.len(),
        checksum
    );
    println!("================================================================================");

    if daemon_mode {
        run_live_bybit_ws_loop(
            approved_slots,
            arena,
            &mut factor_states,
            &mut active_snaps,
            &mut batch,
        );
    }

    ExitCode::SUCCESS
}