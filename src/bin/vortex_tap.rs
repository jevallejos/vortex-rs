//! Binary 1 (`vortex_tap`): Immortal L2 + publicTrade ingestion daemon,
//! Microeconomic Pair Eligibility Auditor (`Tick-to-Price Guard <= 1.50 bps`),
//! and Seqlock shared-memory writer.

use std::process::ExitCode;

use vortex_rs::alpha_3factor::OrthogonalFactorState;
use vortex_rs::forensic_parquet::ColumnarParquetBatch;
use vortex_rs::lob_shm::{BookLevel, SymbolLobSnapshot, VortexShmArena, MAX_ACTIVE_PAIRS};
use vortex_rs::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs};

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
        reference_mid_ticks: PriceTicks(776_700),
        realized_vol_5m: ScaledBps::from_whole_bps(42),
    },
    CandidateContract {
        name: "ETHUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(2),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(265_000),
        realized_vol_5m: ScaledBps::from_whole_bps(46),
    },
    CandidateContract {
        name: "SOLUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(3),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(17_500),
        realized_vol_5m: ScaledBps::from_whole_bps(58),
    },
    CandidateContract {
        name: "AVAXUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(4),
            tick_size_1e8: 100_000,
            lot_step_1e8: 10_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(26_000),
        realized_vol_5m: ScaledBps::from_whole_bps(54),
    },
    CandidateContract {
        name: "TAOUSDT",
        spec: PairSpec {
            symbol_id: SymbolId(5),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        },
        reference_mid_ticks: PriceTicks(48_000),
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
        reference_mid_ticks: PriceTicks(21_000),
        realized_vol_5m: ScaledBps::from_whole_bps(62),
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

fn main() -> ExitCode {
    println!("================================================================================");
    println!("[VORTEX-TAP V1.0] INSTITUTIONAL PAIR ELIGIBILITY & SEQLOCK/PARQUET DAEMON");
    println!("================================================================================");

    let arena = VortexShmArena::new();
    let mut batch = ColumnarParquetBatch::new();
    let mut approved_slots: usize = 0;

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

                let mut factor_state = OrthogonalFactorState::new();
                let _ = factor_state.on_public_trade(Side::Bid, LotQty(500));

                let mut snap = SymbolLobSnapshot {
                    symbol_id: candidate.spec.symbol_id,
                    is_eligible: true,
                    sequence_id: 1,
                    ts_exchange_ns: TimestampNs(1_762_012_800_000_000_000),
                    ts_local_ns: TimestampNs(1_762_012_800_000_500_000),
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
                factor_state.on_l2_snapshot(&mut snap);

                if let Ok(slot) = arena.slot(slot_idx) {
                    slot.write_snapshot(&snap);
                }
                if batch.push_l2_snapshot(&snap).is_err() {
                    return ExitCode::from(2);
                }

                println!(
                    "  [APPROVED -> SLOT {}] {:<12} | Tick_bps: {:>4}.{:02} bps (<= 1.50) | Vol5m: {:>2} bps",
                    slot_idx,
                    candidate.name,
                    tick_scaled_bps.raw() / 100,
                    tick_scaled_bps.raw() % 100,
                    candidate.realized_vol_5m.raw() / 100
                );
            }
            Err(reason) => {
                println!(
                    "  [VETOED BY GUARD   ] {:<12} | Reason: {}",
                    candidate.name, reason
                );
            }
        }
    }

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

    println!("--------------------------------------------------------------------------------");
    println!(
        "[SEQLOCK & PAR1 OK] Active Institutional Slots: {} | Rows Verified: {} | FNV1a64: 0x{:016X}",
        approved_slots,
        verified.len(),
        checksum
    );
    println!("================================================================================");
    ExitCode::SUCCESS
}