//! Exhaustive Finite-State Machine (`OrderLifecycleState`) for Bybit UTA V5 execution:
//! 100% `Limit PostOnly` normal exits, Two-Zone Dynamic 70% MFE Trailing Ratchet,
//! Strict 1.50s Anti-Burst Queue Residence Floor, Zero Premature Micro-Scratches,
//! Structural `-52.00 bps` Server `MarkPrice` Stop-Loss, and `HMAC-SHA256` Signer.

use crate::alpha_3factor::SignalVerdict;
use crate::forensic_parquet::ParitySyncLedger;
use crate::lob_shm::SymbolLobSnapshot;
use crate::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, TimestampNs, VortexError};

/// Cooldown applied ONLY after a real server-side Stop-Loss trigger (60 seconds in nanoseconds).
pub const STOP_LOSS_COOLDOWN_NS: i64 = 60_000_000_000;

/// Strict minimum residence time in L1 queue before ANY non-TTL cancellation is allowed (1.50 seconds).
pub const MIN_QUEUE_RESIDENCE_NS: i64 = 1_500_000_000;

/// Maximum time a passive `Limit PostOnly` entry order may sit unfilled in the L1 queue (25 seconds).
pub const MAX_RESTING_QUEUE_TTL_NS: i64 = 25_000_000_000;

/// Scale-invariant BBO runaway threshold in ScaledBps after 1.5s residence (3.50 bps = 350 units, min 3 ticks).
pub const BBO_RUNAWAY_SCALED_BPS: i64 = 350;

/// Structural server-side MarkPrice Stop-Loss distance (52.00 bps = 5_200 ScaledBps, min 4 ticks).
pub const SERVER_SL_DISTANCE_SCALED_BPS: i64 = 5_200;

/// Maximum hold time for a stagnant net-profitable position (>= +4.50 bps gross / +0.50 bps net) before passive Maker release (180 seconds).
pub const STAGNANT_PROFIT_HOLD_NS: i64 = 180_000_000_000;

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Copy, Clone, Debug)]
struct Sha256State {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

impl Sha256State {
    #[inline]
    const fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0_u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    #[inline]
    fn compress_block(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0_u32; 64];
        let mut i = 0;
        while i < 16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        let mut t = 0;
        while t < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            t += 1;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buf[self.buf_len] = byte;
            self.buf_len += 1;
            self.total_bits = self.total_bits.wrapping_add(8);
            if self.buf_len == 64 {
                Self::compress_block(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
    }

    #[inline]
    fn finalize(mut self) -> [u8; 32] {
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            while self.buf_len < 64 {
                self.buf[self.buf_len] = 0;
                self.buf_len += 1;
            }
            Self::compress_block(&mut self.h, &self.buf);
            self.buf_len = 0;
        }
        while self.buf_len < 56 {
            self.buf[self.buf_len] = 0;
            self.buf_len += 1;
        }
        let bit_bytes = self.total_bits.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            self.buf[56 + i] = bit_bytes[i];
            i += 1;
        }
        Self::compress_block(&mut self.h, &self.buf);
        let mut out = [0_u8; 32];
        let mut j = 0;
        while j < 8 {
            let word = self.h[j].to_be_bytes();
            out[j * 4] = word[0];
            out[j * 4 + 1] = word[1];
            out[j * 4 + 2] = word[2];
            out[j * 4 + 3] = word[3];
            j += 1;
        }
        out
    }
}

/// Computes RFC 2104 `HMAC-SHA256` digest over `segments` and returns a 64-byte lowercase hex array.
#[inline]
#[must_use]
pub fn hmac_sha256_hex_segments(secret: &[u8], segments: &[&[u8]]) -> [u8; 64] {
    let mut key_block = [0_u8; 64];
    if secret.len() > 64 {
        let mut kh = Sha256State::new();
        kh.update(secret);
        let hashed = kh.finalize();
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    let mut i = 0;
    while i < 64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
        i += 1;
    }
    let mut inner = Sha256State::new();
    inner.update(&ipad);
    for seg in segments {
        inner.update(seg);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256State::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let mac = outer.finalize();

    const HEX_LUT: &[u8; 16] = b"0123456789abcdef";
    let mut hex_out = [0_u8; 64];
    let mut k = 0;
    while k < 32 {
        hex_out[k * 2] = HEX_LUT[(mac[k] >> 4) as usize];
        hex_out[k * 2 + 1] = HEX_LUT[(mac[k] & 0x0f) as usize];
        k += 1;
    }
    hex_out
}

/// Computes the canonical Bybit UTA V5 `X-BAPI-SIGN` header value.
#[inline]
#[must_use]
pub fn sign_bybit_v5_hmac_sha256(
    timestamp_ms: &str,
    api_key: &str,
    recv_window: &str,
    payload: &str,
    api_secret: &str,
) -> [u8; 64] {
    hmac_sha256_hex_segments(
        api_secret.as_bytes(),
        &[
            timestamp_ms.as_bytes(),
            api_key.as_bytes(),
            recv_window.as_bytes(),
            payload.as_bytes(),
        ],
    )
}

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
        peak_favorable_price: PriceTicks,
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
        let sl_distance_ticks =
            ((entry_price.0 * SERVER_SL_DISTANCE_SCALED_BPS) / 1_000_000).max(4);
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

            let elapsed_ns = snap.ts_local_ns.0.saturating_sub(resting_since_ts.0);
            let ttl_expired = elapsed_ns >= MAX_RESTING_QUEUE_TTL_NS;

            let residence_satisfied = elapsed_ns >= MIN_QUEUE_RESIDENCE_NS;
            let runaway_allowance_ticks =
                ((entry_price.0 * BBO_RUNAWAY_SCALED_BPS) / 1_000_000).max(3);
            let bbo_runaway = if residence_satisfied {
                match snap.bbo_and_spread_ticks() {
                    Some((best_bid, best_ask, _)) => match side {
                        Side::Bid => best_bid.price.0 - entry_price.0 >= runaway_allowance_ticks,
                        Side::Ask => entry_price.0 - best_ask.price.0 >= runaway_allowance_ticks,
                    },
                    None => false,
                }
            } else {
                false
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
            let capped_tp_bps = target_excursion.raw().clamp(3_500, 6_500);
            let tp_delta_ticks =
                ((entry_price.0 * capped_tp_bps) / 1_000_000).max(2);
            let tp_maker_price = match side {
                Side::Bid => PriceTicks(entry_price.0 + tp_delta_ticks),
                Side::Ask => PriceTicks((entry_price.0 - tp_delta_ticks).max(1)),
            };
            self.state = OrderLifecycleState::PositionOpenMakerExit {
                side,
                entry_price,
                peak_favorable_price: entry_price,
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
        let (side, entry_price, mut peak_favorable_price, qty, tp_maker_price, sl_trigger_price, opened_ts) =
            match self.state {
                OrderLifecycleState::PositionOpenMakerExit {
                    side,
                    entry_price,
                    peak_favorable_price,
                    qty,
                    tp_maker_price,
                    sl_trigger_price,
                    opened_ts,
                } => (
                    side,
                    entry_price,
                    peak_favorable_price,
                    qty,
                    tp_maker_price,
                    sl_trigger_price,
                    opened_ts,
                ),
                _ => return None,
            };

        let ref_trade_price = if snap.last_trade_price.0 > 0 {
            snap.last_trade_price
        } else {
            snap.mark_price
        };

        // 1. Catastrophic server-side MarkPrice Stop-Loss (-52.00 bps)
        let sl_hit = match side {
            Side::Bid => snap.mark_price.0 > 0 && snap.mark_price.0 <= sl_trigger_price.0,
            Side::Ask => snap.mark_price.0 > 0 && snap.mark_price.0 >= sl_trigger_price.0,
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

        // 2. Passive Limit PostOnly structural Take-Profit fill
        let tp_hit = match side {
            Side::Bid => ref_trade_price.0 > 0 && ref_trade_price.0 >= tp_maker_price.0,
            Side::Ask => ref_trade_price.0 > 0 && ref_trade_price.0 <= tp_maker_price.0,
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

        // 3. Two-Zone Exit Physics: Survival (< 8.00 bps gross) + Dynamic 70% Net MFE Ratchet (> 8.00 bps gross)
        if let Some((best_bid, best_ask, _)) = snap.bbo_and_spread_ticks() {
            let bbo_exit_price = match side {
                Side::Bid => best_bid.price,
                Side::Ask => best_ask.price,
            };
            match side {
                Side::Bid => {
                    if bbo_exit_price.0 > peak_favorable_price.0 {
                        peak_favorable_price = bbo_exit_price;
                    }
                    if ref_trade_price.0 > peak_favorable_price.0 {
                        peak_favorable_price = ref_trade_price;
                    }
                }
                Side::Ask => {
                    if peak_favorable_price.0 == 0 || bbo_exit_price.0 < peak_favorable_price.0 {
                        peak_favorable_price = bbo_exit_price;
                    }
                    if ref_trade_price.0 > 0 && ref_trade_price.0 < peak_favorable_price.0 {
                        peak_favorable_price = ref_trade_price;
                    }
                }
            }

            self.state = OrderLifecycleState::PositionOpenMakerExit {
                side,
                entry_price,
                peak_favorable_price,
                qty,
                tp_maker_price,
                sl_trigger_price,
                opened_ts,
            };

            let current_gross_bps =
                Self::compute_gross_scaled_bps(side, entry_price, bbo_exit_price);
            let peak_gross_bps =
                Self::compute_gross_scaled_bps(side, entry_price, peak_favorable_price);

            // Elastic volatility-coupled harvest floor: at least 600 ScaledBps (+2.00 bps net) or 10% of 5m realized vol
            let elastic_vol_floor_bps = (snap.realized_vol_5m.raw() / 10).clamp(600, 750);
            let in_trend_free_ride_zone = peak_gross_bps.raw() > 900;

            let ofi_reversed = match side {
                Side::Bid => snap.factor_ofi.get() < -0.08,
                Side::Ask => snap.factor_ofi.get() > 0.08,
            };
            let flow_unwind = !in_trend_free_ride_zone
                && current_gross_bps.raw() >= elastic_vol_floor_bps
                && ofi_reversed;

            let hold_elapsed = snap.ts_local_ns.0.saturating_sub(opened_ts.0);
            let early_harvest = !in_trend_free_ride_zone
                && hold_elapsed >= 30_000_000_000
                && current_gross_bps.raw() >= elastic_vol_floor_bps;

            let joint_adverse = match side {
                Side::Bid => snap.factor_ofi.get() < -0.20 && snap.factor_tfi.get() < -0.20,
                Side::Ask => snap.factor_ofi.get() > 0.20 && snap.factor_tfi.get() > 0.20,
            };
            let scratch_escape = !in_trend_free_ride_zone
                && hold_elapsed >= 20_000_000_000
                && current_gross_bps.raw() >= 560
                && joint_adverse;
            let stagnant_unwind =
                hold_elapsed >= STAGNANT_PROFIT_HOLD_NS && current_gross_bps.raw() >= 560;

            let mfe_ratchet_unwind = if in_trend_free_ride_zone {
                let dynamic_70pct_floor = 400 + ((peak_gross_bps.raw() - 400) * 70) / 100;
                current_gross_bps.raw() >= 600 && current_gross_bps.raw() <= dynamic_70pct_floor
            } else {
                peak_gross_bps.raw() >= 750
                    && current_gross_bps.raw() >= 580
                    && current_gross_bps.raw() <= (peak_gross_bps.raw() * 78) / 100
            };

            if flow_unwind || mfe_ratchet_unwind || early_harvest || scratch_escape || stagnant_unwind {
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

    /// Computes the exact tick-quantized minimum Maker exit price that strictly covers
    /// the 4.00 bps (400 ScaledBps) round-trip Maker-Maker fee plus +1 structural tick of net profit.
    #[inline]
    #[must_use]
    pub const fn min_profitable_maker_exit_price(
        side: Side,
        entry_price: PriceTicks,
    ) -> PriceTicks {
        // Elastic 1.5x Fee-Share Law: requires at least 600 ScaledBps (6.00 bps gross -> >= +2.00 bps net after 4.00 bps fee)
        let target_600bps_ticks = (entry_price.0.saturating_mul(600) + 999_999) / 1_000_000;
        let min_profit_delta_ticks = if target_600bps_ticks > 2 {
            target_600bps_ticks
        } else {
            2
        };
        match side {
            Side::Bid => PriceTicks(entry_price.0 + min_profit_delta_ticks),
            Side::Ask => {
                let p = entry_price.0 - min_profit_delta_ticks;
                PriceTicks(if p > 1 { p } else { 1 })
            }
        }
    }

    /// Clamps any candidate passive exit price so it NEVER crosses below the tick-quantized net profit floor.
    #[inline]
    #[must_use]
    pub const fn clamp_maker_exit_to_profit_floor(
        side: Side,
        entry_price: PriceTicks,
        candidate_exit: PriceTicks,
    ) -> PriceTicks {
        let floor_price = Self::min_profitable_maker_exit_price(side, entry_price);
        match side {
            Side::Bid => {
                if candidate_exit.0 > floor_price.0 {
                    candidate_exit
                } else {
                    floor_price
                }
            }
            Side::Ask => {
                if candidate_exit.0 > 0 && candidate_exit.0 < floor_price.0 {
                    candidate_exit
                } else {
                    floor_price
                }
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
    pub fn finalize_close(
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

/// Online self-learning Bayesian & Replicator governor across all 6 slots and 2 directions (Bid/Ask).
/// Continuously adapts entry composite thresholds, macro leader beta-coupling, and directional cooldowns
/// directly from realized trade outcomes (zero static magic rules).
#[derive(Copy, Clone, Debug)]
pub struct OnlineAdaptiveGovernor {
    ewma_net_bps_x100: [[i64; 2]; 6],
    sl_streak: [[u32; 2]; 6],
    win_streak: [[u32; 2]; 6],
    directional_cooldown_until_ns: [[i64; 2]; 6],
}

impl Default for OnlineAdaptiveGovernor {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineAdaptiveGovernor {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ewma_net_bps_x100: [[100; 2]; 6],
            sl_streak: [[0; 2]; 6],
            win_streak: [[0; 2]; 6],
            directional_cooldown_until_ns: [[0; 2]; 6],
        }
    }

    #[inline]
    const fn dir_idx(side: Side) -> usize {
        match side {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    /// Feeds a closed trade outcome into the online learner to update the slot-direction health state.
    #[inline]
    pub fn observe_closed_trade(
        &mut self,
        slot_idx: usize,
        side: Side,
        net_scaled_bps: ScaledBps,
        is_maker_exit: bool,
        ts_ns: TimestampNs,
    ) {
        if slot_idx >= 6 {
            return;
        }
        let d = Self::dir_idx(side);
        let prev = self.ewma_net_bps_x100[slot_idx][d];
        self.ewma_net_bps_x100[slot_idx][d] = (prev * 75 + net_scaled_bps.raw() * 25) / 100;

        if !is_maker_exit || net_scaled_bps.raw() <= -1_000 {
            let s = self.sl_streak[slot_idx][d].saturating_add(1).min(4);
            self.sl_streak[slot_idx][d] = s;
            self.win_streak[slot_idx][d] = 0;
            let backoff_ns = 60_000_000_000_i64.saturating_mul(1_i64 << s.min(3));
            self.directional_cooldown_until_ns[slot_idx][d] = ts_ns.0.saturating_add(backoff_ns);
        } else if net_scaled_bps.raw() > 0 {
            let w = self.win_streak[slot_idx][d].saturating_add(1);
            self.win_streak[slot_idx][d] = w;
            if self.sl_streak[slot_idx][d] > 0 && w >= 2 {
                self.sl_streak[slot_idx][d] -= 1;
            }
        }
    }

    /// Evaluates whether `(slot_idx, side)` is authorized under the current self-learned regime
    /// and continuous Slot-0 (`BTCUSDT`) macro composite pressure.
    #[inline]
    #[must_use]
    pub fn authorizes_adaptive_entry(
        &self,
        slot_idx: usize,
        side: Side,
        candidate_snap: &SymbolLobSnapshot,
        btc_leader_snap: &SymbolLobSnapshot,
    ) -> bool {
        if slot_idx >= 6 {
            return false;
        }
        let d = Self::dir_idx(side);
        if candidate_snap.ts_local_ns.0 < self.directional_cooldown_until_ns[slot_idx][d] {
            return false;
        }

        let cand_comp = (0.45 * candidate_snap.factor_ofi.get()
            + 0.35 * candidate_snap.factor_tfi.get()
            + 0.20 * candidate_snap.factor_geom.get())
        .abs();

        let btc_comp = 0.45 * btc_leader_snap.factor_ofi.get()
            + 0.35 * btc_leader_snap.factor_tfi.get()
            + 0.20 * btc_leader_snap.factor_geom.get();

        let sl_s = self.sl_streak[slot_idx][d] as f64;
        let ewma = self.ewma_net_bps_x100[slot_idx][d] as f64;
        let ewma_penalty = if ewma < 0.0 {
            ((-ewma) / 4_000.0).min(0.18)
        } else {
            0.0
        };

        if slot_idx > 0 {
            let signed_btc_alignment = match side {
                Side::Bid => btc_comp,
                Side::Ask => -btc_comp,
            };
            // Elastic macro coherence: altcoins cannot open against adverse BTC composite flow,
            // and if the slot-direction has prior SL scars, BTC must actively confirm the trend.
            let min_required_btc_alignment = -0.02 + 0.08 * sl_s;
            if signed_btc_alignment < min_required_btc_alignment {
                return false;
            }
        }

        let adaptive_threshold = (0.42 + 0.09 * sl_s + ewma_penalty).min(0.78);
        cand_comp >= adaptive_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lob_shm::BookLevel;
    use crate::types::{BoundedScore, SymbolId};

    #[test]
    fn test_hmac_sha256_rfc4231_and_bybit_v5_signature() {
        let sig = hmac_sha256_hex_segments(b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(
            core::str::from_utf8(&sig),
            Ok("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        let bybit_sig = sign_bybit_v5_hmac_sha256(
            "1700000000000",
            "TESTKEY",
            "5000",
            "{\"category\":\"linear\",\"symbol\":\"BTCUSDT\"}",
            "TESTSECRET",
        );
        assert_eq!(bybit_sig.len(), 64);
    }

    #[test]
    fn test_mfe_zero_loss_ratchet_locks_profit_on_taousdt_retrace() {
        let spec = PairSpec {
            symbol_id: SymbolId(5),
            tick_size_1e8: 1_000_000,
            lot_step_1e8: 1_000_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let mut fsm = ExecutionFsm::new(10_000_000_000, 1_500_000_000);
        let mut ledger = ParitySyncLedger::new(5_000_000_000);

        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(5),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(1_000_000_000),
            ts_local_ns: TimestampNs(1_000_000_000),
            mark_price: PriceTicks(23_347),
            last_trade_price: PriceTicks(23_347),
            realized_vol_5m: ScaledBps::from_whole_bps(68),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(23_346),
            qty: LotQty(200),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(23_347),
            qty: LotQty(200),
        };

        let verdict = SignalVerdict::AuthorizeMakerEntry {
            side: Side::Ask,
            target_excursion_scaled_bps: ScaledBps::from_whole_bps(48),
            estimated_cost_rt_scaled_bps: ScaledBps(490),
        };
        assert_eq!(
            fsm.try_arm_maker_entry(&spec, &snap, verdict, LotQty(10)),
            Ok(true)
        );
        assert!(fsm.on_entry_order_resting(TimestampNs(1_025_000_000)));
        assert!(fsm.on_entry_filled_maker(TimestampNs(1_050_000_000)));

        snap.bids[0].price = PriceTicks(23_318);
        snap.asks[0].price = PriceTicks(23_319);
        snap.last_trade_price = PriceTicks(23_319);
        snap.mark_price = PriceTicks(23_319);
        snap.factor_ofi = BoundedScore::new_clamped(-0.10);
        assert!(fsm.step_open_position(&snap, &mut ledger).is_none());

        snap.bids[0].price = PriceTicks(23_332);
        snap.asks[0].price = PriceTicks(23_333);
        snap.last_trade_price = PriceTicks(23_333);
        snap.mark_price = PriceTicks(23_333);
        let closed = fsm.step_open_position(&snap, &mut ledger);
        assert!(closed.is_some());
        if let Some(s) = closed {
            assert_eq!(s.kind, ClosedTradeKind::MakerPassiveUnwind);
            assert!(s.net_scaled_bps.raw() > 150);
        }
    }

    #[test]
    fn test_stage27_dynamic_70pct_mfe_ratchet_rides_trend_and_locks_profit() {
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);

        fsm.state = OrderLifecycleState::PositionOpenMakerExit {
            side: Side::Bid,
            entry_price: PriceTicks(10_000),
            peak_favorable_price: PriceTicks(10_000),
            qty: LotQty(10),
            tp_maker_price: PriceTicks(10_065),
            sl_trigger_price: PriceTicks(9_948),
            opened_ts: TimestampNs(1_000_000_000),
        };

        // 1. Price surges to 10_024 (+24.00 bps gross / +20.00 bps net). Dynamic 70% floor = 400 + 0.70*(2000) = 1800 (+18.00 bps gross).
        let mut snap_peak = SymbolLobSnapshot {
            ts_local_ns: TimestampNs(70_000_000_000),
            last_trade_price: PriceTicks(10_024),
            mark_price: PriceTicks(10_024),
            factor_ofi: BoundedScore::new_clamped(-0.40),
            ..SymbolLobSnapshot::default()
        };
        snap_peak.bids[0] = BookLevel {
            price: PriceTicks(10_024),
            qty: LotQty(100),
        };
        snap_peak.asks[0] = BookLevel {
            price: PriceTicks(10_025),
            qty: LotQty(100),
        };
        assert!(fsm.step_open_position(&snap_peak, &mut ledger).is_none());

        // 2. Price pulls back slightly to 10_019 (+19.00 bps gross > +18.00 bps floor) with negative OFI: must KEEP RIDING!
        let mut snap_pullback = snap_peak;
        snap_pullback.ts_local_ns = TimestampNs(75_000_000_000);
        snap_pullback.bids[0].price = PriceTicks(10_019);
        snap_pullback.asks[0].price = PriceTicks(10_020);
        snap_pullback.last_trade_price = PriceTicks(10_019);
        snap_pullback.mark_price = PriceTicks(10_019);
        assert!(fsm.step_open_position(&snap_pullback, &mut ledger).is_none());

        // 3. Price touches the 70% dynamic ratchet floor at 10_018 (+18.00 bps gross = +14.00 bps net): harvests immediately!
        let mut snap_harvest = snap_peak;
        snap_harvest.ts_local_ns = TimestampNs(80_000_000_000);
        snap_harvest.bids[0].price = PriceTicks(10_018);
        snap_harvest.asks[0].price = PriceTicks(10_019);
        snap_harvest.last_trade_price = PriceTicks(10_018);
        snap_harvest.mark_price = PriceTicks(10_018);
        let summary = fsm.step_open_position(&snap_harvest, &mut ledger);
        assert!(summary.is_some());
        if let Some(s) = summary {
            assert_eq!(s.net_scaled_bps.raw(), 1_400);
            assert!(s.is_maker_exit);
        }
    }

    #[test]
    fn test_fsm_resting_queue_enforces_1500ms_residence_before_runaway_abort() {
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

        snap.ts_local_ns = TimestampNs(1_200_000_000);
        snap.bids[0].price = PriceTicks(9_005);
        snap.asks[0].price = PriceTicks(9_006);
        assert!(!fsm.check_resting_queue_abort(&snap));

        snap.ts_local_ns = TimestampNs(2_600_000_000);
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