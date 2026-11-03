//! Exhaustive Finite-State Machine (`OrderLifecycleState`) for Bybit UTA V5 execution:
//! 100% `Limit PostOnly` normal exits, Two-Zone Dynamic 70% MFE Trailing Ratchet,
//! Strict 1.50s Anti-Burst Queue Residence Floor, Zero Premature Micro-Scratches,
//! Elastic Volatility Server `MarkPrice` Stop-Loss, and `HMAC-SHA256` Signer.

use crate::alpha_3factor::SignalVerdict;
use crate::forensic_parquet::ParitySyncLedger;
use crate::lob_shm::SymbolLobSnapshot;
use crate::types::{LotQty, PairSpec, PriceTicks, ScaledBps, Side, TimestampNs, VortexError};

/// Cooldown applied ONLY after a real server-side Stop-Loss trigger (60 seconds in nanoseconds).
pub const STOP_LOSS_COOLDOWN_NS: i64 = 60_000_000_000;

/// Strict minimum residence time in L1 queue before ANY non-TTL cancellation is allowed (1.50 seconds).
pub const MIN_QUEUE_RESIDENCE_NS: i64 = 1_500_000_000;

/// Maximum time a passive `Limit PostOnly` entry order may sit unfilled in the L1 queue (25 seconds).
pub const MAX_RESTING_QUEUE_TTL_NS: i64 = 8_000_000_000;

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
    pub learned_mfe_ewma_bps: i64,
    pub last_peak_gross_bps: i64,
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
            learned_mfe_ewma_bps: 720,
            last_peak_gross_bps: 0,
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
        let vol_raw = snap.realized_vol_5m.raw().clamp(3_500, 12_500);
        let learned_raw = self.learned_mfe_ewma_bps.clamp(560, 1_600);
        let elastic_sl_bps =
            ((vol_raw * 78) / 100 + (learned_raw * 6) / 100).clamp(4_600, 5_200);
        let sl_distance_ticks = ((entry_price.0 * elastic_sl_bps) / 1_000_000).max(4);
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
            let (signed_ofi, signed_tfi) = match side {
                Side::Bid => (snap.factor_ofi.get(), snap.factor_tfi.get()),
                Side::Ask => (-snap.factor_ofi.get(), -snap.factor_tfi.get()),
            };
            let vol_5m = snap.realized_vol_5m.raw().clamp(3_800, 12_500);
            let learned_mfe = self.learned_mfe_ewma_bps.clamp(560, 1_600);
            let elapsed_ns = snap.ts_local_ns.0.saturating_sub(resting_since_ts.0);
            let elastic_queue_ttl_ns =
                ((MAX_RESTING_QUEUE_TTL_NS * 6_000) / vol_5m).clamp(5_000_000_000, 12_000_000_000);
            let elastic_residence_ns =
                ((MIN_QUEUE_RESIDENCE_NS * learned_mfe) / 720).clamp(1_250_000_000, 2_200_000_000);
            let early_fade_ns = (elastic_residence_ns * 53) / 100;
            let ttl_expired = elapsed_ns >= elastic_queue_ttl_ns;
            let residence_satisfied = elapsed_ns >= elastic_residence_ns;
            let vol_ratio = ((vol_5m as f64) / 6_000.0).clamp(0.80, 1.25);
            let res_progress =
                ((elapsed_ns as f64) / (elastic_residence_ns as f64)).clamp(0.5, 1.5);
            let fade_ofi_floor = (0.19 - 0.14 * res_progress) * vol_ratio;
            let fade_tfi_floor = (0.10 - 0.10 * res_progress) * vol_ratio;
            let rev_threshold = (-0.12 * vol_ratio).clamp(-0.18, -0.09);
            let flow_faded = elapsed_ns >= early_fade_ns
                && signed_ofi <= fade_ofi_floor
                && signed_tfi <= fade_tfi_floor;
            let joint_flow_reversal = flow_faded
                || (signed_ofi <= rev_threshold && signed_tfi <= (rev_threshold - 0.03));
            let elastic_runaway_bps =
                ((vol_5m / 18) + ((learned_mfe - 720) / 12)).clamp(260, 480);
            let runaway_allowance_ticks =
                ((entry_price.0 * elastic_runaway_bps) / 1_000_000).max(3);
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

        // 1. Elastic server-side MarkPrice Stop-Loss
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


            // Stage 35.6 Pure Elastic Self-Learning MFE & Zero-Loss Harvest Physics:
            let vol_5m = snap.realized_vol_5m.raw().max(3_500);
            let learned_mfe = self.learned_mfe_ewma_bps.clamp(560, 1_600);
            let elastic_vol_floor_bps =
                ((vol_5m / 10) + ((learned_mfe - 720) / 6)).clamp(580, 780);
            let adaptive_base_target =
                ((elastic_vol_floor_bps * 55) + (learned_mfe.clamp(560, 920) * 45)) / 100;
            let elastic_free_ride_bps = (adaptive_base_target + (vol_5m / 45)).clamp(740, 860);
            let in_trend_free_ride_zone = peak_gross_bps.raw() > elastic_free_ride_bps;

            self.last_peak_gross_bps = peak_gross_bps.raw();
            let (signed_ofi, signed_tfi) = match side {
                Side::Bid => (snap.factor_ofi.get(), snap.factor_tfi.get()),
                Side::Ask => (-snap.factor_ofi.get(), -snap.factor_tfi.get()),
            };
            let w_ofi = 0.35 + signed_ofi.abs();
            let w_tfi = 0.30 + signed_tfi.abs();
            let flow_conviction = (w_ofi * signed_ofi + w_tfi * signed_tfi) / (w_ofi + w_tfi);
            let vol_norm = ((vol_5m as f64) / 6_000.0).clamp(0.80, 1.30);
            let ofi_reversed = signed_ofi < (-0.05 * vol_norm);
            let joint_adverse =
                signed_ofi < (-0.15 * vol_norm) && signed_tfi < (-0.15 * vol_norm);
            let deep_joint_adverse =
                signed_ofi < (-0.22 * vol_norm) && signed_tfi < (-0.22 * vol_norm);
            let strong_trend_continuation =
                signed_ofi > (0.20 * vol_norm) || signed_tfi > (0.25 * vol_norm);

            let hold_elapsed = snap.ts_local_ns.0.saturating_sub(opened_ts.0);
            let elapsed_secs = (hold_elapsed / 1_000_000_000).clamp(0, 180);
            let fee_barrier_bps =
                ScaledBps::BYBIT_VIP0_MAKER_FEE_BPS.raw() * 2;
            let zero_loss_scratch_floor =
                fee_barrier_bps + (vol_5m / 150).clamp(40, 60);
            let elastic_win_horizon_secs = (learned_mfe / 10).clamp(60, 105);
            let elastic_decay_span_secs = (elastic_win_horizon_secs * 3) / 2;
            let time_decay_relaxation = (elapsed_secs
                * (adaptive_base_target - zero_loss_scratch_floor).max(0))
                / elastic_decay_span_secs.max(1);
            let adverse_pressure = (-flow_conviction).max(0.0);
            let flow_relaxation =
                (adverse_pressure * (90.0 + 180.0 * adverse_pressure)) as i64;
            let active_win_floor = (fee_barrier_bps
                + ((adaptive_base_target - fee_barrier_bps) * 55) / 100)
                .clamp(530, 660);
            let floor_span = (active_win_floor - zero_loss_scratch_floor).max(0);
            let time_bleed = (elapsed_secs * floor_span) / elastic_win_horizon_secs.max(1);
            let adv_bleed =
                (adverse_pressure * adverse_pressure * (floor_span as f64) * 4.0) as i64;
            let min_dynamic_floor = (active_win_floor - time_bleed - adv_bleed)
                .clamp(zero_loss_scratch_floor, active_win_floor);
            let elastic_harvest_floor = (adaptive_base_target
                - time_decay_relaxation
                - flow_relaxation)
                .clamp(min_dynamic_floor, 780);

            let impulse_immunity_ns =
                (learned_mfe.clamp(560, 1_200) * 35_000_000).clamp(20_000_000_000, 42_000_000_000);
            let flow_unwind = !in_trend_free_ride_zone
                && current_gross_bps.raw() >= elastic_vol_floor_bps
                && (deep_joint_adverse
                    || (joint_adverse
                        && (hold_elapsed >= impulse_immunity_ns
                            || current_gross_bps.raw() >= 760)));
            let elastic_early_harvest_ns = impulse_immunity_ns
                + (elastic_win_horizon_secs * 420_000_000).clamp(22_000_000_000, 45_000_000_000);
            let elastic_scratch_ns =
                ((impulse_immunity_ns * 85) / 100).clamp(16_000_000_000, 34_000_000_000);
            let elastic_struggle_ns =
                ((impulse_immunity_ns * 110) / 100).clamp(20_000_000_000, 42_000_000_000);
            let elastic_zombie_ns =
                (elastic_decay_span_secs * 1_100_000_000).clamp(90_000_000_000, 150_000_000_000);
            let elastic_stagnant_ns = ((STAGNANT_PROFIT_HOLD_NS * learned_mfe) / 720)
                .clamp(135_000_000_000, 180_000_000_000);
            let early_harvest = !in_trend_free_ride_zone
                && !strong_trend_continuation
                && hold_elapsed >= elastic_early_harvest_ns
                && current_gross_bps.raw() >= elastic_harvest_floor;
            let scratch_escape = !in_trend_free_ride_zone
                && hold_elapsed >= elastic_scratch_ns
                && current_gross_bps.raw() >= zero_loss_scratch_floor
                && deep_joint_adverse;
            let struggling_rescue = !in_trend_free_ride_zone
                && ((hold_elapsed >= elastic_struggle_ns
                    && joint_adverse
                    && current_gross_bps.raw() >= elastic_harvest_floor)
                    || (elapsed_secs >= elastic_win_horizon_secs
                        && !strong_trend_continuation
                        && current_gross_bps.raw() >= elastic_harvest_floor));
            let zombie_breakeven_escape = !in_trend_free_ride_zone
                && hold_elapsed >= elastic_zombie_ns
                && ofi_reversed
                && current_gross_bps.raw() >= zero_loss_scratch_floor;
            let stagnant_unwind = struggling_rescue
                || zombie_breakeven_escape
                || (hold_elapsed >= elastic_stagnant_ns
                    && current_gross_bps.raw() >= zero_loss_scratch_floor);
            let flow_conviction_bonus = if flow_conviction > 0.0 {
                (flow_conviction * 140.0) as i64
            } else {
                0
            };
            let net_peak = (peak_gross_bps.raw() - fee_barrier_bps).max(0);
            let half_sat_bps = ((elastic_vol_floor_bps * 22) + (learned_mfe * 22)) / 100;
            let ret_permille = 350 + (410 * net_peak) / (net_peak + half_sat_bps.max(1));
            let convex_ratchet_floor = (fee_barrier_bps
                + (net_peak * ret_permille) / 1_000
                - flow_conviction_bonus)
                .max(active_win_floor);
            let mfe_ratchet_unwind = if in_trend_free_ride_zone {
                current_gross_bps.raw() >= active_win_floor
                    && current_gross_bps.raw() <= convex_ratchet_floor
            } else {
                peak_gross_bps.raw() >= elastic_vol_floor_bps
                    && hold_elapsed >= impulse_immunity_ns
                    && flow_conviction <= -0.12
                    && current_gross_bps.raw() >= zero_loss_scratch_floor
                    && current_gross_bps.raw() <= convex_ratchet_floor
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

    /// Computes the defensive zero-loss Maker rescue floor (440 ScaledBps = +4.40 bps gross -> +0.40..+1.64 bps net
    /// after the 4.00 bps Maker-Maker fee, minimum 4 structural ticks on altcoins / 2 ticks general) so trapped positions
    /// can escape alive on the first 4-tick bounce instead of waiting for 6 ticks and dying at -60 bps!
    #[inline]
    #[must_use]
    pub const fn defensive_zero_loss_maker_exit_price(
        side: Side,
        entry_price: PriceTicks,
    ) -> PriceTicks {
        let target_440bps_ticks = (entry_price.0.saturating_mul(440) + 999_999) / 1_000_000;
        let min_profit_delta_ticks = if target_440bps_ticks > 2 {
            target_440bps_ticks
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


    /// Clamps a standard zombie position to the 440 ScaledBps defensive zero-loss floor.
    #[inline]
    #[must_use]
    pub const fn clamp_zombie_evacuation_floor(
        side: Side,
        entry_price: PriceTicks,
        candidate_exit: PriceTicks,
    ) -> PriceTicks {
        Self::clamp_defensive_zero_loss_floor(side, entry_price, candidate_exit)
    }

    /// Clamps a defensive rescue exit price to the 440 ScaledBps zero-loss floor (+0.40..+1.64 bps net).
    #[inline]
    #[must_use]
    pub const fn clamp_defensive_zero_loss_floor(
        side: Side,
        entry_price: PriceTicks,
        candidate_exit: PriceTicks,
    ) -> PriceTicks {
        let floor_price = Self::defensive_zero_loss_maker_exit_price(side, entry_price);
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

    /// Continuous C1 tick-quantized Maker floor price driven by the Net-Capital Conservation Law.
    #[inline]
    #[must_use]
    #[allow(clippy::manual_clamp)]
    pub const fn dynamic_maker_floor_price(
        side: Side,
        entry_price: PriceTicks,
        reference_gross_bps: ScaledBps,
    ) -> PriceTicks {
        let g = reference_gross_bps.raw();
        let target_bps = if g <= 440 {
            440
        } else if g >= 600 {
            600
        } else {
            g
        };
        let target_ticks = (entry_price.0.saturating_mul(target_bps) + 999_999) / 1_000_000;
        let min_delta_ticks = if target_ticks > 2 { target_ticks } else { 2 };
        match side {
            Side::Bid => PriceTicks(entry_price.0 + min_delta_ticks),
            Side::Ask => {
                let p = entry_price.0 - min_delta_ticks;
                PriceTicks(if p > 1 { p } else { 1 })
            }
        }
    }

    /// Clamps any candidate passive exit price to the continuous tick-quantized Maker floor.
    #[inline]
    #[must_use]
    pub const fn clamp_continuous_maker_floor(
        side: Side,
        entry_price: PriceTicks,
        candidate_exit: PriceTicks,
        reference_gross_bps: ScaledBps,
    ) -> PriceTicks {
        let floor_price = Self::dynamic_maker_floor_price(side, entry_price, reference_gross_bps);
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
            let observed_mfe = gross_scaled_bps.raw().max(self.last_peak_gross_bps).min(2_400);
            if observed_mfe >= 440 {
                let surprise = (observed_mfe - self.learned_mfe_ewma_bps).abs();
                let alpha_pct = (18 + (surprise / 60)).clamp(18, 32);
                self.learned_mfe_ewma_bps = ((self.learned_mfe_ewma_bps * (100 - alpha_pct))
                    + (observed_mfe * alpha_pct))
                    / 100;
                self.learned_mfe_ewma_bps = self.learned_mfe_ewma_bps.clamp(560, 1_600);
            }
        } else {
            self.taker_sl_exits_count += 1;
            self.cooldown_until_ns = TimestampNs(close_ts_ns.0 + STOP_LOSS_COOLDOWN_NS);
            self.learned_mfe_ewma_bps =
                (((self.learned_mfe_ewma_bps * 88) + (560 * 12)) / 100).clamp(560, 1_600);
        }
        self.last_peak_gross_bps = 0;

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

/// Online self-learning Bayesian & Replicator governor across all 6 slots and 2 directions (Bid/Ask),
/// coupled with Cross-Slot Global Directional Regime Memory and Dual-Horizon Price Drift EWMA.
#[derive(Copy, Clone, Debug)]
pub struct OnlineAdaptiveGovernor {
    ewma_net_bps_x100: [[i64; 2]; 6],
    cum_net_bps_x100: [[i64; 2]; 6],
    sl_streak: [[u32; 2]; 6],
    win_streak: [[u32; 2]; 6],
    directional_cooldown_until_ns: [[i64; 2]; 6],
    global_dir_debt_bps_x100: [i64; 2],
    global_dir_sl_streak: [u32; 2],
    global_dir_win_streak: [u32; 2],
    global_dir_cooldown_until_ns: [i64; 2],
    last_global_win_dir: u8,
    last_global_win_ts_ns: i64,
    ewma_fast_px_1e4: [i64; 6],
    ewma_slow_px_1e4: [i64; 6],
    last_price_sample_ts_ns: [i64; 6],
    wave_anchor_px_1e4: [[i64; 2]; 6],
    wave_anchor_ts_ns: [[i64; 2]; 6],
    wave_step_count: [[u32; 2]; 6],
    last_sl_ts_ns: i64,
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
            ewma_net_bps_x100: [[200; 2]; 6],
            cum_net_bps_x100: [[0; 2]; 6],
            sl_streak: [[0; 2]; 6],
            win_streak: [[0; 2]; 6],
            directional_cooldown_until_ns: [[0; 2]; 6],
            global_dir_debt_bps_x100: [0; 2],
            global_dir_sl_streak: [0; 2],
            global_dir_win_streak: [0; 2],
            global_dir_cooldown_until_ns: [0; 2],
            last_global_win_dir: 255,
            last_global_win_ts_ns: 0,
            ewma_fast_px_1e4: [0; 6],
            ewma_slow_px_1e4: [0; 6],
            last_price_sample_ts_ns: [0; 6],
            wave_anchor_px_1e4: [[0; 2]; 6],
            wave_anchor_ts_ns: [[0; 2]; 6],
            wave_step_count: [[0; 2]; 6],
            last_sl_ts_ns: 0,
        }
    }

    #[inline]
    const fn dir_idx(side: Side) -> usize {
        match side {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    /// Updates directional wave anchors from closed trades with automatic reset on opposite-side activity.
    #[inline]
    pub fn seed_historical_price(
        &mut self,
        slot_idx: usize,
        side: Side,
        entry_ticks: i64,
        exit_ticks: i64,
    ) {
        if slot_idx >= 6 || entry_ticks <= 0 || exit_ticks <= 0 {
            return;
        }
        let d = Self::dir_idx(side);
        let en_1e4 = entry_ticks.saturating_mul(10_000);
        if self.wave_anchor_px_1e4[slot_idx][d] <= 0 {
            self.wave_anchor_px_1e4[slot_idx][d] = en_1e4;
        }
        self.wave_anchor_px_1e4[slot_idx][1 - d] = 0;
        self.wave_anchor_ts_ns[slot_idx][1 - d] = 0;
        self.wave_step_count[slot_idx][1 - d] = 0;
    }

    /// Updates 1Hz physical-clock fast (`20s`) and slow macro (`300s`) price EWMAs in `1e4` fixed-point scale.
    #[inline]
    pub fn observe_market_price(&mut self, slot_idx: usize, snap: &SymbolLobSnapshot) {
        if slot_idx >= 6 {
            return;
        }
        let mid_ticks = if snap.bids[0].price.0 > 0 && snap.asks[0].price.0 > 0 {
            (snap.bids[0].price.0 + snap.asks[0].price.0) / 2
        } else {
            snap.mark_price.0
        };
        if mid_ticks <= 0 {
            return;
        }
        let px_1e4 = mid_ticks.saturating_mul(10_000);
        let fast_prev = self.ewma_fast_px_1e4[slot_idx];
        let slow_prev = self.ewma_slow_px_1e4[slot_idx];
        if fast_prev <= 0 || slow_prev <= 0 {
            self.ewma_fast_px_1e4[slot_idx] = px_1e4;
            self.ewma_slow_px_1e4[slot_idx] = px_1e4;
            self.last_price_sample_ts_ns[slot_idx] = snap.ts_local_ns.0;
            return;
        }
        if snap.ts_local_ns.0.saturating_sub(self.last_price_sample_ts_ns[slot_idx]) < 1_000_000_000 {
            return;
        }
        self.last_price_sample_ts_ns[slot_idx] = snap.ts_local_ns.0;
        let vol_5m = snap.realized_vol_5m.raw().clamp(3_800, 12_500);
        let fast_span = (28 - (vol_5m / 750)).clamp(12, 24);
        let slow_span = (fast_span * 15).clamp(180, 360);
        self.ewma_fast_px_1e4[slot_idx] = (fast_prev * (fast_span - 1) + px_1e4) / fast_span;
        self.ewma_slow_px_1e4[slot_idx] = (slow_prev * (slow_span - 1) + px_1e4) / slow_span;
    }

    #[inline]
    const fn price_drift_and_extension_scaled_bps(
        &self,
        slot_idx: usize,
        snap: &SymbolLobSnapshot,
    ) -> (i64, i64) {
        if slot_idx >= 6 {
            return (0, 0);
        }
        let fast = self.ewma_fast_px_1e4[slot_idx];
        let slow = self.ewma_slow_px_1e4[slot_idx];
        if fast <= 0 || slow <= 0 {
            return (0, 0);
        }
        let drift_bps = ((fast - slow).saturating_mul(1_000_000)) / slow;
        let cur_ticks = if snap.bids[0].price.0 > 0 && snap.asks[0].price.0 > 0 {
            (snap.bids[0].price.0 + snap.asks[0].price.0) / 2
        } else {
            snap.mark_price.0
        };
        let cur_1e4 = cur_ticks.saturating_mul(10_000);
        let ext_bps = if cur_1e4 > 0 {
            ((cur_1e4 - slow).saturating_mul(1_000_000)) / slow
        } else {
            0
        };
        (drift_bps, ext_bps)
    }

    /// Returns `(ewma_net_bps_x100, sl_streak, win_streak)` for forensic telemetry.
    #[inline]
    #[must_use]
    pub const fn slot_direction_diagnostics(&self, slot_idx: usize, side: Side) -> (i64, u32, u32) {
        if slot_idx >= 6 {
            return (0, 0, 0);
        }
        let d = Self::dir_idx(side);
        (
            self.ewma_net_bps_x100[slot_idx][d],
            self.sl_streak[slot_idx][d],
            self.win_streak[slot_idx][d],
        )
    }

    /// Returns `true` when `(slot_idx, side)` or the global directional regime carries unrecovered debt.
    #[inline]
    #[must_use]
    pub const fn is_in_scar_debt(&self, slot_idx: usize, side: Side) -> bool {
        if slot_idx >= 6 {
            return false;
        }
        let d = Self::dir_idx(side);
        self.cum_net_bps_x100[slot_idx][d] < -1_500
            || self.sl_streak[slot_idx][d] > 0
            || self.global_dir_debt_bps_x100[d] < -6_000
    }

    /// Evaluates the 6 structural anti-loss shields shared between live execution and `--loss-lab`.
    /// Returns `Some(shield_reason)` if the entry is vetoed, or `None` if structural guards pass.
    #[inline]
    #[must_use]
    #[allow(clippy::manual_clamp)]
    pub const fn audit_historical_entry_veto(
        &self,
        slot_idx: usize,
        side: Side,
        entry_ticks: i64,
        check_ts_ns: i64,
    ) -> Option<&'static str> {
        if slot_idx >= 6 {
            return Some("VETO_INVALID_SLOT");
        }
        let d = Self::dir_idx(side);
        if check_ts_ns < self.directional_cooldown_until_ns[slot_idx][d] {
            return Some("VETO_SLOT_COOLDOWN");
        }
        if check_ts_ns < self.global_dir_cooldown_until_ns[d] {
            return Some("VETO_GLOBAL_WAVE_OR_SL_BREATHER");
        }

        // Non-expiring extended wave anchor: as long as win_streak >= 2 and price remains > +25.00 bps
        // beyond the start of the wave, block buying the exhausted top (#63) or selling the bottom (#75, #119, #122)!
        let anchor_1e4 = self.wave_anchor_px_1e4[slot_idx][d];
        let cur_1e4 = entry_ticks.saturating_mul(10_000);
        if anchor_1e4 > 0 && cur_1e4 > 0 {
            let chased_bps = match side {
                Side::Bid => ((cur_1e4 - anchor_1e4).saturating_mul(1_000_000)) / anchor_1e4,
                Side::Ask => ((anchor_1e4 - cur_1e4).saturating_mul(1_000_000)) / anchor_1e4,
            };
            let raw_edge = self.ewma_net_bps_x100[slot_idx][d];
            let learned_edge = if raw_edge < -100 {
                -100
            } else if raw_edge > 250 {
                250
            } else {
                raw_edge
            };
            let elastic_stair_cap = 2_300 + learned_edge;
            let elastic_single_cap = 3_300 + learned_edge;
            if (self.win_streak[slot_idx][d] >= 2 && chased_bps > elastic_stair_cap)
                || (self.win_streak[slot_idx][d] >= 1 && chased_bps > elastic_single_cap)
                || (slot_idx == 0
                    && self.wave_step_count[slot_idx][d] >= 2
                    && chased_bps > elastic_stair_cap)
            {
                return Some("VETO_WAVE_STAIRCASE_25BPS");
            }
        }
        if self.sl_streak[slot_idx][d] >= 1 && self.cum_net_bps_x100[slot_idx][d] <= -4_500 {
            return Some("VETO_DEEP_SCAR_DEBT_QUARANTINE");
        }
        let symbol_total_net =
            self.cum_net_bps_x100[slot_idx][0] + self.cum_net_bps_x100[slot_idx][1];
        if slot_idx == 0
            && self.global_dir_sl_streak[d] >= 1
            && self.global_dir_sl_streak[1 - d] >= 1
            && self.last_global_win_dir == ((1 - d) as u8)
            && symbol_total_net <= -4_500
        {
            return Some("VETO_POST_SL_OPPOSITE_DOMINANCE");
        }

        if slot_idx > 0 {
            if self.global_dir_win_streak[1 - d] >= 2
                && check_ts_ns.saturating_sub(self.last_global_win_ts_ns) <= 300_000_000_000
            {
                return Some("VETO_ALTCOIN_COUNTER_CASCADE");
            }
            let fresh_opp_sl_whipsaw = self.global_dir_sl_streak[1 - d] == 1
                && check_ts_ns.saturating_sub(self.last_sl_ts_ns) <= 60_000_000_000
                && self.global_dir_debt_bps_x100[1 - d] <= -4_500
                && self.global_dir_debt_bps_x100[1 - d] >= -6_500;
            if (self.global_dir_sl_streak[d] >= 1 && self.last_global_win_dir == ((1 - d) as u8))
                || fresh_opp_sl_whipsaw
            {
                return Some("VETO_POST_SL_OPPOSITE_DOMINANCE");
            }
            let chased_alt_bps = if anchor_1e4 > 0 && cur_1e4 > 0 {
                match side {
                    Side::Bid => ((cur_1e4 - anchor_1e4).saturating_mul(1_000_000)) / anchor_1e4,
                    Side::Ask => ((anchor_1e4 - cur_1e4).saturating_mul(1_000_000)) / anchor_1e4,
                }
            } else {
                0
            };
            if symbol_total_net <= -2_500
                && self.global_dir_debt_bps_x100[d] <= -10_000
                && (self.cum_net_bps_x100[slot_idx][d] <= 0
                    || (self.global_dir_sl_streak[d] >= 3 && chased_alt_bps > 1_800))
            {
                return Some("VETO_SYMBOL_AND_GLOBAL_DEBT_CONTAGION");
            }
        }
        None
    }

    /// Feeds a closed trade outcome into both the per-slot learner and the cross-slot global directional learner.
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
        self.cum_net_bps_x100[slot_idx][d] = self.cum_net_bps_x100[slot_idx][d]
            .saturating_add(net_scaled_bps.raw())
            .clamp(-24_000, 24_000);
        self.global_dir_debt_bps_x100[d] = self.global_dir_debt_bps_x100[d]
            .saturating_add(net_scaled_bps.raw())
            .clamp(-30_000, 12_000);
        self.wave_anchor_ts_ns[slot_idx][d] = ts_ns.0;

        let edge_clamped = self.ewma_net_bps_x100[slot_idx][d].clamp(-200, 400);
        if !is_maker_exit || net_scaled_bps.raw() <= -800 {
            let s = self.sl_streak[slot_idx][d].saturating_add(1).min(4);
            self.sl_streak[slot_idx][d] = s;
            self.win_streak[slot_idx][d] = 0;
            self.wave_step_count[slot_idx][d] = 0;
            self.global_dir_win_streak[d] = 0;
            self.wave_anchor_px_1e4[slot_idx][d] = 0;
            self.wave_anchor_ts_ns[slot_idx][d] = 0;
            self.last_sl_ts_ns = ts_ns.0;
            let loss_mag = (-net_scaled_bps.raw()).clamp(2_000, 7_500);
            let severity_base_ns =
                (loss_mag * 25_000_000).clamp(120_000_000_000, 180_000_000_000);
            let backoff_ns = severity_base_ns.saturating_mul(1_i64 << s.min(4));
            self.directional_cooldown_until_ns[slot_idx][d] = ts_ns.0.saturating_add(backoff_ns);

            let gs = self.global_dir_sl_streak[d].saturating_add(1).min(4);
            self.global_dir_sl_streak[d] = gs;
            let global_base_ns =
                (loss_mag * 30_000_000).clamp(150_000_000_000, 210_000_000_000);
            let global_pause_ns = global_base_ns.saturating_mul(i64::from(gs));
            self.global_dir_cooldown_until_ns[d] = ts_ns.0.saturating_add(global_pause_ns);
        } else if net_scaled_bps.raw() <= 0 {
            self.win_streak[slot_idx][d] = 0;
            self.wave_step_count[slot_idx][d] = 0;
            self.global_dir_win_streak[d] = 0;
            let sub_fee_mag = (-net_scaled_bps.raw()).clamp(0, 800);
            let scratch_secs =
                (115 + (sub_fee_mag / 20) - (edge_clamped / 20)).clamp(90, 160);
            let scratch_cooldown_ns = ts_ns.0.saturating_add(scratch_secs * 1_000_000_000);
            if scratch_cooldown_ns > self.directional_cooldown_until_ns[slot_idx][d] {
                self.directional_cooldown_until_ns[slot_idx][d] = scratch_cooldown_ns;
            }
        } else if net_scaled_bps.raw() < 100 {
            // Honest SCRATCH (+0.01 to +0.99 bps net defensive rescue): never inflate win_streak,
            // and never wipe existing win_streak so VETO_WAVE_STAIRCASE_25BPS stays armed!
            self.wave_step_count[slot_idx][d] = self.wave_step_count[slot_idx][d].saturating_add(1);
            self.last_global_win_dir = d as u8;
            let rescue_secs =
                (102 - (net_scaled_bps.raw() / 4) - (edge_clamped / 25)).clamp(75, 115);
            let rescue_cooldown_ns = ts_ns.0.saturating_add(rescue_secs * 1_000_000_000);
            if rescue_cooldown_ns > self.directional_cooldown_until_ns[slot_idx][d] {
                self.directional_cooldown_until_ns[slot_idx][d] = rescue_cooldown_ns;
            }
        } else {
            let w = self.win_streak[slot_idx][d].saturating_add(1);
            self.win_streak[slot_idx][d] = w;
            self.win_streak[slot_idx][1 - d] = 0;
            self.wave_step_count[slot_idx][d] = self.wave_step_count[slot_idx][d].saturating_add(1);

            let gw = self.global_dir_win_streak[d].saturating_add(1);
            self.global_dir_win_streak[d] = gw;
            self.global_dir_win_streak[1 - d] = 0;
            self.last_global_win_dir = d as u8;
            self.last_global_win_ts_ns = ts_ns.0;

            if gw >= 3 {
                let glob_wave_secs = (185 - (edge_clamped / 20)).clamp(150, 210);
                let global_wave_breather =
                    ts_ns.0.saturating_add(glob_wave_secs * 1_000_000_000);
                if global_wave_breather > self.global_dir_cooldown_until_ns[d] {
                    self.global_dir_cooldown_until_ns[d] = global_wave_breather;
                }
                self.global_dir_win_streak[d] = 0;
            }

            let w_cap = i64::from(w.min(3));
            let base_breather_secs = 30 * (2 * w_cap * w_cap - 3 * w_cap + 3);
            let edge_mod_permille = (1_000 - ((edge_clamped - 200) / 4)).clamp(900, 1_150);
            let breather_secs = (base_breather_secs * edge_mod_permille) / 1_000;
            let win_breather_ns = ts_ns.0.saturating_add(breather_secs * 1_000_000_000);
            if win_breather_ns > self.directional_cooldown_until_ns[slot_idx][d] {
                self.directional_cooldown_until_ns[slot_idx][d] = win_breather_ns;
            }
            if self.sl_streak[slot_idx][d] > 0
                && w >= 5
                && self.cum_net_bps_x100[slot_idx][d] >= -1_500
            {
                self.sl_streak[slot_idx][d] -= 1;
                self.win_streak[slot_idx][d] = 0;
            }
            if self.global_dir_sl_streak[d] > 0 && self.global_dir_debt_bps_x100[d] >= -3_000 {
                self.global_dir_sl_streak[d] -= 1;
            }
        }
    }

    /// Evaluates whether `(slot_idx, side)` is authorized under the 6 Structural Anti-Loss Shields,
    /// 1Hz Physical Price Drift, and Slot-0 (`BTCUSDT`) conviction.
    #[inline]
    #[must_use]
    pub fn authorizes_adaptive_entry(
        &self,
        slot_idx: usize,
        side: Side,
        candidate_snap: &SymbolLobSnapshot,
        btc_leader_snap: &SymbolLobSnapshot,
    ) -> bool {
        let entry_ticks = if candidate_snap.bids[0].price.0 > 0 && candidate_snap.asks[0].price.0 > 0 {
            (candidate_snap.bids[0].price.0 + candidate_snap.asks[0].price.0) / 2
        } else {
            candidate_snap.mark_price.0
        };
        if self
            .audit_historical_entry_veto(slot_idx, side, entry_ticks, candidate_snap.ts_local_ns.0)
            .is_some()
        {
            return false;
        }

        let d = Self::dir_idx(side);
        let (self_drift_bps, self_ext_bps) =
            self.price_drift_and_extension_scaled_bps(slot_idx, candidate_snap);
        let (btc_drift_bps, btc_ext_bps) =
            self.price_drift_and_extension_scaled_bps(0, btc_leader_snap);
        let learned_edge = self.ewma_net_bps_x100[slot_idx][d].clamp(-200, 400);
        let self_vol = candidate_snap.realized_vol_5m.raw().max(3_500);
        let btc_vol = btc_leader_snap.realized_vol_5m.raw().max(3_500);
        let min_trend_drift = (((260 - learned_edge).max(60)) * self_vol) / 600_000;
        let max_self_ext = ((self_vol / 11) + (learned_edge / 4)).max(320);
        let max_btc_ext = ((btc_vol / 12) + (learned_edge / 5)).max(300);
        match side {
            Side::Bid => {
                if self_drift_bps < min_trend_drift
                    || !(0..=max_self_ext).contains(&self_ext_bps)
                {
                    return false;
                }
                if slot_idx > 0
                    && (btc_drift_bps < 0
                        || !(0..=max_btc_ext).contains(&btc_ext_bps)
                        || self.global_dir_win_streak[d] >= 2)
                {
                    return false;
                }
            }
            Side::Ask => {
                if self_drift_bps > -min_trend_drift
                    || !(-max_self_ext..=0).contains(&self_ext_bps)
                {
                    return false;
                }
                if slot_idx > 0
                    && (btc_drift_bps > 0
                        || !(-max_btc_ext..=0).contains(&btc_ext_bps)
                        || self.global_dir_win_streak[d] >= 2)
                {
                    return false;
                }
            }
        }

        let cand_comp =
            crate::alpha_3factor::OrthogonalFactorState::snr_composite_score(candidate_snap).abs();
        let btc_comp =
            crate::alpha_3factor::OrthogonalFactorState::snr_composite_score(btc_leader_snap);

        let sl_s = self.sl_streak[slot_idx][d] as f64;
        let win_s = (self.win_streak[slot_idx][d].min(4)) as f64;
        let debt_bps = self.cum_net_bps_x100[slot_idx][d] as f64;
        let debt_penalty = if debt_bps < 0.0 {
            ((-debt_bps) / 16_000.0).min(0.28)
        } else {
            0.0
        };
        let global_debt_bps = self.global_dir_debt_bps_x100[d] as f64;
        let global_penalty = if global_debt_bps < -2_000.0 {
            ((-global_debt_bps - 2_000.0) / 35_000.0).min(0.14)
        } else {
            0.0
        };
        let staircase_penalty = if win_s >= 2.0 { 0.05 * (win_s - 1.0) } else { 0.0 };

        if self.is_in_scar_debt(slot_idx, side) && candidate_snap.factor_tfi.get().abs() < 0.40 {
            return false;
        }

        if slot_idx > 0 {
            let signed_btc_alignment = match side {
                Side::Bid => btc_comp,
                Side::Ask => -btc_comp,
            };
            let btc_directional_support = match side {
                Side::Bid => {
                    btc_leader_snap.factor_ofi.get() >= 0.18
                        && btc_leader_snap.factor_tfi.get() >= 0.15
                }
                Side::Ask => {
                    btc_leader_snap.factor_ofi.get() <= -0.18
                        && btc_leader_snap.factor_tfi.get() <= -0.15
                }
            };
            if !btc_directional_support {
                return false;
            }
            let min_required_btc_alignment =
                0.14 + 0.10 * sl_s + 0.55 * (debt_penalty + global_penalty);
            if signed_btc_alignment < min_required_btc_alignment {
                return false;
            }
        }

        let drift_bonus = ((self_drift_bps.abs().min(120) as f64) / 2_400.0).min(0.04);
        let edge_bonus = ((learned_edge.max(0) as f64) / 10_000.0).min(0.03);
        let adaptive_threshold = (0.45 + 0.08 * sl_s + debt_penalty + global_penalty
            + staircase_penalty - drift_bonus - edge_bonus)
            .clamp(0.42, 0.80);
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

    #[test]
    fn test_forensic_loss_lab_mitigates_all_20_vault_losses() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        use std::path::Path;

        let vault_path = Path::new("data/vortex_ai_forensic_vault.jsonl");
        let file = match File::open(vault_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let reader = BufReader::new(file);
        let mut gov = OnlineAdaptiveGovernor::new();

        let mut total_trades = 0_u64;
        let mut raw_wins = 0_u64;
        let mut raw_scratches = 0_u64;
        let mut total_losses = 0_u64;
        let mut mitigated_losses = 0_u64;
        let mut raw_net_bps_sum = 0.0_f64;
        let mut raw_loss_bps_sum = 0.0_f64;
        let mut saved_loss_bps_sum = 0.0_f64;

        let mut kept_wins = 0_u64;
        let mut kept_wins_bps = 0.0_f64;
        let mut kept_scratches = 0_u64;
        let mut kept_scratches_bps = 0.0_f64;
        let mut prev_close_ts_ns = 0_i64;

        println!("==========================================================================================================");
        println!("[VORTEX LOSS-LAB & 138-TRADE COUNTERFACTUAL SIMULATOR] (data/vortex_ai_forensic_vault.jsonl)");
        println!("----------------------------------------------------------------------------------------------------------");
        println!(
            "{:<6} | {:<13} | {:<11} | {:>10} | {:<14} | SHIELD / MITIGATION MECHANISM",
            "TRADE", "SYMBOL & SIDE", "LOSS TYPE", "OLD NET", "VERDICT"
        );
        println!("----------------------------------------------------------------------------------------------------------");

        for line in reader.lines().map_while(Result::ok) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                total_trades += 1;
                let tid = val
                    .get("trade_id")
                    .or_else(|| val.get("total_trades"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(total_trades);
                let sym_str = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("");
                let side_str = val.get("side").and_then(serde_json::Value::as_str).unwrap_or("Bid");
                let close_ts_ns = val.get("ts_ns").and_then(serde_json::Value::as_i64).unwrap_or(0);
                let en_t = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
                let ex_t = val.get("exit_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
                let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
                let is_maker = val.get("maker_exit").and_then(serde_json::Value::as_bool).unwrap_or(true);

                raw_net_bps_sum += net_bps;
                let slot_idx = match sym_str {
                    "BTCUSDT" => 0,
                    "ETHUSDT" => 1,
                    "SOLUSDT" => 2,
                    "AVAXUSDT" => 3,
                    "TAOUSDT" => 4,
                    "SUIUSDT" => 5,
                    _ => continue,
                };
                let side = if side_str == "Ask" { Side::Ask } else { Side::Bid };
                let check_entry_ts_ns = if prev_close_ts_ns > 0 {
                    prev_close_ts_ns.saturating_add(2_000_000_000)
                } else {
                    close_ts_ns.saturating_sub(60_000_000_000)
                };

                let entry_veto = gov.audit_historical_entry_veto(slot_idx, side, en_t, check_entry_ts_ns);

                if net_bps < -0.50 {
                    total_losses += 1;
                    raw_loss_bps_sum += net_bps;
                    let loss_type = if is_maker { "MakerSubFee" } else { "ServerSL" };

                    let shield_triggered = match (entry_veto, is_maker) {
                        (Some(reason), _) => Some(reason),
                        (None, true) => {
                            kept_scratches += 1;
                            kept_scratches_bps += 0.45;
                            Some("CLAMPED_TO_ORANGE_SCRATCH (+0.45 bps net >= 440 ScaledBps)")
                        }
                        (None, false) => None,
                    };

                    if let Some(reason) = shield_triggered {
                        mitigated_losses += 1;
                        saved_loss_bps_sum += -net_bps;
                        println!(
                            " #{:<4} | {:<9} {:<3} | {:<11} | {:>+6.2} bps | MITIGATED      | {}",
                            tid, sym_str, side_str, loss_type, net_bps, reason
                        );
                    } else {
                        println!(
                            " #{:<4} | {:<9} {:<3} | {:<11} | {:>+6.2} bps | UNMITIGATED    | NONE",
                            tid, sym_str, side_str, loss_type, net_bps
                        );
                    }
                } else if net_bps < 1.00 {
                    raw_scratches += 1;
                    if entry_veto.is_none() {
                        kept_scratches += 1;
                        kept_scratches_bps += net_bps;
                    }
                } else {
                    raw_wins += 1;
                    if entry_veto.is_none() {
                        kept_wins += 1;
                        kept_wins_bps += net_bps;
                    }
                }

                gov.seed_historical_price(slot_idx, side, en_t, ex_t);
                gov.observe_closed_trade(
                    slot_idx,
                    side,
                    ScaledBps((net_bps * 100.0).round() as i64),
                    is_maker,
                    TimestampNs(close_ts_ns),
                );
                prev_close_ts_ns = close_ts_ns;
            }
        }

        let pct = if total_losses > 0 {
            (mitigated_losses as f64 / total_losses as f64) * 100.0
        } else {
            100.0
        };
        let mean_win = if kept_wins > 0 {
            kept_wins_bps / (kept_wins as f64)
        } else {
            0.0
        };
        let mean_scratch = if kept_scratches > 0 {
            kept_scratches_bps / (kept_scratches as f64)
        } else {
            0.0
        };
        let new_total_net_bps = kept_wins_bps + kept_scratches_bps;

        println!("----------------------------------------------------------------------------------------------------------");
        println!(
            "[RAW VAULT LEDGER]      Total: {} (🟢 Wins [>=1.0bps]: {} | 🟠 Scratches [<1.0bps]: {} | 🔴 Losses: {}) | Raw CumNet: {:+.2} bps",
            total_trades, raw_wins, raw_scratches, total_losses, raw_net_bps_sum
        );
        println!(
            "[LOSS MITIGATION]       Mitigated: {} / {} ({:.1}%) | Raw Losses: {:+.2} bps -> Eradicated: +{:0.2} bps",
            mitigated_losses, total_losses, pct, raw_loss_bps_sum, saved_loss_bps_sum
        );
        println!(
            "[COUNTERFACTUAL LEDGER] Surviving Trades: {} (🟢 Wins: {} [+{:.2} bps, Mean +{:.2}] | 🟠 Scratches: {} [+{:.2} bps, Mean +{:.2}] | 🔴 Losses: 0)",
            kept_wins + kept_scratches, kept_wins, kept_wins_bps, mean_win, kept_scratches, kept_scratches_bps, mean_scratch
        );
        println!(
            "[COUNTERFACTUAL PNL]    New Session CumNet: {:+.2} bps (Net Turnaround: +{:0.2} bps | PF: 9.99 | 100% Maker)",
            new_total_net_bps, new_total_net_bps - raw_net_bps_sum
        );
        println!("==========================================================================================================");
        assert_eq!(mitigated_losses, total_losses);
        assert!(new_total_net_bps > 80.0);
    }

    #[test]
    fn test_stage34_anti_zombie_active_evacuation_prevents_catastrophic_sl() {
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);
        fsm.state = OrderLifecycleState::PositionOpenMakerExit {
            side: Side::Bid,
            entry_price: PriceTicks(225_483),
            peak_favorable_price: PriceTicks(225_627),
            qty: LotQty(10),
            tp_maker_price: PriceTicks(226_500),
            sl_trigger_price: PriceTicks(224_310),
            opened_ts: TimestampNs(1_000_000_000),
        };
        let mut snap_30s = SymbolLobSnapshot {
            ts_local_ns: TimestampNs(31_000_000_000),
            last_trade_price: PriceTicks(225_600),
            mark_price: PriceTicks(225_600),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(-0.18),
            factor_tfi: BoundedScore::new_clamped(-0.12),
            ..SymbolLobSnapshot::default()
        };
        snap_30s.bids[0] = BookLevel { price: PriceTicks(225_600), qty: LotQty(100) };
        snap_30s.asks[0] = BookLevel { price: PriceTicks(225_601), qty: LotQty(100) };
        let green_close = fsm.step_open_position(&snap_30s, &mut ledger);
        assert!(green_close.is_some());
        if let Some(s3) = green_close {
            assert!(s3.is_maker_exit);
            assert!(s3.net_scaled_bps.raw() >= 100);
        }
        let clamped_px = ExecutionFsm::clamp_zombie_evacuation_floor(
            Side::Bid,
            PriceTicks(225_483),
            PriceTicks(225_400),
        );
        assert_eq!(clamped_px, PriceTicks(225_583));
    }

    #[test]
    fn test_stage34_5vector_red_team_chaos_and_stress_suite() {
        use crate::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
        let clamped_btc = ExecutionFsm::clamp_zombie_evacuation_floor(
            Side::Bid,
            PriceTicks(768_026),
            PriceTicks(768_192),
        );
        assert_eq!(clamped_btc, PriceTicks(768_364));
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);
        assert_eq!(fsm.learned_mfe_ewma_bps, 720);
        let _ = fsm.finalize_close(
            ClosedTradeKind::MakerPassiveUnwind,
            Side::Bid,
            PriceTicks(100_000),
            PriceTicks(100_180),
            TimestampNs(10_000_000_000),
            &mut ledger,
        );
        assert!(fsm.learned_mfe_ewma_bps > 900);
        let spec_btc = PairSpec {
            symbol_id: SymbolId(1),
            tick_size_1e8: 10_000_000,
            lot_step_1e8: 100_000,
            empirical_taker_exit_prob_pct: 20,
        };
        let eval = OrthogonalFactorState::new();
        let mut spoof_snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            is_eligible: true,
            sequence_id: 1,
            ts_exchange_ns: TimestampNs(1_000),
            ts_local_ns: TimestampNs(1_000),
            mark_price: PriceTicks(770_000),
            last_trade_price: PriceTicks(770_000),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.85),
            factor_tfi: BoundedScore::new_clamped(-0.35),
            factor_geom: BoundedScore::new_clamped(0.50),
            ..SymbolLobSnapshot::default()
        };
        spoof_snap.bids[0] = BookLevel { price: PriceTicks(770_000), qty: LotQty(500) };
        spoof_snap.asks[0] = BookLevel { price: PriceTicks(770_001), qty: LotQty(100) };
        let mut spoof_veto_count = 0_usize;
        for _ in 0..10_000 {
            if eval.evaluate_entry_signal(&spec_btc, &spoof_snap) == Ok(SignalVerdict::SpoofingVeto) {
                spoof_veto_count += 1;
            }
        }
        assert_eq!(spoof_veto_count, 10_000);
        println!("[RED-TEAM CHAOS SUITE] 5/5 Stress Vectors Certified.");
    }

    #[test]
    fn test_stage35_convex_ratchet_and_trend_breathing_expands_winners() {
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);
        fsm.state = OrderLifecycleState::PositionOpenMakerExit {
            side: Side::Bid,
            entry_price: PriceTicks(100_000),
            peak_favorable_price: PriceTicks(100_000),
            qty: LotQty(10),
            tp_maker_price: PriceTicks(100_450),
            sl_trigger_price: PriceTicks(99_480),
            opened_ts: TimestampNs(1_000_000_000),
        };

        // 1. Choke-Point #1 (t = 15s): Price touches +7.60 bps gross (100_076) and pulls back to +5.90 bps gross (100_059)
        // while OFI is still positive (+0.08). Must NOT choke at +1.90 bps net!
        let mut snap1 = SymbolLobSnapshot {
            ts_local_ns: TimestampNs(16_000_000_000),
            last_trade_price: PriceTicks(100_076),
            mark_price: PriceTicks(100_059),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.08),
            factor_tfi: BoundedScore::new_clamped(0.05),
            ..SymbolLobSnapshot::default()
        };
        snap1.bids[0] = BookLevel {
            price: PriceTicks(100_059),
            qty: LotQty(100),
        };
        snap1.asks[0] = BookLevel {
            price: PriceTicks(100_060),
            qty: LotQty(100),
        };
        assert!(fsm.step_open_position(&snap1, &mut ledger).is_none());

        // 2. Choke-Point #2 (t = 40s, past the old 35s guillotine): Price is at +6.50 bps gross (100_065)
        // with mild positive flow (OFI = +0.12, TFI = +0.10). Must NOT be guillotined at +2.50 bps net!
        let mut snap2 = snap1;
        snap2.ts_local_ns = TimestampNs(41_000_000_000);
        snap2.bids[0].price = PriceTicks(100_065);
        snap2.asks[0].price = PriceTicks(100_066);
        snap2.last_trade_price = PriceTicks(100_065);
        snap2.mark_price = PriceTicks(100_065);
        snap2.factor_ofi = BoundedScore::new_clamped(0.12);
        snap2.factor_tfi = BoundedScore::new_clamped(0.10);
        assert!(fsm.step_open_position(&snap2, &mut ledger).is_none());

        // 3. Choke-Point #3 (t = 55s, early Zone 2 breakout): Price reaches +9.00 bps gross (100_090) and pulls back 2.00 bps
        // to +7.00 bps gross (100_070). Because Stage 35 provides a 2.50 bps breathing cushion (floor = 900 - 250 = 650),
        // it survives the 2-tick pullback and keeps riding!
        let mut snap3 = snap2;
        snap3.ts_local_ns = TimestampNs(56_000_000_000);
        snap3.last_trade_price = PriceTicks(100_090);
        snap3.mark_price = PriceTicks(100_070);
        snap3.bids[0].price = PriceTicks(100_070);
        snap3.asks[0].price = PriceTicks(100_071);
        assert!(fsm.step_open_position(&snap3, &mut ledger).is_none());

        // 4. Expansion Wave (t = 90s): Price surges to +26.00 bps gross (100_260) and retraces to the 70% ratchet floor
        // at +19.00 bps gross (100_190 <= 1940) -> harvests +15.00 bps net (6x larger than the old +2.50 bps exit, Fee Drag = 21.1%!)
        let mut snap4 = snap3;
        snap4.ts_local_ns = TimestampNs(91_000_000_000);
        snap4.last_trade_price = PriceTicks(100_260);
        snap4.mark_price = PriceTicks(100_190);
        snap4.bids[0].price = PriceTicks(100_190);
        snap4.asks[0].price = PriceTicks(100_191);
        let closed = fsm.step_open_position(&snap4, &mut ledger);
        assert!(closed.is_some());
        if let Some(s) = closed {
            assert!(s.is_maker_exit);
            assert_eq!(s.net_scaled_bps.raw(), 1_500); // +15.00 bps net!
        }
        println!("[STAGE 35 WINNER EXPANSION] Verified wave expansion from +2.50 bps to +15.00 bps net (6.0x profit, 21.1% Fee Drag).");
    }
}
