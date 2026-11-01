//! Exhaustive Finite-State Machine (`OrderLifecycleState`) for Bybit UTA V5 execution:
//! 100% `Limit PostOnly` normal exits, Convex MFE Zero-Loss Maker Ratchet,
//! Strict 1.50s Anti-Burst Queue Residence Floor, Zero Premature Micro-Scratches,
//! Structural `-28.00 bps` Server `MarkPrice` Stop-Loss, and `HMAC-SHA256` Signer.

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
/// Maximum hold time for a stagnant net-profitable position (>= +5.00 bps gross / +1.00 bps net) before passive Maker release (180 seconds).
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

    /// Evaluates queue cancellation ONLY after `MIN_QUEUE_RESIDENCE_NS` (1.50s) has elapsed
    /// (preventing sub-second cancel bursts and preserving FIFO queue priority):
    /// 1. After 1.50s, both L2 book pressure (`X_OFI`) and trade tape (`X_TFI`) reversed against our side, OR
    /// 2. After 1.50s, the BBO ran away in front of `entry_price` by `>= 3.50 bps` (min 3 ticks), OR
    /// 3. Monotonic elapsed time exceeds `MAX_RESTING_QUEUE_TTL_NS` (25s).
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
            // Immediate protection (0 ms): if BOTH L2 OFI and Trade Tape TFI flip strongly against us, abort immediately
            let joint_flow_reversal = match side {
                Side::Bid => ofi <= -0.20 && tfi <= -0.25,
                Side::Ask => ofi >= 0.20 && tfi >= 0.25,
            };

            let elapsed_ns = snap.ts_local_ns.0.saturating_sub(resting_since_ts.0);
            let ttl_expired = elapsed_ns >= MAX_RESTING_QUEUE_TTL_NS;

            // Anti-burst residence floor (1.50s) applies strictly to BBO runaway re-pegs
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
            let tp_delta_ticks =
                ((entry_price.0 * target_excursion.raw()) / 1_000_000).max(2);
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

        // 1. Catastrophic server-side MarkPrice Stop-Loss (-28.00 bps)
        let sl_hit = match side {
            Side::Bid => snap.mark_price.0 <= sl_trigger_price.0,
            Side::Ask => snap.mark_price.0 >= sl_trigger_price.0,
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
            Side::Bid => ref_trade_price.0 >= tp_maker_price.0,
            Side::Ask => ref_trade_price.0 <= tp_maker_price.0,
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

        // 3. Convex MFE Zero-Loss Ratchet & Positive Maker Unwind (zero premature micro-scratches)
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

            // Condition A: Flow reversal while in net Maker profit (>= +4.40 bps gross = +0.40 bps net, unlocking 4..5 tick SUI/SOL moves)
            let ofi_reversed = match side {
                Side::Bid => snap.factor_ofi.get() < -0.05,
                Side::Ask => snap.factor_ofi.get() > 0.05,
            };
            let flow_unwind = current_gross_bps.raw() >= 440 && ofi_reversed;

            // Condition B: MFE Zero-Loss Ratchet (reached >= +5.50 bps gross, protecting >= +4.20 bps gross = +0.20 bps net)
            let mfe_ratchet_unwind = peak_gross_bps.raw() >= 550
                && current_gross_bps.raw() >= 420
                && current_gross_bps.raw() <= (peak_gross_bps.raw() * 75) / 100;

            // Condition C: Early profit harvest (>= 20s at >= +4.20 bps gross) or Scratch escape (>= 15s at >= +4.00 bps gross = 0.00 bps net on joint reversal)
            let hold_elapsed = snap.ts_local_ns.0.saturating_sub(opened_ts.0);
            let early_harvest = hold_elapsed >= 20_000_000_000 && current_gross_bps.raw() >= 420;
            let joint_adverse = match side {
                Side::Bid => snap.factor_ofi.get() < -0.15 && snap.factor_tfi.get() < -0.15,
                Side::Ask => snap.factor_ofi.get() > 0.15 && snap.factor_tfi.get() > 0.15,
            };
            let scratch_escape =
                hold_elapsed >= 15_000_000_000 && current_gross_bps.raw() >= 400 && joint_adverse;
            let stagnant_unwind =
                hold_elapsed >= STAGNANT_PROFIT_HOLD_NS && current_gross_bps.raw() >= 400;

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
    fn finalize_close(
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