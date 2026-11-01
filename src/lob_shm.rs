//! Zero-allocation L2 Order Book and Hot-State ring over lock-free Seqlock memory.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::types::{BoundedScore, LotQty, PriceTicks, ScaledBps, SymbolId, TimestampNs, VortexError};

/// Canonical depth of Bybit `orderbook.50` stream.
pub const LOB_DEPTH: usize = 50;
/// Maximum number of active institutional pairs in the shared memory segment.
pub const MAX_ACTIVE_PAIRS: usize = 8;
/// Magic header identifying a valid VORTEXL2 shared memory region ("VORTEXL2" in ASCII).
pub const VORTEX_SHM_MAGIC: u64 = 0x564F_5254_4558_4C32;
/// Schema version of the shared memory layout.
pub const VORTEX_SHM_VERSION: u32 = 1;

/// Single price-quantity level in the L2 order book (16 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BookLevel {
    pub price: PriceTicks,
    pub qty: LotQty,
}

/// Immutable snapshot of a symbol's L2 book and pre-warmed orthogonal factors.
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SymbolLobSnapshot {
    pub symbol_id: SymbolId,
    pub is_eligible: bool,
    pub sequence_id: u64,
    pub ts_exchange_ns: TimestampNs,
    pub ts_local_ns: TimestampNs,
    pub mark_price: PriceTicks,
    pub last_trade_price: PriceTicks,
    pub realized_vol_5m: ScaledBps,
    /// Pre-warmed Orthogonal Factor 1: Multi-scale OFI (500ms, 3s, 15s blended).
    pub factor_ofi: BoundedScore,
    /// Pre-warmed Orthogonal Factor 2: Executed Trade Flow Imbalance (publicTrade tape).
    pub factor_tfi: BoundedScore,
    /// Pre-warmed Orthogonal Factor 3: Opposite/Same L1-L10 Liquidity Vacuum Ratio.
    pub factor_geom: BoundedScore,
    pub bids: [BookLevel; LOB_DEPTH],
    pub asks: [BookLevel; LOB_DEPTH],
}

impl Default for SymbolLobSnapshot {
    #[inline]
    fn default() -> Self {
        Self::new_empty()
    }
}

impl SymbolLobSnapshot {
    /// Compile-time zeroed snapshot for static shared-memory initialization.
    #[inline]
    #[must_use]
    pub const fn new_empty() -> Self {
        Self {
            symbol_id: SymbolId(0),
            is_eligible: false,
            sequence_id: 0,
            ts_exchange_ns: TimestampNs(0),
            ts_local_ns: TimestampNs(0),
            mark_price: PriceTicks(0),
            last_trade_price: PriceTicks(0),
            realized_vol_5m: ScaledBps(0),
            factor_ofi: BoundedScore::ZERO,
            factor_tfi: BoundedScore::ZERO,
            factor_geom: BoundedScore::ZERO,
            bids: [BookLevel {
                price: PriceTicks(0),
                qty: LotQty(0),
            }; LOB_DEPTH],
            asks: [BookLevel {
                price: PriceTicks(0),
                qty: LotQty(0),
            }; LOB_DEPTH],
        }
    }

    /// Returns the best bid and best ask (L1 BBO) and the spread in integer ticks.
    #[inline]
    pub const fn bbo_and_spread_ticks(&self) -> Option<(BookLevel, BookLevel, i64)> {
        let best_bid = self.bids[0];
        let best_ask = self.asks[0];
        if best_bid.price.0 <= 0 || best_ask.price.0 <= best_bid.price.0 || best_bid.qty.0 <= 0 || best_ask.qty.0 <= 0 {
            return None;
        }
        let spread = best_ask.price.0 - best_bid.price.0;
        Some((best_bid, best_ask, spread))
    }
}

/// Cache-line aligned Seqlock slot for a single trading pair.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct SeqlockSymbolSlot {
    seq: AtomicU64,
    payload: core::cell::UnsafeCell<SymbolLobSnapshot>,
}

// SAFETY: Single-writer (`vortex-tap`) / single-reader (`vortex-exec`) synchronized via `seq` AtomicU64.
unsafe impl Sync for SeqlockSymbolSlot {}

impl Default for SeqlockSymbolSlot {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SeqlockSymbolSlot {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            payload: core::cell::UnsafeCell::new(SymbolLobSnapshot::new_empty()),
        }
    }

    /// Single-writer lock-free update (`vortex-tap`). Increments `seq` to odd before writing,
    /// and to even on completion with Release ordering.
    #[inline]
    pub fn write_snapshot(&self, snap: &SymbolLobSnapshot) {
        let s0 = self.seq.load(Ordering::Relaxed);
        let s_odd = s0.wrapping_add(1);
        self.seq.store(s_odd, Ordering::Release);
        core::sync::atomic::fence(Ordering::Release);
        // SAFETY: Exclusive writer sets odd sequence counter before mutating payload.
        unsafe {
            core::ptr::write_volatile(self.payload.get(), *snap);
        }
        self.seq.store(s_odd.wrapping_add(1), Ordering::Release);
    }

    /// Lock-free optimistic read (`vortex-exec`). Retries up to `max_retries` if a write is in progress.
    #[inline]
    pub fn read_snapshot(&self, max_retries: usize) -> Result<SymbolLobSnapshot, VortexError> {
        for _ in 0..max_retries {
            let s1 = self.seq.load(Ordering::Acquire);
            if (s1 & 1) != 0 {
                core::hint::spin_loop();
                continue;
            }
            // SAFETY: Volatile read bracketed by sequence parity and equality check.
            let copy = unsafe { core::ptr::read_volatile(self.payload.get()) };
            core::sync::atomic::fence(Ordering::Acquire);
            let s2 = self.seq.load(Ordering::Acquire);
            if s1 == s2 {
                return Ok(copy);
            }
            core::hint::spin_loop();
        }
        Err(VortexError::SharedMemorySeqConflict)
    }
}

/// Complete shared memory arena (`/dev/shm/vortex_lob.mmap`).
#[repr(C, align(64))]
#[derive(Debug)]
pub struct VortexShmArena {
    pub magic: u64,
    pub version: u32,
    pub active_pairs: u32,
    pub heartbeat_ns: AtomicU64,
    pub slots: [SeqlockSymbolSlot; MAX_ACTIVE_PAIRS],
}

impl Default for VortexShmArena {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl VortexShmArena {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            magic: VORTEX_SHM_MAGIC,
            version: VORTEX_SHM_VERSION,
            active_pairs: MAX_ACTIVE_PAIRS as u32,
            heartbeat_ns: AtomicU64::new(0),
            slots: [
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
                SeqlockSymbolSlot::new(),
            ],
        }
    }

    #[inline]
    pub fn slot(&self, idx: usize) -> Result<&SeqlockSymbolSlot, VortexError> {
        self.slots.get(idx).ok_or(VortexError::InvalidSymbolSlot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seqlock_roundtrip_and_bbo_spread() {
        let arena = VortexShmArena::new();
        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            is_eligible: true,
            sequence_id: 42,
            ts_exchange_ns: TimestampNs(1_700_000_000_000_000_000),
            ts_local_ns: TimestampNs(1_700_000_000_005_000_000),
            mark_price: PriceTicks(25_000),
            last_trade_price: PriceTicks(25_001),
            realized_vol_5m: ScaledBps::from_whole_bps(55),
            factor_ofi: BoundedScore::new_clamped(0.68),
            factor_tfi: BoundedScore::new_clamped(0.74),
            factor_geom: BoundedScore::new_clamped(0.52),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(25_000),
            qty: LotQty(150),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(25_001),
            qty: LotQty(120),
        };

        let slot = arena.slot(0);
        assert!(slot.is_ok());
        if let Ok(s) = slot {
            s.write_snapshot(&snap);
            let read_back = s.read_snapshot(8);
            assert_eq!(read_back, Ok(snap));
            if let Ok(rb) = read_back {
                assert_eq!(
                    rb.bbo_and_spread_ticks(),
                    Some((snap.bids[0], snap.asks[0], 1))
                );
            }
        }
    }
}