//! Zero-allocation L2 Order Book and Hot-State ring over lock-free Seqlock memory,
//! backed by POSIX `/dev/shm/vortex_lob.mmap` (`MAP_SHARED`) on Linux.

use core::sync::atomic::{AtomicU64, Ordering};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use crate::types::{BoundedScore, LotQty, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs, VortexError};

/// Canonical depth of Bybit `orderbook.50` stream.
pub const LOB_DEPTH: usize = 50;
/// Maximum number of active institutional pairs in the shared memory segment.
pub const MAX_ACTIVE_PAIRS: usize = 8;
/// Magic header identifying a valid VORTEXL2 shared memory region ("VORTEXL2" in ASCII).
pub const VORTEX_SHM_MAGIC: u64 = 0x564F_5254_4558_4C32;
/// Schema version of the shared memory layout (v5 adds MFE peak price tracking).
pub const VORTEX_SHM_VERSION: u32 = 5;
/// Canonical POSIX shared-memory path on Ubuntu Linux production nodes.
pub const DEFAULT_LINUX_SHM_PATH: &str = "/dev/shm/vortex_lob.mmap";

/// Single price-quantity level in the L2 order book (16 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BookLevel {
    pub price: PriceTicks,
    pub qty: LotQty,
}

/// Immutable snapshot of a symbol's L2 book, cumulative trade-tape volume, and pre-warmed orthogonal factors.
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
    pub cum_buy_trade_lots: LotQty,
    pub cum_sell_trade_lots: LotQty,
    pub realized_vol_5m: ScaledBps,
    pub factor_ofi: BoundedScore,
    pub factor_tfi: BoundedScore,
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
            cum_buy_trade_lots: LotQty(0),
            cum_sell_trade_lots: LotQty(0),
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

    #[inline]
    pub fn clear_book(&mut self) {
        self.bids = [BookLevel::default(); LOB_DEPTH];
        self.asks = [BookLevel::default(); LOB_DEPTH];
    }

    #[inline]
    pub fn apply_level_update(&mut self, side: Side, price: PriceTicks, qty: LotQty) {
        if price.0 <= 0 {
            return;
        }
        let levels = match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        };

        let mut existing_idx: Option<usize> = None;
        let mut i = 0;
        while i < LOB_DEPTH {
            if levels[i].price.0 == price.0 {
                existing_idx = Some(i);
                break;
            }
            if levels[i].price.0 == 0 {
                break;
            }
            i += 1;
        }

        if let Some(idx) = existing_idx {
            if qty.0 <= 0 {
                let mut k = idx;
                while k + 1 < LOB_DEPTH {
                    levels[k] = levels[k + 1];
                    k += 1;
                }
                levels[LOB_DEPTH - 1] = BookLevel::default();
            } else {
                levels[idx].qty = qty;
            }
            return;
        }

        if qty.0 <= 0 {
            return;
        }

        let mut ins_idx = LOB_DEPTH;
        let mut j = 0;
        while j < LOB_DEPTH {
            let cur_p = levels[j].price.0;
            let should_insert_before = match side {
                Side::Bid => cur_p == 0 || price.0 > cur_p,
                Side::Ask => cur_p == 0 || price.0 < cur_p,
            };
            if should_insert_before {
                ins_idx = j;
                break;
            }
            j += 1;
        }

        if ins_idx < LOB_DEPTH {
            let mut m = LOB_DEPTH - 1;
            while m > ins_idx {
                levels[m] = levels[m - 1];
                m -= 1;
            }
            levels[ins_idx] = BookLevel { price, qty };
        }
    }

    #[inline]
    pub const fn bbo_and_spread_ticks(&self) -> Option<(BookLevel, BookLevel, i64)> {
        let best_bid = self.bids[0];
        let best_ask = self.asks[0];
        if best_bid.price.0 <= 0
            || best_ask.price.0 <= best_bid.price.0
            || best_bid.qty.0 <= 0
            || best_ask.qty.0 <= 0
        {
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
    pub exec_state_code: AtomicU64,
    pub exec_active_slot: AtomicU64,
    pub exec_active_symbol: AtomicU64,
    pub exec_side: AtomicU64,
    pub exec_entry_ticks: AtomicU64,
    pub exec_peak_ticks: AtomicU64,
    pub exec_tp_ticks: AtomicU64,
    pub exec_sl_ticks: AtomicU64,
    pub exec_resting_since_ns: AtomicU64,
    pub exec_queue_ahead_lots: AtomicU64,
    pub exec_armed_count: AtomicU64,
    pub exec_abort_count: AtomicU64,
    pub exec_fill_count: AtomicU64,
    pub exec_closed_count: AtomicU64,
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
            exec_state_code: AtomicU64::new(0),
            exec_active_slot: AtomicU64::new(0),
            exec_active_symbol: AtomicU64::new(0),
            exec_side: AtomicU64::new(0),
            exec_entry_ticks: AtomicU64::new(0),
            exec_peak_ticks: AtomicU64::new(0),
            exec_tp_ticks: AtomicU64::new(0),
            exec_sl_ticks: AtomicU64::new(0),
            exec_resting_since_ns: AtomicU64::new(0),
            exec_queue_ahead_lots: AtomicU64::new(0),
            exec_armed_count: AtomicU64::new(0),
            exec_abort_count: AtomicU64::new(0),
            exec_fill_count: AtomicU64::new(0),
            exec_closed_count: AtomicU64::new(0),
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

#[cfg(unix)]
extern "C" {
    fn mmap(
        addr: *mut core::ffi::c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut core::ffi::c_void;
    fn munmap(addr: *mut core::ffi::c_void, length: usize) -> i32;
}

/// Cross-process memory-mapped wrapper for `VortexShmArena`.
#[derive(Debug)]
pub struct MappedShmRegion {
    #[cfg(unix)]
    ptr: *mut VortexShmArena,
    #[cfg(unix)]
    len: usize,
    #[cfg(not(unix))]
    arena: Box<VortexShmArena>,
}

impl MappedShmRegion {
    #[must_use]
    pub fn default_shm_path() -> PathBuf {
        let dev_shm = Path::new("/dev/shm");
        if dev_shm.exists() {
            dev_shm.join("vortex_lob.mmap")
        } else {
            std::env::temp_dir().join("vortex_lob.mmap")
        }
    }

    pub fn open_or_create(path: &Path, _initialize_writer: bool) -> Result<Self, VortexError> {
        let size = core::mem::size_of::<VortexShmArena>();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| VortexError::ColumnarIoFailure)?;

        file.set_len(size as u64)
            .map_err(|_| VortexError::ColumnarIoFailure)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            const PROT_READ: i32 = 0x1;
            const PROT_WRITE: i32 = 0x2;
            const MAP_SHARED: i32 = 0x01;

            // SAFETY: File descriptor is valid and sized to `size_of::<VortexShmArena>()`.
            let raw_ptr = unsafe {
                mmap(
                    core::ptr::null_mut(),
                    size,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if raw_ptr.is_null() || (raw_ptr as usize) == usize::MAX {
                return Err(VortexError::ColumnarIoFailure);
            }
            let arena_ptr = raw_ptr.cast::<VortexShmArena>();
            // SAFETY: `arena_ptr` points to a valid page-aligned `MAP_SHARED` region of `size` bytes.
            unsafe {
                let current_magic = core::ptr::read_volatile(&(*arena_ptr).magic);
                let current_version = core::ptr::read_volatile(&(*arena_ptr).version);
                if current_magic != VORTEX_SHM_MAGIC || current_version != VORTEX_SHM_VERSION {
                    core::ptr::write(arena_ptr, VortexShmArena::new());
                }
            }
            Ok(Self {
                ptr: arena_ptr,
                len: size,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                arena: Box::new(VortexShmArena::new()),
            })
        }
    }

    #[inline]
    #[must_use]
    pub fn arena(&self) -> &VortexShmArena {
        #[cfg(unix)]
        {
            // SAFETY: `self.ptr` remains valid for the lifetime of `MappedShmRegion`.
            unsafe { &*self.ptr }
        }
        #[cfg(not(unix))]
        {
            &self.arena
        }
    }
}

#[cfg(unix)]
impl Drop for MappedShmRegion {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            // SAFETY: Unmaps the region previously mapped in `open_or_create`.
            unsafe {
                let _ = munmap(self.ptr.cast::<core::ffi::c_void>(), self.len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_delta_book_maintenance_sorted_and_zero_removal() {
        let mut snap = SymbolLobSnapshot::new_empty();
        snap.apply_level_update(Side::Bid, PriceTicks(100), LotQty(50));
        snap.apply_level_update(Side::Bid, PriceTicks(102), LotQty(30));
        snap.apply_level_update(Side::Bid, PriceTicks(101), LotQty(40));
        assert_eq!(snap.bids[0].price, PriceTicks(102));
        assert_eq!(snap.bids[1].price, PriceTicks(101));
        assert_eq!(snap.bids[2].price, PriceTicks(100));

        snap.apply_level_update(Side::Bid, PriceTicks(101), LotQty(0));
        assert_eq!(snap.bids[0].price, PriceTicks(102));
        assert_eq!(snap.bids[1].price, PriceTicks(100));
        assert_eq!(snap.bids[2].price, PriceTicks(0));
    }

    #[test]
    fn test_seqlock_roundtrip_and_bbo_spread() {
        let shm_path = std::env::temp_dir().join("vortex_test_shm_region_v5.mmap");
        let region = MappedShmRegion::open_or_create(&shm_path, true);
        assert!(region.is_ok());
        if let Ok(reg) = region {
            let arena = reg.arena();
            let mut snap = SymbolLobSnapshot {
                symbol_id: SymbolId(1),
                is_eligible: true,
                sequence_id: 42,
                ts_exchange_ns: TimestampNs(1_700_000_000_000_000_000),
                ts_local_ns: TimestampNs(1_700_000_000_005_000_000),
                mark_price: PriceTicks(25_000),
                last_trade_price: PriceTicks(25_001),
                cum_buy_trade_lots: LotQty(500),
                cum_sell_trade_lots: LotQty(300),
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
        let _ = std::fs::remove_file(&shm_path);
    }
}