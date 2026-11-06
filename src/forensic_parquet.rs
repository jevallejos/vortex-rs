//! Deterministic columnar `PAR1` persistence for `orderbook.50` + `publicTrade`
//! and 1:1 Bybit UTA V5 `PARITY_SYNC` accounting ledger.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::lob_shm::SymbolLobSnapshot;
use crate::types::{LotQty, PriceTicks, Side, SymbolId, TimestampNs, VortexError};

/// Official Apache Parquet 4-byte magic header/footer ("PAR1").
pub const PARQUET_MAGIC: [u8; 4] = *b"PAR1";
/// Maximum records per pre-allocated in-memory columnar batch before disk flush.
pub const COLUMNAR_BATCH_CAP: usize = 256;
/// Maximum allowed accounting drift between internal ledger and Bybit UTA V5: 0.0001 USDT (10_000 in 1e8 scale).
pub const MAX_PARITY_DRIFT_1E8: i64 = 10_000;

/// Event source recorded in the columnar stream.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MarketEventKind {
    /// Variant L2BookSnapshot.
    L2BookSnapshot = 1,
    /// Variant PublicTradePrint.
    PublicTradePrint = 2,
}

/// Single normalized market event for replay and forensic attribution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ColumnarMarketRow {
    /// Field symbol_id.
    pub symbol_id: SymbolId,
    /// Field event_kind.
    pub event_kind: MarketEventKind,
    /// Field side.
    pub side: Side,
    /// Field sequence_id.
    pub sequence_id: u64,
    /// Field ts_exchange_ns.
    pub ts_exchange_ns: TimestampNs,
    /// Field ts_local_ns.
    pub ts_local_ns: TimestampNs,
    /// Field price_ticks.
    pub price_ticks: PriceTicks,
    /// Field lot_qty.
    pub lot_qty: LotQty,
    /// Field best_bid_ticks.
    pub best_bid_ticks: PriceTicks,
    /// Field best_ask_ticks.
    pub best_ask_ticks: PriceTicks,
    /// Field best_bid_qty.
    pub best_bid_qty: LotQty,
    /// Field best_ask_qty.
    pub best_ask_qty: LotQty,
    /// Field mark_price_ticks.
    pub mark_price_ticks: PriceTicks,
    /// Field ofi_bps.
    pub ofi_bps: i32,
    /// Field tfi_bps.
    pub tfi_bps: i32,
    /// Field geom_bps.
    pub geom_bps: i32,
}

/// Columnar batch storing homogeneous arrays for cache-friendly vectorized replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnarParquetBatch {
    len: usize,
    /// Field symbol_id.
    pub symbol_id: [u16; COLUMNAR_BATCH_CAP],
    /// Field event_kind.
    pub event_kind: [u8; COLUMNAR_BATCH_CAP],
    /// Field side.
    pub side: [u8; COLUMNAR_BATCH_CAP],
    /// Field sequence_id.
    pub sequence_id: [u64; COLUMNAR_BATCH_CAP],
    /// Field ts_exchange_ns.
    pub ts_exchange_ns: [i64; COLUMNAR_BATCH_CAP],
    /// Field ts_local_ns.
    pub ts_local_ns: [i64; COLUMNAR_BATCH_CAP],
    /// Field price_ticks.
    pub price_ticks: [i64; COLUMNAR_BATCH_CAP],
    /// Field lot_qty.
    pub lot_qty: [i64; COLUMNAR_BATCH_CAP],
    /// Field best_bid_ticks.
    pub best_bid_ticks: [i64; COLUMNAR_BATCH_CAP],
    /// Field best_ask_ticks.
    pub best_ask_ticks: [i64; COLUMNAR_BATCH_CAP],
    /// Field best_bid_qty.
    pub best_bid_qty: [i64; COLUMNAR_BATCH_CAP],
    /// Field best_ask_qty.
    pub best_ask_qty: [i64; COLUMNAR_BATCH_CAP],
    /// Field mark_price_ticks.
    pub mark_price_ticks: [i64; COLUMNAR_BATCH_CAP],
    /// Field ofi_bps.
    pub ofi_bps: [i32; COLUMNAR_BATCH_CAP],
    /// Field tfi_bps.
    pub tfi_bps: [i32; COLUMNAR_BATCH_CAP],
    /// Field geom_bps.
    pub geom_bps: [i32; COLUMNAR_BATCH_CAP],
}

impl Default for ColumnarParquetBatch {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ColumnarParquetBatch {
    /// pub const fn new.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            len: 0,
            symbol_id: [0; COLUMNAR_BATCH_CAP],
            event_kind: [0; COLUMNAR_BATCH_CAP],
            side: [0; COLUMNAR_BATCH_CAP],
            sequence_id: [0; COLUMNAR_BATCH_CAP],
            ts_exchange_ns: [0; COLUMNAR_BATCH_CAP],
            ts_local_ns: [0; COLUMNAR_BATCH_CAP],
            price_ticks: [0; COLUMNAR_BATCH_CAP],
            lot_qty: [0; COLUMNAR_BATCH_CAP],
            best_bid_ticks: [0; COLUMNAR_BATCH_CAP],
            best_ask_ticks: [0; COLUMNAR_BATCH_CAP],
            best_bid_qty: [0; COLUMNAR_BATCH_CAP],
            best_ask_qty: [0; COLUMNAR_BATCH_CAP],
            mark_price_ticks: [0; COLUMNAR_BATCH_CAP],
            ofi_bps: [0; COLUMNAR_BATCH_CAP],
            tfi_bps: [0; COLUMNAR_BATCH_CAP],
            geom_bps: [0; COLUMNAR_BATCH_CAP],
        }
    }

    /// Returns the number of rows currently stored in the batch.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the batch contains zero rows.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Resets the batch row counter to zero without deallocating.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Appends a row into the columnar arrays without heap allocation.
    #[inline]
    pub fn push_row(&mut self, row: &ColumnarMarketRow) -> Result<(), VortexError> {
        if self.len >= COLUMNAR_BATCH_CAP {
            return Err(VortexError::BatchCapacityExceeded);
        }
        let idx = self.len;
        self.symbol_id[idx] = row.symbol_id.0;
        self.event_kind[idx] = row.event_kind as u8;
        self.side[idx] = row.side as u8;
        self.sequence_id[idx] = row.sequence_id;
        self.ts_exchange_ns[idx] = row.ts_exchange_ns.0;
        self.ts_local_ns[idx] = row.ts_local_ns.0;
        self.price_ticks[idx] = row.price_ticks.0;
        self.lot_qty[idx] = row.lot_qty.0;
        self.best_bid_ticks[idx] = row.best_bid_ticks.0;
        self.best_ask_ticks[idx] = row.best_ask_ticks.0;
        self.best_bid_qty[idx] = row.best_bid_qty.0;
        self.best_ask_qty[idx] = row.best_ask_qty.0;
        self.mark_price_ticks[idx] = row.mark_price_ticks.0;
        self.ofi_bps[idx] = row.ofi_bps;
        self.tfi_bps[idx] = row.tfi_bps;
        self.geom_bps[idx] = row.geom_bps;
        self.len += 1;
        Ok(())
    }

    /// Appends an L2 snapshot directly into the columnar batch.
    #[inline]
    pub fn push_l2_snapshot(&mut self, snap: &SymbolLobSnapshot) -> Result<(), VortexError> {
        let best_bid = snap.bids[0];
        let best_ask = snap.asks[0];
        let row = ColumnarMarketRow {
            symbol_id: snap.symbol_id,
            event_kind: MarketEventKind::L2BookSnapshot,
            side: Side::Bid,
            sequence_id: snap.sequence_id,
            ts_exchange_ns: snap.ts_exchange_ns,
            ts_local_ns: snap.ts_local_ns,
            price_ticks: snap.last_trade_price,
            lot_qty: LotQty(0),
            best_bid_ticks: best_bid.price,
            best_ask_ticks: best_ask.price,
            best_bid_qty: best_bid.qty,
            best_ask_qty: best_ask.qty,
            mark_price_ticks: snap.mark_price,
            ofi_bps: snap.factor_ofi.to_bps_i32(),
            tfi_bps: snap.factor_tfi.to_bps_i32(),
            geom_bps: snap.factor_geom.to_bps_i32(),
        };
        self.push_row(&row)
    }

    /// Reconstructs a `ColumnarMarketRow` at index `idx` for `vortex-replay`.
    #[inline]
    pub const fn row_at(&self, idx: usize) -> Option<ColumnarMarketRow> {
        if idx >= self.len {
            return None;
        }
        let event_kind = if self.event_kind[idx] == 2 {
            MarketEventKind::PublicTradePrint
        } else {
            MarketEventKind::L2BookSnapshot
        };
        let side = if self.side[idx] == 1 {
            Side::Ask
        } else {
            Side::Bid
        };
        Some(ColumnarMarketRow {
            symbol_id: SymbolId(self.symbol_id[idx]),
            event_kind,
            side,
            sequence_id: self.sequence_id[idx],
            ts_exchange_ns: TimestampNs(self.ts_exchange_ns[idx]),
            ts_local_ns: TimestampNs(self.ts_local_ns[idx]),
            price_ticks: PriceTicks(self.price_ticks[idx]),
            lot_qty: LotQty(self.lot_qty[idx]),
            best_bid_ticks: PriceTicks(self.best_bid_ticks[idx]),
            best_ask_ticks: PriceTicks(self.best_ask_ticks[idx]),
            best_bid_qty: LotQty(self.best_bid_qty[idx]),
            best_ask_qty: LotQty(self.best_ask_qty[idx]),
            mark_price_ticks: PriceTicks(self.mark_price_ticks[idx]),
            ofi_bps: self.ofi_bps[idx],
            tfi_bps: self.tfi_bps[idx],
            geom_bps: self.geom_bps[idx],
        })
    }

    /// Computes 64-bit FNV-1a checksum over all active rows in the batch.
    #[inline]
    #[must_use]
    pub fn compute_fnv1a64(&self) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let prime: u64 = 0x0100_0000_01b3;
        let mut idx = 0;
        while idx < self.len {
            for b in self.symbol_id[idx].to_le_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(prime);
            }
            hash ^= u64::from(self.event_kind[idx]);
            hash = hash.wrapping_mul(prime);
            hash ^= u64::from(self.side[idx]);
            hash = hash.wrapping_mul(prime);
            for b in self.sequence_id[idx].to_le_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(prime);
            }
            for b in self.ts_local_ns[idx].to_le_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(prime);
            }
            for b in self.price_ticks[idx].to_le_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(prime);
            }
            for b in self.lot_qty[idx].to_le_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(prime);
            }
            idx += 1;
        }
        hash
    }

    /// Flushes the columnar batch to a file with `PAR1` header/footer and FNV-1a 64-bit integrity seal.
    pub fn write_to_file(&self, path: &Path) -> Result<u64, VortexError> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);

        w.write_all(&PARQUET_MAGIC)
            ?;
        let count_u32 = (self.len as u32).to_le_bytes();
        w.write_all(&count_u32)
            ?;

        for i in 0..self.len {
            w.write_all(&self.symbol_id[i].to_le_bytes())
                ?;
            w.write_all(&[self.event_kind[i], self.side[i]])
                ?;
            w.write_all(&self.sequence_id[i].to_le_bytes())
                ?;
            w.write_all(&self.ts_exchange_ns[i].to_le_bytes())
                ?;
            w.write_all(&self.ts_local_ns[i].to_le_bytes())
                ?;
            w.write_all(&self.price_ticks[i].to_le_bytes())
                ?;
            w.write_all(&self.lot_qty[i].to_le_bytes())
                ?;
            w.write_all(&self.best_bid_ticks[i].to_le_bytes())
                ?;
            w.write_all(&self.best_ask_ticks[i].to_le_bytes())
                ?;
            w.write_all(&self.best_bid_qty[i].to_le_bytes())
                ?;
            w.write_all(&self.best_ask_qty[i].to_le_bytes())
                ?;
            w.write_all(&self.mark_price_ticks[i].to_le_bytes())
                ?;
            w.write_all(&self.ofi_bps[i].to_le_bytes())
                ?;
            w.write_all(&self.tfi_bps[i].to_le_bytes())
                ?;
            w.write_all(&self.geom_bps[i].to_le_bytes())
                ?;
        }

        let checksum = self.compute_fnv1a64();
        w.write_all(&checksum.to_le_bytes())
            ?;
        w.write_all(&PARQUET_MAGIC)
            ?;
        w.flush()?;
        Ok(checksum)
    }

    /// Reads and verifies a `PAR1` columnar batch from disk.
    pub fn read_from_file(path: &Path) -> Result<Self, VortexError> {
        let file = File::open(path)?;
        let mut r = BufReader::new(file);

        let mut magic_head = [0_u8; 4];
        r.read_exact(&mut magic_head)
            ?;
        if magic_head != PARQUET_MAGIC {
            return Err(VortexError::ColumnarFormatCorrupted);
        }

        let mut count_buf = [0_u8; 4];
        r.read_exact(&mut count_buf)
            ?;
        let count = u32::from_le_bytes(count_buf) as usize;
        if count > COLUMNAR_BATCH_CAP {
            return Err(VortexError::BatchCapacityExceeded);
        }

        let mut batch = Self::new();
        batch.len = count;

        for i in 0..count {
            let mut b2 = [0_u8; 2];
            let mut b4 = [0_u8; 4];
            let mut b8 = [0_u8; 8];

            r.read_exact(&mut b2)
                ?;
            batch.symbol_id[i] = u16::from_le_bytes(b2);

            r.read_exact(&mut b2)
                ?;
            batch.event_kind[i] = b2[0];
            batch.side[i] = b2[1];

            r.read_exact(&mut b8)
                ?;
            batch.sequence_id[i] = u64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.ts_exchange_ns[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.ts_local_ns[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.price_ticks[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.lot_qty[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.best_bid_ticks[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.best_ask_ticks[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.best_bid_qty[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.best_ask_qty[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b8)
                ?;
            batch.mark_price_ticks[i] = i64::from_le_bytes(b8);

            r.read_exact(&mut b4)
                ?;
            batch.ofi_bps[i] = i32::from_le_bytes(b4);

            r.read_exact(&mut b4)
                ?;
            batch.tfi_bps[i] = i32::from_le_bytes(b4);

            r.read_exact(&mut b4)
                ?;
            batch.geom_bps[i] = i32::from_le_bytes(b4);
        }

        let mut checksum_buf = [0_u8; 8];
        r.read_exact(&mut checksum_buf)
            ?;
        let stored_checksum = u64::from_le_bytes(checksum_buf);

        let mut magic_foot = [0_u8; 4];
        r.read_exact(&mut magic_foot)
            ?;
        if magic_foot != PARQUET_MAGIC || batch.compute_fnv1a64() != stored_checksum {
            return Err(VortexError::ColumnarFormatCorrupted);
        }

        Ok(batch)
    }
}

/// 1:1 Accounting Parity Guard (`PARITY_SYNC`) against Bybit UTA V5 wallet equity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ParitySyncLedger {
    /// Field initial_equity_1e8.
    pub initial_equity_1e8: i64,
    /// Field cumulative_net_pnl_1e8.
    pub cumulative_net_pnl_1e8: i64,
    /// Field cumulative_fees_1e8.
    pub cumulative_fees_1e8: i64,
    /// Field closed_trades_count.
    pub closed_trades_count: u64,
}

impl ParitySyncLedger {
    /// pub const fn new.
    #[inline]
    #[must_use]
    pub const fn new(initial_equity_1e8: i64) -> Self {
        Self {
            initial_equity_1e8,
            cumulative_net_pnl_1e8: 0,
            cumulative_fees_1e8: 0,
            closed_trades_count: 0,
        }
    }

    /// Records a closed trade gross PnL and fee into the cumulative parity ledger.
    #[inline]
    pub fn record_closed_trade(&mut self, gross_pnl_1e8: i64, fee_1e8: i64) {
        let net = gross_pnl_1e8 - fee_1e8;
        self.cumulative_net_pnl_1e8 += net;
        self.cumulative_fees_1e8 += fee_1e8;
        self.closed_trades_count += 1;
    }

    /// Verifies that internal accounting matches `exchange_wallet_balance_1e8` within `MAX_PARITY_DRIFT_1E8`.
    #[inline]
    pub const fn verify_exchange_parity(&self, exchange_wallet_balance_1e8: i64) -> Result<i64, VortexError> {
        let expected_internal = self.initial_equity_1e8 + self.cumulative_net_pnl_1e8;
        let drift = (expected_internal - exchange_wallet_balance_1e8).abs();
        if drift > MAX_PARITY_DRIFT_1E8 {
            return Err(VortexError::AccountingParityDrift {
                internal_balance_1e8: expected_internal,
                exchange_balance_1e8: exchange_wallet_balance_1e8,
                drift_1e8: drift,
            });
        }
        Ok(drift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lob_shm::BookLevel;
    use crate::types::BoundedScore;

    #[test]
    fn test_columnar_parquet_roundtrip_and_checksum_integrity() {
        let mut batch = ColumnarParquetBatch::new();
        let mut snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            is_eligible: true,
            sequence_id: 777,
            ts_exchange_ns: TimestampNs(1_700_000_000_000_000_000),
            ts_local_ns: TimestampNs(1_700_000_000_001_000_000),
            mark_price: PriceTicks(776_700),
            last_trade_price: PriceTicks(776_705),
            factor_ofi: BoundedScore::new_clamped(0.55),
            factor_tfi: BoundedScore::new_clamped(0.48),
            factor_geom: BoundedScore::new_clamped(0.31),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(776_700),
            qty: LotQty(250),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(776_701),
            qty: LotQty(180),
        };

        assert_eq!(batch.push_l2_snapshot(&snap), Ok(()));
        let temp_path = std::env::temp_dir().join("vortex_test_stage3b.parquet");
        let write_res = batch.write_to_file(&temp_path);
        assert!(write_res.is_ok());

        let loaded = ColumnarParquetBatch::read_from_file(&temp_path);
        let _ = std::fs::remove_file(&temp_path);
        assert_eq!(loaded, Ok(batch));
    }

    #[test]
    fn test_parity_sync_ledger_detects_micro_drift() {
        let mut ledger = ParitySyncLedger::new(5_200_000_000); // 52.00000000 USDT
        ledger.record_closed_trade(15_000_000, 3_000_000); // +0.12000000 USDT net
        assert_eq!(ledger.verify_exchange_parity(5_212_005_000), Ok(5_000));
        assert!(matches!(
            ledger.verify_exchange_parity(5_210_000_000),
            Err(VortexError::AccountingParityDrift { .. })
        ));
    }
}