//! VORTEX-L2 - Institutional Low-Latency Execution Core (`VORTEX-RS-V1.0`).

/// Orthogonal 3-factor microstructural alpha model (`X_OFI`, `X_TFI`, `X_Geom`).
pub mod alpha_3factor;
/// Exhaustive finite-state machine (`ExecutionFsm`) and adaptive governor (`OnlineAdaptiveGovernor`).
pub mod execution_fsm;
/// Deterministic columnar `PAR1` persistence and 1:1 accounting parity ledger.
pub mod forensic_parquet;
/// Lock-free POSIX `/dev/shm` Seqlock L2 order book arena (`SHM v9`).
pub mod lob_shm;
/// Compile-time dimensional newtypes, fixed-point parsers, and SSOT pair specifications.
pub mod types;
