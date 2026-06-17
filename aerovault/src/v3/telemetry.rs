//! Optional telemetry seam for AEROVAULT3 operations.
//!
//! The crate's vault operations are pure and emit no telemetry by default. An
//! embedder (the AeroFTP application, mainly) can attach a [`VaultTelemetrySink`]
//! to an [`OpenVaultV3`](super::vault::OpenVaultV3) via
//! [`set_telemetry_sink`](super::vault::OpenVaultV3::set_telemetry_sink) to
//! receive a behind-the-scenes "receipt" of what the content pipeline did
//! (chunking, dedup, compression, packing, Error Correction) without the crate
//! depending on the embedder's report type.
//!
//! The events mirror the instrumentation points the application historically
//! inlined, so the receipt it builds is byte-for-byte the same as before the app
//! converged onto the crate. When no sink is attached every call is a no-op and
//! the produced container bytes are unchanged (the T5 golden proves this).

// SPDX-License-Identifier: GPL-3.0-only

/// A sink that receives technical telemetry events as an AEROVAULT3 operation
/// runs. All methods default to no-ops so an embedder only implements what it
/// needs. Must be `Send` so an [`OpenVaultV3`](super::vault::OpenVaultV3) carrying
/// one can move into a blocking worker thread.
pub trait VaultTelemetrySink: Send {
    /// One content block was ingested. `is_new` is false for a dedup hit (the
    /// block already existed, so `compressed`/`encrypted` are 0 and `plaintext`
    /// is the deduplicated chunk's plaintext length).
    fn on_chunk(&mut self, _is_new: bool, _plaintext: u64, _compressed: u64, _encrypted: u64) {}

    /// One file entry was added. `packed` is true when it came through the
    /// small-file packing path rather than the per-file path.
    fn on_file(&mut self, _packed: bool) {}

    /// One pack (a batch of small files) was assembled and chunked.
    fn on_pack(&mut self) {}

    /// The content-defined-chunking bounds in effect for the operation.
    fn set_cdc(&mut self, _min: usize, _avg: usize, _max: usize) {}

    /// Error Correction parity was (re)computed on seal: total shards, bytes of
    /// the protected block stream, and the measured overhead percentage.
    fn set_error_correction(&mut self, _shards: u64, _bytes_protected: u64, _overhead_pct: f64) {}

    /// A human-readable step line for the receipt's behind-the-scenes log.
    fn step(&mut self, _message: &str) {}
}
