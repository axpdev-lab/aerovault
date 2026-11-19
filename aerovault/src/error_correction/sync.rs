// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Windowed `.aerocorrect` error correction for streamed / sync use cases.
//!
//! Single implementation of the windowed-sidecar generate + external-hash verify/repair
//! API. The AeroFTP app's AeroSync download path and its standalone `correct` command
//! both route here (M7 convergence: the app no longer keeps a forked copy). Sidecar bytes
//! are byte-identical to the app's prior output (cross-impl golden T5).
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

use super::sidecar::{
    aerocorrect_sidecar_path, aerocorrect_windows, estimate_windowed_sidecar_len,
    validate_window_tiling, validate_window_tiling_iter, AeroCorrectSegment, AeroCorrectSidecar,
    AeroCorrectSidecarReader, AEROCORRECT_WINDOW_SIZE,
};
use super::{
    compute_error_correction_shards_grid, error_correction_grid, reconstruct_from_error_correction,
    scan_error_correction_health, ShardHealth,
};

/// Default per-file cap for sync error correction. Windowed streaming bounds the
/// *plaintext* memory of generation/verification/repair to a single window
/// (`AEROCORRECT_WINDOW_SIZE`), so a large file no longer has to fit in RAM. The cap
/// still prevents accidental huge explicit EC runs in the sync pipeline; callers may
/// raise `max_file_size` when they intentionally accept the transfer/storage cost.
pub const AEROSYNC_EC_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Read buffer for the streaming hash pass (fast verify). Independent of the parity
/// window; just bounds the read syscall size.
const HASH_READ_CHUNK: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SyncEcGeneratedSidecar {
    pub sidecar_bytes: Vec<u8>,
    pub file_size: u64,
    pub file_sha256: [u8; 32],
    pub shards: u64,
    pub bytes_protected: u64,
    pub overhead_pct: f64,
    pub avec_payload_len: u64,
    pub sidecar_len: u64,
}

#[derive(Debug, Clone)]
pub enum SyncEcGenerateResult {
    Generated(SyncEcGeneratedSidecar),
    SkippedTooLarge {
        file_size: u64,
        max_file_size: u64,
    },
    /// The sidecar's storage cost would exceed the caller's minimum-benefit threshold
    /// (its size as a percentage of the file is above `max_overhead_pct`). Tiny files hit
    /// this because the fixed parity-shard floor makes even a 100-byte file produce a
    /// multi-KiB sidecar. `overhead_pct` is the rejected ratio (sidecar bytes * 100 / file
    /// bytes). Only produced when the caller opts in (`max_overhead_pct > 0`).
    SkippedLowBenefit {
        file_size: u64,
        overhead_pct: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEcRepairResult {
    Verified,
    Repaired { recovered_shards: usize },
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn parse_sha256_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|e| format!("invalid SHA-256 hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "invalid SHA-256 hex length".to_string())?;
    Ok(arr)
}

pub fn sync_error_correction_sidecar_path(remote_path: &str) -> String {
    aerocorrect_sidecar_path(remote_path)
}

/// Exact serialized size (in bytes) of the `.aerocorrect` sidecar that
/// `generate_sync_sidecar_for_bytes` produces for a `file_size`-byte file at overhead level
/// `pct`, derived from the same v2 fixed-grid geometry WITHOUT allocating or hashing.
///
/// This is the source of truth for the sync-doctor cost preview. A flat `size * pct / 100`
/// underestimates the real sidecar by orders of magnitude for small files (the
/// `ERROR_CORRECTION_MIN_SHARD` floor forces ≥4 KiB parity shards) and under-reports at the
/// `ERROR_CORRECTION_MAX_SHARD` cliff. It now also accounts for the per-window segment headers
/// of a windowed (large-file) sidecar.
///
/// Invariant (checked by `aerosync_estimate_matches_real_sidecar_len`):
/// `estimate_aerorec_sidecar_len(n, pct) == generate_sync_sidecar_for_bytes(_, &[_; n], pct).sidecar_len`.
pub fn estimate_aerorec_sidecar_len(file_size: u64, pct: u32) -> u64 {
    estimate_windowed_sidecar_len(file_size, pct, AEROCORRECT_WINDOW_SIZE)
}

/// Build a windowed sidecar from an in-memory buffer: one segment per window, each
/// carrying that window's own RS parity. Returns the sidecar plus aggregate telemetry.
fn build_windowed_sidecar(data: &[u8], pct: u32, window: u64) -> (AeroCorrectSidecar, u64, u64) {
    let file_size = data.len() as u64;
    let (k, p) = error_correction_grid(pct);
    let mut segments = Vec::new();
    let mut total_shards = 0u64;
    let mut total_avec = 0u64;
    for (off, len) in aerocorrect_windows(file_size, window) {
        let w = &data[off as usize..(off + len) as usize];
        let (avec_bytes, shards, _protected, _overhead) =
            compute_error_correction_shards_grid(&[w], k, p);
        total_shards += shards;
        total_avec += avec_bytes.len() as u64;
        segments.push(AeroCorrectSegment {
            window_offset: off,
            window_len: len,
            avec_bytes,
        });
    }
    let sidecar = AeroCorrectSidecar::new(sha256_bytes(data), file_size, segments);
    (sidecar, total_shards, total_avec)
}

fn generated_from(
    sidecar: AeroCorrectSidecar,
    file_size: u64,
    file_sha256: [u8; 32],
    shards: u64,
    avec_payload_len: u64,
) -> SyncEcGeneratedSidecar {
    let sidecar_bytes = sidecar.to_bytes();
    let overhead_pct = if file_size > 0 {
        (avec_payload_len as f64 / file_size as f64) * 100.0
    } else {
        0.0
    };
    SyncEcGeneratedSidecar {
        sidecar_len: sidecar_bytes.len() as u64,
        sidecar_bytes,
        file_size,
        file_sha256,
        shards,
        bytes_protected: file_size,
        overhead_pct,
        avec_payload_len,
    }
}

pub fn generate_sync_sidecar_for_bytes(
    _rel_path: &str,
    data: &[u8],
    pct: u32,
) -> SyncEcGeneratedSidecar {
    generate_sync_sidecar_for_bytes_windowed(_rel_path, data, pct, AEROCORRECT_WINDOW_SIZE)
}

/// `generate_sync_sidecar_for_bytes` with an explicit window size (tests use a small
/// window to exercise the multi-window path cheaply).
fn generate_sync_sidecar_for_bytes_windowed(
    _rel_path: &str,
    data: &[u8],
    pct: u32,
    window: u64,
) -> SyncEcGeneratedSidecar {
    let file_sha256 = sha256_bytes(data);
    let (sidecar, shards, avec) = build_windowed_sidecar(data, pct, window);
    generated_from(sidecar, data.len() as u64, file_sha256, shards, avec)
}

pub fn generate_sync_sidecar_for_bytes_capped(
    rel_path: &str,
    data: &[u8],
    pct: u32,
    max_file_size: u64,
) -> SyncEcGenerateResult {
    let file_size = data.len() as u64;
    if file_size > max_file_size {
        return SyncEcGenerateResult::SkippedTooLarge {
            file_size,
            max_file_size,
        };
    }
    SyncEcGenerateResult::Generated(generate_sync_sidecar_for_bytes(rel_path, data, pct))
}

/// `max_overhead_pct`: minimum-benefit gate. When > 0, skip generation (returning
/// `SkippedLowBenefit`) if the sidecar's serialized size would exceed this percentage of
/// the file size, computed WITHOUT generating it. 0 disables the gate (default).
pub fn generate_sync_sidecar_for_file_capped(
    rel_path: &str,
    path: &Path,
    pct: u32,
    max_file_size: u64,
    max_overhead_pct: u32,
) -> Result<SyncEcGenerateResult, String> {
    generate_sync_sidecar_for_file_capped_windowed(
        rel_path,
        path,
        pct,
        max_file_size,
        max_overhead_pct,
        AEROCORRECT_WINDOW_SIZE,
        &mut |_, _| {},
    )
}

/// `generate_sync_sidecar_for_file_capped` with a `(bytes_done, bytes_total)`
/// progress callback invoked after each window's parity is computed (#5:
/// progress for `correct` generation).
pub fn generate_sync_sidecar_for_file_capped_with_progress(
    rel_path: &str,
    path: &Path,
    pct: u32,
    max_file_size: u64,
    max_overhead_pct: u32,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SyncEcGenerateResult, String> {
    generate_sync_sidecar_for_file_capped_windowed(
        rel_path,
        path,
        pct,
        max_file_size,
        max_overhead_pct,
        AEROCORRECT_WINDOW_SIZE,
        progress,
    )
}

/// Stream a file into a windowed sidecar with bounded memory: read at most one
/// `window`-sized buffer at a time, compute that window's parity, and accumulate a
/// rolling SHA-256 of the whole file. Never loads the whole file into RAM.
fn generate_sync_sidecar_for_file_capped_windowed(
    _rel_path: &str,
    path: &Path,
    pct: u32,
    max_file_size: u64,
    max_overhead_pct: u32,
    window: u64,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SyncEcGenerateResult, String> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        format!(
            "read metadata for AeroSync EC source {}: {e}",
            path.display()
        )
    })?;
    let file_size = metadata.len();
    if file_size > max_file_size {
        return Ok(SyncEcGenerateResult::SkippedTooLarge {
            file_size,
            max_file_size,
        });
    }
    // Minimum-benefit gate (opt-in): reject absurd overhead BEFORE generating, using the
    // exact serialized cost. A tiny file at any level produces a multi-KiB sidecar (the
    // parity-shard floor), so its overhead can be many hundreds of percent.
    if max_overhead_pct > 0 && file_size > 0 {
        let estimate = estimate_windowed_sidecar_len(file_size, pct, window);
        let overhead_pct = ((estimate as u128 * 100) / file_size as u128) as u64;
        if overhead_pct > max_overhead_pct as u64 {
            return Ok(SyncEcGenerateResult::SkippedLowBenefit {
                file_size,
                overhead_pct,
            });
        }
    }
    let mut file = crate::source::open_regular(path)
        .map_err(|e| format!("open AeroSync EC source {}: {e}", path.display()))?;
    let (k, p) = error_correction_grid(pct);
    let mut hasher = Sha256::new();
    let mut segments = Vec::new();
    let mut total_shards = 0u64;
    let mut total_avec = 0u64;
    for (off, len) in aerocorrect_windows(file_size, window) {
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf).map_err(|e| {
            format!(
                "read AeroSync EC source window at {off} (+{len}) of {}: {e}",
                path.display()
            )
        })?;
        hasher.update(&buf);
        let (avec_bytes, shards, _protected, _overhead) =
            compute_error_correction_shards_grid(&[&buf], k, p);
        total_shards += shards;
        total_avec += avec_bytes.len() as u64;
        segments.push(AeroCorrectSegment {
            window_offset: off,
            window_len: len,
            avec_bytes,
        });
        progress(off.saturating_add(len), file_size);
    }
    let file_sha256 = finalize_sha256(hasher);
    let sidecar = AeroCorrectSidecar::new(file_sha256, file_size, segments);
    Ok(SyncEcGenerateResult::Generated(generated_from(
        sidecar,
        file_size,
        file_sha256,
        total_shards,
        total_avec,
    )))
}

/// Shared sidecar validation for the verify/repair paths: parse, content-bind against
/// the expected (good) hash, confirm the declared length, and confirm the windows tile
/// the stream cleanly. Returns the parsed sidecar.
fn validated_sidecar_for(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    stream_len: u64,
    sidecar_bytes: &[u8],
) -> Result<AeroCorrectSidecar, String> {
    let sidecar = AeroCorrectSidecar::from_bytes(sidecar_bytes)?;
    // Binding is by content: the sidecar must belong to the expected (good) file hash
    // the sync index recorded for this path, not to the bytes we just downloaded (those
    // may be corrupt). The rel_path/file_size identity is the sync layer's concern.
    sidecar.verify_binding(expected_sha256).map_err(|e| {
        format!("AeroSync EC sidecar for {rel_path} does not match the expected file: {e}")
    })?;
    if sidecar.total_len != stream_len {
        return Err(format!(
            "AeroSync EC sidecar total length {} != file length {stream_len} for {rel_path}",
            sidecar.total_len
        ));
    }
    validate_window_tiling(&sidecar.segments, stream_len)
        .map_err(|e| format!("AeroSync EC sidecar for {rel_path}: {e}"))?;
    Ok(sidecar)
}

pub fn verify_repair_sync_bytes(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    data: &mut Vec<u8>,
    sidecar_bytes: &[u8],
) -> Result<SyncEcRepairResult, String> {
    let sidecar =
        validated_sidecar_for(rel_path, expected_sha256, data.len() as u64, sidecar_bytes)?;

    if sha256_bytes(data) == *expected_sha256 {
        return Ok(SyncEcRepairResult::Verified);
    }

    // Repair on a clone so the buffer is all-or-nothing: only adopt the result once the
    // whole-file SHA matches. Each window is repaired independently from its own parity.
    let mut work = data.clone();
    let mut recovered_shards = 0usize;
    for seg in &sidecar.segments {
        let start = seg.window_offset as usize;
        let end = start + seg.window_len as usize;
        let mut blocks = vec![work[start..end].to_vec()];
        recovered_shards += reconstruct_from_error_correction(&mut blocks, &seg.avec_bytes)?;
        work[start..end].copy_from_slice(&blocks[0]);
    }
    if sha256_bytes(&work) != *expected_sha256 {
        return Err("AeroSync EC repair failed post-repair SHA-256 verification".to_string());
    }
    *data = work;
    Ok(SyncEcRepairResult::Repaired { recovered_shards })
}

#[cfg(test)]
thread_local! { pub(crate) static HASH_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

/// Stream a file and return its SHA-256 with bounded memory (one `HASH_READ_CHUNK`
/// buffer at a time). Shared by the verify fast path and the standalone verify.
fn hash_file_streaming(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(test)]
    HASH_READS.with(|n| n.set(n.get() + 1));

    let mut file = crate::source::open_regular(path)
        .map_err(|e| format!("open {} for hashing: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_READ_CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {} for hashing: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(finalize_sha256(hasher))
}

/// Run `write` (which replaces `path` or writes its `.aerocorrect`) under the
/// write lock of `path`, after checking that `path` still holds the bytes that
/// were read, by their SHA-256 `read_sha256`. The file was read without the
/// lock, so a writer may have replaced it meanwhile (a vault created at that
/// path, a vault save): the write is then refused instead of overwriting it.
/// The lock is taken for any file, not only a vault, so the file cannot turn
/// into one between the check and the write.
pub(crate) fn write_if_unchanged(
    path: &Path,
    read_sha256: &[u8; 32],
    write: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    write_if_unchanged_with_lock(path, read_sha256, |lock| write(lock.source_path()))
}

pub(crate) fn write_if_unchanged_with_lock(
    path: &Path,
    read_sha256: &[u8; 32],
    write: impl FnOnce(&crate::lock::WriteLock) -> Result<(), String>,
) -> Result<(), String> {
    #[cfg(test)]
    run_hook(&BEFORE_WRITE_LOCK);
    let _lock = crate::lock::acquire(path).map_err(|e| e.to_string())?;
    assert_unchanged(_lock.source_path(), read_sha256)?;
    #[cfg(test)]
    run_hook(&IN_WRITE_WINDOW);
    write(&_lock)
}

/// Recheck after acquiring any additional destination guard, without taking
/// the already held source lock recursively.
pub(crate) fn assert_unchanged(path: &Path, read_sha256: &[u8; 32]) -> Result<(), String> {
    if hash_file_streaming(path)? != *read_sha256 {
        return Err(format!(
            "{} changed while it was being read; retry",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
type Hook = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
thread_local! {
    /// Test seam: runs before [`write_if_unchanged`] takes the lock.
    pub(crate) static BEFORE_WRITE_LOCK: Hook = const { std::cell::RefCell::new(None) };
    /// Test seam: runs between the unchanged check and the write, lock held.
    pub(crate) static IN_WRITE_WINDOW: Hook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn run_hook(hook: &'static std::thread::LocalKey<Hook>) {
    if let Some(f) = hook.with(|h| h.borrow_mut().take()) {
        f();
    }
}

pub fn verify_repair_sync_file(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    path: &Path,
    sidecar_bytes: &[u8],
) -> Result<SyncEcRepairResult, String> {
    let pinned = crate::lock::anchored(path).map_err(|e| e.to_string())?;
    let path = pinned.as_path();

    crate::lock::refuse_lock_file_name(path).map_err(|e| e.to_string())?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("stat AeroSync EC target {}: {e}", path.display()))?
        .len();
    let sidecar = validated_sidecar_for(rel_path, expected_sha256, file_size, sidecar_bytes)?;

    // Fast path: stream the file once and hash it. Bounded memory (one read chunk).
    if hash_file_streaming(path)? == *expected_sha256 {
        return Ok(SyncEcRepairResult::Verified);
    }

    // Repair path: stream window by window into a temp file in the same directory,
    // repairing each window from its own parity, then atomically replace the original
    // ONLY if the whole repaired stream hashes to the expected value. Bounded memory
    // (one window at a time); all-or-nothing (a failed verify leaves the original intact).
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(windows)]
    let private = crate::v3::strip_transaction::private_dir(parent, ".aerorepair-private-")?;
    #[cfg(windows)]
    let stage_parent = private.path();
    #[cfg(not(windows))]
    let stage_parent = parent;
    let tmp = tempfile::NamedTempFile::new_in(stage_parent).map_err(|e| {
        format!(
            "create AeroSync EC repair temp in {}: {e}",
            parent.display()
        )
    })?;
    let mut src = crate::source::open_regular(path)
        .map_err(|e| format!("open AeroSync EC target {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut read_hasher = Sha256::new();
    let mut recovered_shards = 0usize;
    {
        let mut out = std::io::BufWriter::new(tmp.as_file());
        for seg in &sidecar.segments {
            let mut buf = vec![0u8; seg.window_len as usize];
            src.read_exact(&mut buf)
                .map_err(|e| format!("read AeroSync EC target window {}: {e}", path.display()))?;
            read_hasher.update(&buf);
            let mut blocks = vec![buf];
            recovered_shards += reconstruct_from_error_correction(&mut blocks, &seg.avec_bytes)?;
            hasher.update(&blocks[0]);
            out.write_all(&blocks[0])
                .map_err(|e| format!("write AeroSync EC repair temp {}: {e}", path.display()))?;
        }
        out.flush()
            .map_err(|e| format!("flush AeroSync EC repair temp {}: {e}", path.display()))?;
    }
    if finalize_sha256(hasher) != *expected_sha256 {
        // tmp is dropped (removed) here; the original file is byte-for-byte untouched.
        return Err("AeroSync EC repair failed post-repair SHA-256 verification".to_string());
    }
    // Release the read handle on the target before persisting. On Windows, renaming the
    // repaired temp onto a file that still has a live read handle fails with
    // ERROR_ACCESS_DENIED (os error 5) (audit M1). The repair loop above is the only
    // reader of `src`, so the handle is safe to drop here.
    drop(src);
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync AeroSync EC repair temp {}: {e}", path.display()))?;
    // On a persist failure (or a refusal) the temp file is removed, so a
    // decrypted-plaintext `.tmp*` is never left beside the target (audit M1
    // plaintext-at-rest).
    write_if_unchanged(path, &finalize_sha256(read_hasher), |locked_path| {
        // The private stage stays private throughout any wait. Permission-only
        // changes do not affect the content hash, so sample them under guard.
        let permissions = std::fs::metadata(locked_path)
            .map_err(|e| e.to_string())?
            .permissions();
        std::fs::set_permissions(tmp.path(), permissions).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let descriptor = crate::v3::windows_security::capture(locked_path)?;
        #[cfg(windows)]
        crate::v3::windows_security::apply(tmp.path(), &descriptor, true)?;
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        crate::v3::vault::persist_over(tmp, locked_path).map_err(|e| {
            format!(
                "persist repaired AeroSync EC target {}: {e}",
                path.display()
            )
        })?;
        #[cfg(windows)]
        crate::v3::windows_security::apply(locked_path, &descriptor, false).map_err(|e| {
            format!("Repaired file committed, but restoring destination DACL failed: {e}")
        })?;
        Ok(())
    })?;
    Ok(SyncEcRepairResult::Repaired { recovered_shards })
}

/// Streaming counterpart of `verify_repair_sync_file`: instead of taking the whole
/// sidecar in memory, read it from `sidecar_path` window by window via
/// `AeroCorrectSidecarReader`. Memory is bounded to one window of plaintext plus that
/// window's parity, regardless of file OR sidecar size. Used by the sync download path,
/// where the sidecar is kept on disk rather than read into RAM (the §1 "streaming
/// sidecar" follow-up: lifts the last O(sidecar size) RAM constraint).
pub fn verify_repair_sync_file_streamed(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    path: &Path,
    sidecar_path: &Path,
) -> Result<SyncEcRepairResult, String> {
    verify_repair_sync_file_streamed_with_progress(
        rel_path,
        expected_sha256,
        path,
        sidecar_path,
        &mut |_, _| {},
    )
}

/// `verify_repair_sync_file_streamed` with a `(bytes_done, bytes_total)` progress
/// callback invoked after each window is streamed/repaired (#5: progress for
/// `correct` repair). On the fast verified path (file already intact) no per-window
/// callback fires.
pub fn verify_repair_sync_file_streamed_with_progress(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    path: &Path,
    sidecar_path: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SyncEcRepairResult, String> {
    repair_streamed(rel_path, expected_sha256, path, sidecar_path, progress)
}

/// The streamed verify/repair shared by the streamed and standalone entry points.
fn repair_streamed(
    rel_path: &str,
    expected_sha256: &[u8; 32],
    path: &Path,
    sidecar_path: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SyncEcRepairResult, String> {
    let pinned = crate::lock::anchored(path).map_err(|e| e.to_string())?;
    let path = pinned.as_path();

    crate::lock::refuse_lock_file_name(path).map_err(|e| e.to_string())?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("stat AeroSync EC target {}: {e}", path.display()))?
        .len();
    let mut reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    // Same validation as the in-memory path: content binding, declared length, tiling.
    reader.verify_binding(expected_sha256).map_err(|e| {
        format!("AeroSync EC sidecar for {rel_path} does not match the expected file: {e}")
    })?;
    if reader.total_len != file_size {
        return Err(format!(
            "AeroSync EC sidecar total length {} != file length {file_size} for {rel_path}",
            reader.total_len
        ));
    }
    validate_window_tiling_iter(
        reader
            .segments()
            .iter()
            .map(|s| (s.window_offset, s.window_len)),
        file_size,
    )
    .map_err(|e| format!("AeroSync EC sidecar for {rel_path}: {e}"))?;

    // Fast path: stream the file once and hash it. Bounded memory.
    if hash_file_streaming(path)? == *expected_sha256 {
        return Ok(SyncEcRepairResult::Verified);
    }

    // Repair path: stream window by window into a temp file in the same directory,
    // reading each window's parity from the sidecar on demand, then atomically replace
    // the original ONLY if the whole repaired stream hashes to the expected value.
    // Bounded memory (one window + its parity); all-or-nothing.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(windows)]
    let private = crate::v3::strip_transaction::private_dir(parent, ".aerorepair-private-")?;
    #[cfg(windows)]
    let stage_parent = private.path();
    #[cfg(not(windows))]
    let stage_parent = parent;
    let tmp = tempfile::NamedTempFile::new_in(stage_parent).map_err(|e| {
        format!(
            "create AeroSync EC repair temp in {}: {e}",
            parent.display()
        )
    })?;
    let mut src = crate::source::open_regular(path)
        .map_err(|e| format!("open AeroSync EC target {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut read_hasher = Sha256::new();
    let mut recovered_shards = 0usize;
    {
        let mut out = std::io::BufWriter::new(tmp.as_file());
        for idx in 0..reader.segments().len() {
            let window_len = usize::try_from(reader.segments()[idx].window_len)
                .map_err(|_| format!("AeroSync EC sidecar window {idx} length exceeds usize"))?;
            let avec = reader.read_segment_avec(idx)?;
            let mut buf = vec![0u8; window_len];
            src.read_exact(&mut buf)
                .map_err(|e| format!("read AeroSync EC target window {}: {e}", path.display()))?;
            read_hasher.update(&buf);
            let mut blocks = vec![buf];
            recovered_shards += reconstruct_from_error_correction(&mut blocks, &avec)?;
            hasher.update(&blocks[0]);
            out.write_all(&blocks[0])
                .map_err(|e| format!("write AeroSync EC repair temp {}: {e}", path.display()))?;
            progress(
                reader.segments()[idx]
                    .window_offset
                    .saturating_add(reader.segments()[idx].window_len),
                file_size,
            );
        }
        out.flush()
            .map_err(|e| format!("flush AeroSync EC repair temp {}: {e}", path.display()))?;
    }
    if finalize_sha256(hasher) != *expected_sha256 {
        // tmp is dropped (removed) here; the original file is byte-for-byte untouched.
        return Err("AeroSync EC repair failed post-repair SHA-256 verification".to_string());
    }
    // Release the read handle on the target before persisting. On Windows, renaming the
    // repaired temp onto a file that still has a live read handle fails with
    // ERROR_ACCESS_DENIED (os error 5) (audit M1). The repair loop above is the only
    // reader of `src`, so the handle is safe to drop here.
    drop(src);
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync AeroSync EC repair temp {}: {e}", path.display()))?;
    // On a persist failure (or a refusal) the temp file is removed, so a
    // decrypted-plaintext `.tmp*` is never left beside the target (audit M1
    // plaintext-at-rest).
    write_if_unchanged(path, &finalize_sha256(read_hasher), |locked_path| {
        // The private stage stays private throughout any wait. Permission-only
        // changes do not affect the content hash, so sample them under guard.
        let permissions = std::fs::metadata(locked_path)
            .map_err(|e| e.to_string())?
            .permissions();
        std::fs::set_permissions(tmp.path(), permissions).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let descriptor = crate::v3::windows_security::capture(locked_path)?;
        #[cfg(windows)]
        crate::v3::windows_security::apply(tmp.path(), &descriptor, true)?;
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        crate::v3::vault::persist_over(tmp, locked_path).map_err(|e| {
            format!(
                "persist repaired AeroSync EC target {}: {e}",
                path.display()
            )
        })?;
        #[cfg(windows)]
        crate::v3::windows_security::apply(locked_path, &descriptor, false).map_err(|e| {
            format!("Repaired file committed, but restoring destination DACL failed: {e}")
        })?;
        Ok(())
    })?;
    Ok(SyncEcRepairResult::Repaired { recovered_shards })
}

/// Outcome of a read-only standalone verify (the file is never mutated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandaloneVerifyResult {
    Verified,
    NeedsRepair,
}

/// Read-only verify of a standalone file against its on-disk `.aerocorrect`
/// sidecar. It keeps only the segment directory and checksum buffer in memory,
/// never the whole sidecar.
pub fn verify_standalone_file_streamed(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
) -> Result<StandaloneVerifyResult, String> {
    let reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    let expected = reader.content_sha256;
    reader.verify_binding(&expected).map_err(|e| {
        format!("Standalone EC sidecar for {rel_path} is internally inconsistent: {e}")
    })?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if reader.total_len != file_size {
        return Err(format!(
            "Standalone EC sidecar total length {} != file length {file_size} for {rel_path}",
            reader.total_len
        ));
    }
    validate_window_tiling_iter(
        reader
            .segments()
            .iter()
            .map(|s| (s.window_offset, s.window_len)),
        file_size,
    )
    .map_err(|e| format!("Standalone EC sidecar for {rel_path}: {e}"))?;
    if hash_file_streaming(path)? == expected {
        Ok(StandaloneVerifyResult::Verified)
    } else {
        Ok(StandaloneVerifyResult::NeedsRepair)
    }
}

/// Read-only scan of a standalone file against its `.aerocorrect` sidecar that
/// returns BOTH the verified verdict and a per-shard health readout (#9), in a
/// single streamed pass (bounded memory: one window plus its parity). The file
/// is never mutated. The hot sync path keeps using the lighter
/// `verify_standalone_file_streamed` (hash-only); this is the explicit
/// `correct verify` health readout.
pub fn scan_standalone_file_streamed(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<(StandaloneVerifyResult, ShardHealth), String> {
    let mut reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    let expected = reader.content_sha256;
    reader.verify_binding(&expected).map_err(|e| {
        format!("Standalone EC sidecar for {rel_path} is internally inconsistent: {e}")
    })?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if reader.total_len != file_size {
        return Err(format!(
            "Standalone EC sidecar total length {} != file length {file_size} for {rel_path}",
            reader.total_len
        ));
    }
    validate_window_tiling_iter(
        reader
            .segments()
            .iter()
            .map(|s| (s.window_offset, s.window_len)),
        file_size,
    )
    .map_err(|e| format!("Standalone EC sidecar for {rel_path}: {e}"))?;

    let mut src =
        crate::source::open_regular(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut health = ShardHealth::default();
    for idx in 0..reader.segments().len() {
        let window_len = usize::try_from(reader.segments()[idx].window_len)
            .map_err(|_| format!("Standalone EC sidecar window {idx} length exceeds usize"))?;
        let avec = reader.read_segment_avec(idx)?;
        let mut buf = vec![0u8; window_len];
        src.read_exact(&mut buf)
            .map_err(|e| format!("read {} window {idx}: {e}", path.display()))?;
        hasher.update(&buf);
        let blocks = vec![buf];
        scan_error_correction_health(&blocks, &avec, &mut health)?;
        progress(
            reader.segments()[idx]
                .window_offset
                .saturating_add(reader.segments()[idx].window_len),
            file_size,
        );
    }
    let result = if finalize_sha256(hasher) == expected {
        StandaloneVerifyResult::Verified
    } else {
        StandaloneVerifyResult::NeedsRepair
    };
    Ok((result, health))
}

/// Repair a standalone file from its own `.aerocorrect` sidecar (atomic, all-or-nothing).
/// The sidecar's stored `content_sha256` is the expected good hash; parity is
/// read window-by-window by `verify_repair_sync_file_streamed`.
///
/// Trust model (audit M3): a bare standalone repair reconstructs toward WHATEVER the
/// sidecar declares (integrity, not authenticity). Pass `expect_sha256` (an out-of-band
/// good hash) to anchor authenticity: a sidecar whose declared hash differs is refused
/// before any write.
pub fn verify_repair_standalone_file_streamed(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
    expect_sha256: Option<&[u8; 32]>,
) -> Result<SyncEcRepairResult, String> {
    verify_repair_standalone_file_streamed_with_progress(
        rel_path,
        path,
        sidecar_path,
        expect_sha256,
        &mut |_, _| {},
    )
}

/// `verify_repair_standalone_file_streamed` with a `(bytes_done, bytes_total)`
/// progress callback (#5: progress for standalone `correct repair`).
pub fn verify_repair_standalone_file_streamed_with_progress(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
    expect_sha256: Option<&[u8; 32]>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SyncEcRepairResult, String> {
    let reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    let expected = reader.content_sha256;
    drop(reader);
    if let Some(anchor) = expect_sha256 {
        if anchor != &expected {
            return Err(format!(
                "Standalone EC sidecar for {rel_path} declares a content hash that does not match the expected (anchored) hash; refusing repair"
            ));
        }
    }
    repair_streamed(rel_path, &expected, path, sidecar_path, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data(len: usize) -> Vec<u8> {
        let mut seed = *blake3::hash(b"aerosync-ec-p1-seed").as_bytes();
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            seed = *blake3::hash(&seed).as_bytes();
            out.extend_from_slice(&seed);
        }
        out.truncate(len);
        out
    }

    fn generate_during_destination_wait(
        source: &Path,
        out: &Path,
        edit: impl FnOnce(),
    ) -> Result<super::super::CorrectGenerateReport, String> {
        let guard = crate::lock::acquire(out).unwrap();
        let (waiting, seen) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                crate::lock::ON_LOCK_CONTENTION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || waiting.send(()).unwrap()))
                });
                super::super::correct_generate(
                    source.to_str().unwrap(),
                    20,
                    Some(out.to_str().unwrap()),
                )
            });
            let encountered_held_lock =
                seen.recv_timeout(std::time::Duration::from_secs(5)).is_ok();
            if encountered_held_lock {
                edit();
            }
            drop(guard);
            let result = worker.join().unwrap();
            assert!(
                encountered_held_lock,
                "writer never encountered the held destination lock"
            );
            result
        })
    }

    #[test]
    fn review_generate_rechecks_after_destination_wait() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        std::fs::write(&source, b"original source").unwrap();
        let out = dir.path().join("out.aerocorrect");
        std::fs::write(&out, b"keep previous parity").unwrap();
        let err = generate_during_destination_wait(&source, &out, || {
            std::fs::write(&source, b"edited source").unwrap()
        })
        .unwrap_err();
        assert!(err.contains("changed"), "{err}");
        assert_eq!(std::fs::read(&out).unwrap(), b"keep previous parity");
    }

    #[cfg(unix)]
    #[test]
    fn review_generate_refuses_retargeted_input_link() {
        for parent_link in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let a = dir.path().join("a");
            let b = dir.path().join("b");
            std::fs::create_dir(&a).unwrap();
            std::fs::create_dir(&b).unwrap();
            std::fs::write(
                a.join("source.bin"),
                b"same contents, different writer namespace",
            )
            .unwrap();
            std::fs::copy(a.join("source.bin"), b.join("source.bin")).unwrap();
            let link = dir.path().join("link");
            let (target_a, target_b, input) = if parent_link {
                (a.clone(), b.clone(), link.join("source.bin"))
            } else {
                (a.join("source.bin"), b.join("source.bin"), link.clone())
            };
            std::os::unix::fs::symlink(&target_a, &link).unwrap();
            let out = dir.path().join("out.aerocorrect");
            std::fs::write(&out, b"keep previous parity").unwrap();
            let err = generate_during_destination_wait(&input, &out, || {
                std::fs::remove_file(&link).unwrap();
                std::os::unix::fs::symlink(&target_b, &link).unwrap();
            })
            .unwrap_err();
            assert!(err.contains("changed target"), "{err}");
            assert_eq!(std::fs::read(&out).unwrap(), b"keep previous parity");
        }
    }

    #[cfg(unix)]
    #[test]
    fn review_replacement_requires_a_real_lock() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.bin");
        std::fs::write(&path, b"original").unwrap();
        let hash = hash_file_streaming(&path).unwrap();
        let staged = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        std::fs::write(staged.path(), b"replacement").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.path().join("probe"), b"").is_ok() {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }
        let mut ran = false;
        let result = write_if_unchanged(&path, &hash, |_| {
            ran = true;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(staged.path(), &path).unwrap();
            Ok(())
        });
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err(), "replacement accepted without a real lock");
        assert!(!ran);
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    #[test]
    fn aerosync_estimate_matches_real_sidecar_len() {
        // The sync-doctor cost preview MUST equal the byte size the generator actually writes.
        for &len in &[0usize, 1, 100, 4096, 4097, 50_000, 1_000_000] {
            for &pct in &[7u32, 15, 20, 25, 30, 50] {
                let data = sample_data(len);
                let real = generate_sync_sidecar_for_bytes("backup/x.bin", &data, pct).sidecar_len;
                let est = estimate_aerorec_sidecar_len(len as u64, pct);
                assert_eq!(est, real, "estimate != real for len={len} pct={pct}");
            }
        }
        // MAX_SHARD cliff: a 10 MiB file at 50% spills into multiple full-parity groups.
        let big = sample_data(10 * 1024 * 1024);
        let real = generate_sync_sidecar_for_bytes("backup/big.bin", &big, 50).sidecar_len;
        assert_eq!(estimate_aerorec_sidecar_len(big.len() as u64, 50), real);
    }

    #[test]
    fn aerosync_sidecar_round_trips_single_segment() {
        let data = sample_data(96 * 1024 + 17);
        let generated = generate_sync_sidecar_for_bytes("backup/photos.raw", &data, 15);
        assert_eq!(generated.file_size, data.len() as u64);
        assert_eq!(generated.bytes_protected, data.len() as u64);
        assert_eq!(generated.shards, 15);
        assert!(generated.overhead_pct > 0.0);
        assert!(generated.avec_payload_len > 0);
        assert_eq!(generated.sidecar_len, generated.sidecar_bytes.len() as u64);
        assert_eq!(
            sync_error_correction_sidecar_path("backup/photos.raw"),
            "backup/photos.raw.aerocorrect"
        );

        let sidecar =
            AeroCorrectSidecar::from_bytes(&generated.sidecar_bytes).expect("parse aerocorrect");
        assert_eq!(sidecar.to_bytes(), generated.sidecar_bytes);
        sidecar
            .verify_binding(&generated.file_sha256)
            .expect("binding should match");
        // A small file is a single full-file window.
        assert_eq!(sidecar.segments.len(), 1);
        assert_eq!(sidecar.segments[0].window_offset, 0);
        assert_eq!(sidecar.segments[0].window_len, data.len() as u64);
    }

    #[test]
    fn aerosync_sidecar_rejects_wrong_content_binding() {
        let data = sample_data(64 * 1024);
        let generated = generate_sync_sidecar_for_bytes("backup/config.tar", &data, 20);
        // A different expected hash (different content) must be rejected by the binding,
        // regardless of which path the sync layer paired the sidecar to.
        let other = sample_data(64 * 1024 + 1);
        let mut downloaded = data.clone();
        let err = verify_repair_sync_bytes(
            "backup/config.tar",
            &sha256_bytes(&other),
            &mut downloaded,
            &generated.sidecar_bytes,
        )
        .expect_err("wrong expected content must reject");
        assert!(err.contains("binding mismatch"));
    }

    #[test]
    fn aerosync_sidecar_repairs_corrupt_file_bytes() {
        let data = sample_data(128 * 1024 + 9);
        let generated = generate_sync_sidecar_for_bytes("backup/archive.bin", &data, 20);
        let mut damaged = data.clone();
        damaged[17_123] ^= 0xA5;

        let result = verify_repair_sync_bytes(
            "backup/archive.bin",
            &generated.file_sha256,
            &mut damaged,
            &generated.sidecar_bytes,
        )
        .expect("repair should succeed");

        match result {
            SyncEcRepairResult::Repaired { recovered_shards } => assert!(recovered_shards >= 1),
            SyncEcRepairResult::Verified => panic!("damaged data should need repair"),
        }
        assert_eq!(damaged, data);
    }

    #[test]
    fn scan_reports_shard_health_on_corruption() {
        // #9: the read-only scan returns a per-shard health readout alongside the
        // verified verdict, for both an intact and a lightly-damaged file.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("data.bin");
        let data = sample_data(200 * 1024 + 7);
        std::fs::write(&file, &data).expect("write file");
        let file_str = file.to_str().unwrap();
        crate::error_correction::correct_generate(file_str, 20, None).expect("generate sidecar");
        let sidecar = crate::error_correction::aerocorrect_sidecar_path_for(file_str);
        let sidecar_path = std::path::Path::new(&sidecar);

        // Intact: verified, zero damage, sane non-zero totals.
        let (res, health) =
            scan_standalone_file_streamed("data.bin", &file, sidecar_path, &mut |_, _| {})
                .expect("scan intact");
        assert_eq!(res, StandaloneVerifyResult::Verified);
        assert_eq!(health.damaged_data_shards, 0);
        assert_eq!(health.damaged_parity_shards, 0);
        assert_eq!(health.unrecoverable_groups, 0);
        assert!(health.total_data_shards > 0);
        assert!(health.total_parity_shards > 0);

        // One flipped byte: needs repair, at least one damaged data shard, still
        // within recovery (no unrecoverable group), totals unchanged.
        let mut damaged = data.clone();
        damaged[123_456] ^= 0xA5;
        std::fs::write(&file, &damaged).expect("write damaged");
        let (res2, health2) =
            scan_standalone_file_streamed("data.bin", &file, sidecar_path, &mut |_, _| {})
                .expect("scan damaged");
        assert_eq!(res2, StandaloneVerifyResult::NeedsRepair);
        assert!(health2.damaged_data_shards >= 1);
        assert_eq!(
            health2.unrecoverable_groups, 0,
            "single-byte damage must stay recoverable"
        );
        assert_eq!(health2.total_data_shards, health.total_data_shards);
    }

    #[test]
    fn correct_generate_reports_progress_to_total() {
        // #5: the progress callback fires during sidecar generation and reaches
        // (total, total) on the last window.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("d.bin");
        let data = sample_data(300 * 1024 + 5);
        std::fs::write(&file, &data).expect("write");
        let mut calls = 0u32;
        let mut last = (0u64, 0u64);
        crate::error_correction::correct_generate_with_progress(
            file.to_str().unwrap(),
            20,
            None,
            &mut |done, total| {
                calls += 1;
                last = (done, total);
            },
        )
        .expect("generate with progress");
        assert!(calls >= 1, "progress callback must fire at least once");
        assert_eq!(last.1, data.len() as u64, "total should be the file size");
        assert_eq!(last.0, last.1, "final progress should reach the total");
    }

    #[test]
    fn aerosync_generation_skips_too_large_files() {
        let data = sample_data(4097);
        match generate_sync_sidecar_for_bytes_capped("backup/large.bin", &data, 20, 4096) {
            SyncEcGenerateResult::SkippedTooLarge {
                file_size,
                max_file_size,
            } => {
                assert_eq!(file_size, 4097);
                assert_eq!(max_file_size, 4096);
            }
            other => panic!("oversize file should be skipped, got {other:?}"),
        }

        match generate_sync_sidecar_for_bytes_capped(
            "backup/large.bin",
            &data,
            20,
            AEROSYNC_EC_MAX_FILE_SIZE,
        ) {
            SyncEcGenerateResult::Generated(generated) => {
                assert_eq!(generated.file_size, data.len() as u64);
                assert!(generated.sidecar_len > generated.avec_payload_len);
            }
            other => panic!("default cap should allow this test file, got {other:?}"),
        }
    }

    // --- Windowed (large-file) streaming ---

    #[test]
    fn windowed_sidecar_has_multiple_segments_and_round_trips() {
        let window = 40_000u64;
        let data = sample_data(135_000); // 4 windows (40k,40k,40k,15k)
        let generated =
            generate_sync_sidecar_for_bytes_windowed("backup/big.bin", &data, 20, window);
        let sidecar =
            AeroCorrectSidecar::from_bytes(&generated.sidecar_bytes).expect("parse windowed");
        assert_eq!(sidecar.segments.len(), 4);
        assert_eq!(sidecar.segments[0].window_len, 40_000);
        assert_eq!(sidecar.segments[3].window_len, 15_000);
        assert_eq!(generated.bytes_protected, data.len() as u64);
        assert!(generated.avec_payload_len > 0);
    }

    #[test]
    fn windowed_repair_fixes_damage_in_each_window() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let generated =
            generate_sync_sidecar_for_bytes_windowed("backup/big.bin", &data, 20, window);
        let mut damaged = data.clone();
        // Corrupt one byte in each of the four windows.
        for off in [10_000usize, 50_000, 90_000, 130_000] {
            damaged[off] ^= 0x5A;
        }
        let result = verify_repair_sync_bytes(
            "backup/big.bin",
            &generated.file_sha256,
            &mut damaged,
            &generated.sidecar_bytes,
        )
        .expect("multi-window repair should succeed");
        assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
        assert_eq!(damaged, data);
    }

    #[test]
    fn windowed_repair_fails_when_a_window_is_beyond_recovery() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let generated =
            generate_sync_sidecar_for_bytes_windowed("backup/big.bin", &data, 20, window);
        let mut damaged = data.clone();
        // Obliterate a whole window: beyond the per-window parity budget.
        for b in damaged[0..40_000].iter_mut() {
            *b ^= 0xFF;
        }
        let err = verify_repair_sync_bytes(
            "backup/big.bin",
            &generated.file_sha256,
            &mut damaged,
            &generated.sidecar_bytes,
        )
        .expect_err("unrecoverable window must fail post-verify");
        assert!(err.contains("post-repair SHA-256"));
    }

    #[test]
    fn streaming_file_generation_matches_in_memory_and_repairs() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, &data).unwrap();

        // Streaming file generation must be byte-identical to in-memory generation.
        let in_mem = generate_sync_sidecar_for_bytes_windowed("rel", &data, 20, window);
        let streamed = match generate_sync_sidecar_for_file_capped_windowed(
            "rel",
            &path,
            20,
            AEROSYNC_EC_MAX_FILE_SIZE,
            0,
            window,
            &mut |_, _| {},
        )
        .unwrap()
        {
            SyncEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        assert_eq!(streamed.sidecar_bytes, in_mem.sidecar_bytes);
        assert_eq!(streamed.file_sha256, in_mem.file_sha256);

        // Corrupt the file across two windows, then stream-repair it in place.
        let mut corrupt = data.clone();
        corrupt[5_000] ^= 0xAA;
        corrupt[100_000] ^= 0xBB;
        std::fs::write(&path, &corrupt).unwrap();
        let result =
            verify_repair_sync_file("rel", &streamed.file_sha256, &path, &streamed.sidecar_bytes)
                .expect("streaming repair should succeed");
        assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), data);

        // A clean file verifies without rewriting.
        let verified =
            verify_repair_sync_file("rel", &streamed.file_sha256, &path, &streamed.sidecar_bytes)
                .expect("verify clean file");
        assert_eq!(verified, SyncEcRepairResult::Verified);
    }

    #[test]
    fn streamed_repair_from_on_disk_sidecar_is_byte_identical() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, &data).unwrap();

        // Generate a multi-window sidecar and persist it next to the file.
        let generated = match generate_sync_sidecar_for_file_capped_windowed(
            "rel",
            &path,
            20,
            AEROSYNC_EC_MAX_FILE_SIZE,
            0,
            window,
            &mut |_, _| {},
        )
        .unwrap()
        {
            SyncEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        let sidecar_path = dir.path().join("payload.bin.aerocorrect");
        std::fs::write(&sidecar_path, &generated.sidecar_bytes).unwrap();

        // Corrupt two distinct windows, then repair streaming from the on-disk sidecar.
        let mut corrupt = data.clone();
        corrupt[5_000] ^= 0xAA;
        corrupt[100_000] ^= 0xBB;
        std::fs::write(&path, &corrupt).unwrap();
        let result =
            verify_repair_sync_file_streamed("rel", &generated.file_sha256, &path, &sidecar_path)
                .expect("streamed repair should succeed");
        assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), data, "byte-identical repair");

        // A clean file verifies without rewriting.
        assert_eq!(
            verify_repair_sync_file_streamed("rel", &generated.file_sha256, &path, &sidecar_path)
                .unwrap(),
            SyncEcRepairResult::Verified
        );

        // A wrong expected hash (foreign/stale sidecar) fails closed, leaving the file intact.
        let before = std::fs::read(&path).unwrap();
        let wrong = [0u8; 32];
        assert!(
            verify_repair_sync_file_streamed("rel", &wrong, &path, &sidecar_path).is_err(),
            "binding mismatch must fail"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "file untouched on failure"
        );
    }

    /// Self-resilient sidecar (#276 Ehud point 2): a `.aerocorrect` with a stray flip
    /// in its PARITY region must still recover the target. The flipped parity byte is a
    /// rotted shard, which `reconstruct_from_error_correction` already routes around via
    /// the per-shard checksum, so the only thing that could break recovery is a wholesale
    /// envelope reject at open time. This test pins the SHIPPED behavior: the sidecar
    /// opens despite the parity rot and repairs the target byte-identically.
    #[test]
    fn lightly_corrupt_sidecar_parity_still_recovers() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, &data).unwrap();

        let generated = match generate_sync_sidecar_for_file_capped_windowed(
            "rel",
            &path,
            20,
            AEROSYNC_EC_MAX_FILE_SIZE,
            0,
            window,
            &mut |_, _| {},
        )
        .unwrap()
        {
            SyncEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        let sidecar_path = dir.path().join("payload.bin.aerocorrect");
        let mut sidecar_bytes = generated.sidecar_bytes.clone();
        // Flip one byte deep in the sidecar's parity region (the tail is parity data:
        // a rotted parity shard, not part of the locator). Stay clear of any trailing
        // metadata by landing in the middle of the payload.
        let flip = sidecar_bytes.len() / 2;
        sidecar_bytes[flip] ^= 0xFF;
        std::fs::write(&sidecar_path, &sidecar_bytes).unwrap();

        // Corrupt the target file in a recoverable way (one byte in one window).
        let mut corrupt = data.clone();
        corrupt[5_000] ^= 0xAA;
        std::fs::write(&path, &corrupt).unwrap();

        let result =
            verify_repair_sync_file_streamed("rel", &generated.file_sha256, &path, &sidecar_path)
                .expect("a lightly-corrupted sidecar must still recover");
        assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            data,
            "byte-identical recovery from a parity-rotted sidecar"
        );
    }

    /// Audit M1 regression (app copy): the target read handle used to be held across
    /// `persist`, which on Windows failed the rename (os error 5) and left a
    /// decrypted-plaintext `.tmp*` beside the target. After the fix, both the in-memory
    /// and on-disk-sidecar repair paths must restore the bytes and leave no temp artifact.
    #[test]
    fn repair_restores_and_leaves_no_temp_artifact() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        for streamed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("payload.bin");
            std::fs::write(&path, &data).unwrap();

            let generated = match generate_sync_sidecar_for_file_capped_windowed(
                "rel",
                &path,
                20,
                AEROSYNC_EC_MAX_FILE_SIZE,
                0,
                window,
                &mut |_, _| {},
            )
            .unwrap()
            {
                SyncEcGenerateResult::Generated(g) => g,
                other => panic!("should generate, got {other:?}"),
            };
            let sidecar_path = dir.path().join("payload.bin.aerocorrect");
            std::fs::write(&sidecar_path, &generated.sidecar_bytes).unwrap();

            let mut corrupt = data.clone();
            corrupt[5_000] ^= 0xAA;
            corrupt[100_000] ^= 0xBB;
            std::fs::write(&path, &corrupt).unwrap();

            let result = if streamed {
                verify_repair_sync_file_streamed(
                    "rel",
                    &generated.file_sha256,
                    &path,
                    &sidecar_path,
                )
            } else {
                verify_repair_sync_file(
                    "rel",
                    &generated.file_sha256,
                    &path,
                    &generated.sidecar_bytes,
                )
            }
            .expect("repair should succeed on every OS");
            assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
            assert_eq!(
                std::fs::read(&path).unwrap(),
                data,
                "repair must restore bytes"
            );

            let leftovers: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                // `payload.bin.aerolock`: the repair's write lock, left in place on purpose.
                .filter(|n| {
                    n != "payload.bin"
                        && n != "payload.bin.aerocorrect"
                        && n != "payload.bin.aerolock"
                })
                .collect();
            assert!(
                leftovers.is_empty(),
                "repair (streamed={streamed}) must not leave a temp artifact, found: {leftovers:?}"
            );
        }
    }

    #[test]
    fn minimum_benefit_gate_skips_tiny_high_overhead_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tiny.bin");
        // 100 bytes at 15% still produces a multi-KiB sidecar (parity-shard floor), so the
        // real overhead is many hundreds of percent.
        std::fs::write(&path, sample_data(100)).unwrap();

        // Confirm the estimate really is far above the file size (precondition for the gate).
        let est = estimate_windowed_sidecar_len(100, 15, AEROCORRECT_WINDOW_SIZE);
        assert!(
            est > 100 * 3,
            "tiny-file sidecar should be >300% of the file"
        );

        // Gate off (0): generates as before.
        match generate_sync_sidecar_for_file_capped(
            "tiny.bin",
            &path,
            15,
            AEROSYNC_EC_MAX_FILE_SIZE,
            0,
        )
        .unwrap()
        {
            SyncEcGenerateResult::Generated(_) => {}
            other => panic!("gate disabled should generate, got {other:?}"),
        }

        // Gate at 300%: the tiny file is skipped with its real overhead reported.
        match generate_sync_sidecar_for_file_capped(
            "tiny.bin",
            &path,
            15,
            AEROSYNC_EC_MAX_FILE_SIZE,
            300,
        )
        .unwrap()
        {
            SyncEcGenerateResult::SkippedLowBenefit {
                file_size,
                overhead_pct,
            } => {
                assert_eq!(file_size, 100);
                assert!(
                    overhead_pct > 300,
                    "reported overhead must exceed the threshold"
                );
            }
            other => panic!("tiny file should be skipped as low benefit, got {other:?}"),
        }
    }

    #[test]
    fn minimum_benefit_gate_keeps_large_low_overhead_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        // A 1 MiB file at 15% has a sidecar far below 50% of the file, so a 300% gate keeps it.
        std::fs::write(&path, sample_data(1024 * 1024)).unwrap();
        match generate_sync_sidecar_for_file_capped(
            "big.bin",
            &path,
            15,
            AEROSYNC_EC_MAX_FILE_SIZE,
            300,
        )
        .unwrap()
        {
            SyncEcGenerateResult::Generated(_) => {}
            other => panic!("large low-overhead file should generate, got {other:?}"),
        }
    }

    #[test]
    fn streaming_repair_leaves_original_untouched_when_unrecoverable() {
        let window = 40_000u64;
        let data = sample_data(90_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let generated = generate_sync_sidecar_for_bytes_windowed("rel", &data, 20, window);

        // Destroy a whole window beyond recovery and write it to disk.
        let mut corrupt = data.clone();
        for b in corrupt[0..40_000].iter_mut() {
            *b ^= 0xFF;
        }
        std::fs::write(&path, &corrupt).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = verify_repair_sync_file(
            "rel",
            &generated.file_sha256,
            &path,
            &generated.sidecar_bytes,
        )
        .expect_err("unrecoverable window must fail");
        assert!(err.contains("post-repair SHA-256"));
        // Original on disk is byte-for-byte untouched (temp discarded).
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    #[cfg(unix)]
    #[test]
    fn review_repair_applies_permissions_only_after_source_lock() {
        use std::os::unix::fs::PermissionsExt;
        for streamed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("payload.bin");
            let data = sample_data(40_000);
            let generated = generate_sync_sidecar_for_bytes("rel", &data, 20);
            let sidecar = dir.path().join("parity");
            std::fs::write(&sidecar, &generated.sidecar_bytes).unwrap();
            let mut damaged = data.clone();
            damaged[5000] ^= 1;
            std::fs::write(&path, damaged).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let parent = dir.path().to_path_buf();
            let target = path.clone();
            BEFORE_WRITE_LOCK.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    let stage = std::fs::read_dir(&parent)
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with(".tmp"))
                        .unwrap();
                    assert_eq!(
                        std::fs::metadata(stage).unwrap().permissions().mode() & 0o077,
                        0
                    );
                    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }))
            });
            let result = if streamed {
                verify_repair_sync_file_streamed("rel", &generated.file_sha256, &path, &sidecar)
            } else {
                verify_repair_sync_file(
                    "rel",
                    &generated.file_sha256,
                    &path,
                    &generated.sidecar_bytes,
                )
            }
            .unwrap();
            assert!(matches!(result, SyncEcRepairResult::Repaired { .. }));
            assert_eq!(std::fs::read(&path).unwrap(), data);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn round7_generate_pins_alias_before_progress() {
        for parent_link in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let a = dir.path().join("a");
            let b = dir.path().join("b");
            std::fs::create_dir(&a).unwrap();
            std::fs::create_dir(&b).unwrap();
            std::fs::write(a.join("payload"), sample_data(40_000)).unwrap();
            std::fs::copy(a.join("payload"), b.join("payload")).unwrap();
            let alias = dir.path().join("alias");
            let (first, next, input) = if parent_link {
                (a, b, alias.join("payload"))
            } else {
                (a.join("payload"), b.join("payload"), alias.clone())
            };
            std::os::unix::fs::symlink(first, &alias).unwrap();
            let out = dir.path().join("recovery");
            std::fs::write(&out, b"keep prior parity").unwrap();
            let mut changed = false;
            let err = super::super::correct_generate_with_progress(
                input.to_str().unwrap(),
                20,
                Some(out.to_str().unwrap()),
                &mut |_, _| {
                    if !changed {
                        std::fs::remove_file(&alias).unwrap();
                        std::os::unix::fs::symlink(&next, &alias).unwrap();
                        changed = true;
                    }
                },
            )
            .unwrap_err();
            assert!(changed);
            assert!(err.contains("changed target"), "{err}");
            assert_eq!(std::fs::read(out).unwrap(), b"keep prior parity");
        }
    }

    #[cfg(windows)]
    #[test]
    fn round7_windows_repair_keeps_stage_and_target_restricted() {
        use crate::v3::windows_security as acl;
        for streamed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            acl::apply(
                dir.path(),
                "D:P(A;OICI;FA;;;OW)(A;OICI;FR;;;BG)(A;OICI;FA;;;SY)",
                true,
            )
            .unwrap();
            let path = dir.path().join("private.bin");
            let data = sample_data(40_000);
            let g = generate_sync_sidecar_for_bytes("rel", &data, 20);
            let parity = dir.path().join("recovery");
            std::fs::write(&parity, &g.sidecar_bytes).unwrap();
            let mut damaged = data.clone();
            damaged[5000] ^= 1;
            std::fs::write(&path, damaged).unwrap();
            acl::apply(&path, "D:P(D;;FR;;;BG)(A;;FA;;;OW)(A;;FA;;;SY)", true).unwrap();
            let guard = crate::lock::acquire(&path).unwrap();
            let target = path.clone();
            let sidecar = parity.clone();
            std::thread::scope(|scope| {
                let (tx, rx) = std::sync::mpsc::channel();
                let worker = scope.spawn(move || {
                    crate::lock::ON_LOCK_CONTENTION
                        .with(|h| *h.borrow_mut() = Some(Box::new(move || tx.send(()).unwrap())));
                    if streamed {
                        verify_repair_sync_file_streamed("rel", &g.file_sha256, &target, &sidecar)
                    } else {
                        verify_repair_sync_file("rel", &g.file_sha256, &target, &g.sidecar_bytes)
                    }
                });
                let waiting = rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok();
                if waiting {
                    let private = std::fs::read_dir(dir.path())
                        .unwrap()
                        .map(|e| e.unwrap().path())
                        .find(|p| {
                            p.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".aerorepair-private-")
                        })
                        .unwrap();
                    assert_eq!(acl::guest_effective_rights(&private).unwrap() & 1, 0);
                    let stage = std::fs::read_dir(private)
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    assert_eq!(acl::guest_effective_rights(&stage).unwrap() & 1, 0);
                }
                drop(guard);
                assert!(waiting, "repair never waited for held source guard");
                assert!(matches!(
                    worker.join().unwrap().unwrap(),
                    SyncEcRepairResult::Repaired { .. }
                ));
            });
            assert_eq!(std::fs::read(&path).unwrap(), data);
            assert_eq!(acl::guest_effective_rights(&path).unwrap() & 1, 0);
        }
        eprintln!("Windows repair: second-principal read denied during contention and after both repair publications");
    }
}
