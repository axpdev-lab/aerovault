// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AEROVAULT3 rev. 4 Error Correction (Reed-Solomon `.aerocorrect`).
//!
//! A faithful, byte-for-byte port of the AeroFTP application's AEROVAULT3 Error
//! Correction operations (`src-tauri/src/aerovault_v3.rs`), minus the Tauri
//! command layer, async and telemetry. Saves and `export_parity` take the
//! crate's cross-process write lock (`<vault>.aerolock`, see `crate::lock`).
//!
//! Error Correction is NON-CRITICAL: the embedded extension and the
//! metadata-parity extension are both `critical=false`, so a rev. 3 reader still
//! opens and extracts a rev. 4 container; the on-disk major stays 3. Recovery is
//! ALL-OR-NOTHING: every reconstructed region is re-verified against the vault's
//! authenticated values (header MAC / manifest cipher_hash) before it is
//! persisted, so a foreign or stale sidecar can only make a repair FAIL, never
//! overwrite good data (CLAUDE-AV-ECC-01). The `.aerocorrect` content-SHA binding
//! is informational and is never enforced on the repair path (#276).

// SPDX-License-Identifier: MPL-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::constants::{
    DATA_OFFSET, ERROR_CORRECTION_ALGORITHM_ID, ERROR_CORRECTION_ALGORITHM_VERSION,
    ERROR_CORRECTION_EXTENSION_ID, ERROR_CORRECTION_META_EXTENSION_ID, HEADER_SIZE, MAX_BLOCK_SIZE,
    MAX_EXTENSION_DIR_SIZE, MAX_MANIFEST_SIZE,
};
use super::format::VaultHeaderV3;
use super::manifest::{ChunkRecordV3, ExtensionEntryV3};
use super::vault::{
    assert_vault_generation_current, atomic_write, open_header_bytes, read_capped, save_open_vault,
    OpenVaultV3, UnlockedHeader,
};
use crate::error_correction::{
    compute_error_correction_shards_grid, compute_metadata_parity, manifest_error_correction_grid,
    reconstruct_from_error_correction,
};
use crate::error_correction::{AeroCorrectSegment, AeroCorrectSidecar};

/// Segment roles in a vault's `.aerocorrect` sidecar, by fixed index.
const VAULT_SIDECAR_SEG_HEADER: usize = 0;
const VAULT_SIDECAR_SEG_MANIFEST: usize = 1;
const VAULT_SIDECAR_SEG_DATA: usize = 2;

/// Where Error Correction parity lives relative to the vault container.
///
/// - `Embedded`: parity is a non-critical extension inside the `.aerovault` file,
///   recomputed on every seal (auto-fresh, but it grows the container).
/// - `Detached`: parity lives in a sibling `.aerocorrect` sidecar; the container
///   stays byte-identical to a non-Error-Correction vault. The sidecar is
///   regenerated on demand via `export_parity` (par2 semantics).
/// - `Both`: embed AND write the sidecar (detached-first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPlacement {
    Embedded,
    Detached,
    Both,
}

impl RecoveryPlacement {
    /// Parse `embedded|detached|both` (case-insensitive, trimmed).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "embedded" => Ok(Self::Embedded),
            "detached" => Ok(Self::Detached),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "Unknown recovery placement: {other} (expected embedded|detached|both)"
            )),
        }
    }

    /// True when the placement keeps a copy of the parity inside the container.
    pub(super) fn embeds(self) -> bool {
        matches!(self, Self::Embedded | Self::Both)
    }

    /// True when the placement writes a `.aerocorrect` sidecar.
    pub(super) fn writes_sidecar(self) -> bool {
        matches!(self, Self::Detached | Self::Both)
    }
}

/// Which source `resolve_parity_source` ended up using, for honest reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParitySource {
    Explicit,
    Detached,
    Embedded,
    None,
}

impl ParitySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Detached => "detached",
            Self::Embedded => "embedded",
            Self::None => "none",
        }
    }
}

/// Returns the stub ExtensionEntry for the Error Correction layer (length 0
/// payload at create time). Marked non-critical so rev. 3 readers can extract.
pub(super) fn error_correction_stub_extension() -> ExtensionEntryV3 {
    ExtensionEntryV3 {
        extension_id: ERROR_CORRECTION_EXTENSION_ID.to_string(),
        algorithm_id: ERROR_CORRECTION_ALGORITHM_ID.to_string(),
        algorithm_version: ERROR_CORRECTION_ALGORITHM_VERSION,
        critical: false,
        offset: 0, // overwritten by build_file_bytes when placed after manifest
        length: 0,
    }
}

/// Default sidecar path for a vault: `X` gets `X.aerocorrect`.
pub(super) fn default_sidecar_path(vault_path: &Path) -> PathBuf {
    let mut native = vault_path.as_os_str().to_os_string();
    native.push(".aerocorrect");
    PathBuf::from(native)
}

pub(super) fn legacy_sidecar_path(vault: &Path) -> Option<PathBuf> {
    let old = PathBuf::from(crate::error_correction::sidecar::aerocorrect_sidecar_path(
        &vault.to_string_lossy(),
    ));
    (old != default_sidecar_path(vault)).then_some(old)
}

fn recovery_sidecar_path(vault: &Path) -> PathBuf {
    let native = default_sidecar_path(vault);
    if std::fs::symlink_metadata(&native).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        if let Some(legacy) = legacy_sidecar_path(vault).filter(|p| p.exists()) {
            return legacy;
        }
    }
    native
}

/// An automatic recovery filename is not authorization to replace another
/// vault or a non-file. Call only while its destination guard is held.
pub(crate) fn validate_automatic_sidecar_destination(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Inspect automatic sidecar destination: {e}")),
        Ok(meta) if !meta.is_file() => {
            return Err(
                "Automatic sidecar destination is not a regular file; vault left unchanged"
                    .to_string(),
            )
        }
        Ok(_) => {}
    }
    let file = crate::source::open_regular_no_follow(path).map_err(|e| e.to_string())?;
    let mut magic = Vec::with_capacity(9);
    file.take(9)
        .read_to_end(&mut magic)
        .map_err(|e| e.to_string())?;
    // A damaged vault can still recover its magic from its own parity. Only
    // recognizable sidecar framing authorizes an automatic refresh. Inspect
    // a fixed prefix, not an attacker-sized locator or parity payload.
    if magic.len() != 9
        || &magic[..8] != crate::error_correction::AEROCORRECT_MAGIC
        || !matches!(magic[8], 1 | crate::error_correction::AEROCORRECT_VERSION)
    {
        return Err("Automatic sidecar destination contains a vault or unrecognized file; move it aside or choose an explicit output path".to_string());
    }
    // A recognizable prefix alone is insufficient: even those bytes of a
    // damaged vault can be reconstructed from its own header parity. Validate
    // the supported framing with a bounded locator and no parity allocation.
    // Only legacy v1 needs a whole-file checksum scan; refuse oversized legacy
    // candidates here rather than letting recognition scan an arbitrary file.
    use crate::error_correction::sidecar::{AeroCorrectSidecarReader, SidecarReadLimits};
    AeroCorrectSidecarReader::open_bounded(path, SidecarReadLimits {
        segments: 1024,
        file_len: if magic[8] == 1 { 1024 * 1024 * 1024 } else { u64::MAX },
    }).map_err(|e| format!("Automatic sidecar destination is an unrecognized or unbounded recovery file ({e}); choose an explicit output path to replace it"))?;
    Ok(())
}

/// SHA-256 of a byte slice (the unified `.aerocorrect` format binds by content).
fn container_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn container_sha256_file(path: &Path) -> Result<([u8; 32], u64), String> {
    use sha2::{Digest, Sha256};
    let mut file = crate::source::open_regular(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    let mut len = 0u64;
    loop {
        let n = file.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        len = len
            .checked_add(n as u64)
            .ok_or("container length overflow")?;
    }
    Ok((hash.finalize().into(), len))
}

/// Build a vault's `.aerocorrect` sidecar from the three region parities, in the
/// fixed segment order (header, manifest, data). An empty parity vector marks an
/// unprotected region. The container SHA-256 is the informational content
/// binding (never enforced on the repair path).
fn build_vault_sidecar(
    container_hash: [u8; 32],
    container_len: u64,
    header: &VaultHeaderV3,
    data_parity: Vec<u8>,
    manifest_parity: Vec<u8>,
    header_parity: Vec<u8>,
) -> AeroCorrectSidecar {
    let segments = vec![
        AeroCorrectSegment {
            window_offset: 0,
            window_len: HEADER_SIZE as u64,
            avec_bytes: header_parity,
        },
        AeroCorrectSegment {
            window_offset: header.manifest_offset,
            window_len: header.manifest_len,
            avec_bytes: manifest_parity,
        },
        AeroCorrectSegment {
            window_offset: header.data_offset,
            window_len: header.data_len,
            avec_bytes: data_parity,
        },
    ];
    AeroCorrectSidecar::new(container_hash, container_len, segments)
}

/// The parity (AVEC) bytes a vault sidecar carries for one region, by fixed
/// segment index. Empty slice when the region is absent or unprotected.
#[cfg(test)]
fn vault_sidecar_parity(sidecar: &AeroCorrectSidecar, role: usize) -> &[u8] {
    sidecar
        .segments
        .get(role)
        .map(|s| s.avec_bytes.as_slice())
        .unwrap_or(&[])
}

/// Seed an empty three-region sidecar at create time (detached/both placements),
/// so the file exists from creation; `export_parity` fills it once files are
/// added. `container_bytes` are the just-written empty-vault bytes. The caller
/// holds the destination guard from before replacing the source through this write.
pub(super) fn seed_empty_sidecar(
    path: &Path,
    container_bytes: &[u8],
    _out_lock: &Option<crate::lock::WriteLock>,
) -> Result<(), String> {
    let segments = vec![
        AeroCorrectSegment {
            window_offset: 0,
            window_len: HEADER_SIZE as u64,
            avec_bytes: Vec::new(),
        },
        AeroCorrectSegment {
            window_offset: DATA_OFFSET,
            window_len: 0,
            avec_bytes: Vec::new(),
        },
        AeroCorrectSegment {
            window_offset: DATA_OFFSET,
            window_len: 0,
            avec_bytes: Vec::new(),
        },
    ];
    let sidecar = AeroCorrectSidecar::new(
        container_sha256(container_bytes),
        container_bytes.len() as u64,
        segments,
    );
    let out = default_sidecar_path(path);
    atomic_write(&out, &sidecar.to_bytes())
}

/// Collect the live on-disk blocks in data-section order ([u64 len][ciphertext]),
/// the exact stream the Error Correction parity is computed over. A block whose
/// recorded range falls outside the data section contributes an empty slice.
fn collect_live_block_refs(vault: &OpenVaultV3) -> Vec<&[u8]> {
    let mut ranges: Vec<(usize, usize)> = vault
        .manifest
        .chunks
        .values()
        .map(|rec| (rec.data_offset as usize, rec.block_len as usize))
        .collect();
    ranges.sort_by_key(|(off, _)| *off);
    ranges
        .into_iter()
        .map(|(start, block_len)| {
            // Every add is checked: a corrupted manifest can drive data_offset or
            // block_len near usize::MAX. An out-of-range block contributes an empty
            // slice instead of panicking (matches scrub_vault's hardening). Repair
            // re-verifies each block, so a dropped range can only make repair fail,
            // never corrupt good data (CLAUDE-AV-ECC unchecked-add hardening).
            let end = block_len
                .checked_add(8)
                .and_then(|full| start.checked_add(full));
            match end {
                Some(end) if end <= vault.data.len() => &vault.data[start..end],
                _ => &[] as &[u8],
            }
        })
        .collect()
}

/// Geometry-derived upper bounds apply before parsing even a legacy locator.
/// Parity bytes and checksum counts have independent monotone upper bounds.
fn open_vault_sidecar(
    vault_path: &Path,
    sidecar: &Path,
) -> Result<crate::error_correction::sidecar::AeroCorrectSidecarReader, String> {
    use crate::error_correction::{
        parity_payload_bound,
        sidecar::{AeroCorrectSidecarReader, SidecarReadLimits},
    };
    let size = crate::source::open_regular(vault_path)
        .and_then(|f| f.metadata())
        .map_err(|e| e.to_string())?
        .len();
    let data = parity_payload_bound(size)?;
    let manifest = parity_payload_bound(size.min(MAX_MANIFEST_SIZE))?;
    let header = parity_payload_bound(HEADER_SIZE as u64)?;
    let max = data
        .checked_add(manifest)
        .and_then(|n| n.checked_add(header))
        .ok_or("sidecar bound overflow")?;
    AeroCorrectSidecarReader::open_bounded(sidecar, SidecarReadLimits::vault(max)?)
}

fn read_vault_segment(
    vault_path: &Path,
    sidecar: &Path,
    index: usize,
    region_len: u64,
) -> Result<Vec<u8>, String> {
    let max = crate::error_correction::parity_payload_bound(region_len)?;
    let max = usize::try_from(max).map_err(|_| "sidecar parity exceeds address space")?;
    open_vault_sidecar(vault_path, sidecar)?.read_segment_avec_bounded(index, max)
}

/// Read the embedded `ERROR_CORRECTION_EXTENSION_ID` payload from the vault file,
/// if present and non-empty. Located via the MAC-verified header.
fn read_embedded_error_correction(vault: &OpenVaultV3) -> Result<Option<Vec<u8>>, String> {
    let entry = match vault
        .extensions
        .iter()
        .find(|e| e.extension_id == ERROR_CORRECTION_EXTENSION_ID)
    {
        Some(e) if e.length > 0 => e.clone(),
        _ => return Ok(None),
    };
    let mut f = crate::source::open_regular(&vault.path)
        .map_err(|e| format!("open for parity read: {e}"))?;
    let abs = vault.header.extension_payload_offset + entry.offset;
    f.seek(SeekFrom::Start(abs))
        .map_err(|e| format!("seek for parity read: {e}"))?;
    let mut b = vec![0u8; entry.length as usize];
    f.read_exact(&mut b)
        .map_err(|e| format!("read error_correction payload: {e}"))?;
    Ok(Some(b))
}

/// Resolve the Error Correction data-block parity bytes for a vault, in priority
/// order: explicit `parity` path -> detached `.aerocorrect` sidecar -> embedded
/// extension. The content binding is NOT enforced here; a stale/foreign sidecar
/// can only make a repair fail the caller's re-verify, never overwrite good data.
pub(super) fn resolve_parity_source(
    vault: &OpenVaultV3,
    explicit: Option<&Path>,
) -> Result<(Vec<u8>, ParitySource), String> {
    // Read only the selected parity region under the vault-specific limits.
    if let Some(p) = explicit {
        return Ok((
            read_vault_segment(
                &vault.path,
                p,
                VAULT_SIDECAR_SEG_DATA,
                vault.header.data_len,
            )?,
            ParitySource::Explicit,
        ));
    }
    let sidecar_path = recovery_sidecar_path(&vault.path);
    if sidecar_path.exists() {
        let parity = read_vault_segment(
            &vault.path,
            &sidecar_path,
            VAULT_SIDECAR_SEG_DATA,
            vault.header.data_len,
        )?;
        if !parity.is_empty() {
            return Ok((parity, ParitySource::Detached));
        }
    }
    // 3. Embedded extension payload.
    if let Some(bytes) = read_embedded_error_correction(vault)? {
        return Ok((bytes, ParitySource::Embedded));
    }
    Err(
        "No Error Correction parity available (no --parity, no .aerocorrect sidecar, no embedded extension)"
            .to_string(),
    )
}

/// A parsed empty creation seed has no recovery to protect. Missing sidecars
/// likewise do not block salvage; unreadable/malformed recovery stays protected.
pub(super) fn detached_recovery_needs_protection(path: &Path) -> bool {
    let sidecar = recovery_sidecar_path(path);
    if !sidecar.exists() {
        return false;
    }
    match open_vault_sidecar(path, &sidecar) {
        Ok(reader) => reader.segments().iter().any(|s| s.avec_len != 0),
        Err(_) => true,
    }
}

/// Read the raw on-disk encrypted-manifest bytes (the exact bytes the manifest
/// parity must protect; re-encrypting would use a fresh nonce and not match).
fn read_manifest_raw(vault_path: &Path, header: &VaultHeaderV3) -> Result<Vec<u8>, String> {
    let mut f = crate::source::open_regular(vault_path)
        .map_err(|e| format!("open for manifest read: {e}"))?;
    read_capped(
        &mut f,
        header.manifest_offset,
        header.manifest_len,
        MAX_MANIFEST_SIZE,
        "manifest",
    )
}

/// Outcome of [`export_parity`].
#[derive(Debug, Clone)]
pub struct ExportParityResult {
    pub path: PathBuf,
    pub shards: u64,
    pub bytes_protected: u64,
    pub overhead_pct: f64,
    pub payload_len: u64,
    pub file_len: u64,
    /// Bytes of header parity carried in the sidecar (0 when none).
    pub header_parity_len: u64,
    /// Bytes of manifest (locator) parity carried in the sidecar (0 when none).
    pub manifest_parity_len: u64,
}

/// Write a detached `.aerocorrect` recovery file for an existing vault. The
/// encrypted container is read but never rewritten. Defaults to
/// `<vault>.aerocorrect`; pass `out_path` to override.
pub(super) fn export_parity(
    vault_path: &Path,
    password: &str,
    out_path: Option<&Path>,
) -> Result<ExportParityResult, String> {
    if let Some(p) = out_path {
        crate::lock::refuse_destination(p, vault_path).map_err(|e| e.to_string())?;
    }
    // Export only reads its source: resolve a leaf link, lock its target, and
    // keep output checks against both the supplied alias and the real source.
    let real =
        std::fs::canonicalize(vault_path).map_err(|e| format!("Resolve export source: {e}"))?;
    if let Some(p) = out_path {
        crate::lock::refuse_destination(p, &real).map_err(|e| e.to_string())?;
    }
    let lock = crate::lock::acquire_for_export(&real).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if let Some(hook) = AFTER_EXPORT_SOURCE_LOCK.with(|h| h.borrow_mut().take()) {
        hook();
    }
    // Only a symbolic leaf keeps an alias namespace on open. Windows regular
    // 8.3/case aliases open under their canonical long leaf instead.
    if out_path.is_some()
        || !std::fs::symlink_metadata(vault_path).is_ok_and(|m| m.file_type().is_symlink())
    {
        return export_parity_locked(lock.source_path(), password, out_path, &lock);
    }
    let out = default_sidecar_path(vault_path);
    crate::lock::refuse_destination(&out, vault_path).map_err(|e| e.to_string())?;
    crate::lock::refuse_destination(&out, &real).map_err(|e| e.to_string())?;
    export_parity_locked_impl(lock.source_path(), password, &out, true, &lock)
}

/// [`export_parity`] under the caller's write lock, held from the read of the
/// vault to the publication of the sidecar. While the caller holds a real
/// source lock, no writer that takes it can save in between. A read-only export
/// from media with no creatable lock has only the generation check below.
/// A writer that does not take the lock (an older version, a
/// manual copy) is caught only if it changed the vault before the generation
/// check below; one that replaces it between that check and the publication
/// is not.
pub(super) fn export_parity_locked(
    vault_path: &Path,
    password: &str,
    out_path: Option<&Path>,
    _lock: &crate::lock::WriteLock,
) -> Result<ExportParityResult, String> {
    let out = out_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sidecar_path(vault_path));
    export_parity_locked_impl(vault_path, password, &out, out_path.is_none(), _lock)
}

fn export_parity_locked_impl(
    vault_path: &Path,
    password: &str,
    out: &Path,
    automatic: bool,
    source_lock: &crate::lock::WriteLock,
) -> Result<ExportParityResult, String> {
    std::fs::create_dir_all(super::vault::output_parent_dir(out)).map_err(|e| e.to_string())?;
    let out = crate::lock::anchored(out).map_err(|e| e.to_string())?;
    let out_lock = crate::lock::acquire_destination(&out, vault_path, source_lock)
        .map_err(|e| e.to_string())?;
    if automatic {
        validate_automatic_sidecar_destination(&out)?;
    }
    export_parity_under_locks(vault_path, password, &out, source_lock, &out_lock)
}

/// Export with both namespace locks held; also used by password-change refresh,
/// which holds the destination lock across the save and any stale-sidecar cleanup.
pub(super) fn export_parity_under_locks(
    vault_path: &Path,
    password: &str,
    out: &Path,
    _source_lock: &crate::lock::WriteLock,
    _out_lock: &Option<crate::lock::WriteLock>,
) -> Result<ExportParityResult, String> {
    let vault = super::vault::open_vault_under_guard(vault_path, password, _source_lock)?;
    if vault.manifest_repaired_on_open {
        return Err(
            "Vault manifest was recovered on open: run repair before exporting parity".to_string(),
        );
    }
    if !scrub_vault(&vault).is_empty() {
        return Err("Vault has damaged blocks: run repair before exporting parity".to_string());
    }
    // QR-style overhead level (#276): the grid recorded on the vault drives every
    // parity section so a detached sidecar matches the user's chosen overhead.
    let (k, p) = manifest_error_correction_grid(vault.manifest.error_correction_pct);
    let blocks = collect_live_block_refs(&vault);
    let (payload, shards, protected, overhead) =
        compute_error_correction_shards_grid(&blocks, k, p);
    // GAP-4 metadata bundle: protect the two regions the detached container cannot
    // self-locate once damaged. Header parity is over the authoritative in-memory
    // header (`to_bytes()` round-trips a clean header byte-for-byte); manifest
    // parity is over the exact on-disk encrypted bytes (a re-encrypt would use a
    // fresh nonce and not match).
    let header_parity = compute_metadata_parity(&vault.header.to_bytes(), k, p);
    let manifest_raw = read_manifest_raw(vault_path, &vault.header)?;
    let manifest_parity = compute_metadata_parity(&manifest_raw, k, p);
    let payload_len = payload.len() as u64;
    let header_parity_len = header_parity.len() as u64;
    let manifest_parity_len = manifest_parity.len() as u64;
    // Content binding: the SHA-256 of the on-disk container we are protecting.
    let (container_hash, container_len) = container_sha256_file(vault_path)?;
    let sidecar = build_vault_sidecar(
        container_hash,
        container_len,
        &vault.header,
        payload,
        manifest_parity,
        header_parity,
    );
    let bytes = sidecar.to_bytes();
    // Lock-aware writers are held off by the lock. This check also catches a
    // writer that does not take it (an older version, a manual copy), if it
    // changed the vault before this point; not one that does so after it.
    #[cfg(test)]
    super::vault::run_before_sidecar_publish_hook();
    assert_vault_generation_current(&vault)?;
    #[cfg(test)]
    if let Some(hook) = AFTER_EXPORT_GENERATION.with(|h| h.borrow_mut().take()) {
        hook();
    }
    atomic_write(out, &bytes)?;
    Ok(ExportParityResult {
        path: out.to_path_buf(),
        shards,
        bytes_protected: protected,
        overhead_pct: overhead,
        payload_len,
        file_len: bytes.len() as u64,
        header_parity_len,
        manifest_parity_len,
    })
}

#[cfg(test)]
thread_local! {
    static AFTER_EXPORT_SOURCE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_EXPORT_GENERATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Outcome of [`strip_parity`].
#[derive(Debug, Clone)]
pub struct StripParityResult {
    pub sidecar_present: bool,
    pub sidecar_path: PathBuf,
}

/// Drop the embedded Error Correction extension on the next seal. Refuses unless
/// a detached sidecar supplies parity for the current blocks or `force` is set, so a vault is never
/// silently left with zero recovery.
pub(super) fn strip_parity(
    vault_path: &Path,
    password: &str,
    force: bool,
) -> Result<StripParityResult, String> {
    // Under the lock from the sidecar check to the save, so a writer that
    // removes the sidecar meanwhile (a failed password-change refresh) cannot
    // leave the vault with no recovery at all.
    let lock = super::vault::write_lock(vault_path)?;
    let vault_path = lock.source_path();
    let mut vault = super::vault::open_vault_under_guard(vault_path, password, &lock)?;
    let had_embedded = vault
        .extensions
        .iter()
        .any(|e| e.extension_id == ERROR_CORRECTION_EXTENSION_ID);
    if !had_embedded {
        return Err("Vault has no embedded Error Correction parity to strip".to_string());
    }
    let sidecar = default_sidecar_path(vault_path);
    let _sidecar_lock = if !force {
        // We read the recovery file itself: the export-only symlink-replacement
        // exception cannot protect a symlink target while validating it.
        Some(crate::lock::acquire(&sidecar).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let has_sidecar = sidecar.exists();
    if !has_sidecar && !force {
        return Err(
            "Refusing to strip embedded parity: no detached recovery file exists. Run \"vault export-parity\" first, or pass --force to drop recovery entirely."
                .to_string(),
        );
    }
    if !force {
        if !scrub_vault(&vault).is_empty() {
            return Err("Vault has damaged blocks: run repair before stripping parity".to_string());
        }
        let mut detached = open_vault_sidecar(vault_path, &sidecar)?;
        detached
            .verify_binding(&container_sha256_file(vault_path)?.0)
            .map_err(|e| format!("{e}; run export-parity before stripping, or pass --force"))?;
        let blocks = collect_live_block_refs(&vault);
        let (k, p) = manifest_error_correction_grid(vault.manifest.error_correction_pct);
        let (expected, _, _, _) = compute_error_correction_shards_grid(&blocks, k, p);
        if detached.read_segment_avec_bounded(VAULT_SIDECAR_SEG_DATA, expected.len())? != expected {
            return Err("Refusing to strip embedded parity: detached data parity is missing, damaged or stale. Run \"vault export-parity\" first, or pass --force to drop recovery entirely.".to_string());
        }
        {
            // Data parity alone cannot protect current metadata, even when
            // data blocks have not changed since an earlier export.
            let header = compute_metadata_parity(&vault.header.to_bytes(), k, p);
            let manifest =
                compute_metadata_parity(&read_manifest_raw(vault_path, &vault.header)?, k, p);
            if detached.read_segment_avec_bounded(VAULT_SIDECAR_SEG_HEADER, header.len())? != header
                || detached.read_segment_avec_bounded(VAULT_SIDECAR_SEG_MANIFEST, manifest.len())?
                    != manifest
            {
                return Err("Refusing to strip embedded parity: detached metadata parity is missing, damaged or stale. Run \"vault export-parity\" first, or pass --force.".to_string());
            }
        }
    }
    vault
        .extensions
        .retain(|e| e.extension_id != ERROR_CORRECTION_EXTENSION_ID);
    if force {
        super::vault::save_locked(&mut vault, &lock)?;
    } else {
        let prepared = super::strip_transaction::private_dir(
            super::vault::output_parent_dir(vault_path),
            ".aerostrip-prepare-",
        )?;
        super::strip_transaction::copy_file(vault_path, &prepared.path().join("old-vault"))?;
        super::strip_transaction::copy_file(&sidecar, &prepared.path().join("old-sidecar"))?;
        let staged = prepared.path().join("new-vault");
        super::vault::save_locked_to(&mut vault, &lock, &staged)?;
        // The staged seal is complete; release the original data before opening
        // it again for parity. Rollback is a synced on-disk copy, never a Vec.
        drop(vault);
        export_parity_under_locks(
            &staged,
            password,
            &prepared.path().join("new-sidecar"),
            &lock,
            &_sidecar_lock,
        )?;
        super::strip_transaction::publish(vault_path, prepared, &lock)?;
    }
    Ok(StripParityResult {
        sidecar_present: has_sidecar,
        sidecar_path: sidecar,
    })
}

/// A damaged chunk found by [`scrub_vault`].
#[derive(Debug, Clone)]
pub struct DamagedChunk {
    pub record: ChunkRecordV3,
    /// Start offset in the vault file's data section (includes the u64 prefix).
    pub on_disk_start: u64,
    /// Full length of the stored unit (8 + cipher len).
    pub on_disk_len: u64,
}

/// Walk the chunks in data-section order, verify each `cipher_hash` against the
/// stored ciphertext block. Returns the damaged chunks with their full on-disk
/// byte range (starting at the u64 length prefix).
pub(super) fn scrub_vault(vault: &OpenVaultV3) -> Vec<DamagedChunk> {
    let mut damaged = vec![];

    let mut chunks: Vec<_> = vault.manifest.chunks.values().cloned().collect();
    chunks.sort_by_key(|c| c.data_offset);

    for rec in chunks {
        let start = rec.data_offset as usize;
        // A corrupted length prefix can make `data_offset` (or the stored block
        // length below) point near usize::MAX; every offset add is checked so a
        // hostile manifest is reported as damaged instead of panicking on
        // overflow (CLAUDE-AV-ECC, unchecked-add hardening).
        let len_end = match start.checked_add(8) {
            Some(end) if end <= vault.data.len() => end,
            _ => {
                // Truncated or out-of-range block - definitely damaged.
                damaged.push(DamagedChunk {
                    record: rec.clone(),
                    on_disk_start: rec.data_offset,
                    on_disk_len: 8,
                });
                continue;
            }
        };

        let stored_len =
            u64::from_le_bytes(vault.data[start..len_end].try_into().expect("slice")) as usize;

        let block_start = len_end;
        let block_end = block_start.checked_add(stored_len);

        // `8 + stored_len` is reported even on the damaged path, so compute it
        // saturating: a corrupted prefix can drive stored_len near usize::MAX.
        let on_disk_len = (stored_len as u64).saturating_add(8);

        let Some(block_end) = block_end.filter(|&end| end <= vault.data.len()) else {
            damaged.push(DamagedChunk {
                record: rec.clone(),
                on_disk_start: rec.data_offset,
                on_disk_len,
            });
            continue;
        };
        if stored_len != rec.block_len as usize {
            damaged.push(DamagedChunk {
                record: rec.clone(),
                on_disk_start: rec.data_offset,
                on_disk_len,
            });
            continue;
        }

        let cipher_block = &vault.data[block_start..block_end];
        let actual_hash = blake3::hash(cipher_block).to_hex().to_string();

        if actual_hash != rec.cipher_hash {
            damaged.push(DamagedChunk {
                record: rec.clone(),
                on_disk_start: rec.data_offset,
                on_disk_len,
            });
        }
    }

    damaged
}

/// Repair damaged blocks from Error-Correction parity. ALL-OR-NOTHING: every
/// reconstructed block is re-verified against its manifest `cipher_hash` and the
/// vault is persisted only if the entire reconstructed stream verifies; any
/// failure leaves the vault byte-for-byte untouched (CLAUDE-AV-ECC-01).
pub(super) fn repair_vault(
    vault: &mut OpenVaultV3,
    dry_run: bool,
    parity: Option<&Path>,
) -> Result<(usize, ParitySource), String> {
    super::vault::validate_chunk_identities(&vault.manifest)?;
    let damaged = scrub_vault(vault);
    if damaged.is_empty() {
        // GAP-4 / HEADER: no damaged data blocks, but if open had to rebuild a
        // corrupted manifest (metadata parity) or header (sidecar header parity),
        // persist the healed region. The seal rewrites the header with a fresh
        // MAC and re-encrypts the (correct, in-memory) manifest, regenerating
        // parities.
        if vault.manifest_repaired_on_open || vault.header_repaired_on_open {
            if !dry_run {
                save_open_vault(vault)?;
            }
            return Ok((1, ParitySource::None));
        }
        return Ok((0, ParitySource::None));
    }

    // Resolve parity in priority order (explicit -> detached sidecar -> embedded).
    // An explicitly named source that fails is a hard error; a missing default
    // source just means "nothing to repair from", leaving the vault untouched.
    let (error_correction_bytes, source) = match resolve_parity_source(vault, parity) {
        Ok((b, s)) => (Some(b), s),
        Err(e) => {
            if parity.is_some() {
                return Err(e);
            }
            (None, ParitySource::None)
        }
    };

    let mut repaired_count = 0;

    if let Some(error_correction_b) = error_correction_bytes {
        let mut ordered: Vec<(String, ChunkRecordV3)> = vault
            .manifest
            .chunks
            .iter()
            .map(|(id, r)| (id.clone(), r.clone()))
            .collect();
        ordered.sort_by_key(|(_, r)| r.data_offset);
        // On the plaintext lane block_len comes from an unauthenticated manifest
        // and sizes the buffers below: bound each block like every other reader,
        // and the total by the data section, since live blocks never overlap.
        let total = ordered.iter().try_fold(0u64, |acc, (_, r)| {
            (r.block_len <= MAX_BLOCK_SIZE)
                .then(|| acc.checked_add(8 + r.block_len))
                .flatten()
        });
        if !matches!(total, Some(t) if t <= vault.data.len() as u64) {
            return Err(
                "AeroVault v3 chunk records exceed the block limit or the data section".to_string(),
            );
        }

        let mut blocks: Vec<Vec<u8>> = ordered
            .iter()
            .map(|(_, rec)| {
                let start = rec.data_offset as usize;
                let full = 8 + rec.block_len as usize;
                // Always a fixed-length (8 + block_len) buffer so the
                // concatenated stream length matches what the parity was computed
                // over, even when the block is truncated on disk: the missing tail
                // is zero-padded here, flagged as damaged by its shard checksum,
                // then reconstructed.
                let mut buf = vec![0u8; full];
                if start < vault.data.len() {
                    let avail = (vault.data.len() - start).min(full);
                    buf[..avail].copy_from_slice(&vault.data[start..start + avail]);
                }
                buf
            })
            .collect();

        let bad_indices: Vec<usize> = damaged
            .iter()
            .filter_map(|d| ordered.iter().position(|(id, _)| id == &d.record.id))
            .collect();

        let _ = reconstruct_from_error_correction(&mut blocks, &error_correction_b)?;

        // Safety gate (CLAUDE-AV-ECC-01): RS reconstruction is only correct when
        // the surviving data shards AND the parity shards were themselves intact.
        // The parity lives in the extension payload, which scrub does not cover,
        // so a rotted parity shard (or more erasures than parity in a stripe)
        // silently yields wrong bytes. Verify every reconstructed block against
        // its authenticated manifest cipher_hash before trusting it, including
        // blocks that scrub considered healthy: a stale/foreign sidecar can mark
        // those shards as erasures and rewrite them too. Persist only when the
        // entire reconstructed stream matches the manifest, preserving the
        // all-or-nothing repair safety contract ("never overwrite without hash
        // verification").
        let block_verified = |i: usize| {
            let blk = &blocks[i];
            if blk.len() < 8 {
                return false;
            }
            let body_u64 = u64::from_le_bytes(blk[0..8].try_into().unwrap());
            let Ok(body) = usize::try_from(body_u64) else {
                return false;
            };
            let Some(full_len) = 8usize.checked_add(body) else {
                return false;
            };
            blk.len() == full_len
                && body_u64 == ordered[i].1.block_len
                && blake3::hash(&blk[8..8 + body]).to_hex().to_string() == ordered[i].1.cipher_hash
        };
        let all_verified = blocks.iter().enumerate().all(|(i, _)| block_verified(i));

        if all_verified {
            repaired_count = bad_indices.len();
            if !dry_run {
                let mut new_data = vec![];
                let mut new_chunks = BTreeMap::new();
                for (i, (id, mut rec)) in ordered.into_iter().enumerate() {
                    rec.data_offset = new_data.len() as u64;
                    if blocks[i].len() >= 8 {
                        rec.block_len = u64::from_le_bytes(blocks[i][0..8].try_into().unwrap());
                    }
                    new_data.extend_from_slice(&blocks[i]);
                    new_chunks.insert(id, rec);
                }
                let old_data = std::mem::replace(&mut vault.data, new_data);
                let old_chunks = std::mem::replace(&mut vault.manifest.chunks, new_chunks);
                if let Err(error) = save_open_vault(vault) {
                    vault.data = old_data;
                    vault.manifest.chunks = old_chunks;
                    return Err(error);
                }
            }
        }
        // else: reconstruction could not be verified -> leave the vault
        // byte-for-byte untouched (repaired_count stays 0) so no redundancy is lost.
    }

    // Damage was found but nothing could be repaired (no parity, damage beyond
    // the parity budget, or a stale/foreign sidecar): say so instead of
    // returning a zero count that reads as "nothing to repair".
    if repaired_count == 0 {
        return Err(format!(
            "{} damaged block(s) could not be repaired from the available Error Correction parity",
            damaged.len()
        ));
    }
    Ok((repaired_count, source))
}

/// HEADER parity: rebuild a corrupted 1024-byte header from the detached
/// sidecar's header parity, returning the verified header + keys when the rebuild
/// unlocks with `password`. `Ok(None)` when there is no sidecar / no header
/// parity / the rebuild does not verify (caller keeps the original open error).
pub(super) fn recover_header_from_sidecar(
    vault_path: &Path,
    on_disk_header: &[u8],
    password: &str,
) -> Result<Option<UnlockedHeader>, String> {
    let sidecar_path = recovery_sidecar_path(vault_path);
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let header_parity = match read_vault_segment(
        vault_path,
        &sidecar_path,
        VAULT_SIDECAR_SEG_HEADER,
        HEADER_SIZE as u64,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if header_parity.is_empty() {
        return Ok(None);
    }
    // The header is a single fixed-length block; reconstruct requires the on-disk
    // bytes at exactly HEADER_SIZE so the stream lengths line up.
    if on_disk_header.len() != HEADER_SIZE {
        return Ok(None);
    }
    let mut blocks = vec![on_disk_header.to_vec()];
    if reconstruct_from_error_correction(&mut blocks, &header_parity).is_err() {
        return Ok(None);
    }
    let rebuilt = match blocks.into_iter().next() {
        Some(b) if b.len() == HEADER_SIZE => b,
        _ => return Ok(None),
    };
    if sidecar_path != default_sidecar_path(vault_path)
        && on_disk_header.get(12..124) != rebuilt.get(12..124)
    {
        // Different raw salt/wrapped keys can belong to another vault sharing
        // this lossy name. Without unchanged key material, require an explicit
        // owner-selected migration rather than guessing that file's identity.
        return Err("Legacy recovery name is ambiguous because stored key material differs; copy the verified recovery file to the native .aerocorrect path before recovery".to_string());
    }
    match open_header_bytes(&rebuilt, password) {
        Ok(triple) => Ok(Some(triple)),
        Err(_) => Ok(None),
    }
}

/// GAP-4 (detached): rebuild a corrupted encrypted manifest from the sidecar's
/// manifest parity. Returns the rebuilt encrypted-manifest bytes; the caller
/// proves correctness by a successful AEAD decrypt. `Ok(None)` when there is no
/// sidecar / no manifest parity.
pub(super) fn reconstruct_manifest_from_sidecar(
    vault_path: &Path,
    on_disk_manifest: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let sidecar_path = recovery_sidecar_path(vault_path);
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let manifest_parity = match read_vault_segment(
        vault_path,
        &sidecar_path,
        VAULT_SIDECAR_SEG_MANIFEST,
        on_disk_manifest.len() as u64,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if manifest_parity.is_empty() {
        return Ok(None);
    }
    let mut blocks = vec![on_disk_manifest.to_vec()];
    if reconstruct_from_error_correction(&mut blocks, &manifest_parity).is_err() {
        return Ok(None);
    }
    Ok(blocks.into_iter().next())
}

/// Which GAP-4 metadata regions a vault's detached sidecar protects, read without
/// the password. Returns `(manifest_parity_present, header_parity_present)`;
/// `(false, false)` when there is no sidecar or it cannot be parsed.
fn sidecar_parity_flags(vault_path: &Path) -> (bool, bool) {
    let sidecar_path = default_sidecar_path(vault_path);
    match open_vault_sidecar(vault_path, &sidecar_path) {
        Ok(reader) => (
            reader
                .segments()
                .get(VAULT_SIDECAR_SEG_MANIFEST)
                .is_some_and(|s| s.avec_len != 0),
            reader
                .segments()
                .get(VAULT_SIDECAR_SEG_HEADER)
                .is_some_and(|s| s.avec_len != 0),
        ),
        Err(_) => (false, false),
    }
}

/// GAP-4: try to rebuild a corrupted encrypted manifest from the metadata-parity
/// extension. Located via the MAC-verified header. Returns the reconstructed
/// encrypted-manifest bytes when a metadata extension is present, else `None`
/// (caller keeps the original decrypt error). Correctness is not asserted here:
/// the caller re-runs `decrypt_manifest`, whose AEAD authentication is the proof.
pub(super) fn reconstruct_encrypted_manifest(
    file: &mut File,
    header: &VaultHeaderV3,
    file_len: u64,
) -> Result<Option<Vec<u8>>, String> {
    let ext_json = read_capped(
        file,
        header.extension_dir_offset,
        header.extension_dir_len,
        MAX_EXTENSION_DIR_SIZE,
        "extension directory",
    )?;
    let extensions: Vec<ExtensionEntryV3> = match serde_json::from_slice(&ext_json) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let meta = match extensions
        .iter()
        .find(|e| e.extension_id == ERROR_CORRECTION_META_EXTENSION_ID)
    {
        Some(m) if m.length > 0 => m,
        _ => return Ok(None),
    };
    let payload_abs = header
        .extension_payload_offset
        .checked_add(meta.offset)
        .ok_or("metadata parity offset overflows")?;
    let end = payload_abs
        .checked_add(meta.length)
        .ok_or("metadata parity range overflows")?;
    if end > file_len {
        return Err("metadata parity range exceeds file size".to_string());
    }
    // Manifest parity is at most ~20% over the manifest plus a per-shard checksum
    // table; bound it generously by the manifest cap.
    let meta_payload = read_capped(
        file,
        payload_abs,
        meta.length,
        2 * MAX_MANIFEST_SIZE,
        "metadata parity",
    )?;
    let corrupt = read_capped(
        file,
        header.manifest_offset,
        header.manifest_len,
        MAX_MANIFEST_SIZE,
        "manifest",
    )?;
    let mut blocks = vec![corrupt];
    reconstruct_from_error_correction(&mut blocks, &meta_payload)?;
    Ok(blocks.into_iter().next())
}

/// Lightweight check for the embedded Error Correction extension. Reads only the
/// header and the plaintext extension directory; no password needed.
pub(super) fn has_error_correction(path: &Path) -> Result<bool, String> {
    let mut file = crate::source::open_regular(path)
        .map_err(|e| format!("Open vault for Error Correction check: {e}"))?;

    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("Read header for Error Correction check: {e}"))?;

    let header = VaultHeaderV3::from_bytes(&header_bytes)?;

    if header.extension_dir_len == 0 {
        return Ok(false);
    }

    let extension_json = read_capped(
        &mut file,
        header.extension_dir_offset,
        header.extension_dir_len,
        MAX_EXTENSION_DIR_SIZE,
        "extension directory (has_error_correction)",
    )?;

    let extensions: Vec<ExtensionEntryV3> = serde_json::from_slice(&extension_json)
        .map_err(|e| format!("Extension directory parse (has_error_correction): {e}"))?;

    Ok(extensions
        .iter()
        .any(|e| e.extension_id == ERROR_CORRECTION_EXTENSION_ID))
}

/// Recovery surfaces available for a vault without the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStatus {
    /// Embedded in-container Error Correction extension present.
    pub embedded: bool,
    /// A sibling `.aerocorrect` sidecar exists.
    pub detached: bool,
    /// Either source is present.
    pub any: bool,
    /// The detached sidecar carries manifest (locator) parity.
    pub manifest_parity: bool,
    /// The detached sidecar carries header parity.
    pub header_parity: bool,
}

/// Report the Error Correction recovery surfaces for a vault without the password.
pub(super) fn recovery_status(path: &Path) -> Result<RecoveryStatus, String> {
    let embedded = has_error_correction(path).unwrap_or(false);
    let detached = default_sidecar_path(path).exists();
    let (manifest_parity, header_parity) = sidecar_parity_flags(path);
    Ok(RecoveryStatus {
        embedded,
        detached,
        any: embedded || detached,
        manifest_parity,
        header_parity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::vault::{CreateOptionsV3, VaultV3};

    const PW: &str = "ec-test-password-123";

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("av3-ec-{}-{}", rand::random::<u64>(), name));
        p
    }

    /// Write a tree of files into `vault`, large enough to force the per-file CDC
    /// path so we get real data blocks (not just a packed micro-block).
    fn seed_tree(vault: &mut OpenVaultV3, dir: &Path) {
        let big = dir.join("big.bin");
        let mut payload = vec![0u8; super::super::constants::PACK_SMALL_FILE_THRESHOLD + 400_000];
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&big, &payload).unwrap();
        let small = dir.join("note.txt");
        std::fs::write(&small, b"a small note in the vault").unwrap();
        VaultV3::create_directory(vault, "docs").unwrap();
        VaultV3::add_files(
            vault,
            &[
                (big, "big.bin".to_string()),
                (small, "docs/note.txt".to_string()),
            ],
        )
        .unwrap();
    }

    /// Flip a span of bytes inside the on-disk data section of a vault file.
    /// Returns the byte length flipped.
    fn corrupt_data_section(vault_path: &Path, span: usize) -> usize {
        let info = VaultV3::peek(vault_path).unwrap();
        assert!(
            info.data_len as usize >= span,
            "vault has enough data to corrupt"
        );
        let mut bytes = std::fs::read(vault_path).unwrap();
        let start = DATA_OFFSET as usize + 64; // skip the first block's len prefix region
        for b in bytes.iter_mut().skip(start).take(span) {
            *b ^= 0xFF;
        }
        std::fs::write(vault_path, &bytes).unwrap();
        span
    }

    #[test]
    fn review_strip_preserves_current_metadata_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        // Make the encrypted manifest larger than the recovery shard budget:
        // strip's fresh nonce changes every ciphertext shard, not just a label.
        let template = vault
            .manifest
            .entries
            .iter()
            .find(|e| !e.is_dir)
            .unwrap()
            .clone();
        for n in 0..500 {
            let mut entry = template.clone();
            entry.path = format!("copy-{n}-{}.bin", "x".repeat(120));
            vault.manifest.entries.push(entry);
        }
        save_open_vault(&mut vault).unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        VaultV3::rename_entry(&mut vault, "big.bin", "renamed.bin").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            VaultV3::strip_parity(&path, PW, false).is_err(),
            "stale metadata was accepted"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        VaultV3::export_parity(&path, PW, None).unwrap();
        VaultV3::strip_parity(&path, PW, false).unwrap();
        let current = VaultV3::open(&path, PW).unwrap();
        let header = current.header.clone();
        let count = current.manifest.entries.len();
        drop(current);
        let parity =
            AeroCorrectSidecar::from_bytes(&std::fs::read(default_sidecar_path(&path)).unwrap())
                .unwrap();
        assert!(vault_sidecar_parity(&parity, VAULT_SIDECAR_SEG_HEADER).len() > HEADER_SIZE);
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[header.manifest_offset as usize + 4] ^= 1;
        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        let recovered = VaultV3::open(&path, PW).unwrap();
        assert!(recovered.header_repaired_on_open);
        assert!(recovered.manifest_repaired_on_open);
        assert_eq!(recovered.manifest.entries.len(), count);
        assert!(recovered
            .manifest
            .entries
            .iter()
            .any(|e| e.path == "renamed.bin"));
        assert!(!recovered
            .manifest
            .entries
            .iter()
            .any(|e| e.path == "big.bin"));
    }

    #[test]
    fn review_strip_refresh_failure_restores_embedded_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let original = std::fs::read(&path).unwrap();
        let sidecar = default_sidecar_path(&path);
        let original_sidecar = std::fs::read(&sidecar).unwrap();
        let transaction_source = path.clone();
        super::super::strip_transaction::AFTER_STRIP_VAULT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let journal = super::super::strip_transaction::journal_path(&transaction_source);
                std::fs::remove_file(journal.join("new-sidecar")).unwrap();
            }))
        });
        let err = VaultV3::strip_parity(&path, PW, false).unwrap_err();
        assert!(err.contains("original vault restored"), "{err}");
        assert_eq!(std::fs::read(&sidecar).unwrap(), original_sidecar);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(VaultV3::has_error_correction(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn review_shared_normalized_namespace_does_not_relock_itself() {
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.aerovault");
        let out = dir.path().join("SOURCE.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        if out.exists() {
            return;
        } // case-insensitive filesystem: this is the input itself
        VaultV3::export_parity(&path, PW, Some(&out)).unwrap();
        assert!(AeroCorrectSidecar::from_bytes(&std::fs::read(&out).unwrap()).is_ok());
        crate::error_correction::correct_generate(
            path.to_str().unwrap(),
            20,
            Some(out.to_str().unwrap()),
        )
        .unwrap();
        // No fallback token may stand in for a real destination lock.
        let unlocked = crate::lock::test_unlocked_export_guard();
        let held = crate::lock::acquire(&path).unwrap();
        assert!(crate::lock::acquire_destination(&out, &path, &unlocked).is_err());
        drop(held);
    }

    #[test]
    fn review_empty_strip_requires_real_metadata_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(VaultV3::strip_parity(&path, PW, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        VaultV3::export_parity(&path, PW, None).unwrap();
        VaultV3::strip_parity(&path, PW, false).unwrap();
        assert!(!VaultV3::has_error_correction(&path).unwrap());
        let opened = VaultV3::open(&path, PW).unwrap();
        let offset = opened.header.manifest_offset as usize;
        drop(opened);
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[offset + 4] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(
            VaultV3::open(&path, PW).is_ok(),
            "exported empty-vault recovery was unusable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn review_strip_refuses_symlink_and_oversized_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let sidecar = default_sidecar_path(&path);
        VaultV3::export_parity(&path, PW, None).unwrap();
        let target = dir.path().join("recovery");
        std::fs::rename(&sidecar, &target).unwrap();
        std::os::unix::fs::symlink(&target, &sidecar).unwrap();
        assert!(VaultV3::strip_parity(&path, PW, false)
            .unwrap_err()
            .contains("symbolic link"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&sidecar).unwrap();
        // A sparse malformed file must be refused without reading/allocating its size.
        let oversized = std::fs::File::create(&sidecar).unwrap();
        oversized.set_len(8 * 1024 * 1024 * 1024).unwrap();
        drop(oversized);
        assert!(VaultV3::strip_parity(&path, PW, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // A valid directory can also declare more parity than this vault needs.
        let mut large = AeroCorrectSidecar::from_bytes(&std::fs::read(&target).unwrap()).unwrap();
        large.segments[VAULT_SIDECAR_SEG_DATA].avec_bytes = vec![0; 4096];
        large.segments[VAULT_SIDECAR_SEG_DATA].window_len = 4096;
        std::fs::write(&sidecar, large.to_bytes()).unwrap();
        assert!(VaultV3::strip_parity(&path, PW, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn review_empty_seed_allows_salvaging_healthy_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("salvage.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        seed_tree(&mut vault, dir.path());
        drop(vault);
        corrupt_data_section(&path, 32);
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        assert!(!VaultV3::scrub(&vault).is_empty());
        VaultV3::delete_entry(&mut vault, "big.bin").unwrap();
        let vault = VaultV3::open_plaintext(&path).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());
        let output = dir.path().join("out");
        let extracted = VaultV3::extract_entry(&vault, "docs/note.txt", &output).unwrap();
        assert_eq!(
            std::fs::read(extracted).unwrap(),
            b"a small note in the vault"
        );
    }

    #[test]
    fn detached_rev4_round_trip_scrub_repair_byte_identical() {
        let vp = tmp("detached.aerovault");
        let src = tmp("detached-src");
        std::fs::create_dir_all(&src).unwrap();

        // Create rev. 4 (detached), add a tree, export the .aerocorrect sidecar.
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        // Non-EC reader still opens a rev-4 (detached) container: the container is
        // byte-identical to a plain vault, with no embedded extension.
        assert!(!VaultV3::has_error_correction(&vp).unwrap());

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);

        let exp = VaultV3::export_parity(&vp, PW, None).unwrap();
        assert!(exp.shards > 0 && exp.payload_len > 0);
        assert!(exp.header_parity_len > 0 && exp.manifest_parity_len > 0);

        let status = VaultV3::recovery_status(&vp).unwrap();
        assert!(status.detached && status.any);
        assert!(status.manifest_parity && status.header_parity);
        assert!(!status.embedded);

        // Snapshot the intact extraction for byte-identity comparison.
        let good_out = tmp("detached-good");
        VaultV3::extract_all(&VaultV3::open(&vp, PW).unwrap(), &good_out).unwrap();

        // Corrupt the data section and confirm scrub flags damage.
        corrupt_data_section(&vp, 800);
        let vault = VaultV3::open(&vp, PW).unwrap();
        let damaged = VaultV3::scrub(&vault);
        assert!(!damaged.is_empty(), "scrub must detect the corruption");
        drop(vault);

        // Repair restores the vault from the detached sidecar.
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let (repaired, source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        assert_eq!(source, ParitySource::Detached);
        drop(vault);

        // Post-repair: clean scrub + byte-identical re-extraction.
        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());
        let after_out = tmp("detached-after");
        VaultV3::extract_all(&vault, &after_out).unwrap();
        assert_eq!(
            std::fs::read(after_out.join("big.bin")).unwrap(),
            std::fs::read(good_out.join("big.bin")).unwrap(),
        );
        assert_eq!(
            std::fs::read(after_out.join("docs/note.txt")).unwrap(),
            b"a small note in the vault"
        );

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&good_out);
        let _ = std::fs::remove_dir_all(&after_out);
    }

    #[test]
    fn embedded_rev4_opens_via_ec_unaware_path_and_repairs() {
        let vp = tmp("embedded.aerovault");
        let src = tmp("embedded-src");
        std::fs::create_dir_all(&src).unwrap();

        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        // Embedded placement: the EC extension is present (non-critical).
        assert!(VaultV3::has_error_correction(&vp).unwrap());

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);

        // A rev-3-style reader (the same open path: it skips non-critical
        // extensions) still opens and extracts the rev-4 embedded container.
        let good_out = tmp("embedded-good");
        let vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::extract_all(&vault, &good_out).unwrap();
        assert_eq!(
            std::fs::read(good_out.join("docs/note.txt")).unwrap(),
            b"a small note in the vault"
        );
        drop(vault);

        // Corrupt + repair from the embedded extension (no sidecar present).
        corrupt_data_section(&vp, 600);
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        assert!(!VaultV3::scrub(&vault).is_empty());
        let (repaired, source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        assert_eq!(source, ParitySource::Embedded);
        drop(vault);

        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());
        let after_out = tmp("embedded-after");
        VaultV3::extract_all(&vault, &after_out).unwrap();
        assert_eq!(
            std::fs::read(after_out.join("big.bin")).unwrap(),
            std::fs::read(good_out.join("big.bin")).unwrap(),
        );

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&good_out);
        let _ = std::fs::remove_dir_all(&after_out);
    }

    #[test]
    fn plaintext_lane_embedded_ec_scrub_repair_over_plaintext() {
        // `.aerovz` (#7) + Error Correction: parity is computed over the
        // PLAINTEXT (compressed, unencrypted) data region. Corrupt it, scrub must
        // detect, repair from the embedded extension restores byte-identical.
        let vp = tmp("aerovz-embedded.aerovz");
        let src = tmp("aerovz-embedded-src");
        std::fs::create_dir_all(&src).unwrap();

        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&vp),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        assert!(VaultV3::has_error_correction(&vp).unwrap());

        // Passwordless open (auto-detected via the header flag).
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);

        let good_out = tmp("aerovz-embedded-good");
        VaultV3::extract_all(&VaultV3::open_plaintext(&vp).unwrap(), &good_out).unwrap();

        corrupt_data_section(&vp, 600);
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        assert!(
            !VaultV3::scrub(&vault).is_empty(),
            "scrub must detect plaintext-region corruption"
        );
        let (repaired, source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        assert_eq!(source, ParitySource::Embedded);
        drop(vault);

        let vault = VaultV3::open_plaintext(&vp).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());
        let after_out = tmp("aerovz-embedded-after");
        VaultV3::extract_all(&vault, &after_out).unwrap();
        assert_eq!(
            std::fs::read(after_out.join("big.bin")).unwrap(),
            std::fs::read(good_out.join("big.bin")).unwrap(),
        );

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&good_out);
        let _ = std::fs::remove_dir_all(&after_out);
    }

    #[test]
    fn beyond_budget_corruption_fails_closed_vault_untouched() {
        let vp = tmp("budget.aerovault");
        let src = tmp("budget-src");
        std::fs::create_dir_all(&src).unwrap();

        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        // A single ~280 KiB file -> exactly one CDC block, so the data section is
        // [8-byte len prefix][one ciphertext body]. Corrupting deep in the body
        // (past the prefix) keeps framing valid while flipping far more shards than
        // the P=2 budget can cover, so repair must fail closed.
        let only = src.join("solo.bin");
        let mut payload = vec![0u8; super::super::constants::CDC_MIN + 30_000];
        let mut x = 0x1234_5678_9abc_def0u64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&only, &payload).unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(&mut vault, &[(only, "solo.bin".to_string())]).unwrap();
        assert_eq!(
            vault.manifest.chunks.len(),
            1,
            "expected a single data block"
        );
        drop(vault);
        VaultV3::export_parity(&vp, PW, None).unwrap();

        // Flip most of the single body, starting 256 bytes past the length prefix
        // (the prefix stays intact so block framing decodes; scrub flags damage via
        // cipher_hash). The contiguous damaged span crosses far more shards than the
        // P=2 per-group erasure budget, so RS cannot reconstruct.
        let info = VaultV3::peek(&vp).unwrap();
        let body_start = DATA_OFFSET as usize + 8 + 256;
        let span = (info.data_len as usize).saturating_sub(8 + 256 + 8);
        {
            let mut bytes = std::fs::read(&vp).unwrap();
            for b in bytes.iter_mut().skip(body_start).take(span) {
                *b ^= 0xFF;
            }
            std::fs::write(&vp, &bytes).unwrap();
        }
        let corrupt_bytes = std::fs::read(&vp).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let err = VaultV3::repair(&mut vault, false, None).unwrap_err();
        assert!(
            err.contains("could not be repaired"),
            "beyond-budget repair must heal nothing: {err}"
        );
        drop(vault);

        // The container is left byte-for-byte untouched (all-or-nothing).
        assert_eq!(std::fs::read(&vp).unwrap(), corrupt_bytes);

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn non_ec_vault_round_trips_and_has_no_recovery() {
        // The legacy/no-EC path: a plain rev. 3 vault still round-trips and
        // reports no recovery surfaces, unchanged by T6.
        let vp = tmp("plain.aerovault");
        let src = tmp("plain-src");
        std::fs::create_dir_all(&src).unwrap();

        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        assert!(!VaultV3::has_error_correction(&vp).unwrap());
        let status = VaultV3::recovery_status(&vp).unwrap();
        assert!(!status.any && !status.embedded && !status.detached);

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        let out = tmp("plain-out");
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("docs/note.txt")).unwrap(),
            b"a small note in the vault"
        );
        // scrub is available on a non-EC vault (no parity) and finds no damage.
        assert!(VaultV3::scrub(&vault).is_empty());
        // repair with no parity source is a no-op, not an error.
        let (repaired, source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert_eq!(repaired, 0);
        assert_eq!(source, ParitySource::None);

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn rotted_plaintext_flag_bit_still_recovers_header_from_sidecar() {
        // One flipped flag bit on an encrypted header used to send open down the
        // plaintext branch, which failed on the public MAC and never tried the
        // sidecar header parity.
        let vp = tmp("flagrot.aerovault");
        let src = tmp("flagrot-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        VaultV3::export_parity(&vp, PW, None).unwrap();

        let mut bytes = std::fs::read(&vp).unwrap();
        bytes[11] ^= 0x01;
        std::fs::write(&vp, &bytes).unwrap();

        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(vault.header_repaired_on_open);
        drop(vault);

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn recovered_header_still_exports_and_repairs() {
        // Damage in the header MAC is recovered from the sidecar at open; the
        // disk keeps the damaged bytes. That is not another writer: the export
        // and the repair save must both go through.
        let vp = tmp("mac-rot.aerovault");
        let src = tmp("mac-rot-src");
        let other = tmp("mac-rot-copy.aerocorrect");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        VaultV3::export_parity(&vp, PW, None).unwrap();

        let mut bytes = std::fs::read(&vp).unwrap();
        let mac = super::super::constants::HEADER_MAC_OFFSET;
        for b in &mut bytes[mac..mac + 4] {
            *b ^= 0xff;
        }
        std::fs::write(&vp, &bytes).unwrap();

        VaultV3::export_parity(&vp, PW, Some(&other)).unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        assert!(vault.header_repaired_on_open);
        VaultV3::repair(&mut vault, false, None).unwrap();
        drop(vault);
        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(
            !vault.header_repaired_on_open,
            "repair persisted the header"
        );
        drop(vault);

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_file(&other);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn change_password_refreshes_sidecar_so_old_password_stops_working() {
        // A sidecar exported before a password change held the old header's
        // parity; header recovery rebuilt it and the old password still opened.
        let vp = tmp("chpw.aerovault");
        let src = tmp("chpw-src");
        std::fs::create_dir_all(&src).unwrap();
        const NEW_PW: &str = "ec-test-new-password-456";
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        VaultV3::export_parity(&vp, PW, None).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::change_password(&mut vault, NEW_PW).unwrap();
        drop(vault);

        assert!(VaultV3::open(&vp, PW).is_err());
        assert!(VaultV3::open(&vp, NEW_PW).is_ok());

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn repair_bounds_chunk_records_before_sizing_buffers() {
        // On the plaintext lane block_len comes from an unauthenticated manifest
        // and sizes the repair buffers: refuse one block above the limit, and
        // records that add up to more than the data section, file untouched.
        let vp = tmp("repair-bounds.aerovz");
        let src = tmp("repair-bounds-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&vp),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        let before = std::fs::read(&vp).unwrap();

        for block_len in [MAX_BLOCK_SIZE + 1, MAX_BLOCK_SIZE] {
            let mut vault = VaultV3::open_plaintext(&vp).unwrap();
            let rec = vault.manifest.chunks.values_mut().next().unwrap();
            rec.block_len = block_len;
            let err = VaultV3::repair(&mut vault, false, None).unwrap_err();
            assert!(err.contains("exceed"), "{err}");
            drop(vault);
            assert_eq!(std::fs::read(&vp).unwrap(), before);
        }

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn writes_refuse_damaged_blocks_so_embedded_parity_survives() {
        // Every save recomputes the embedded parity from the current blocks;
        // over a damaged block that would destroy the parity that repairs it.
        let vp = tmp("embedded-damaged.aerovault");
        let src = tmp("embedded-damaged-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        corrupt_data_section(&vp, 32);
        let damaged = std::fs::read(&vp).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let err = VaultV3::change_password(&mut vault, "ec-test-new-password-456").unwrap_err();
        assert!(err.contains("damaged"), "{err}");
        let extra = src.join("extra.txt");
        std::fs::write(&extra, b"extra").unwrap();
        let err = VaultV3::add_files(&mut vault, &[(extra, "extra.txt".to_string())]).unwrap_err();
        assert!(err.contains("damaged"), "{err}");
        assert_eq!(std::fs::read(&vp).unwrap(), damaged);

        let (repaired, _) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        drop(vault);
        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn refused_writes_are_not_persisted_by_a_later_repair() {
        // Two small files share one packed chunk, which gets damaged. Every
        // write is refused before it changes the handle, so repairing through
        // the same handle must bring back exactly the original tree.
        let vp = tmp("refused-delete.aerovault");
        let src = tmp("refused-delete-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let (a, b) = (src.join("a.txt"), src.join("b.txt"));
        std::fs::write(&a, b"first small file").unwrap();
        std::fs::write(&b, b"second small file").unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[(a, "a.txt".to_string()), (b, "b.txt".to_string())],
        )
        .unwrap();
        assert_eq!(vault.manifest.chunks.len(), 1, "both files in one pack");
        drop(vault);
        corrupt_data_section(&vp, 32);
        let damaged = std::fs::read(&vp).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let before = vault.manifest.clone();
        for err in [
            VaultV3::delete_entry(&mut vault, "a.txt").map(|_| ()),
            VaultV3::rename_entry(&mut vault, "b.txt", "c.txt"),
            VaultV3::copy_entry(&mut vault, "a.txt", "d.txt"),
            VaultV3::create_directory(&mut vault, "dir").map(|_| ()),
        ] {
            assert!(err.unwrap_err().contains("damaged"));
        }
        assert_eq!(std::fs::read(&vp).unwrap(), damaged);
        assert_eq!(vault.manifest.entries.len(), before.entries.len());

        let (repaired, _) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        drop(vault);
        let vault = VaultV3::open(&vp, PW).unwrap();
        let paths: Vec<&str> = vault
            .manifest
            .entries
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(paths, ["a.txt", "b.txt"]);
        let out = tmp("refused-delete-out");
        let got = VaultV3::extract_entry(&vault, "a.txt", &out).unwrap();
        assert_eq!(std::fs::read(got).unwrap(), b"first small file");
        let got = VaultV3::extract_entry(&vault, "b.txt", &out).unwrap();
        assert_eq!(std::fs::read(got).unwrap(), b"second small file");

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn change_password_refuses_damaged_blocks_and_keeps_sidecar() {
        // Refreshing the sidecar over a damaged block would replace the parity
        // that can still repair it: the change must be refused, nothing touched.
        let vp = tmp("chpw-damaged.aerovault");
        let src = tmp("chpw-damaged-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);
        VaultV3::export_parity(&vp, PW, None).unwrap();
        let sidecar = std::fs::read(default_sidecar_path(&vp)).unwrap();
        corrupt_data_section(&vp, 32);

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let err = VaultV3::change_password(&mut vault, "ec-test-new-password-456").unwrap_err();
        assert!(err.contains("damaged"), "{err}");
        drop(vault);
        assert_eq!(std::fs::read(default_sidecar_path(&vp)).unwrap(), sidecar);
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::repair(&mut vault, false, None).is_ok());

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn review_failed_repair_can_retry_on_the_same_handle() {
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let vp = dir.path().join("repair.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&vp),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        seed_tree(&mut vault, dir.path());
        drop(vault);
        corrupt_data_section(&vp, 32);
        let bytes = std::fs::read(&vp).unwrap();
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        let old_data = vault.data.clone();
        let old_chunks = serde_json::to_value(&vault.manifest.chunks).unwrap();
        let held = crate::lock::acquire(&vp).unwrap();
        let err = VaultV3::repair(&mut vault, false, None).unwrap_err();
        assert!(err.contains("locked by another writer"), "{err}");
        assert!(
            vault.data == old_data,
            "failed repair changed in-memory data"
        );
        assert_eq!(
            serde_json::to_value(&vault.manifest.chunks).unwrap(),
            old_chunks
        );
        assert_eq!(std::fs::read(&vp).unwrap(), bytes);
        drop(held);
        assert!(VaultV3::repair(&mut vault, false, None).unwrap().0 > 0);
        let reopened = VaultV3::open_plaintext(&vp).unwrap();
        assert!(VaultV3::scrub(&reopened).is_empty());
    }

    #[test]
    fn review_strip_requires_current_usable_detached_parity() {
        let dir = tempfile::tempdir().unwrap();
        let vp = dir.path().join("strip.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        drop(vault);
        let before = std::fs::read(&vp).unwrap();
        let err = VaultV3::strip_parity(&vp, PW, false).unwrap_err();
        assert!(err.contains("export-parity"), "{err}");
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        VaultV3::export_parity(&vp, PW, None).unwrap();
        let current = std::fs::read(default_sidecar_path(&vp)).unwrap();
        let mut bad = AeroCorrectSidecar::from_bytes(&current).unwrap();
        let data = &mut bad.segments[VAULT_SIDECAR_SEG_DATA].avec_bytes;
        let last = data.len() - 1;
        data[last] ^= 1;
        std::fs::write(default_sidecar_path(&vp), bad.to_bytes()).unwrap();
        assert!(VaultV3::strip_parity(&vp, PW, false).is_err());
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        std::fs::write(default_sidecar_path(&vp), current).unwrap();
        VaultV3::strip_parity(&vp, PW, false).unwrap();
        assert!(!VaultV3::has_error_correction(&vp).unwrap());
        corrupt_data_section(&vp, 32);
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::repair(&mut vault, false, None).unwrap().0 > 0);
        assert!(VaultV3::scrub(&VaultV3::open(&vp, PW).unwrap()).is_empty());
    }

    #[test]
    fn review_damaged_data_never_replaces_usable_detached_recovery() {
        for placement in [
            RecoveryPlacement::Detached,
            RecoveryPlacement::Embedded,
            RecoveryPlacement::Both,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("protected.aerozip");
            VaultV3::create_with_error_correction(
                &CreateOptionsV3::new_plaintext(&path),
                placement,
                20,
            )
            .unwrap();
            let mut vault = VaultV3::open_plaintext(&path).unwrap();
            seed_tree(&mut vault, dir.path());
            drop(vault);
            VaultV3::export_parity(&path, "", None).unwrap();
            corrupt_data_section(&path, 32);
            let damaged = std::fs::read(&path).unwrap();
            let sidecar = std::fs::read(default_sidecar_path(&path)).unwrap();
            let extra = dir.path().join("extra.txt");
            std::fs::write(&extra, b"must not survive a refused add").unwrap();
            let mut vault = VaultV3::open_plaintext(&path).unwrap();
            let err =
                VaultV3::add_files(&mut vault, &[(extra.clone(), "extra.txt".into())]).unwrap_err();
            assert!(err.contains("damaged"), "{err}");
            let err = VaultV3::export_parity(&path, "", None).unwrap_err();
            assert!(err.contains("damaged"), "{err}");
            assert!(
                std::fs::read(&path).unwrap() == damaged,
                "refusal changed the vault"
            );
            assert!(
                std::fs::read(default_sidecar_path(&path)).unwrap() == sidecar,
                "refusal replaced the recovery"
            );
            assert!(VaultV3::repair(&mut vault, false, None).unwrap().0 > 0);
            let mut reopened = VaultV3::open_plaintext(&path).unwrap();
            assert!(VaultV3::scrub(&reopened).is_empty());
            assert!(!VaultV3::summary(&reopened)
                .entries
                .iter()
                .any(|e| e.path == "extra.txt"));
            VaultV3::add_files(&mut reopened, &[(extra, "extra.txt".into())]).unwrap();
            VaultV3::export_parity(&path, "", None).unwrap();
        }
    }

    #[test]
    fn empty_seed_sidecar_does_not_hide_embedded_parity() {
        // `Both` seeds an empty sidecar at create time; repair must fall back to
        // the embedded parity instead of resolving to that empty sidecar.
        let vp = tmp("both-seed.aerovault");
        let src = tmp("both-seed-src");
        std::fs::create_dir_all(&src).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&vp, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        assert!(default_sidecar_path(&vp).exists());
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        seed_tree(&mut vault, &src);
        drop(vault);

        corrupt_data_section(&vp, 600);
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let (repaired, source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert!(repaired > 0);
        assert_eq!(source, ParitySource::Embedded);
        drop(vault);
        let vault = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::scrub(&vault).is_empty());
        drop(vault);

        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_file(default_sidecar_path(&vp));
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn scrub_reports_overflowing_block_offsets_without_panicking() {
        // A corrupted manifest/length prefix can drive a block offset near
        // usize::MAX. scrub must report such a chunk as damaged, never panic on
        // an unchecked add (CLAUDE-AV-ECC unchecked-add hardening). In debug the
        // pre-fix `start + 8` / `block_start + stored_len` would overflow-panic.
        let vp = tmp("overflow.aerovault");
        let src = tmp("overflow-src");
        std::fs::create_dir_all(&src).unwrap();
        let only = src.join("solo.bin");
        let mut payload = vec![0u8; super::super::constants::CDC_MIN + 20_000];
        let mut x = 0xdead_beef_cafe_babeu64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&only, &payload).unwrap();

        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(&mut vault, &[(only, "solo.bin".to_string())]).unwrap();
        assert_eq!(
            vault.manifest.chunks.len(),
            1,
            "expected a single data block"
        );
        let key = vault.manifest.chunks.keys().next().unwrap().clone();

        // Case 1: data_offset near usize::MAX -> `start + 8` would overflow.
        {
            let rec = vault.manifest.chunks.get_mut(&key).unwrap();
            rec.data_offset = u64::MAX - 3;
        }
        let damaged = VaultV3::scrub(&vault);
        assert_eq!(
            damaged.len(),
            1,
            "out-of-range offset must be flagged damaged"
        );

        // Case 2: valid offset but an on-disk length prefix of u64::MAX ->
        // `block_start + stored_len` would overflow.
        {
            let rec = vault.manifest.chunks.get_mut(&key).unwrap();
            rec.data_offset = 0;
            for slot in vault.data.iter_mut().take(8) {
                *slot = 0xFF;
            }
        }
        let damaged = VaultV3::scrub(&vault);
        assert_eq!(
            damaged.len(),
            1,
            "overflowing block length must be flagged damaged"
        );

        drop(vault);
        crate::lock::remove_vault_and_lock(&vp);
        let _ = std::fs::remove_dir_all(&src);
    }
    #[test]
    fn review_export_preserves_recovered_manifest_parity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        VaultV3::export_parity(&path, PW, None).unwrap();
        let sidecar = default_sidecar_path(&path);
        let before = std::fs::read(&sidecar).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[vault.header.manifest_offset as usize + 5] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let mut recovered = VaultV3::open(&path, PW).unwrap();
        assert!(recovered.manifest_repaired_on_open);
        let error = VaultV3::export_parity(&path, PW, None).unwrap_err();
        assert!(
            error.contains("manifest") && error.contains("repair"),
            "{error}"
        );
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        assert!(VaultV3::open(&path, PW).unwrap().manifest_repaired_on_open);
        VaultV3::repair(&mut recovered, false, None).unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        assert!(!VaultV3::open(&path, PW).unwrap().manifest_repaired_on_open);
    }

    #[test]
    fn review_export_holds_source_after_final_generation_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("publication.aerovault");
        let out = dir.path().join("custom.aerocorrect");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let writer_path = path.clone();
        AFTER_EXPORT_GENERATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // A custom output leaves the source's default destination free, so
                // only the real source guard can exclude this writer in this window.
                let error = std::thread::spawn(move || {
                    crate::lock::set_short_wait_for_this_thread();
                    let mut writer = VaultV3::open(&writer_path, PW).unwrap();
                    VaultV3::create_directory(&mut writer, "late").unwrap_err()
                })
                .join()
                .unwrap();
                assert!(
                    error.starts_with("vault is locked by another writer ("),
                    "{error}"
                );
            }))
        });
        VaultV3::export_parity(&path, PW, Some(&out)).unwrap();
        let sidecar = AeroCorrectSidecar::from_bytes(&std::fs::read(&out).unwrap()).unwrap();
        sidecar
            .verify_binding(&container_sha256_file(&path).unwrap().0)
            .unwrap();
        let mut writer = VaultV3::open(&path, PW).unwrap();
        VaultV3::create_directory(&mut writer, "after").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn review_export_parent_retarget_never_borrows_an_unheld_lock() {
        use std::os::unix::fs::symlink;
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let alias = dir.path().join("alias");
        symlink(&a, &alias).unwrap();
        let source = a.join("source.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&source, PW)).unwrap();
        std::fs::copy(&source, b.join("source.aerovault")).unwrap();
        let out = b.join("SOURCE.aerovault");
        if out.exists() {
            return;
        } // case-insensitive filesystem: output aliases source
        VaultV3::create(&CreateOptionsV3::new(&out, PW)).unwrap();
        let original = std::fs::read(&out).unwrap();
        let guard = crate::lock::acquire(&out).unwrap();
        let alias2 = alias.clone();
        AFTER_EXPORT_SOURCE_LOCK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&alias2).unwrap();
                symlink(&b, &alias2).unwrap();
            }))
        });
        let error =
            VaultV3::export_parity(&alias.join("source.aerovault"), PW, Some(&out)).unwrap_err();
        assert!(error.contains("locked by another writer"), "{error}");
        assert_eq!(std::fs::read(&out).unwrap(), original);
        drop(guard);
    }

    #[test]
    fn review_repair_rejects_mismatched_chunk_identity_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        let before = std::fs::read(&path).unwrap();
        let record = vault.manifest.chunks.values_mut().next().unwrap();
        record.id = "foreign-id".to_string();
        let offset = record.data_offset as usize + 9;
        vault.data[offset] ^= 1;
        let error = VaultV3::repair(&mut vault, false, None).unwrap_err();
        assert!(error.contains("identity"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn review_strip_restarts_with_usable_metadata_at_each_publication_boundary() {
        const KEY: &str = "AEROVAULT_STRIP_RESTART_DIR";
        if let Some(root) = std::env::var_os(KEY) {
            let path = PathBuf::from(root).join(if cfg!(windows) {
                "RESTART.AEROVAULT"
            } else {
                "restart.aerovault"
            });
            let phase = std::env::var("AEROVAULT_STRIP_RESTART_PHASE").unwrap();
            let crash: Box<dyn FnOnce()> = Box::new(|| std::process::exit(77));
            match phase.as_str() {
                "journal" => super::super::strip_transaction::AFTER_STRIP_JOURNAL
                    .with(|h| *h.borrow_mut() = Some(crash)),
                "vault" => super::super::strip_transaction::AFTER_STRIP_VAULT
                    .with(|h| *h.borrow_mut() = Some(crash)),
                "sidecar" => super::super::strip_transaction::AFTER_STRIP_SIDECAR
                    .with(|h| *h.borrow_mut() = Some(crash)),
                _ => panic!("unknown boundary"),
            }
            #[cfg(unix)]
            let expected_modes = {
                use std::os::unix::fs::PermissionsExt;
                [
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    std::fs::metadata(default_sidecar_path(&path))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                ]
            };
            let parent = path.parent().unwrap().to_path_buf();
            super::super::strip_transaction::BEFORE_STRIP_JOURNAL.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let prepared = std::fs::read_dir(&parent)
                            .unwrap()
                            .map(|e| e.unwrap().path())
                            .find(|p| {
                                p.file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .starts_with(".aerostrip-prepare-")
                            })
                            .unwrap();
                        assert_eq!(
                            std::fs::metadata(&prepared).unwrap().permissions().mode() & 0o077,
                            0
                        );
                        // Backups and journal remain private files. New files
                        // carry the original mode inside the 0700 directory
                        // so each atomic publication already has its final mode.
                        for name in ["old-vault", "old-sidecar", "journal.json"] {
                            assert_eq!(
                                std::fs::metadata(prepared.join(name))
                                    .unwrap()
                                    .permissions()
                                    .mode()
                                    & 0o077,
                                0,
                                "{name}"
                            );
                        }
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let prepared = std::fs::read_dir(&parent)
                            .unwrap()
                            .map(|e| e.unwrap().path())
                            .find(|p| {
                                p.file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .starts_with(".aerostrip-prepare-")
                            })
                            .unwrap();
                        for (name, mode) in
                            ["new-vault", "new-sidecar"].into_iter().zip(expected_modes)
                        {
                            assert_eq!(
                                std::fs::metadata(prepared.join(name))
                                    .unwrap()
                                    .permissions()
                                    .mode()
                                    & 0o777,
                                mode,
                                "{name}"
                            );
                        }
                    }
                    if std::env::var_os("AEROVAULT_WAITING_WRITER").is_some() {
                        std::fs::write(parent.join("strip-ready"), b"ready").unwrap();
                        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
                        while !parent.join("writer-blocked").exists() {
                            assert!(
                                std::time::Instant::now() < until,
                                "writer never reached source contention"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }))
            });
            VaultV3::strip_parity(&path, PW, false).unwrap();
            panic!("crash boundary was not reached");
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for phase in ["journal", "vault", "sidecar"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("restart.aerovault");
            VaultV3::create_with_error_correction(
                &CreateOptionsV3::new(&path, PW),
                RecoveryPlacement::Both,
                20,
            )
            .unwrap();
            let mut vault = VaultV3::open(&path, PW).unwrap();
            seed_tree(&mut vault, dir.path());
            drop(vault);
            VaultV3::export_parity(&path, PW, None).unwrap();
            let old_vault = std::fs::read(&path).unwrap();
            let old_sidecar = std::fs::read(default_sidecar_path(&path)).unwrap();
            #[cfg(unix)]
            let old_sidecar_inode = {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
                std::fs::set_permissions(
                    default_sidecar_path(&path),
                    std::fs::Permissions::from_mode(0o640),
                )
                .unwrap();
                std::fs::metadata(default_sidecar_path(&path))
                    .unwrap()
                    .ino()
            };
            let mut child = Child(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "v3::ec::tests::review_strip_restarts_with_usable_metadata_at_each_publication_boundary", "--nocapture"])
                .env(KEY, dir.path()).env("AEROVAULT_STRIP_RESTART_PHASE", phase).spawn().unwrap());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "restart child timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(77), "{phase}: {status}");
            assert!(super::super::strip_transaction::journal_path(&path).exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let journal = super::super::strip_transaction::journal_path(&path);
                assert_eq!(
                    std::fs::metadata(&journal).unwrap().permissions().mode() & 0o077,
                    0
                );
                for name in ["old-vault", "old-sidecar", "journal.json"] {
                    assert_eq!(
                        std::fs::metadata(journal.join(name))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o077,
                        0
                    );
                }
            }
            #[cfg(unix)]
            let reopen_path = if phase == "vault" {
                let alias = dir.path().join("linked.aerovault");
                std::os::unix::fs::symlink(&path, &alias).unwrap();
                alias
            } else {
                path.clone()
            };
            #[cfg(not(unix))]
            let reopen_path = path.clone();
            let case_alias = dir.path().join("RESTART.AEROVAULT");
            let reopen_path = if phase == "vault" && case_alias.exists() {
                case_alias
            } else {
                reopen_path
            };
            let current = VaultV3::open(&reopen_path, PW).unwrap();

            assert!(!super::super::strip_transaction::journal_path(&path).exists());
            if phase != "sidecar" {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    assert_eq!(
                        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                        0o640
                    );
                    let meta = std::fs::metadata(default_sidecar_path(&path)).unwrap();
                    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
                    assert_eq!(
                        meta.ino(),
                        old_sidecar_inode,
                        "untouched original sidecar was replaced"
                    );
                }
                assert_eq!(std::fs::read(&path).unwrap(), old_vault);
                assert_eq!(
                    std::fs::read(default_sidecar_path(&path)).unwrap(),
                    old_sidecar
                );
                assert!(VaultV3::has_error_correction(&path).unwrap());
            } else {
                assert!(!VaultV3::has_error_correction(&path).unwrap());
            }
            let mut damaged = std::fs::read(&path).unwrap();
            damaged[current.header.manifest_offset as usize + 4] ^= 1;
            std::fs::write(&path, damaged).unwrap();
            let recovered = VaultV3::open(&path, PW).unwrap();
            assert!(recovered.manifest_repaired_on_open, "{phase}");
            assert_eq!(
                recovered.manifest.entries.len(),
                current.manifest.entries.len()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires the dedicated HFS+ CI image"]
    fn review_hfs_multibyte_sidecar_is_locked_during_password_rotation() {
        let root = std::env::var_os("AEROVAULT_TEST_HFS_ROOT")
            .expect("run with the dedicated HFS+ image mounted");
        let dir = tempfile::tempdir_in(root).unwrap();
        let path = dir.path().join(format!("{}.aerovault", "界".repeat(90)));
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let sidecar = default_sidecar_path(&path);
        assert!(crate::lock::destination_can_exist(&sidecar).unwrap());
        let before = std::fs::read(&path).unwrap();
        let recovery = std::fs::read(&sidecar).unwrap();
        crate::lock::set_short_wait_for_this_thread();
        let guard = crate::lock::acquire(&sidecar).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        assert!(
            VaultV3::change_password(&mut vault, "replacement-password-123")
                .unwrap_err()
                .contains("locked")
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read(&sidecar).unwrap(), recovery);
        drop(guard);
        VaultV3::change_password(&mut vault, "replacement-password-123").unwrap();
        assert!(VaultV3::open(&path, "replacement-password-123").is_ok());
        assert!(VaultV3::open(&path, PW).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_strip_streams_rollback_and_binding_under_memory_limit() {
        const KEY: &str = "AEROVAULT_STRIP_MEMORY_PATH";
        if let Some(path) = std::env::var_os(KEY) {
            crate::source::memory_test::limit();
            let path = PathBuf::from(path);
            VaultV3::strip_parity(&path, "", false).unwrap();
            let current = VaultV3::open_plaintext(&path).unwrap();
            assert_eq!(current.data.len(), 512 * 1024 * 1024);
            assert!(!VaultV3::has_error_correction(&path).unwrap());
            assert!(!super::super::strip_transaction::journal_path(&path).exists());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        vault.data.resize(512 * 1024 * 1024, 0);
        save_open_vault(&mut vault).unwrap();
        drop(vault);
        VaultV3::export_parity(&path, "", None).unwrap();
        crate::source::memory_test::run(
            "v3::ec::tests::review_strip_streams_rollback_and_binding_under_memory_limit",
            KEY,
            &path,
        );
    }
    #[test]
    fn review_strip_rollback_does_not_overwrite_a_newer_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conflict.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let other = dir.path().join("other.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&other, PW)).unwrap();
        let newer = std::fs::read(&other).unwrap();
        let copy = newer.clone();
        let target = path.clone();
        super::super::strip_transaction::AFTER_STRIP_VAULT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                // An uncooperative filesystem writer bypasses the namespace lock.
                std::fs::write(&target, &copy).unwrap();
                std::fs::remove_file(
                    super::super::strip_transaction::journal_path(&target).join("new-sidecar"),
                )
                .unwrap();
            }))
        });
        let error = VaultV3::strip_parity(&path, PW, false).unwrap_err();
        assert!(
            error.contains("pending strip transaction conflicts"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), newer);
        assert!(super::super::strip_transaction::journal_path(&path).exists());
        assert!(VaultV3::open(&path, PW)
            .unwrap_err()
            .contains("pending strip transaction conflicts"));
        assert_eq!(std::fs::read(&path).unwrap(), newer);
    }
    #[test]
    fn review_detached_parity_repairs_shard_boundary_streams() {
        use super::super::manifest::ManifestEntryV3;
        for len in [8192usize, 8193] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("boundary.aerozip");
            VaultV3::create_with_error_correction(
                &CreateOptionsV3::new_plaintext(&path),
                RecoveryPlacement::Detached,
                20,
            )
            .unwrap();
            let mut vault = VaultV3::open_plaintext(&path).unwrap();
            let payload: Vec<u8> = (0..len - 8).map(|i| (i % 251) as u8).collect();
            let key = crate::aerocrypt::hkdf_expand::<32>(
                &vault.master_key,
                super::super::constants::HKDF_CHUNK_ID,
            )
            .unwrap();
            let id = super::super::chunking::keyed_chunk_id(&key, &payload);
            vault.data = ((len - 8) as u64).to_le_bytes().to_vec();
            vault.data.extend_from_slice(&payload);
            vault.manifest.chunks.insert(
                id.clone(),
                ChunkRecordV3 {
                    id: id.clone(),
                    block_index: 0,
                    data_offset: 0,
                    block_len: payload.len() as u64,
                    plaintext_len: payload.len() as u64,
                    compressed_len: payload.len() as u64,
                    cipher_hash: blake3::hash(&payload).to_hex().to_string(),
                    stored_raw: true,
                },
            );
            vault.manifest.entries.push(ManifestEntryV3 {
                path: "item.bin".into(),
                size: payload.len() as u64,
                modified: vault.manifest.modified.clone(),
                is_dir: false,
                chunks: vec![id],
                pack_offset: None,
            });
            let lock = super::super::vault::write_lock(&path).unwrap();
            super::super::vault::save_locked(&mut vault, &lock).unwrap();
            drop(lock);
            drop(vault);
            let intact = VaultV3::open_plaintext(&path).unwrap();
            assert_eq!(
                collect_live_block_refs(&intact)
                    .iter()
                    .map(|b| b.len())
                    .sum::<usize>(),
                len
            );
            VaultV3::export_parity(&path, "", None).unwrap();
            assert!(!read_vault_segment(
                &path,
                &default_sidecar_path(&path),
                VAULT_SIDECAR_SEG_DATA,
                len as u64
            )
            .unwrap()
            .is_empty());
            corrupt_data_section(&path, 32);
            let mut damaged = VaultV3::open_plaintext(&path).unwrap();
            assert!(VaultV3::repair(&mut damaged, false, None).unwrap().0 > 0);
            let reopened = VaultV3::open_plaintext(&path).unwrap();
            assert!(VaultV3::scrub(&reopened).is_empty());
            let output =
                VaultV3::extract_entry(&reopened, "item.bin", &dir.path().join("out")).unwrap();
            assert_eq!(std::fs::read(output).unwrap(), payload);
        }
    }

    // The fixture needs a filesystem accepting arbitrary native byte names;
    // macOS rejects its directory name with EILSEQ before vault code runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn review_native_non_utf8_paths_remain_writable_and_recoverable() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"parent-\xff".to_vec()));
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join(std::ffi::OsString::from_vec(b"vault-\xfe.aerozip".to_vec()));
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        let source = parent.join("input");
        std::fs::write(&source, b"native path contents").unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut vault, &[(source, "item".into())]).unwrap();
        drop(vault);
        let mut expected = path.as_os_str().to_os_string();
        expected.push(".aerocorrect");
        assert_eq!(
            default_sidecar_path(&path).as_os_str(),
            expected.as_os_str()
        );
        VaultV3::export_parity(&path, "", None).unwrap();
        VaultV3::strip_parity(&path, "", false).unwrap();
        let reopened = VaultV3::open_plaintext(&path).unwrap();
        let output = VaultV3::extract_entry(&reopened, "item", &parent.join("out")).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), b"native path contents");
    }

    #[test]
    fn review_strip_rechecks_sidecar_after_destination_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late-sidecar.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, "", None).unwrap();
        let sidecar = default_sidecar_path(&path);
        let ready = std::fs::read(&sidecar).unwrap();
        std::fs::remove_file(&sidecar).unwrap();
        std::thread::scope(|scope| {
            let guard = crate::lock::acquire(&sidecar).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let p = path.clone();
            let worker = scope.spawn(move || {
                crate::lock::ON_LOCK_CONTENTION.with(|h| {
                    *h.borrow_mut() = Some(Box::new(move || {
                        tx.send(()).unwrap();
                    }))
                });
                VaultV3::strip_parity(&p, "", false)
            });
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            std::fs::write(&sidecar, ready).unwrap();
            drop(guard);
            assert!(worker.join().unwrap().unwrap().sidecar_present);
        });
        assert!(!VaultV3::has_error_correction(&path).unwrap());
        assert!(VaultV3::open_plaintext(&path).is_ok());
    }

    #[test]
    fn review_strip_sync_error_reports_completed_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, "", None).unwrap();
        super::super::strip_transaction::FAIL_FINAL_SYNC.with(|f| f.set(true));
        let error = VaultV3::strip_parity(&path, "", false).unwrap_err();
        assert!(
            error.contains("stripped vault and refreshed sidecar remain"),
            "{error}"
        );
        assert!(!error.contains("original vault restored"));
        assert!(!VaultV3::has_error_correction(&path).unwrap());
        assert!(!super::super::strip_transaction::journal_path(&path).exists());
        let mut current = VaultV3::open_plaintext(&path).unwrap();
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[current.header.manifest_offset as usize + 4] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        current = VaultV3::open_plaintext(&path).unwrap();
        assert!(current.manifest_repaired_on_open);
    }

    #[test]
    fn review_waiting_writers_recover_strip_under_the_acquired_guard() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for (phase, operation) in [
            ("journal", "save"),
            ("vault", "create"),
            ("journal", "export"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("restart.aerovault");
            VaultV3::create_with_error_correction(
                &CreateOptionsV3::new(&path, PW),
                RecoveryPlacement::Both,
                20,
            )
            .unwrap();
            VaultV3::export_parity(&path, PW, None).unwrap();
            let mut old_handle = VaultV3::open(&path, PW).unwrap();
            let mut child=Child(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","v3::ec::tests::review_strip_restarts_with_usable_metadata_at_each_publication_boundary","--nocapture"])
                .env("AEROVAULT_STRIP_RESTART_DIR",dir.path()).env("AEROVAULT_STRIP_RESTART_PHASE",phase)
                .env("AEROVAULT_WAITING_WRITER","1").spawn().unwrap());
            let until = std::time::Instant::now() + std::time::Duration::from_secs(45);
            while !dir.path().join("strip-ready").exists() {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "strip child exited before readiness"
                );
                assert!(
                    std::time::Instant::now() < until,
                    "strip child readiness timeout"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            std::thread::scope(|scope| {
                let target = path.clone();
                let blocked = dir.path().join("writer-blocked");
                let worker = scope.spawn(move || {
                    crate::lock::ON_LOCK_CONTENTION.with(|h| {
                        *h.borrow_mut() = Some(Box::new(move || {
                            std::fs::write(blocked, b"blocked").unwrap();
                        }))
                    });
                    match operation {
                        "save" => VaultV3::create_directory(&mut old_handle, "waiter").map(|_| ()),
                        "create" => VaultV3::create(&CreateOptionsV3::new(&target, PW)),
                        "export" => VaultV3::export_parity(&target, PW, None).map(|_| ()),
                        _ => unreachable!(),
                    }
                });
                let status = loop {
                    if let Some(s) = child.0.try_wait().unwrap() {
                        break s;
                    }
                    assert!(
                        std::time::Instant::now() < until,
                        "strip child exit timeout"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                assert_eq!(status.code(), Some(77));
                worker.join().unwrap().unwrap();
            });
            assert!(!super::super::strip_transaction::journal_path(&path).exists());
            let reopened = VaultV3::open(&path, PW).unwrap();
            if operation == "save" {
                assert!(reopened.manifest.entries.iter().any(|e| e.path == "waiter"));
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn review_export_accepts_read_only_leaf_link_and_protects_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.aerovault");
        let alias = dir.path().join("alias.aerovault");
        let out = dir.path().join("custom.aerocorrect");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        let before = std::fs::read(&path).unwrap();
        VaultV3::export_parity(&alias, PW, Some(&out)).unwrap();
        let reader =
            crate::error_correction::sidecar::AeroCorrectSidecarReader::open(&out).unwrap();
        reader.verify_binding(&container_sha256(&before)).unwrap();
        assert!(VaultV3::export_parity(&alias, PW, Some(&alias)).is_err());
        assert!(VaultV3::export_parity(&alias, PW, Some(&path)).is_err());
        assert!(std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn review_automatic_sidecar_refuses_vault_published_during_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.aerovault");
        let other = dir.path().join("other.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&other, PW)).unwrap();
        let other_bytes = std::fs::read(&other).unwrap();
        let sidecar = default_sidecar_path(&path);
        let guard = crate::lock::acquire(&sidecar).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let p = path.clone();
            let worker = scope.spawn(move || {
                crate::lock::ON_LOCK_CONTENTION.with(|h| {
                    *h.borrow_mut() = Some(Box::new(move || {
                        tx.send(()).unwrap();
                    }))
                });
                VaultV3::export_parity(&p, PW, None)
            });
            let waited = rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok();
            if waited {
                std::fs::write(&sidecar, &other_bytes).unwrap();
            }
            drop(guard);
            let error = worker.join().unwrap().unwrap_err();
            assert!(waited, "export did not encounter destination guard");
            assert!(error.contains("contains a vault"), "{error}");
        });
        assert_eq!(std::fs::read(&sidecar).unwrap(), other_bytes);
        assert!(VaultV3::open(&sidecar, PW).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_legacy_lossy_sidecar_recovers_without_mutating_shared_name() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(std::ffi::OsString::from_vec(
            b"vault-\xff.aerovault".to_vec(),
        ));
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        drop(vault);
        VaultV3::export_parity(&path, PW, None).unwrap();
        let native = default_sidecar_path(&path);
        let legacy = legacy_sidecar_path(&path).unwrap();
        std::fs::rename(&native, &legacy).unwrap();
        let parity = std::fs::read(&legacy).unwrap();
        let healthy = std::fs::read(&path).unwrap();
        let info = VaultV3::open(&path, PW).unwrap();
        let manifest_offset = info.header.manifest_offset as usize;
        for offset in [
            super::super::constants::HEADER_MAC_OFFSET,
            manifest_offset + 4,
        ] {
            let mut damaged = healthy.clone();
            damaged[offset] ^= 1;
            std::fs::write(&path, damaged).unwrap();
            let recovered = VaultV3::open(&path, PW).unwrap();
            if offset == manifest_offset + 4 {
                assert!(recovered.manifest_repaired_on_open);
            } else {
                assert!(recovered.header_repaired_on_open);
            }
            assert!(VaultV3::open(&path, "incorrect-password-123").is_err());
            assert!(!native.exists());
            assert_eq!(std::fs::read(&legacy).unwrap(), parity);
        }
        std::fs::write(&path, &healthy).unwrap();
        corrupt_data_section(&path, 32);
        let mut damaged = VaultV3::open(&path, PW).unwrap();
        assert!(VaultV3::create_directory(&mut damaged, "refused")
            .unwrap_err()
            .contains("damaged blocks"));
        assert!(VaultV3::repair(&mut damaged, false, None).unwrap().0 > 0);
        assert!(VaultV3::scrub(&VaultV3::open(&path, PW).unwrap()).is_empty());
        assert_eq!(std::fs::read(&legacy).unwrap(), parity);
        std::fs::write(&path, &healthy).unwrap();
        let mut current = VaultV3::open(&path, PW).unwrap();
        assert!(VaultV3::change_password(&mut current, "new-password-123")
            .unwrap_err()
            .contains("Legacy lossy-name"));
        assert_eq!(std::fs::read(&path).unwrap(), healthy);
        // A same-password foreign sidecar at the ambiguous legacy name cannot substitute its header.
        let foreign = dir.path().join("foreign.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&foreign, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&foreign, PW, None).unwrap();
        let foreign_parity = std::fs::read(default_sidecar_path(&foreign)).unwrap();
        std::fs::write(&legacy, &foreign_parity).unwrap();
        let mut damaged = healthy.clone();
        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&path, &damaged).unwrap();
        let error = VaultV3::open(&path, PW).unwrap_err();
        assert!(
            error.contains("Legacy recovery name is ambiguous"),
            "{error}"
        );
        assert_eq!(std::fs::read(&legacy).unwrap(), foreign_parity);
        std::fs::write(&legacy, &parity).unwrap();
        // A present native file takes priority: do not hide its damage with a legacy copy.
        std::fs::write(&native, b"broken native sidecar").unwrap();
        assert!(VaultV3::open(&path, PW).is_err());
        std::fs::remove_file(&native).unwrap();
        std::fs::write(&path, &healthy).unwrap();
        // Explicit owner migration permits rotation; only the new password can recover afterwards.
        std::fs::rename(&legacy, &native).unwrap();
        let mut current = VaultV3::open(&path, PW).unwrap();
        VaultV3::change_password(&mut current, "new-password-123").unwrap();
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(VaultV3::open(&path, PW).is_err());
        assert!(
            VaultV3::open(&path, "new-password-123")
                .unwrap()
                .header_repaired_on_open
        );
    }

    #[test]
    fn review_automatic_export_preserves_a_magic_damaged_recoverable_vault() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&source, PW)).unwrap();
        let destination = default_sidecar_path(&source);
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&destination, PW),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&destination, PW, None).unwrap();
        let healthy = std::fs::read(&destination).unwrap();
        for spoof_sidecar_prefix in [false, true] {
            let mut bytes = healthy.clone();
            if spoof_sidecar_prefix {
                bytes[..8].copy_from_slice(crate::error_correction::AEROCORRECT_MAGIC);
                bytes[8] = crate::error_correction::AEROCORRECT_VERSION;
            } else {
                bytes[0] ^= 1;
            }
            std::fs::write(&destination, &bytes).unwrap();
            assert!(
                VaultV3::open(&destination, PW)
                    .unwrap()
                    .header_repaired_on_open
            );
            let error = VaultV3::export_parity(&source, PW, None).unwrap_err();
            assert!(error.contains("unrecognized"), "{error}");
            assert_eq!(std::fs::read(&destination).unwrap(), bytes);
            assert!(VaultV3::open(&destination, PW).is_ok());
        }
        // A caller-selected explicit replacement keeps its documented semantics.
        VaultV3::export_parity(&source, PW, Some(&destination)).unwrap();
        assert!(std::fs::read(&destination)
            .unwrap()
            .starts_with(crate::error_correction::AEROCORRECT_MAGIC));
    }

    #[cfg(unix)]
    #[test]
    fn review_default_leaf_link_export_supports_manifest_recovery_through_alias() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("real.aerovault");
        let alias = dir.path().join("alias.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&source, PW)).unwrap();
        let mut vault = VaultV3::open(&source, PW).unwrap();
        seed_tree(&mut vault, dir.path());
        let manifest = vault.header.manifest_offset as usize;
        drop(vault);
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        let report = VaultV3::export_parity(&alias, PW, None).unwrap();
        assert_eq!(report.path, default_sidecar_path(&alias));
        assert!(!default_sidecar_path(&source).exists());
        let mut bytes = std::fs::read(&source).unwrap();
        bytes[manifest + 4] ^= 1;
        std::fs::write(&source, bytes).unwrap();
        assert!(VaultV3::open(&alias, PW).unwrap().manifest_repaired_on_open);
        assert!(std::fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn review_supported_grids_allow_authenticated_manifest_recovery() {
        let dir = tempfile::tempdir().unwrap();
        for pct in [5, 20, 50] {
            let path = dir.path().join(format!("manifest-{pct}.aerovault"));
            VaultV3::create_with_error_correction(
                &CreateOptionsV3::new(&path, PW),
                RecoveryPlacement::Detached,
                pct,
            )
            .unwrap();
            let mut vault = VaultV3::open(&path, PW).unwrap();
            seed_tree(&mut vault, dir.path());
            let at = vault.header.manifest_offset as usize;
            let expected = vault.manifest.entries.len();
            drop(vault);
            VaultV3::export_parity(&path, PW, None).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[at + 4] ^= 1;
            std::fs::write(&path, bytes).unwrap();
            let recovered = VaultV3::open(&path, PW).unwrap();
            assert!(recovered.manifest_repaired_on_open);
            assert_eq!(recovered.manifest.entries.len(), expected);
        }
    }
    #[cfg(windows)]
    #[test]
    fn review_windows_strip_preserves_second_principal_effective_access() {
        use super::super::windows_security as acl;
        let dir = tempfile::tempdir().unwrap();
        acl::apply(
            dir.path(),
            "D:P(A;OICI;FA;;;OW)(A;OICI;FR;;;BG)(A;OICI;FA;;;SY)",
            true,
        )
        .unwrap();
        let path = dir.path().join("restricted.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        // The parent would grant this second principal read access; the vault
        // explicitly denies it. No account, token or machine policy is changed.
        assert_ne!(acl::guest_effective_rights(&path).unwrap() & 1, 0);
        acl::apply(&path, "D:P(D;;FR;;;BG)(A;;FA;;;OW)(A;;FA;;;SY)", true).unwrap();
        let before = acl::guest_effective_rights(&path).unwrap();
        assert_eq!(before & 1, 0);
        VaultV3::export_parity(&path, PW, None).unwrap();
        let journal = super::super::strip_transaction::journal_path(&path);
        super::super::strip_transaction::AFTER_STRIP_JOURNAL.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                for name in ["old-vault", "new-vault"] {
                    assert_eq!(
                        acl::guest_effective_rights(&journal.join(name)).unwrap() & 1,
                        0,
                        "{name}"
                    );
                }
            }))
        });
        let private =
            super::super::strip_transaction::private_dir(dir.path(), ".acl-check-").unwrap();
        assert_eq!(acl::guest_effective_rights(private.path()).unwrap() & 1, 0);
        VaultV3::strip_parity(&path, PW, false).unwrap();
        assert_eq!(acl::guest_effective_rights(&path).unwrap() & 1, before & 1);
        assert!(VaultV3::open(&path, PW).is_ok());
        // Exercise the rollback path under the same permissive parent too.
        let rollback = dir.path().join("rollback.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&rollback, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        acl::apply(&rollback, "D:P(D;;FR;;;BG)(A;;FA;;;OW)(A;;FA;;;SY)", true).unwrap();
        VaultV3::export_parity(&rollback, PW, None).unwrap();
        let original = std::fs::read(&rollback).unwrap();
        let journal = super::super::strip_transaction::journal_path(&rollback);
        super::super::strip_transaction::AFTER_STRIP_VAULT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(journal.join("new-sidecar")).unwrap();
            }))
        });
        let error = VaultV3::strip_parity(&rollback, PW, false).unwrap_err();
        assert!(error.contains("original vault restored"), "{error}");
        assert_eq!(std::fs::read(&rollback).unwrap(), original);
        assert_eq!(acl::guest_effective_rights(&rollback).unwrap() & 1, 0);
        assert!(VaultV3::open(&rollback, PW).is_ok());
        eprintln!("Windows DACL: second-principal read denied in private staging, publication and rollback");
    }
}
