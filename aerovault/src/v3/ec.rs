//! AEROVAULT3 rev. 4 Error Correction (Reed-Solomon `.aerocorrect`).
//!
//! A faithful, byte-for-byte port of the AeroFTP application's AEROVAULT3 Error
//! Correction operations (`src-tauri/src/aerovault_v3.rs`), minus the Tauri
//! command layer, async, telemetry, and the cross-process file lock (the crate's
//! `save_open_vault` already guards concurrent seals with an in-process
//! generation check; `export_parity` only reads).
//!
//! Error Correction is NON-CRITICAL: the embedded extension and the
//! metadata-parity extension are both `critical=false`, so a rev. 3 reader still
//! opens and extracts a rev. 4 container; the on-disk major stays 3. Recovery is
//! ALL-OR-NOTHING: every reconstructed region is re-verified against the vault's
//! authenticated values (header MAC / manifest cipher_hash) before it is
//! persisted, so a foreign or stale sidecar can only make a repair FAIL, never
//! overwrite good data (CLAUDE-AV-ECC-01). The `.aerocorrect` content-SHA binding
//! is informational and is never enforced on the repair path (#276).

// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::constants::{
    DATA_OFFSET, ERROR_CORRECTION_ALGORITHM_ID, ERROR_CORRECTION_ALGORITHM_VERSION,
    ERROR_CORRECTION_EXTENSION_ID, ERROR_CORRECTION_META_EXTENSION_ID, HEADER_SIZE,
    MAX_EXTENSION_DIR_SIZE, MAX_MANIFEST_SIZE,
};
use super::format::VaultHeaderV3;
use super::manifest::{ChunkRecordV3, ExtensionEntryV3};
use super::vault::{
    atomic_write, open_header_bytes, open_vault, read_capped, save_open_vault, OpenVaultV3,
};
use crate::aerocrypt::KEY_SIZE;
use crate::error_correction::sidecar::aerocorrect_sidecar_path;
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

/// A parsed, MAC-verified header together with its unwrapped MAC and master keys.
type UnlockedHeader = (VaultHeaderV3, [u8; KEY_SIZE], [u8; KEY_SIZE]);

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
fn default_sidecar_path(vault_path: &Path) -> PathBuf {
    PathBuf::from(aerocorrect_sidecar_path(&vault_path.to_string_lossy()))
}

/// SHA-256 of a byte slice (the unified `.aerocorrect` format binds by content).
fn container_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Build a vault's `.aerocorrect` sidecar from the three region parities, in the
/// fixed segment order (header, manifest, data). An empty parity vector marks an
/// unprotected region. The container SHA-256 is the informational content
/// binding (never enforced on the repair path).
fn build_vault_sidecar(
    container_bytes: &[u8],
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
    AeroCorrectSidecar::new(
        container_sha256(container_bytes),
        container_bytes.len() as u64,
        segments,
    )
}

/// The parity (AVEC) bytes a vault sidecar carries for one region, by fixed
/// segment index. Empty slice when the region is absent or unprotected.
fn vault_sidecar_parity(sidecar: &AeroCorrectSidecar, role: usize) -> &[u8] {
    sidecar
        .segments
        .get(role)
        .map(|s| s.avec_bytes.as_slice())
        .unwrap_or(&[])
}

/// Seed an empty three-region sidecar at create time (detached/both placements),
/// so the file exists from creation; `export_parity` fills it once files are
/// added. `container_bytes` are the just-written empty-vault bytes.
pub(super) fn seed_empty_sidecar(path: &Path, container_bytes: &[u8]) -> Result<(), String> {
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
    atomic_write(&default_sidecar_path(path), &sidecar.to_bytes())
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
    let mut f = File::open(&vault.path).map_err(|e| format!("open for parity read: {e}"))?;
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
    // 1. Explicit parity wins; an unreadable or malformed file is a hard error.
    if let Some(p) = explicit {
        let bytes =
            std::fs::read(p).map_err(|e| format!("read recovery file {}: {e}", p.display()))?;
        let sidecar = AeroCorrectSidecar::from_bytes(&bytes)?;
        return Ok((
            vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_DATA).to_vec(),
            ParitySource::Explicit,
        ));
    }
    // 2. Detached sidecar next to the vault.
    let sidecar_path = default_sidecar_path(&vault.path);
    if sidecar_path.exists() {
        let bytes = std::fs::read(&sidecar_path)
            .map_err(|e| format!("read recovery file {}: {e}", sidecar_path.display()))?;
        let sidecar = AeroCorrectSidecar::from_bytes(&bytes)?;
        return Ok((
            vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_DATA).to_vec(),
            ParitySource::Detached,
        ));
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

/// Read the raw on-disk encrypted-manifest bytes (the exact bytes the manifest
/// parity must protect; re-encrypting would use a fresh nonce and not match).
fn read_manifest_raw(vault_path: &Path, header: &VaultHeaderV3) -> Result<Vec<u8>, String> {
    let mut f = File::open(vault_path).map_err(|e| format!("open for manifest read: {e}"))?;
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
    let vault = open_vault(vault_path, password)?;
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
    let container_bytes = std::fs::read(vault_path)
        .map_err(|e| format!("read vault container for sidecar binding: {e}"))?;
    let sidecar = build_vault_sidecar(
        &container_bytes,
        &vault.header,
        payload,
        manifest_parity,
        header_parity,
    );
    let bytes = sidecar.to_bytes();
    let out = out_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_sidecar_path(vault_path));
    atomic_write(&out, &bytes)?;
    Ok(ExportParityResult {
        path: out,
        shards,
        bytes_protected: protected,
        overhead_pct: overhead,
        payload_len,
        file_len: bytes.len() as u64,
        header_parity_len,
        manifest_parity_len,
    })
}

/// Outcome of [`strip_parity`].
#[derive(Debug, Clone)]
pub struct StripParityResult {
    pub sidecar_present: bool,
    pub sidecar_path: PathBuf,
}

/// Drop the embedded Error Correction extension on the next seal. Refuses unless
/// a detached sidecar already exists or `force` is set, so a vault is never
/// silently left with zero recovery.
pub(super) fn strip_parity(
    vault_path: &Path,
    password: &str,
    force: bool,
) -> Result<StripParityResult, String> {
    let mut vault = open_vault(vault_path, password)?;
    let had_embedded = vault
        .extensions
        .iter()
        .any(|e| e.extension_id == ERROR_CORRECTION_EXTENSION_ID);
    if !had_embedded {
        return Err("Vault has no embedded Error Correction parity to strip".to_string());
    }
    let sidecar = default_sidecar_path(vault_path);
    let has_sidecar = sidecar.exists();
    if !has_sidecar && !force {
        return Err(
            "Refusing to strip embedded parity: no detached recovery file exists. Run \"vault export-parity\" first, or pass --force to drop recovery entirely."
                .to_string(),
        );
    }
    vault
        .extensions
        .retain(|e| e.extension_id != ERROR_CORRECTION_EXTENSION_ID);
    save_open_vault(&mut vault)?;
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
                vault.data = new_data;
                vault.manifest.chunks = new_chunks;
                save_open_vault(vault)?;
            }
        }
        // else: reconstruction could not be verified -> leave the vault
        // byte-for-byte untouched (repaired_count stays 0) so no redundancy is lost.
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
    let sidecar_path = default_sidecar_path(vault_path);
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let bytes = match std::fs::read(&sidecar_path) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let sidecar = match AeroCorrectSidecar::from_bytes(&bytes) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let header_parity = vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_HEADER);
    if header_parity.is_empty() {
        return Ok(None);
    }
    // The header is a single fixed-length block; reconstruct requires the on-disk
    // bytes at exactly HEADER_SIZE so the stream lengths line up.
    if on_disk_header.len() != HEADER_SIZE {
        return Ok(None);
    }
    let mut blocks = vec![on_disk_header.to_vec()];
    if reconstruct_from_error_correction(&mut blocks, header_parity).is_err() {
        return Ok(None);
    }
    let rebuilt = match blocks.into_iter().next() {
        Some(b) if b.len() == HEADER_SIZE => b,
        _ => return Ok(None),
    };
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
    let sidecar_path = default_sidecar_path(vault_path);
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let bytes = match std::fs::read(&sidecar_path) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let sidecar = match AeroCorrectSidecar::from_bytes(&bytes) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let manifest_parity = vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_MANIFEST);
    if manifest_parity.is_empty() {
        return Ok(None);
    }
    let mut blocks = vec![on_disk_manifest.to_vec()];
    if reconstruct_from_error_correction(&mut blocks, manifest_parity).is_err() {
        return Ok(None);
    }
    Ok(blocks.into_iter().next())
}

/// Which GAP-4 metadata regions a vault's detached sidecar protects, read without
/// the password. Returns `(manifest_parity_present, header_parity_present)`;
/// `(false, false)` when there is no sidecar or it cannot be parsed.
fn sidecar_parity_flags(vault_path: &Path) -> (bool, bool) {
    let sidecar_path = default_sidecar_path(vault_path);
    match std::fs::read(&sidecar_path)
        .ok()
        .and_then(|b| AeroCorrectSidecar::from_bytes(&b).ok())
    {
        Some(sidecar) => (
            !vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_MANIFEST).is_empty(),
            !vault_sidecar_parity(&sidecar, VAULT_SIDECAR_SEG_HEADER).is_empty(),
        ),
        None => (false, false),
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
    let mut file =
        File::open(path).map_err(|e| format!("Open vault for Error Correction check: {e}"))?;

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

        let _ = std::fs::remove_file(&vp);
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

        let _ = std::fs::remove_file(&vp);
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

        let _ = std::fs::remove_file(&vp);
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
        let (repaired, _source) = VaultV3::repair(&mut vault, false, None).unwrap();
        assert_eq!(repaired, 0, "beyond-budget repair must heal nothing");
        drop(vault);

        // The container is left byte-for-byte untouched (all-or-nothing).
        assert_eq!(std::fs::read(&vp).unwrap(), corrupt_bytes);

        let _ = std::fs::remove_file(&vp);
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

        let _ = std::fs::remove_file(&vp);
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&out);
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
        let _ = std::fs::remove_file(&vp);
        let _ = std::fs::remove_dir_all(&src);
    }
}
