// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AEROVAULT3 sync vault operations engine.
//!
//! A faithful, byte-for-byte port of the AeroFTP application's AEROVAULT3 vault
//! operations (`src-tauri/src/aerovault_v3.rs`), minus the Tauri command layer,
//! async, telemetry (`VaultReport`), and Error Correction (rev. 4). The on-disk
//! content pipeline, manifest shape, header layout, packing, chunking, and
//! extract path-traversal safety are preserved exactly so a container produced
//! here cross-opens with one produced by the app (T5 contract).
//!
//! Error Correction (parity sidecars, scrub/repair, shard recompute on seal) is
//! intentionally out of scope; it is wired in T6. Every place the app branched
//! on EC is marked with a `// T6:` comment.

// SPDX-License-Identifier: MPL-2.0

use crate::lock::WriteLock;
use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use super::block::{build_file_bytes, write_container};
use super::chunking::{chunk_ranges_with, keyed_chunk_id, CdcBounds, StreamingChunker};
use super::constants::{
    CDC_MAX, CRYPT_ALGORITHM_ENCRYPTED, CRYPT_ALGORITHM_NONE, DATA_OFFSET, DEFAULT_ZSTD_LEVEL,
    FLAG_PLAINTEXT_CONTENT, HEADER_SIZE, HKDF_CHUNK_ID, INCOMPRESSIBLE_PROBE_LEVEL,
    INCOMPRESSIBLE_PROBE_MAX_SAMPLE, INCOMPRESSIBLE_PROBE_SAMPLE, INCOMPRESSIBLE_RATIO_PCT,
    MAC_SIZE, MAGIC, MAX_BLOCK_SIZE, MAX_EXTENSION_DIR_SIZE, MAX_MANIFEST_SIZE,
    MAX_PLAINTEXT_BLOCK_SIZE, MIN_PASSWORD_LEN, PACK_SMALL_FILE_THRESHOLD, PACK_TARGET,
    SUPPORTED_WRAPPER_HEADER_VERSION, VERSION,
};

use super::format::{aerovz_mac_key, derive_keks, VaultHeaderV3};
use super::manifest::{
    block_aad, decrypt_manifest, empty_manifest, empty_manifest_plaintext, manifest_cdc_bounds,
    manifest_is_plaintext, manifest_zstd_level, next_block_index, now_iso,
    parse_manifest_plaintext, AlgorithmSpec, ChunkRecordV3, ExtensionEntryV3, ManifestEntryV3,
    VaultManifestV3, WrapperManifest,
};
use crate::aerocrypt::{
    decrypt_with_aad, derive_base_kek, encrypt_with_aad, hkdf_expand, random_array, unwrap_key,
    wrap_key, KEY_SIZE, SALT_SIZE, WRAPPED_KEY_SIZE,
};

const DATA_BUDGET_ENV: &str = "AEROVAULT_V3_DATA_BUDGET_BYTES";

/// Optional resource policy for opening and editing a v3 container.
///
/// The data section is kept in memory. This limits its stored bytes, not the
/// total process memory needed for compression, encryption or Error Correction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VaultV3Limits {
    max_data_bytes: Option<u64>,
}

impl VaultV3Limits {
    /// Limit the data section at open and on subsequent saves of the handle.
    /// By default, there is no fixed size limit beyond the address space and
    /// available memory.
    pub const fn with_max_data_bytes(mut self, max: u64) -> Self {
        self.max_data_bytes = Some(max);
        self
    }

    fn from_env() -> Self {
        // Keep the valid values accepted by 0.6.9 when set explicitly.
        let max_data_bytes = std::env::var(DATA_BUDGET_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|&size| (1024 * 1024 * 1024..=isize::MAX as u64).contains(&size));
        Self { max_data_bytes }
    }

    fn check_data_len(self, size: u64) -> Result<(), String> {
        if let Some(max) = self.max_data_bytes.filter(|&max| size > max) {
            return Err(format!(
                "Vault data section of {size} bytes exceeds the configured {max}-byte data budget"
            ));
        }
        Ok(())
    }
}

/// Error returned by [`VaultV3::open`] for a plaintext container. Kept stable:
/// embedders match on it to tell the user the file is not a vault.
const PLAINTEXT_NOT_A_VAULT: &str =
    "unencrypted .aerozip archive (plaintext lane), not an encrypted vault: open it with open_plaintext";

/// Which cryptographic lane a container uses.
///
/// The encrypted lane is the standard password-protected `.aerovault`. The
/// plaintext lane is the unencrypted `.aerovz` archive (#7): the same
/// pack/chunk/compress/Error-Correction pipeline minus the encrypt stage —
/// content blocks and the manifest are stored in the clear, there is no
/// password, and the header carries an integrity-only public MAC. It is
/// integrity + recovery, NOT confidentiality; the data is readable by anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLane {
    /// Password-protected, AES-256-GCM-SIV content + encrypted manifest.
    Encrypted,
    /// Unencrypted `.aerovz`: compressed + EC, no encryption, no password.
    Plaintext,
}

/// Options for creating an AEROVAULT3 container. Without an Error-Correction
/// placement this produces a plain rev. 3 container; setting one (see
/// [`VaultV3::create_with_error_correction`]) opts into rev. 4.
pub struct CreateOptionsV3 {
    /// Destination path for the `.aerovault` / `.aerovz` container.
    pub path: PathBuf,
    /// Master password (>= [`MIN_PASSWORD_LEN`] characters). Ignored — and may be
    /// empty — when `lane` is [`VaultLane::Plaintext`].
    pub password: String,
    /// zstd compression level recorded on the `compression` wrapper.
    pub zstd_level: i32,
    /// Optional explicit CDC bounds. When absent, the historical level-driven
    /// defaults are used (`level >= 19` selects the archive profile).
    pub cdc_bounds: Option<CdcBounds>,
    /// Cryptographic lane. [`VaultLane::Encrypted`] by default.
    pub lane: VaultLane,
    /// rev. 4 Error-Correction placement. `None` keeps the container plain rev. 3.
    pub(super) error_correction: Option<super::ec::RecoveryPlacement>,
    /// QR-style EC overhead percentage; only meaningful when
    /// `error_correction` is `Some`. Defaults to the original K=10/P=2 grid.
    pub(super) error_correction_pct: u32,
}

impl CreateOptionsV3 {
    /// New encrypted-lane options with the default ([`DEFAULT_ZSTD_LEVEL`])
    /// compression level.
    pub fn new(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: password.into(),
            zstd_level: DEFAULT_ZSTD_LEVEL,
            cdc_bounds: None,
            lane: VaultLane::Encrypted,
            error_correction: None,
            error_correction_pct: crate::error_correction::ERROR_CORRECTION_DEFAULT_PCT,
        }
    }

    /// New plaintext-lane (`.aerovz`) options: no password, content + manifest
    /// stored unencrypted. Compression and (optional) Error Correction still
    /// apply. See [`VaultLane::Plaintext`] for the security caveat.
    pub fn new_plaintext(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            password: String::new(),
            zstd_level: DEFAULT_ZSTD_LEVEL,
            cdc_bounds: None,
            lane: VaultLane::Plaintext,
            error_correction: None,
            error_correction_pct: crate::error_correction::ERROR_CORRECTION_DEFAULT_PCT,
        }
    }

    /// Override the zstd compression level.
    pub fn with_zstd_level(mut self, level: i32) -> Self {
        self.zstd_level = level;
        self
    }

    /// Override content-defined chunking bounds independently from the zstd
    /// level, so high compression levels can keep fine-grained deduplication.
    pub fn with_cdc_bounds(mut self, bounds: CdcBounds) -> Self {
        self.cdc_bounds = Some(bounds);
        self
    }
}

/// An unlocked, fully in-memory AEROVAULT3 container.
///
/// Holds the decrypted master and MAC keys plus the whole data section in RAM.
/// Drop it when done: the [`Drop`] impl zeroizes the key material.
pub struct OpenVaultV3 {
    pub(super) path: PathBuf,
    pub(super) header: VaultHeaderV3,
    /// Length and BLAKE3 hash of the whole file as read at open (or as written
    /// by the last save): the generation baseline. Taken from the bytes on
    /// disk, so a header recovered from the sidecar does not count as a change.
    pub(super) opened_file_len: u64,
    opened_hash: [u8; 32],
    limits: VaultV3Limits,
    pub(super) master_key: [u8; KEY_SIZE],
    pub(super) mac_key: [u8; KEY_SIZE],
    pub(super) manifest: VaultManifestV3,
    pub(super) extensions: Vec<ExtensionEntryV3>,
    pub(super) data: Vec<u8>,
    /// Set when `open_vault` had to rebuild a corrupted encrypted manifest from
    /// Error-Correction parity (rev. 4). `repair` persists the healed region.
    pub(super) manifest_repaired_on_open: bool,
    /// Set when `open_vault` had to rebuild a corrupted header from the detached
    /// sidecar's header parity (rev. 4). `repair` persists the healed region.
    pub(super) header_repaired_on_open: bool,
    /// Optional embedder telemetry sink (see [`super::telemetry`]). `None` by
    /// default, so the content pipeline emits nothing and produces identical
    /// bytes; attach one with [`OpenVaultV3::set_telemetry_sink`].
    pub(super) telemetry: Option<Box<dyn super::telemetry::VaultTelemetrySink + Send>>,
}

impl std::fmt::Debug for OpenVaultV3 {
    /// Manual `Debug` (the optional telemetry sink is not `Debug`); never prints
    /// key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVaultV3")
            .field("path", &self.path)
            .field("opened_file_len", &self.opened_file_len)
            .field("entries", &self.manifest.entries.len())
            .field("chunks", &self.manifest.chunks.len())
            .field("data_len", &self.data.len())
            .field("manifest_repaired_on_open", &self.manifest_repaired_on_open)
            .field("header_repaired_on_open", &self.header_repaired_on_open)
            .field("telemetry", &self.telemetry.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for OpenVaultV3 {
    /// Wipe the long-lived key material when the open vault is dropped.
    /// Ephemeral KEKs and plaintext/pack buffers are zeroized at every use
    /// site; the master/MAC keys live for the whole operation, so without this
    /// they would linger in freed memory after every mutation.
    fn drop(&mut self) {
        self.master_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl OpenVaultV3 {
    /// The container's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attach an embedder telemetry sink to receive content-pipeline events for
    /// the operations run on this open vault (see [`super::telemetry`]). Without
    /// one the pipeline emits nothing; attaching one never changes the bytes
    /// written.
    pub fn set_telemetry_sink(
        &mut self,
        sink: Box<dyn super::telemetry::VaultTelemetrySink + Send>,
    ) {
        self.telemetry = Some(sink);
    }

    /// Run `f` against the attached telemetry sink, if any. A no-op when no sink
    /// is attached.
    pub(super) fn emit(
        &mut self,
        f: impl FnOnce(&mut (dyn super::telemetry::VaultTelemetrySink + Send)),
    ) {
        if let Some(sink) = self.telemetry.as_deref_mut() {
            f(sink);
        }
    }
}

/// One entry as surfaced by [`list`].
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Canonical vault-relative path (uses `/` separators).
    pub path: String,
    /// Logical file size in bytes (0 for directories).
    pub size: u64,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Last-modified timestamp in the app's `%Y-%m-%dT%H:%M:%SZ` form.
    pub modified: String,
    /// Number of logical content chunks this entry references (0 for
    /// directories). Logical, not deduplicated: two entries sharing a chunk
    /// each count it.
    pub chunk_count: usize,
}

/// Aggregate view of an open vault, sufficient for an embedder to build a
/// JSON/info summary without reaching into the (private) manifest. Mirrors the
/// totals the app historically derived from the manifest.
#[derive(Debug, Clone)]
pub struct VaultSummaryV3 {
    /// On-disk format version ([`VERSION`]).
    pub version: u8,
    /// Number of file (non-directory) entries.
    pub file_count: usize,
    /// Number of distinct physical content chunks stored.
    pub chunk_count: usize,
    /// Deduplicated chunks: logical chunk references minus physical chunks.
    pub dedup_chunks: usize,
    /// Effective zstd compression level recorded in the manifest.
    pub compression_level: i32,
    /// Ordered wrapper chain (`"packing:small-file-batching v1"`, ...) derived
    /// from the manifest, for the technical receipt.
    pub algorithms: Vec<String>,
    /// Every entry (files and directories) with its logical chunk count.
    pub entries: Vec<EntryInfo>,
}

/// Header-only info available without a password.
#[derive(Debug, Clone)]
pub struct PeekInfo {
    /// On-disk format version (always [`VERSION`] for a valid file).
    pub version: u8,
    /// Total on-disk file length.
    pub file_len: u64,
    /// Length of the data section, per the (unverified) header.
    pub data_len: u64,
    /// Length of the encrypted manifest, per the (unverified) header.
    pub manifest_len: u64,
}

/// Namespace handle for the AEROVAULT3 sync API.
///
/// Mirrors the legacy v2 `Vault::create/open/is_vault/peek` shape, but every
/// mutating op takes a `&mut OpenVaultV3` and persists with [`save_open_vault`]
/// internally, exactly like the app's command layer drove the sync core.
pub struct VaultV3;

impl VaultV3 {
    /// Create a new empty container at `opts.path`. A plain rev. 3 container
    /// unless `opts` carries an Error-Correction placement (rev. 4).
    pub fn create(opts: &CreateOptionsV3) -> Result<(), String> {
        create_empty_vault(
            &opts.path,
            &opts.password,
            opts.zstd_level,
            opts.cdc_bounds,
            opts.lane,
            opts.error_correction,
            opts.error_correction_pct,
        )
    }

    /// Create a new empty rev. 4 container with Reed-Solomon Error Correction.
    ///
    /// `placement` selects where parity lives: `Embedded` (non-critical
    /// in-container extension, recomputed on every seal), `Detached` (a sibling
    /// `.aerocorrect` sidecar, container stays byte-identical to a plain vault),
    /// or `Both`. The embedded extension is non-critical so rev. 3 readers can
    /// still open + extract (#276). `pct` is the QR-style overhead level
    /// (clamped to `[MIN_PCT, MAX_PCT]`); the default reproduces the original
    /// K=10/P=2 (~20%) grid.
    pub fn create_with_error_correction(
        opts: &CreateOptionsV3,
        placement: super::ec::RecoveryPlacement,
        pct: u32,
    ) -> Result<(), String> {
        create_empty_vault(
            &opts.path,
            &opts.password,
            opts.zstd_level,
            opts.cdc_bounds,
            opts.lane,
            Some(placement),
            pct,
        )
    }

    /// Write a detached `.aerocorrect` recovery file for an existing vault
    /// without rewriting the container ("add Error Correction later"). Defaults
    /// to `<vault>.aerocorrect`; pass `out` to override.
    pub fn export_parity(
        vault_path: &Path,
        password: &str,
        out: Option<&Path>,
    ) -> Result<super::ec::ExportParityResult, String> {
        Self::export_parity_with_limits(vault_path, password, out, VaultV3Limits::from_env())
    }

    /// Export a sidecar with an explicit data budget, independent of the environment.
    pub fn export_parity_with_limits(
        vault_path: &Path,
        password: &str,
        out: Option<&Path>,
        limits: VaultV3Limits,
    ) -> Result<super::ec::ExportParityResult, String> {
        super::ec::export_parity(vault_path, password, out, limits)
    }

    /// Drop the embedded Error-Correction extension on the next seal. Refuses
    /// unless detached parity covers the current data blocks, header and manifest,
    /// including for an empty vault, or `force` is set. Run [`Self::export_parity`]
    /// first to provide the required current metadata parity.
    pub fn strip_parity(
        vault_path: &Path,
        password: &str,
        force: bool,
    ) -> Result<super::ec::StripParityResult, String> {
        Self::strip_parity_with_limits(vault_path, password, force, VaultV3Limits::from_env())
    }

    /// Strip embedded parity with an explicit data budget, independent of the environment.
    pub fn strip_parity_with_limits(
        vault_path: &Path,
        password: &str,
        force: bool,
        limits: VaultV3Limits,
    ) -> Result<super::ec::StripParityResult, String> {
        super::ec::strip_parity(vault_path, password, force, limits)
    }

    /// Verify every stored content block against its manifest `cipher_hash`,
    /// returning the damaged chunks (read-only).
    pub fn scrub(vault: &OpenVaultV3) -> Vec<super::ec::DamagedChunk> {
        super::ec::scrub_vault(vault)
    }

    /// Repair damaged blocks from Error-Correction parity (explicit `parity`
    /// path, else detached sidecar, else embedded extension). All-or-nothing:
    /// every reconstructed block is re-verified against the manifest
    /// `cipher_hash` and persisted only if all pass; on `dry_run` nothing is
    /// written. Returns `(repaired_block_count, parity_source)`; zero means
    /// no damaged content blocks were detected. Detected damage that cannot be
    /// fully repaired from available parity returns `Err`, including in dry-run
    /// mode, rather than `Ok((0, _))`.
    pub fn repair(
        vault: &mut OpenVaultV3,
        dry_run: bool,
        parity: Option<&Path>,
    ) -> Result<(usize, super::ec::ParitySource), String> {
        super::ec::repair_vault(vault, dry_run, parity)
    }

    /// True if `path` carries the embedded Error-Correction extension (no
    /// password needed; reads only the header + plaintext extension directory).
    pub fn has_error_correction(path: &Path) -> Result<bool, String> {
        super::ec::has_error_correction(path)
    }

    /// Pre-flight: which Error-Correction parity source a [`repair`](Self::repair)
    /// would draw from (`explicit` path wins, else the detached sidecar, else the
    /// embedded extension). An explicit path that is unreadable/malformed is a
    /// hard error; an absent default source returns
    /// [`ParitySource::None`](super::ec::ParitySource). Read-only; discards the
    /// resolved parity bytes.
    pub fn resolve_parity_source(
        vault: &OpenVaultV3,
        explicit: Option<&Path>,
    ) -> Result<super::ec::ParitySource, String> {
        super::ec::resolve_parity_source(vault, explicit).map(|(_, source)| source)
    }

    /// Recovery surfaces available for a vault without the password.
    pub fn recovery_status(path: &Path) -> Result<super::ec::RecoveryStatus, String> {
        super::ec::recovery_status(path)
    }

    /// True if `path` begins with the AEROVAULT3 magic + version.
    pub fn is_vault_v3(path: impl AsRef<Path>) -> bool {
        let Ok(mut file) = crate::source::open_regular(path.as_ref()) else {
            return false;
        };
        let mut buf = [0u8; 11];
        if file.read_exact(&mut buf).is_err() {
            return false;
        }
        &buf[..10] == MAGIC && buf[10] == VERSION
    }

    /// Open and unlock an encrypted container with `password`.
    ///
    /// Errors on a plaintext (`.aerovz`) container: it has no password, so
    /// accepting it here would let anyone who can replace the file turn a
    /// password unlock into an unencrypted archive whose later writes are stored
    /// in the clear. Open those with [`VaultV3::open_plaintext`].
    pub fn open(path: impl Into<PathBuf>, password: &str) -> Result<OpenVaultV3, String> {
        Self::open_with_limits(path, password, VaultV3Limits::from_env())
    }

    /// Open an encrypted vault using the caller's limits instead of the environment.
    /// The returned handle retains the same limits for all later mutations.
    pub fn open_with_limits(
        path: impl Into<PathBuf>,
        password: &str,
        limits: VaultV3Limits,
    ) -> Result<OpenVaultV3, String> {
        // Refused from the header alone, before any payload is read.
        let vault = open_vault_with_guard(path, password, true, None, limits)?;
        if vault.header.flags & FLAG_PLAINTEXT_CONTENT != 0 {
            return Err(PLAINTEXT_NOT_A_VAULT.to_string());
        }
        Ok(vault)
    }

    /// Open a plaintext (`.aerovz`) container, which has no password.
    /// Errors if the container is an encrypted `.aerovault`.
    pub fn open_plaintext(path: impl Into<PathBuf>) -> Result<OpenVaultV3, String> {
        Self::open_plaintext_with_limits(path, VaultV3Limits::from_env())
    }

    /// Open the plaintext lane with an explicit budget retained by the handle.
    pub fn open_plaintext_with_limits(
        path: impl Into<PathBuf>,
        limits: VaultV3Limits,
    ) -> Result<OpenVaultV3, String> {
        let vault = open_vault_with_guard(path, "", false, None, limits)?;
        if vault.header.flags & FLAG_PLAINTEXT_CONTENT == 0 {
            return Err("Not a plaintext .aerovz archive (it is encrypted)".to_string());
        }
        Ok(vault)
    }

    /// Read header-only info without a password.
    pub fn peek(path: impl AsRef<Path>) -> Result<PeekInfo, String> {
        let mut file =
            crate::source::open_regular(path.as_ref()).map_err(|e| format!("Open vault: {e}"))?;
        let file_len = file
            .metadata()
            .map_err(|e| format!("Vault metadata: {e}"))?
            .len();
        let mut header_bytes = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)
            .map_err(|e| format!("Read header: {e}"))?;
        let header = VaultHeaderV3::from_bytes(&header_bytes)?;
        Ok(PeekInfo {
            version: VERSION,
            file_len,
            data_len: header.data_len,
            manifest_len: header.manifest_len,
        })
    }

    /// List every entry (files and directories) in the manifest.
    pub fn list(vault: &OpenVaultV3) -> Vec<EntryInfo> {
        vault
            .manifest
            .entries
            .iter()
            .map(|entry| EntryInfo {
                path: entry.path.clone(),
                size: entry.size,
                is_dir: entry.is_dir,
                modified: entry.modified.clone(),
                chunk_count: entry.chunks.len(),
            })
            .collect()
    }

    /// Aggregate stats + entry list for an open vault, mirroring the totals the
    /// app historically derived from the manifest (file count, physical/dedup
    /// chunk counts, compression level). Lets an embedder build an info/JSON
    /// view without manifest access.
    pub fn summary(vault: &OpenVaultV3) -> VaultSummaryV3 {
        let entries = Self::list(vault);
        let file_count = entries.iter().filter(|e| !e.is_dir).count();
        let logical_chunks: usize = entries.iter().map(|e| e.chunk_count).sum();
        let chunk_count = vault.manifest.chunks.len();
        VaultSummaryV3 {
            version: VERSION,
            file_count,
            chunk_count,
            dedup_chunks: logical_chunks.saturating_sub(chunk_count),
            compression_level: super::manifest::manifest_zstd_level(&vault.manifest),
            algorithms: algorithm_chain(&vault.manifest),
            entries,
        }
    }

    /// Add files into the vault at the given vault-relative paths, then persist.
    pub fn add_files(vault: &mut OpenVaultV3, sources: &[(PathBuf, String)]) -> Result<(), String> {
        write_op(vault, |v, lock, _| {
            append_sources_batched(v, sources)?;
            save_locked(v, lock)
        })
    }

    /// Add `sources` into directory `target_dir`, joining each source's file
    /// name under it, then persist. `target_dir` empty means the vault root.
    pub fn add_files_to_dir(
        vault: &mut OpenVaultV3,
        sources: &[PathBuf],
        target_dir: &str,
    ) -> Result<(), String> {
        let target = target_dir.trim().trim_matches('/');
        let mut mapped: Vec<(PathBuf, String)> = Vec::with_capacity(sources.len());
        for source in sources {
            let name = safe_entry_name(source)?;
            let entry_path = if target.is_empty() {
                name
            } else {
                let target = normalize_vault_relative_path(target)?;
                join_vault_path(&target, &name)
            };
            mapped.push((source.clone(), entry_path));
        }
        write_op(vault, |v, lock, _| {
            if !target.is_empty() {
                create_directory_in_manifest(&mut v.manifest, target)?;
            }
            append_sources_batched(v, &mapped)?;
            save_locked(v, lock)
        })
    }

    /// Create a directory (and any missing parents) inside the vault, persist.
    /// Returns `true` when the leaf directory was newly created, `false` when it
    /// already existed.
    pub fn create_directory(vault: &mut OpenVaultV3, dir_path: &str) -> Result<bool, String> {
        write_op(vault, |v, lock, _| {
            let created = create_directory_in_manifest(&mut v.manifest, dir_path)?;
            save_locked(v, lock)?;
            Ok(created)
        })
    }

    /// Recursively add `source_dir` (depth <= 100, <= 500000 entries) under
    /// `target_prefix` (or the root when `None`), then persist.
    pub fn add_directory(
        vault: &mut OpenVaultV3,
        source_dir: &Path,
        target_prefix: Option<&str>,
    ) -> Result<(usize, usize), String> {
        write_op(vault, |v, lock, sidecar| {
            add_directory_into(v, source_dir, target_prefix, lock, sidecar)
        })
    }

    /// Delete a single entry (file or empty directory), then persist.
    pub fn delete_entry(vault: &mut OpenVaultV3, entry_name: &str) -> Result<usize, String> {
        Self::delete_entries(vault, std::slice::from_ref(&entry_name.to_string()), false)
    }

    /// Delete entries; with `recursive` a directory drops its whole subtree.
    pub fn delete_entries(
        vault: &mut OpenVaultV3,
        entry_names: &[String],
        recursive: bool,
    ) -> Result<usize, String> {
        write_op(vault, |v, lock, _| {
            // Compaction replaces the data section: keep the old one until the
            // save succeeds, so a failed delete leaves the handle as it was.
            let (removed, replaced) = delete_entries_from_manifest(v, entry_names, recursive)?;
            if let Err(e) = save_locked(v, lock) {
                if let Some(data) = replaced {
                    v.data = data;
                }
                return Err(e);
            }
            Ok(removed)
        })
    }

    /// Move (or rename across directories) an entry/subtree, then persist.
    pub fn move_entry(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
        write_op(vault, |v, lock, _| {
            move_entry_in_manifest(v, from, to)?;
            save_locked(v, lock)
        })
    }

    /// Rename an entry within its parent directory, then persist.
    pub fn rename_entry(
        vault: &mut OpenVaultV3,
        current_name: &str,
        new_name: &str,
    ) -> Result<(), String> {
        let current = normalize_vault_relative_path(current_name)?;
        let leaf = normalize_leaf_name(new_name)?;
        let target = match path_parent(&current) {
            Some(parent) => join_vault_path(parent, &leaf),
            None => leaf,
        };
        write_op(vault, |v, lock, _| {
            move_entry_in_manifest(v, &current, &target)?;
            save_locked(v, lock)
        })
    }

    /// Copy an entry/subtree (reusing the same content chunks), then persist.
    pub fn copy_entry(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
        write_op(vault, |v, lock, _| {
            copy_entry_in_manifest(v, from, to)?;
            save_locked(v, lock)
        })
    }

    /// Re-wrap the keys under a new password (new salt + KEKs), then persist.
    /// A `<vault>.aerocorrect` sidecar is re-exported under the new header.
    pub fn change_password(vault: &mut OpenVaultV3, new_password: &str) -> Result<(), String> {
        // A sidecar exported before the change holds parity of the old header,
        // and header recovery would rebuild that header, so the old password
        // would keep opening the vault. It is refreshed under the new header,
        // which first needs intact blocks: parity of a damaged block would
        // replace the parity that can still repair it (embedded parity is
        // recomputed on every save, so the same holds without a sidecar).
        // One lock across the sidecar check, the save and the refresh: no
        // other writer can save or export in between, so the sidecar that
        // exists is refreshed and is of this header. The new password is
        // checked first, so a policy error does not wait for another writer.
        if new_password.len() < MIN_PASSWORD_LEN {
            return Err("Password must be at least 8 characters".to_string());
        }
        let lock = write_lock(&vault.path)?;
        vault.path = lock.source_path().to_path_buf();
        let sidecar = super::ec::default_sidecar_path(lock.source_path());
        // An export from another source can target this path too. Lock before
        // the existence check, even when no sidecar has been published yet.
        let sidecar_lock =
            if crate::lock::destination_can_exist(&sidecar).map_err(|e| e.to_string())? {
                Some(crate::lock::acquire(&sidecar).map_err(|e| e.to_string())?)
            } else {
                // The destination filesystem refuses this basename; neither
                // a default export nor a competing writer can publish it.
                None
            };
        if sidecar_lock.is_some() {
            super::ec::validate_automatic_sidecar_destination(&sidecar)?;
        }
        if super::ec::legacy_sidecar_path(lock.source_path()).is_some_and(|p| p.exists()) {
            // This ambiguous old name can be shared by several byte-distinct
            // vaults. Never silently leave an automatically used old-password
            // recovery copy, or delete/overwrite another vault's shared copy.
            return Err("Legacy lossy-name recovery file exists; migrate the verified recovery file to the native sidecar path and retire the shared legacy name before changing the password".to_string());
        }
        let refresh = sidecar.exists();
        if (refresh || has_embedded_parity(vault)) && !super::ec::scrub_vault(vault).is_empty() {
            return Err(
                "Vault has damaged blocks: run repair before changing the password".to_string(),
            );
        }
        let previous = (
            vault.header.clone(),
            vault.manifest.modified.clone(),
            vault.opened_file_len,
            vault.opened_hash,
            vault.header_repaired_on_open,
            vault.manifest_repaired_on_open,
        );
        change_password_in_place(vault, new_password)?;
        let mut staged = false;
        let result = (|| {
            if !refresh {
                return save_locked(vault, &lock);
            }
            // A process interruption between two independent renames must not
            // leave old-header recovery beside a newly rotated container.
            // Use the same bounded, restart-recoverable pair transaction as
            // non-forced stripping, under the already held source/sidecar locks.
            let prepared = super::strip_transaction::private_dir(
                output_parent_dir(lock.source_path()),
                ".aeropassword-prepare-",
            )?;
            super::strip_transaction::copy_file(
                lock.source_path(),
                &prepared.path().join("old-vault"),
            )?;
            super::strip_transaction::copy_file(&sidecar, &prepared.path().join("old-sidecar"))?;
            let target = prepared.path().join("new-vault");
            save_locked_to(vault, &lock, &target)?;
            staged = true;
            super::ec::export_parity_from_sealed(
                vault,
                &target,
                &prepared.path().join("new-sidecar"),
            )?;
            super::strip_transaction::publish(lock.source_path(), prepared, &lock)
        })();
        if let Err(error) = result {
            if staged && assert_vault_generation_current(vault).is_ok() {
                return Err(format!("Password changed on disk, but paired recovery publication reported an error ({error}); recovery may be pending; preserve the vault, sidecar and journal and reopen before further writes"));
            }
            // Restore every field updated by a staged seal. A later mutation
            // on this handle must not persist a password reported as failed.
            (
                vault.header,
                vault.manifest.modified,
                vault.opened_file_len,
                vault.opened_hash,
                vault.header_repaired_on_open,
                vault.manifest_repaired_on_open,
            ) = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Extract one entry (file or directory subtree) to `dest`.
    pub fn extract_entry(
        vault: &OpenVaultV3,
        entry_name: &str,
        dest: &Path,
    ) -> Result<PathBuf, String> {
        extract_entry(vault, entry_name, dest)
    }

    /// Extract the entire vault tree under `dest`, returning files written.
    pub fn extract_all(vault: &OpenVaultV3, dest: &Path) -> Result<u64, String> {
        extract_all_entries(vault, dest)
    }

    /// `extract_all` with a `(bytes_done, bytes_total)` progress callback invoked
    /// after each file is written (#5: progress for extract, GUI + CLI). The
    /// embedder turns this into a live bar; `extract_all` is the no-op-callback
    /// shorthand.
    pub fn extract_all_with_progress(
        vault: &OpenVaultV3,
        dest: &Path,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<u64, String> {
        extract_all_entries_with_progress(vault, dest, progress)
    }
}

// --- Internal port of the app sync core ---------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKindV3 {
    File,
    Directory,
}

/// Ordered wrapper chain for the technical receipt, derived from the manifest
/// wrappers (`"packing:small-file-batching v1"`, `"chunking:gear-cdc v1"`, ...).
fn algorithm_chain(manifest: &VaultManifestV3) -> Vec<String> {
    let w = &manifest.wrappers;
    let line = |name: &str, s: &AlgorithmSpec| {
        format!("{name}:{} v{}", s.algorithm_id, s.algorithm_version)
    };
    vec![
        line("packing", &w.packing),
        line("chunking", &w.chunking),
        line("chunk_id", &w.chunk_id),
        line("compression", &w.compression),
        line("crypt", &w.crypt),
        line("cipher_hash", &w.cipher_hash),
    ]
}

fn validate_vault_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\0')
        || path.contains('\\')
        || path.split('/').any(|part| part == "..")
        || path.as_bytes().get(1) == Some(&b':')
    {
        return Err(format!("Invalid AeroVault path: {path}"));
    }
    Ok(())
}

fn safe_entry_name(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("Invalid file name: {}", path.display()))?
        .to_string_lossy()
        .to_string();
    validate_vault_path(&name)?;
    Ok(name)
}

fn normalize_vault_relative_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err("Invalid AeroVault path: empty".to_string());
    }
    validate_vault_path(trimmed)?;
    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == ".")
    {
        return Err(format!("Invalid AeroVault path: {trimmed}"));
    }
    Ok(trimmed.to_string())
}

fn normalize_leaf_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('\0')
    {
        return Err("Invalid AeroVault name".to_string());
    }
    Ok(trimmed.to_string())
}

fn validate_manifest_paths(manifest: &VaultManifestV3) -> Result<(), String> {
    let mut seen = HashSet::new();
    for entry in &manifest.entries {
        let normalized = normalize_vault_relative_path(&entry.path)?;
        if normalized != entry.path {
            return Err(format!(
                "Invalid non-canonical AeroVault path: {}",
                entry.path
            ));
        }
        if !seen.insert(entry.path.as_str()) {
            return Err(format!(
                "Duplicate AeroVault path in manifest: {}",
                entry.path
            ));
        }
    }
    Ok(())
}

/// Audit M4 hardening: validate the extension directory at open time. The header
/// MAC authenticates the directory's offset/length but NOT its JSON bytes, so a
/// file-level attacker could forge the entry list within the MAC-fixed window. Bound
/// the blast radius to a clean refusal (it is otherwise DoS-only, since every recovery
/// re-verifies reconstructed bytes against authenticated material): reject duplicate
/// extension ids and any entry whose payload slice escapes the authenticated
/// extension-payload region. Full authentication of the directory bytes is a version-2
/// header change (breaks v1 cross-compat) and is tracked as a follow-up.
fn validate_extension_dir(
    extensions: &[ExtensionEntryV3],
    extension_payload_len: u64,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for ext in extensions {
        // A rev. 3 reader rejects any critical extension; the rev. 4 EC layers are
        // deliberately non-critical so this stays a forward-compat skip.
        if ext.critical {
            return Err(format!(
                "Unsupported critical AeroVault v3 extension: {}",
                ext.extension_id
            ));
        }
        if !seen.insert(ext.extension_id.as_str()) {
            return Err(format!(
                "Duplicate AeroVault v3 extension id: {}",
                ext.extension_id
            ));
        }
        let end = ext
            .offset
            .checked_add(ext.length)
            .ok_or_else(|| format!("Extension {} payload range overflow", ext.extension_id))?;
        if end > extension_payload_len {
            return Err(format!(
                "Extension {} payload slice [{}..{}] escapes the {extension_payload_len}-byte extension payload",
                ext.extension_id, ext.offset, end
            ));
        }
    }
    Ok(())
}

fn join_vault_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn path_parent(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_descendant_of(path: &str, parent: &str) -> bool {
    path.len() > parent.len()
        && path.starts_with(parent)
        && path.as_bytes().get(parent.len()) == Some(&b'/')
}

fn entry_kind(manifest: &VaultManifestV3, path: &str) -> Option<EntryKindV3> {
    if let Some(entry) = manifest.entries.iter().find(|entry| entry.path == path) {
        return Some(if entry.is_dir {
            EntryKindV3::Directory
        } else {
            EntryKindV3::File
        });
    }
    if manifest
        .entries
        .iter()
        .any(|entry| is_descendant_of(&entry.path, path))
    {
        return Some(EntryKindV3::Directory);
    }
    None
}

fn ensure_no_file_ancestor(manifest: &VaultManifestV3, path: &str) -> Result<(), String> {
    let mut current = path;
    while let Some(parent) = path_parent(current) {
        if manifest
            .entries
            .iter()
            .any(|entry| entry.path == parent && !entry.is_dir)
        {
            return Err(format!("Parent path is a file: {parent}"));
        }
        current = parent;
    }
    Ok(())
}

fn sort_entries(manifest: &mut VaultManifestV3) {
    manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));
}

fn create_directory_in_manifest(
    manifest: &mut VaultManifestV3,
    dir_path: &str,
) -> Result<bool, String> {
    let dir_path = normalize_vault_relative_path(dir_path)?;
    ensure_no_file_ancestor(manifest, &dir_path)?;

    if let Some(existing) = manifest.entries.iter().find(|entry| entry.path == dir_path) {
        return if existing.is_dir {
            Ok(false)
        } else {
            Err(format!("A file already exists at: {dir_path}"))
        };
    }

    if let Some(parent) = path_parent(&dir_path) {
        create_directory_in_manifest(manifest, parent)?;
    }

    manifest.entries.push(ManifestEntryV3 {
        path: dir_path,
        size: 0,
        modified: now_iso(),
        is_dir: true,
        chunks: Vec::new(),
        pack_offset: None,
    });
    sort_entries(manifest);
    manifest.modified = now_iso();
    Ok(true)
}

fn ensure_parent_directories(manifest: &mut VaultManifestV3, path: &str) -> Result<(), String> {
    if let Some(parent) = path_parent(path) {
        create_directory_in_manifest(manifest, parent)?;
    }
    Ok(())
}

/// Cheap incompressibility probe (#10-B): trial-compress representative chunk
/// samples at a fast level and report whether they failed to shrink past the threshold.
/// `true` => store the chunk raw and skip the full, possibly expensive, pass.
/// A probe error is non-fatal: fall back to the normal compression path.
fn probe_incompressible(chunk: &[u8]) -> bool {
    if chunk.is_empty() {
        return false;
    }
    let sample = representative_probe_sample(chunk);
    match zstd::stream::encode_all(sample.as_ref(), INCOMPRESSIBLE_PROBE_LEVEL) {
        // Incompressible when the probe output is >= RATIO% of the sample.
        Ok(probed) => {
            Zeroizing::new(probed).len() as u64 * 100
                >= sample.as_ref().len() as u64 * INCOMPRESSIBLE_RATIO_PCT
        }
        Err(_) => false,
    }
}

enum ProbeSample<'a> {
    Borrowed(&'a [u8]),
    Owned(Zeroizing<Vec<u8>>),
}
impl AsRef<[u8]> for ProbeSample<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(b) => b,
        }
    }
}

fn representative_probe_sample(chunk: &[u8]) -> ProbeSample<'_> {
    if chunk.len() <= INCOMPRESSIBLE_PROBE_MAX_SAMPLE {
        return ProbeSample::Borrowed(chunk);
    }

    let window_len = INCOMPRESSIBLE_PROBE_SAMPLE.min(chunk.len());
    let window_count = (INCOMPRESSIBLE_PROBE_MAX_SAMPLE / window_len).max(1);
    let mut sample = Zeroizing::new(Vec::with_capacity(window_count * window_len));
    let max_start = chunk.len() - window_len;

    for idx in 0..window_count {
        let start = if window_count == 1 {
            0
        } else {
            idx * max_start / (window_count - 1)
        };
        sample.extend_from_slice(&chunk[start..start + window_len]);
    }

    ProbeSample::Owned(sample)
}

/// Compress + encrypt + dedup one already-delimited plaintext chunk; returns the
/// chunk id. Shared by the per-file and pack paths. Incompressible chunks are
/// stored raw (still encrypted) so high zstd levels don't burn CPU re-packing
/// already-compressed data; the manifest's `stored_raw` flag drives decode.
/// (Telemetry dropped.)
fn ingest_chunk(
    vault: &mut OpenVaultV3,
    chunk: &[u8],
    chunk_key: &[u8; KEY_SIZE],
    level: i32,
) -> Result<String, String> {
    let chunk_id = keyed_chunk_id(chunk_key, chunk);
    if !vault.manifest.chunks.contains_key(&chunk_id) {
        // Decide the stored representation: skip the full compress when the
        // cheap probe says incompressible, and also fall back to raw if the
        // full pass somehow failed to shrink the chunk (never store a block
        // larger than the plaintext for zero gain).
        let mut stored_raw = probe_incompressible(chunk);
        let mut compressed = if stored_raw {
            Zeroizing::new(Vec::new())
        } else {
            let out = Zeroizing::new(
                zstd::stream::encode_all(chunk, level)
                    .map_err(|e| format!("zstd compress failed: {e}"))?,
            );
            if out.len() >= chunk.len() {
                stored_raw = true;
                Zeroizing::new(Vec::new())
            } else {
                out
            }
        };
        let payload: &[u8] = if stored_raw { chunk } else { &compressed };
        let block_index = next_block_index(&vault.manifest);
        let aad = block_aad(block_index, &chunk_id);
        // Plaintext (`.aerovz`) lane: store the compressed-or-raw payload
        // directly, skipping AES-256-GCM-SIV. `cipher_hash` is taken over the
        // stored bytes either way (ciphertext on the encrypted lane, the payload
        // here), so the decode-side integrity check is unchanged.
        let plaintext = manifest_is_plaintext(&vault.manifest);
        let encrypted = Zeroizing::new(if plaintext {
            payload.to_vec()
        } else {
            encrypt_with_aad(&vault.master_key, payload, &aad)?
        });
        let (pt, cz, enc) = (
            chunk.len() as u64,
            payload.len() as u64,
            encrypted.len() as u64,
        );
        compressed.zeroize();
        // Readers refuse a block above MAX_BLOCK_SIZE, which custom CDC bounds
        // can exceed. Fail the write instead of sealing a block nobody can read.
        if enc > MAX_BLOCK_SIZE {
            return Err(format!(
                "AeroVault v3 block of {enc} bytes exceeds the {MAX_BLOCK_SIZE}-byte limit; use a smaller CDC max bound"
            ));
        }
        let cipher_hash = blake3::hash(&encrypted).to_hex().to_string();
        let data_offset = vault.data.len() as u64;
        let end = data_offset
            .checked_add(8)
            .and_then(|start| start.checked_add(enc))
            .ok_or("Vault data length overflow")?;
        vault.limits.check_data_len(end)?;
        let additional = encrypted.len() + 8;
        if plaintext {
            crate::secret::reserve_vec(&mut vault.data, additional)
                .map_err(|e| format!("Cannot reserve the next vault block: {e}"))?;
        } else {
            vault
                .data
                .try_reserve(additional)
                .map_err(|e| format!("Cannot reserve the next vault block: {e}"))?;
        }
        vault
            .data
            .extend_from_slice(&(encrypted.len() as u64).to_le_bytes());
        vault.data.extend_from_slice(&encrypted);
        vault.manifest.chunks.insert(
            chunk_id.clone(),
            ChunkRecordV3 {
                id: chunk_id.clone(),
                block_index,
                data_offset,
                block_len: enc,
                plaintext_len: pt,
                compressed_len: cz,
                cipher_hash,
                stored_raw,
            },
        );
        vault.emit(|s| s.on_chunk(true, pt, cz, enc));
    } else {
        vault.emit(|s| s.on_chunk(false, chunk.len() as u64, 0, 0));
    }
    Ok(chunk_id)
}

fn append_file_at(vault: &mut OpenVaultV3, source: &Path, entry_path: &str) -> Result<(), String> {
    let entry_path = normalize_vault_relative_path(entry_path)?;
    if !source.is_file() {
        return Err(format!("Not a regular file: {}", source.display()));
    }
    ensure_parent_directories(&mut vault.manifest, &entry_path)?;

    if let Some(kind) = entry_kind(&vault.manifest, &entry_path) {
        match kind {
            EntryKindV3::Directory => {
                return Err(format!(
                    "Destination already exists as directory: {entry_path}"
                ));
            }
            EntryKindV3::File => {
                vault
                    .manifest
                    .entries
                    .retain(|entry| entry.path != entry_path);
            }
        }
    }

    let chunk_key = Zeroizing::new(hkdf_expand::<KEY_SIZE>(&vault.master_key, HKDF_CHUNK_ID)?);
    let level = manifest_zstd_level(&vault.manifest);
    let bounds = manifest_cdc_bounds(&vault.manifest)?;
    let mut entry_chunks = Vec::new();

    // Stream the source through the bounded-buffer chunker so peak memory is one
    // CDC window (`bounds.max` + a refill), not the whole file. The streamed
    // boundaries are byte-identical to `chunk_ranges_with` over the same bytes
    // (pinned by `streaming_chunker_matches_whole_buffer`), so chunk ids and the
    // on-disk container are unchanged. `size` is accumulated from the streamed
    // chunks, so it equals the bytes actually ingested (as `plaintext.len()` did).
    let file = crate::source::open_regular(source)
        .map_err(|e| format!("Read {}: {e}", source.display()))?;
    let mut chunker = StreamingChunker::new(file, bounds);
    let mut size = 0u64;
    while let Some(mut chunk) = chunker
        .next_chunk()
        .map_err(|e| format!("Read {}: {e}", source.display()))?
    {
        size += chunk.len() as u64;
        // Wipe the plaintext chunk on the error path too.
        let chunk_id = ingest_chunk(vault, &chunk, &chunk_key, level);
        chunk.zeroize();
        entry_chunks.push(chunk_id?);
    }

    vault.manifest.entries.push(ManifestEntryV3 {
        path: entry_path,
        size,
        modified: now_iso(),
        is_dir: false,
        chunks: entry_chunks,
        pack_offset: None,
    });
    vault.emit(|s| s.on_file(false));
    sort_entries(&mut vault.manifest);
    vault.manifest.modified = now_iso();
    Ok(())
}

/// Chunk one assembled pack, ingest its chunks, then map every member file to
/// the chunks covering its byte span plus the first-byte offset inside the first
/// covering chunk. The manifest is the index; the pack carries no per-file
/// framing.
fn flush_pack(
    vault: &mut OpenVaultV3,
    pack: &[u8],
    members: &[(String, u64, u64)],
    chunk_key: &[u8; KEY_SIZE],
    level: i32,
    bounds: &CdcBounds,
) -> Result<(), String> {
    if members.is_empty() {
        return Ok(());
    }
    vault.emit(|s| s.on_pack());

    let ranges = chunk_ranges_with(pack, bounds);
    let mut chunks: Vec<(String, u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in &ranges {
        let id = ingest_chunk(vault, &pack[*start..*end], chunk_key, level)?;
        chunks.push((id, *start as u64, *end as u64));
    }
    let (member_count, pack_len, chunk_count) = (members.len(), pack.len(), chunks.len());
    vault.emit(|s| {
        s.step(&format!(
            "pack: {member_count} file(s), {pack_len} B -> chunk+compress+encrypt {chunk_count} chunk(s)"
        ))
    });

    for (entry_path, fstart, flen) in members {
        let fstart_v = *fstart;
        let flen_v = *flen;
        let fend = fstart_v + flen_v;

        ensure_parent_directories(&mut vault.manifest, entry_path)?;
        if let Some(kind) = entry_kind(&vault.manifest, entry_path) {
            match kind {
                EntryKindV3::Directory => {
                    return Err(format!(
                        "Destination already exists as directory: {entry_path}"
                    ));
                }
                EntryKindV3::File => {
                    vault.manifest.entries.retain(|e| &e.path != entry_path);
                }
            }
        }

        let (covering, pack_offset) = if flen_v == 0 {
            (Vec::new(), Some(0u64))
        } else {
            let mut cov = Vec::new();
            let mut first: Option<u64> = None;
            for (id, cstart, cend) in &chunks {
                if *cstart < fend && fstart_v < *cend {
                    if first.is_none() {
                        first = Some(*cstart);
                    }
                    cov.push(id.clone());
                }
            }
            let fc = first.ok_or_else(|| format!("Packing failed to cover file: {entry_path}"))?;
            (cov, Some(fstart_v - fc))
        };

        vault.manifest.entries.push(ManifestEntryV3 {
            path: entry_path.clone(),
            size: flen_v,
            modified: now_iso(),
            is_dir: false,
            chunks: covering,
            pack_offset,
        });
        vault.emit(|s| s.on_file(true));
    }
    Ok(())
}

/// Add a set of sources, batching sub-threshold files into shared packs before
/// chunking and routing large files through the per-file path. Deterministic
/// path ordering keeps packs (and therefore dedup) stable across identical adds.
/// Extract progress total: file sizes come from the manifest, so the sum saturates.
fn progress_total(entries: &[&ManifestEntryV3]) -> u64 {
    entries
        .iter()
        .filter(|e| !e.is_dir)
        .fold(0u64, |acc, e| acc.saturating_add(e.size))
}

/// Run a mutation and its save. A vault with embedded or default detached
/// parity and damaged blocks is refused before anything changes: a save would
/// recompute embedded parity or make detached parity stale and unusable. On
/// any later error the manifest and the appended data are restored, so a later
/// write (or a repair) on this handle cannot persist a change the caller was
/// told had failed. Operations that replace the data section (delete) restore
/// it themselves.
fn write_op<T>(
    vault: &mut OpenVaultV3,
    op: impl FnOnce(&mut OpenVaultV3, &WriteLock, Option<&WriteLock>) -> Result<T, String>,
) -> Result<T, String> {
    let lock = write_lock(&vault.path)?;
    #[cfg(test)]
    if let Some(hook) = BEFORE_MUTATION_SIDECAR_LOCK.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let sidecar_lock = lock_default_sidecar(&vault.path)?;
    if (has_embedded_parity(vault) || super::ec::detached_recovery_needs_protection(&vault.path))
        && !super::ec::scrub_vault(vault).is_empty()
    {
        return Err("Vault has damaged blocks: run repair before writing to it".to_string());
    }
    let manifest = vault.manifest.clone();
    let data_len = vault.data.len();
    let result = op(vault, &lock, sidecar_lock.as_ref());
    if result.is_err() {
        vault.manifest = manifest;
        if let Some(appended) = vault.data.get_mut(data_len..) {
            appended.zeroize();
            #[cfg(test)]
            if let Some(inspect) = INSPECT_REJECTED_ADD.with(|h| h.borrow_mut().take()) {
                inspect(appended);
            }
        }
        vault.data.truncate(data_len);
    }
    result
}

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_MUTATION_SIDECAR_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static INSPECT_REJECTED_ADD: std::cell::RefCell<Option<InspectRejectedAdd>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type InspectRejectedAdd = Box<dyn FnOnce(&[u8])>;

fn lock_default_sidecar(path: &Path) -> Result<Option<WriteLock>, String> {
    let sidecar = super::ec::default_sidecar_path(path);
    if crate::lock::destination_can_exist(&sidecar).map_err(|e| e.to_string())? {
        crate::lock::acquire(&sidecar)
            .map(Some)
            .map_err(|e| e.to_string())
    } else {
        Ok(None)
    }
}

pub(super) fn validate_chunk_identities(manifest: &VaultManifestV3) -> Result<(), String> {
    if manifest
        .chunks
        .iter()
        .any(|(key, record)| key != &record.id)
    {
        return Err("Vault chunk map key does not match record identity".to_string());
    }
    Ok(())
}

fn has_embedded_parity(vault: &OpenVaultV3) -> bool {
    vault
        .extensions
        .iter()
        .any(|e| e.extension_id == super::constants::ERROR_CORRECTION_EXTENSION_ID)
}

fn append_sources_batched(
    vault: &mut OpenVaultV3,
    sources: &[(PathBuf, String)],
) -> Result<(), String> {
    let chunk_key = Zeroizing::new(hkdf_expand::<KEY_SIZE>(&vault.master_key, HKDF_CHUNK_ID)?);
    let level = manifest_zstd_level(&vault.manifest);
    let bounds = manifest_cdc_bounds(&vault.manifest)?;
    let (cdc_min, cdc_avg, cdc_max) = (bounds.min, bounds.avg, bounds.max);
    vault.emit(|s| s.set_cdc(cdc_min, cdc_avg, cdc_max));
    let source_count = sources.len();
    vault.emit(|s| s.step(&format!("scan: {source_count} source(s) to add")));

    let mut small_meta: Vec<(PathBuf, String)> = Vec::new();
    let mut large_count = 0usize;
    for (source, entry_path) in sources {
        let entry_path = normalize_vault_relative_path(entry_path)?;
        if !source.is_file() {
            return Err(format!("Not a regular file: {}", source.display()));
        }
        let len = std::fs::metadata(source)
            .map_err(|e| format!("Stat {}: {e}", source.display()))?
            .len();
        if (len as usize) < PACK_SMALL_FILE_THRESHOLD {
            small_meta.push((source.clone(), entry_path));
        } else {
            large_count += 1;
            append_file_at(vault, source, &entry_path)?;
        }
    }
    let small_count = small_meta.len();
    vault.emit(|s| {
        s.step(&format!(
            "partition: {small_count} small (< {PACK_SMALL_FILE_THRESHOLD} B, batched) / {large_count} large (per-file)"
        ))
    });

    if !small_meta.is_empty() {
        small_meta.sort_by(|a, b| a.1.cmp(&b.1));

        let mut pack = Zeroizing::new(Vec::new());
        let mut members: Vec<(String, u64, u64)> = Vec::new();
        for (source, entry_path) in &small_meta {
            let mut file = crate::source::open_regular(source)
                .map_err(|e| format!("Read {}: {e}", source.display()))?;
            let mut data = Zeroizing::new(Vec::new());
            crate::secret::read_to_end(&mut file, &mut data)
                .map_err(|e| format!("Read {}: {e}", source.display()))?;
            let start = pack.len() as u64;
            crate::secret::reserve(&mut pack, data.len()).map_err(|e| format!("Pack: {e}"))?;
            pack.extend_from_slice(&data);
            let len = data.len() as u64;
            data.zeroize();
            members.push((entry_path.clone(), start, len));
            if pack.len() >= PACK_TARGET {
                let flushed = flush_pack(vault, &pack, &members, &chunk_key, level, &bounds);
                pack.zeroize();
                flushed?;
                pack.clear();
                members.clear();
            }
        }
        if !members.is_empty() {
            let flushed = flush_pack(vault, &pack, &members, &chunk_key, level, &bounds);
            pack.zeroize();
            flushed?;
        }
    }

    sort_entries(&mut vault.manifest);
    vault.manifest.modified = now_iso();
    Ok(())
}

/// Garbage-collect orphaned chunks: keep only chunk records still referenced by
/// a live entry, rewrite the data section in block-index order, and remap each
/// surviving record's `data_offset`.
/// Rewrite the data section with only the live chunks; returns the old one.
fn compact_live_chunks(vault: &mut OpenVaultV3) -> Result<Vec<u8>, String> {
    let live_chunk_ids: HashSet<String> = vault
        .manifest
        .entries
        .iter()
        .flat_map(|entry| entry.chunks.iter().cloned())
        .collect();

    if live_chunk_ids.is_empty() {
        vault.manifest.chunks.clear();
        return Ok(std::mem::take(&mut vault.data));
    }

    let mut ordered_ids: Vec<(u64, String)> = vault
        .manifest
        .chunks
        .iter()
        .filter(|(id, _)| live_chunk_ids.contains(*id))
        .map(|(id, record)| (record.block_index, id.clone()))
        .collect();
    ordered_ids.sort_by_key(|(index, _)| *index);

    let mut new_data = Vec::new();
    let mut new_chunks = BTreeMap::new();

    for (_, chunk_id) in ordered_ids {
        let mut record = vault
            .manifest
            .chunks
            .get(&chunk_id)
            .cloned()
            .ok_or_else(|| format!("Missing chunk record: {chunk_id}"))?;
        let len_start = record.data_offset as usize;
        let len_end = len_start
            .checked_add(8)
            .ok_or_else(|| "Chunk length offset overflow".to_string())?;
        if len_end > vault.data.len() {
            return Err("Chunk length is outside data section".to_string());
        }
        let block_len = u64::from_le_bytes(
            vault.data[len_start..len_end]
                .try_into()
                .expect("slice length"),
        );
        if block_len != record.block_len || block_len > MAX_BLOCK_SIZE {
            return Err("Chunk length metadata mismatch".to_string());
        }
        let block_start = len_end;
        let block_end = block_start
            .checked_add(block_len as usize)
            .ok_or_else(|| "Chunk block offset overflow".to_string())?;
        if block_end > vault.data.len() {
            return Err("Chunk block is outside data section".to_string());
        }

        record.data_offset = new_data.len() as u64;
        new_data.extend_from_slice(&block_len.to_le_bytes());
        new_data.extend_from_slice(&vault.data[block_start..block_end]);
        new_chunks.insert(chunk_id, record);
    }

    vault.manifest.chunks = new_chunks;
    Ok(std::mem::replace(&mut vault.data, new_data))
}

/// Returns the removed count and, when compaction ran, the data section it
/// replaced.
fn delete_entries_from_manifest(
    vault: &mut OpenVaultV3,
    entry_names: &[String],
    recursive: bool,
) -> Result<(usize, Option<Vec<u8>>), String> {
    let mut removed = 0usize;

    for entry_name in entry_names {
        let entry_name = normalize_vault_relative_path(entry_name)?;
        let kind = entry_kind(&vault.manifest, &entry_name)
            .ok_or_else(|| format!("Entry not found: {entry_name}"))?;

        match kind {
            EntryKindV3::File => {
                let before = vault.manifest.entries.len();
                vault
                    .manifest
                    .entries
                    .retain(|entry| entry.path != entry_name);
                removed += before.saturating_sub(vault.manifest.entries.len());
            }
            EntryKindV3::Directory => {
                let has_children = vault
                    .manifest
                    .entries
                    .iter()
                    .any(|entry| is_descendant_of(&entry.path, &entry_name));
                if has_children && !recursive {
                    return Err(format!("Directory is not empty: {entry_name}"));
                }
                let before = vault.manifest.entries.len();
                vault.manifest.entries.retain(|entry| {
                    entry.path != entry_name && !is_descendant_of(&entry.path, &entry_name)
                });
                removed += before.saturating_sub(vault.manifest.entries.len());
            }
        }
    }

    let mut replaced = None;
    if removed > 0 {
        replaced = Some(compact_live_chunks(vault)?);
        sort_entries(&mut vault.manifest);
        vault.manifest.modified = now_iso();
    }

    Ok((removed, replaced))
}

fn remap_entry_path(path: &str, from: &str, to: &str) -> String {
    if path == from {
        to.to_string()
    } else {
        format!("{}/{}", to, &path[from.len() + 1..])
    }
}

fn prepare_relocation(
    manifest: &VaultManifestV3,
    from: &str,
    to: &str,
) -> Result<EntryKindV3, String> {
    let from = normalize_vault_relative_path(from)?;
    let to = normalize_vault_relative_path(to)?;
    let kind = entry_kind(manifest, &from).ok_or_else(|| format!("Entry not found: {from}"))?;

    if from == to {
        return Ok(kind);
    }
    if kind == EntryKindV3::Directory && is_descendant_of(&to, &from) {
        return Err("Cannot move a directory inside itself".to_string());
    }
    if entry_kind(manifest, &to).is_some() {
        return Err(format!("Destination already exists: {to}"));
    }
    ensure_no_file_ancestor(manifest, &to)?;
    Ok(kind)
}

fn move_entry_in_manifest(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
    let from = normalize_vault_relative_path(from)?;
    let to = normalize_vault_relative_path(to)?;
    let _ = prepare_relocation(&vault.manifest, &from, &to)?;
    if from == to {
        return Ok(());
    }
    ensure_parent_directories(&mut vault.manifest, &to)?;
    for entry in &mut vault.manifest.entries {
        if entry.path == from || is_descendant_of(&entry.path, &from) {
            entry.path = remap_entry_path(&entry.path, &from, &to);
            entry.modified = now_iso();
        }
    }
    sort_entries(&mut vault.manifest);
    vault.manifest.modified = now_iso();
    Ok(())
}

fn copy_entry_in_manifest(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
    let from = normalize_vault_relative_path(from)?;
    let to = normalize_vault_relative_path(to)?;
    let _ = prepare_relocation(&vault.manifest, &from, &to)?;
    if from == to {
        return Ok(());
    }
    ensure_parent_directories(&mut vault.manifest, &to)?;
    let clones: Vec<ManifestEntryV3> = vault
        .manifest
        .entries
        .iter()
        .filter(|entry| entry.path == from || is_descendant_of(&entry.path, &from))
        .cloned()
        .map(|mut entry| {
            entry.path = remap_entry_path(&entry.path, &from, &to);
            entry.modified = now_iso();
            entry
        })
        .collect();
    if clones.is_empty() {
        return Err(format!("Entry not found: {from}"));
    }
    vault.manifest.entries.extend(clones);
    sort_entries(&mut vault.manifest);
    vault.manifest.modified = now_iso();
    Ok(())
}

fn change_password_in_place(vault: &mut OpenVaultV3, new_password: &str) -> Result<(), String> {
    if vault.header.flags & FLAG_PLAINTEXT_CONTENT != 0 {
        return Err("A plaintext .aerovz archive has no password to change".to_string());
    }
    if new_password.len() < MIN_PASSWORD_LEN {
        return Err("Password must be at least 8 characters".to_string());
    }
    let salt = random_array::<SALT_SIZE>();
    let base_kek = Zeroizing::new(derive_base_kek(new_password, &salt)?);
    let (kek_master, kek_mac) = derive_keks(&base_kek)?;
    let kek_master = Zeroizing::new(kek_master);
    let kek_mac = Zeroizing::new(kek_mac);
    drop(base_kek);
    vault.header.salt = salt;
    vault.header.wrapped_master_key = wrap_key(&kek_master, &vault.master_key)?;
    vault.header.wrapped_mac_key = wrap_key(&kek_mac, &vault.mac_key)?;
    vault.manifest.modified = now_iso();
    Ok(())
}

/// True if `meta` (obtained via `symlink_metadata`, i.e. about the link itself, not
/// its target) describes a reparse point. On Windows this covers BOTH directory
/// junctions (`mklink /J`, no admin needed) and symlinks via the
/// `FILE_ATTRIBUTE_REPARSE_POINT` bit; on Unix it is any symlink.
#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Create the directory chain `root/rel` one component at a time, refusing to
/// FOLLOW any pre-existing reparse point (Windows junction/symlink). This closes
/// the intermediate-directory extract escape (audit M2): a pre-planted
/// `dest/sub -> victim` junction would otherwise let `create_dir_all` + the temp
/// rename write decrypted plaintext into `victim`. The prior AV-001 fix only
/// covered a *leaf* reparse point (replaced by the rename); an intermediate
/// directory component was uncovered.
///
/// `rel` is a relative path whose components have already been validated
/// (`validate_manifest_paths` / `normalize_vault_relative_path`: no `..`, absolute,
/// or drive component). Any non-`Normal` component is still rejected defensively.
fn create_contained_dirs(root: &Path, rel: &Path) -> Result<(), String> {
    use std::path::Component;
    let mut current = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            _ => {
                return Err(format!(
                    "Refusing extraction: unexpected path component in {}",
                    rel.display()
                ))
            }
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if is_reparse_point(&meta) {
                    return Err(format!(
                        "Refusing extraction: {} is a reparse point; it would redirect writes outside {}",
                        current.display(),
                        root.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "Refusing extraction: {} exists and is not a directory",
                        current.display()
                    ));
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::lock::refuse_lock_named_dir(&current)
                    .map_err(|e| format!("Refusing extraction: {e}"))?;
                std::fs::create_dir(&current)
                    .map_err(|e| format!("Create output dir {}: {e}", current.display()))?;
            }
            Err(e) => {
                return Err(format!("Resolve output dir {}: {e}", current.display()));
            }
        }
    }
    Ok(())
}

/// Safely create `output`'s parent directory chain under `root` and confirm the
/// resolved parent is still contained in `root`. Fails closed on any reparse-point
/// escape (audit M2). `output` is always built as `root.join(rel)` by the extract
/// callers, so its parent is lexically under `root`; `root` may be a friendly
/// (non-canonical) path — the containment assertion canonicalizes both sides.
struct ExtractionParent {
    root: PathBuf,
    root_identity: same_file::Handle,
    path: PathBuf,
    identity: same_file::Handle,
    pinned: Vec<std::fs::File>,
}

impl ExtractionParent {
    fn recheck(&self) -> Result<(), String> {
        let unchanged = |path: &Path, identity: &same_file::Handle| {
            path.canonicalize().is_ok_and(|resolved| resolved == path)
                && super::extraction_stage::directory_identity(path)
                    .is_ok_and(|current| current == *identity)
        };
        if !unchanged(&self.root, &self.root_identity) || !unchanged(&self.path, &self.identity) {
            return Err("Refusing extraction: the validated output directory changed".into());
        }
        Ok(())
    }

    fn recheck_stage(&self, stage: &super::extraction_stage::Stage) -> Result<(), String> {
        self.recheck()
            .and_then(|()| {
                stage
                    .verify()
                    .map_err(|e| format!("Refusing extraction: {e}"))
            })
            .inspect_err(|_| {
                let _ = stage.file().set_len(0);
            })
    }

    fn check_publication(&self, _overwrite: bool) -> std::io::Result<()> {
        self.recheck().map_err(std::io::Error::other)?;
        #[cfg(all(test, unix))]
        AFTER_EXTRACTION_PUBLICATION_CHECK.with(|slot| {
            let mut pending = slot.borrow_mut();
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| *expected == _overwrite)
            {
                if let Some((_, hook)) = pending.take() {
                    hook();
                }
            }
        });
        Ok(())
    }
}

fn prepare_output_parent(root: &Path, output: &Path) -> Result<ExtractionParent, String> {
    let parent = output_parent_dir(output);
    let rel = parent.strip_prefix(root).map_err(|_| {
        format!(
            "Refusing extraction: {} is outside destination root {}",
            parent.display(),
            root.display()
        )
    })?;
    // Defense in depth: the fully-resolved parent must still live inside the
    // fully-resolved root (both canonicalize to `\\?\`-verbatim paths on Windows).
    let canon_root = root
        .canonicalize()
        .map_err(|e| format!("Resolve destination {}: {e}", root.display()))?;
    let root_identity =
        super::extraction_stage::directory_identity(&canon_root).map_err(|e| e.to_string())?;
    create_contained_dirs(&canon_root, rel)?;
    let canon_parent = canon_root
        .join(rel)
        .canonicalize()
        .map_err(|e| format!("Resolve output dir {}: {e}", parent.display()))?;
    if !canon_parent.starts_with(&canon_root) {
        return Err(format!(
            "Refusing extraction: resolved {} escapes destination root {}",
            canon_parent.display(),
            canon_root.display()
        ));
    }
    let pinned = super::extraction_stage::pin(&canon_parent).map_err(|e| e.to_string())?;
    let identity = same_file::Handle::from_file(pinned[0].try_clone().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(ExtractionParent {
        root: canon_root,
        root_identity,
        path: canon_parent,
        identity,
        pinned,
    })
}

#[cfg(test)]
type ExtractionHook = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
thread_local! {
    static AFTER_EXTRACTION_PARENT: ExtractionHook = const { std::cell::RefCell::new(None) };
    static AFTER_EXTRACTION_STAGE: ExtractionHook = const { std::cell::RefCell::new(None) };
    static BEFORE_EXTRACTION_PUBLISH: ExtractionHook = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
type PublicationHook = std::cell::RefCell<Option<(bool, Box<dyn FnOnce()>)>>;

#[cfg(all(test, unix))]
thread_local! {
    static AFTER_EXTRACTION_PUBLICATION_CHECK: PublicationHook = const { std::cell::RefCell::new(None) };
}

fn extract_file_entry(
    vault: &OpenVaultV3,
    entry: &ManifestEntryV3,
    output_path: &Path,
    dest_root: &Path,
) -> Result<PathBuf, String> {
    // Create + contain the parent before decoding/writing any plaintext (audit M2).
    let parent = prepare_output_parent(dest_root, output_path)?;
    #[cfg(test)]
    if let Some(hook) = AFTER_EXTRACTION_PARENT.with(|h| h.borrow_mut().take()) {
        hook();
    }
    parent.recheck()?;
    let destination = parent
        .path
        .join(output_path.file_name().ok_or("Missing output basename")?);
    let guard = if crate::lock::refuse_lock_file_name(&destination).is_ok() {
        crate::lock::refuse_destination(&destination, &vault.path).map_err(|e| e.to_string())?;
        let lock = match std::fs::symlink_metadata(&destination) {
            // An absent recovery destination may be in use by a password
            // rotation. Refuse contention instead of publishing once it exits.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::lock::try_acquire(&destination)
            }
            Err(e) => return Err(format!("Inspect extraction destination: {e}")),
            Ok(_) => crate::lock::acquire(&destination),
        };
        Some(lock.map_err(|e| e.to_string())?)
    } else {
        None
    };
    parent.recheck()?;
    if guard
        .as_ref()
        .is_some_and(|lock| lock.source_path().parent() != Some(parent.path.as_path()))
    {
        return Err("Refusing extraction: the locked output directory changed".into());
    }

    // We only ever slice `out[offset..offset+size]`, so decoding never needs to
    // grow `out` past that bound. Tracking it lets us stop early and refuse a
    // manifest that repeats the same chunk id to amplify memory use far beyond
    // the entry's real extent (CLAUDE-AV-005).
    let offset = entry.pack_offset.unwrap_or(0) as usize;
    let size = entry.size as usize;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| "Entry slice range overflow".to_string())?;

    // The largest plaintext a single block may legitimately hold is this vault's
    // recorded chunking `max` (or the default), clamped to the format ceiling.
    let max_block_plaintext = vault
        .manifest
        .wrappers
        .chunking
        .bounds
        .map(|b| b.max as u64)
        .unwrap_or(CDC_MAX as u64)
        .min(MAX_PLAINTEXT_BLOCK_SIZE);

    // Plaintext (`.aerovz`) lane: blocks are stored unencrypted, so the decode
    // skips AES-256-GCM-SIV and treats the on-disk block bytes as the
    // compressed-or-raw payload directly. Computed once for the whole entry.
    let plaintext_lane = manifest_is_plaintext(&vault.manifest);

    // Stream the entry to disk one block at a time: decode each chunk, write the
    // portion that falls inside the requested slice [offset, end) straight to a
    // temp file, and keep only the current decoded block in RAM. Peak memory is
    // one block (bounded by `max_block_plaintext`), not the whole entry. The temp
    // is atomically promoted only after the full slice has been written, so a
    // failure mid-decode leaves no partial output and no plaintext temp artifact.
    let mut tmp = super::extraction_stage::Stage::new(&parent.pinned[0], &parent.path)
        .map_err(|e| format!("Create temp file: {e}"))?;
    parent.recheck_stage(&tmp)?;
    #[cfg(test)]
    if let Some(hook) = AFTER_EXTRACTION_STAGE.with(|h| h.borrow_mut().take()) {
        hook();
    }

    // Cumulative decoded plaintext length so far == the old `out.len()`; used to
    // place each block against the requested slice and to detect a short entry.
    let mut decoded_len = 0usize;
    {
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(tmp.file());
        for chunk_id in &entry.chunks {
            if decoded_len >= end {
                // Everything this entry slices is already written; ignore the
                // rest (a hostile pack may list extra/duplicate chunks).
                break;
            }
            let record = vault
                .manifest
                .chunks
                .get(chunk_id)
                .ok_or_else(|| format!("Missing chunk record: {chunk_id}"))?;
            let len_start = record.data_offset as usize;
            let len_end = len_start
                .checked_add(8)
                .ok_or_else(|| "Chunk length offset overflow".to_string())?;
            if len_end > vault.data.len() {
                return Err("Chunk length is outside data section".to_string());
            }
            let block_len = u64::from_le_bytes(
                vault.data[len_start..len_end]
                    .try_into()
                    .expect("slice length"),
            );
            if block_len != record.block_len || block_len > MAX_BLOCK_SIZE {
                return Err("Chunk length metadata mismatch".to_string());
            }
            // Reject an over-declared plaintext length before decompressing so a
            // single block cannot expand to gigabytes (CLAUDE-AV-005).
            if record.plaintext_len > max_block_plaintext {
                return Err(format!(
                    "Plaintext block too large for chunk {chunk_id}: {} bytes (max {max_block_plaintext})",
                    record.plaintext_len
                ));
            }
            let block_start = len_end;
            let block_end = block_start
                .checked_add(block_len as usize)
                .ok_or_else(|| "Chunk block offset overflow".to_string())?;
            if block_end > vault.data.len() {
                return Err("Chunk block is outside data section".to_string());
            }
            let encrypted = &vault.data[block_start..block_end];
            let actual_hash = blake3::hash(encrypted).to_hex().to_string();
            if actual_hash != record.cipher_hash {
                return Err(format!("Cipher block hash mismatch for chunk {chunk_id}"));
            }
            let aad = block_aad(record.block_index, chunk_id);
            // `Zeroizing` wipes the decrypted bytes on every exit path, including
            // the zstd-init / decode / write-error early returns below (the old
            // manual `.zeroize()` calls missed those error paths).
            let decrypted: Zeroizing<Vec<u8>> = Zeroizing::new(if plaintext_lane {
                encrypted.to_vec()
            } else {
                decrypt_with_aad(&vault.master_key, encrypted, &aad)?
            });
            // A raw-stored (incompressible, #10-B) block is the plaintext itself;
            // a normal block is zstd and is decoded with a `plaintext_len + 1`
            // ceiling so a zstd bomb cannot materialise more than one chunk before
            // the length mismatch below trips.
            let plaintext: Zeroizing<Vec<u8>> = if record.stored_raw {
                decrypted
            } else {
                let mut decoder = zstd::stream::read::Decoder::new(&decrypted[..])
                    .map_err(|e| format!("zstd decompress init failed: {e}"))?;
                let mut decoded = Zeroizing::new(Vec::new());
                crate::secret::read_to_end(
                    &mut decoder.by_ref().take(record.plaintext_len + 1),
                    &mut decoded,
                )
                .map_err(|e| format!("zstd decompress failed: {e}"))?;
                decoded
            };
            if plaintext.len() as u64 != record.plaintext_len {
                return Err(format!("Plaintext length mismatch for chunk {chunk_id}"));
            }
            // Write only the slice of this block that intersects [offset, end);
            // the windowed equivalent of the old `out[offset..end]`.
            let block_pos = decoded_len;
            let next_pos = block_pos + plaintext.len();
            let w_start = offset.max(block_pos);
            let w_end = end.min(next_pos);
            if w_start < w_end {
                writer
                    .write_all(&plaintext[w_start - block_pos..w_end - block_pos])
                    .map_err(|e| format!("Write extracted file: {e}"))?;
            }
            decoded_len = next_pos;
        }
        writer
            .flush()
            .map_err(|e| format!("Flush extracted file: {e}"))?;
    }
    // The decoded stream must reach the end of the requested slice (matches the
    // old `end > out.len()` guard).
    if decoded_len < end {
        return Err(format!(
            "Entry slice [{offset}..{end}] exceeds decoded data ({decoded_len})"
        ));
    }
    tmp.file()
        .sync_all()
        .map_err(|e| format!("Sync temp file: {e}"))?;
    #[cfg(test)]
    if let Some(hook) = BEFORE_EXTRACTION_PUBLISH.with(|h| h.borrow_mut().take()) {
        hook();
    }
    parent.recheck_stage(&tmp)?;
    // An entry named like a lock file is extracted only where no file is:
    // replacing an existing one could replace a vault's lock file. A lock file
    // is empty, so an empty entry over an empty file (extracting the same
    // folder again) has nothing to write and keeps the file that is there.
    if let Some(guard) = guard {
        match tmp.publish(guard.source_path(), false, || {
            parent.check_publication(false)
        }) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                guard_extraction_replacement(guard.source_path())?;
                parent.recheck_stage(&tmp)?;
                tmp.publish(guard.source_path(), true, || parent.check_publication(true))
                    .map_err(|e| format!("Persist extracted file: {e}"))?;
            }
            Err(e) => return Err(format!("Persist extracted file: {e}")),
        }
    } else if let Err(e) = tmp.publish(&destination, false, || parent.check_publication(false)) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!("Persist vault: {e}"));
        }
        let both_empty = tmp.file().metadata().is_ok_and(|m| m.len() == 0)
            && std::fs::symlink_metadata(&destination).is_ok_and(|m| m.is_file() && m.len() == 0);
        if !both_empty {
            return Err(format!(
                "{}: a file is there and its name is a vault lock file name, \
                     so it is not written over ({})",
                output_path.display(),
                e
            ));
        }
    }
    fsync_parent_dir(&parent.path);
    Ok(output_path.to_path_buf())
}

fn guard_extraction_replacement(path: &Path) -> Result<(), String> {
    let file = crate::source::open_regular_no_follow(path).map_err(|e| {
        format!(
            "Cannot inspect extraction destination {}: {e}",
            path.display()
        )
    })?;
    let mut magic = Vec::with_capacity(MAGIC.len());
    file.take(MAGIC.len() as u64)
        .read_to_end(&mut magic)
        .map_err(|e| format!("Cannot read extraction destination {}: {e}", path.display()))?;
    if magic == MAGIC || magic == crate::constants::MAGIC {
        return Err("Refusing extraction over an existing vault".into());
    }
    if magic.starts_with(crate::error_correction::AEROCORRECT_MAGIC) {
        return Err("Refusing extraction over an existing recovery sidecar".into());
    }
    let sidecar = super::ec::recovery_sidecar_path(path);
    if crate::lock::destination_can_exist(&sidecar).map_err(|e| e.to_string())?
        && super::ec::validate_standalone_sidecar_destination(&sidecar).is_err()
    {
        return Err(format!(
            "Refusing extraction over a possible vault with recovery material at {}",
            sidecar.display()
        ));
    }
    Ok(())
}

/// Resolve the directory an output/temp file lives in, mapping a parent-less or
/// empty parent to the current directory. Shared by `atomic_write` and the
/// streaming `extract_file_entry` so both place their temp beside the target.
pub(crate) fn output_parent_dir(target: &Path) -> &Path {
    target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Best-effort fsync of a directory so a freshly persisted rename is durable on
/// crash (Unix). A no-op on other platforms. Single definition so the durability
/// discipline cannot drift between the write paths that rely on it.
pub(super) fn fsync_parent_dir(parent: &Path) {
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
}

pub(crate) fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = output_parent_dir(target);
    std::fs::create_dir_all(parent).map_err(|e| format!("Create parent dir: {e}"))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".aerovault-v3-")
        .tempfile_in(parent)
        .map_err(|e| format!("Create temp file: {e}"))?;
    use std::io::Write;
    tmp.write_all(bytes)
        .map_err(|e| format!("Write temp file: {e}"))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| format!("Sync temp file: {e}"))?;
    persist_over(tmp, target).map_err(|e| format!("Persist vault: {e}"))?;
    fsync_parent_dir(parent);
    Ok(())
}

/// Rename a finished temp file over `dest`. `NamedTempFile::persist` uses
/// `MoveFileExW` alone on Windows, which fails while another process (a
/// reader) has `dest` open; `std::fs::rename` then retries with a
/// POSIX-semantics rename. On error the temp file is removed.
pub(crate) fn persist_over(tmp: tempfile::NamedTempFile, dest: &Path) -> std::io::Result<()> {
    crate::lock::refuse_lock_file_name(dest)?;
    // `keep` clears the Windows temporary attribute and the delete-on-drop.
    let (file, kept) = tmp.keep().map_err(|e| e.error)?;
    drop(file);
    std::fs::rename(&kept, dest).inspect_err(|_| {
        let _ = std::fs::remove_file(&kept);
    })
}

pub(super) fn read_capped(
    file: &mut std::fs::File,
    offset: u64,
    len: u64,
    cap: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    if len > cap {
        return Err(format!("{label} too large: {len} bytes"));
    }
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| format!("Seek {label}: {e}"))?;
    let size = usize::try_from(len).map_err(|_| format!("{label} exceeds address space"))?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(size)
        .map_err(|e| format!("Cannot allocate {label}: {e}"))?;
    buf.resize(size, 0);
    file.read_exact(&mut buf)
        .map_err(|e| format!("Read {label}: {e}"))?;
    Ok(buf)
}

/// Reject a manifest whose wrapper algorithms differ from the ones this build
/// hardcodes. Fields are authenticated; asserting them turns a future
/// version-confusion bug into a clean fail-closed error.
fn check_wrapper(slot: &str, spec: &AlgorithmSpec, id: &str, ver: u32) -> Result<(), String> {
    if spec.algorithm_id != id || spec.algorithm_version != ver {
        return Err(format!(
            "Unsupported AeroVault v3 {slot} algorithm: {} v{} (expected {id} v{ver})",
            spec.algorithm_id, spec.algorithm_version
        ));
    }
    Ok(())
}

fn validate_supported_wrappers(w: &WrapperManifest) -> Result<(), String> {
    check_wrapper("packing", &w.packing, "small-file-batching", 1)?;
    check_wrapper("chunking", &w.chunking, "gear-cdc", 1)?;
    check_wrapper("chunk_id", &w.chunk_id, "blake3-keyed-128", 1)?;
    check_wrapper("compression", &w.compression, "zstd", 1)?;
    // crypt: the encrypted lane records `aes-256-gcm-siv`, the plaintext
    // (`.aerovz`) lane records `none`. Both are version 1.
    match w.crypt.algorithm_id.as_str() {
        CRYPT_ALGORITHM_ENCRYPTED | CRYPT_ALGORITHM_NONE => {
            if w.crypt.algorithm_version != 1 {
                return Err(format!(
                    "Unsupported crypt wrapper version: {}",
                    w.crypt.algorithm_version
                ));
            }
        }
        other => return Err(format!("Unsupported crypt wrapper: {other}")),
    }
    check_wrapper("cipher_hash", &w.cipher_hash, "blake3-256", 1)?;
    Ok(())
}

/// A parsed, MAC-verified header with its unwrapped MAC and master keys.
pub(super) type UnlockedHeader = (
    VaultHeaderV3,
    Zeroizing<[u8; KEY_SIZE]>,
    Zeroizing<[u8; KEY_SIZE]>,
);

pub(super) fn open_header_bytes(
    header_bytes: &[u8],
    password: &str,
) -> Result<UnlockedHeader, String> {
    let header = VaultHeaderV3::from_bytes(header_bytes)?;
    // Every key here is wiped on every exit path, the `?` early returns
    // included; the unwrapped keys stay wrapped until they move into the handle.
    let base_kek = Zeroizing::new(derive_base_kek(password, &header.salt)?);
    let (kek_master, kek_mac) = derive_keks(&base_kek)?;
    let kek_master = Zeroizing::new(kek_master);
    let kek_mac = Zeroizing::new(kek_mac);
    drop(base_kek);
    let mac_key = Zeroizing::new(unwrap_key(&kek_mac, &header.wrapped_mac_key)?);
    header.verify_mac(&mac_key)?;
    if header.wrapper_header_version != SUPPORTED_WRAPPER_HEADER_VERSION {
        return Err(format!(
            "Unsupported AeroVault v3 wrapper-header version: {} (expected {})",
            header.wrapper_header_version, SUPPORTED_WRAPPER_HEADER_VERSION
        ));
    }
    let master_key = Zeroizing::new(unwrap_key(&kek_master, &header.wrapped_master_key)?);
    Ok((header, mac_key, master_key))
}

fn create_empty_vault(
    path: &Path,
    password: &str,
    level: i32,
    cdc_bounds: Option<CdcBounds>,
    lane: VaultLane,
    error_correction: Option<super::ec::RecoveryPlacement>,
    error_correction_pct: u32,
) -> Result<(), String> {
    // The plaintext (`.aerovz`) lane has no password: zero salt + zero wrapped
    // keys in the header, a public deterministic chunk-id key (all-zero master),
    // and the header HMAC keyed by the fixed PUBLIC integrity key. The encrypted
    // lane derives everything from the password exactly as before.
    let plaintext = lane == VaultLane::Plaintext;

    // The options are checked before anything touches the disk.
    if !plaintext && password.len() < MIN_PASSWORD_LEN {
        return Err("Password must be at least 8 characters".to_string());
    }
    if let Some(bounds) = &cdc_bounds {
        bounds.validate()?;
    }

    // Then the lock, as for every write, so a create refused by it derives no
    // key. The lock file lives next to the vault: create the folder first, as
    // `atomic_write` would, unless the vault path names a lock file.
    crate::lock::refuse_lock_file_name(path).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(output_parent_dir(path))
        .map_err(|e| format!("Create parent dir: {e}"))?;
    let _lock = write_lock(path)?;
    let path = _lock.source_path();

    // Keys are zeroized on every return, the early ones included.
    let (salt, wrapped_master_key, wrapped_mac_key, master_key, mac_key, flags) = if plaintext {
        (
            [0u8; SALT_SIZE],
            [0u8; WRAPPED_KEY_SIZE],
            [0u8; WRAPPED_KEY_SIZE],
            Zeroizing::new([0u8; KEY_SIZE]),
            Zeroizing::new(aerovz_mac_key()?),
            FLAG_PLAINTEXT_CONTENT,
        )
    } else {
        let salt = random_array::<SALT_SIZE>();
        let base_kek = Zeroizing::new(derive_base_kek(password, &salt)?);
        let (kek_master, kek_mac) = derive_keks(&base_kek)?;
        let kek_master = Zeroizing::new(kek_master);
        let kek_mac = Zeroizing::new(kek_mac);
        drop(base_kek);
        let master_key = Zeroizing::new(random_array::<KEY_SIZE>());
        let mac_key = Zeroizing::new(random_array::<KEY_SIZE>());
        let wrapped_master_key = wrap_key(&kek_master, &master_key)?;
        let wrapped_mac_key = wrap_key(&kek_mac, &mac_key)?;
        (
            salt,
            wrapped_master_key,
            wrapped_mac_key,
            master_key,
            mac_key,
            0u8,
        )
    };

    let header = VaultHeaderV3 {
        flags,
        salt,
        wrapped_master_key,
        wrapped_mac_key,
        data_offset: DATA_OFFSET,
        data_len: 0,
        manifest_offset: DATA_OFFSET,
        manifest_len: 0,
        extension_dir_offset: DATA_OFFSET,
        extension_dir_len: 0,
        extension_payload_offset: DATA_OFFSET,
        extension_payload_len: 0,
        wrapper_header_version: 1,
        header_mac: [0u8; MAC_SIZE],
    };

    let mut manifest = if plaintext {
        empty_manifest_plaintext(level)
    } else {
        empty_manifest(level)
    };
    if let Some(bounds) = cdc_bounds {
        manifest.wrappers.chunking.bounds = Some(bounds);
    }
    // Record the QR-style overhead level so every later seal / export uses the
    // same grid (#276). Only meaningful when Error Correction is enabled.
    if error_correction.is_some() {
        manifest.error_correction_pct = Some(error_correction_pct.clamp(
            crate::error_correction::ERROR_CORRECTION_MIN_PCT,
            crate::error_correction::ERROR_CORRECTION_MAX_PCT,
        ));
    }
    // Embed the extension only when the placement keeps an in-container copy.
    let embed = error_correction.is_some_and(|p| p.embeds());
    let mut extensions = if embed {
        vec![super::ec::error_correction_stub_extension()]
    } else {
        vec![]
    };
    let ext_payloads = if embed {
        let (p, _shards, _prot, _ov) =
            crate::error_correction::compute_error_correction_shards(&[]);
        if let Some(e) = extensions.first_mut() {
            e.offset = 0;
            e.length = p.len() as u64;
        }
        p
    } else {
        vec![]
    };
    let bytes = build_file_bytes(
        header,
        &mac_key,
        &master_key,
        &manifest,
        &extensions,
        &ext_payloads,
        &[],
    )?;
    drop((master_key, mac_key));
    // Refuse sidecar contention before replacing even the container itself.
    let sidecar_lock = if error_correction.is_some_and(|p| p.writes_sidecar()) {
        let out = super::ec::default_sidecar_path(path);
        let guard =
            crate::lock::acquire_destination(&out, path, &_lock).map_err(|e| e.to_string())?;
        super::ec::validate_automatic_sidecar_destination(&out)?;
        guard
    } else {
        None
    };
    if error_correction.is_some_and(|p| p.writes_sidecar()) {
        let sidecar = super::ec::default_sidecar_path(path);
        let prepared =
            super::strip_transaction::private_dir(output_parent_dir(path), ".aerocreate-prepare-")?;
        if path.exists() {
            super::strip_transaction::copy_file(path, &prepared.path().join("old-vault"))?;
        }
        if sidecar.exists() {
            super::strip_transaction::copy_file(&sidecar, &prepared.path().join("old-sidecar"))?;
        }
        atomic_write(&prepared.path().join("new-vault"), &bytes)?;
        let seed = super::ec::empty_sidecar_bytes(&bytes);
        atomic_write(&prepared.path().join("new-sidecar"), &seed)?;
        super::strip_transaction::publish(path, prepared, &_lock)?;
    } else {
        atomic_write(path, &bytes)?;
    }
    drop(sidecar_lock);
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once right after a save renames its file into place,
    /// so a test can let another writer change the vault in that window.
    static AFTER_PERSIST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static BEFORE_IMPORT_IDENTITY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_OPEN_RECOVERY_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once in an open, after the header is checked and right
    /// before the file is hashed.
    static BEFORE_OPEN_GENERATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once at the end of an open, after everything is decoded.
    static AFTER_OPEN_DECODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once in `export_parity` right before the sidecar is
    /// published, so a test can let another writer save in that window.
    pub(super) static BEFORE_SIDECAR_PUBLISH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn run_before_sidecar_publish_hook() {
    if let Some(hook) = BEFORE_SIDECAR_PUBLISH.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once after the generation check, right before the
    /// rename, the window a second writer would have to race into.
    static IN_SAVE_WINDOW: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static FAIL_SAVED_HEADER_PARSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn run_in_save_window_hook() {
    if let Some(hook) = IN_SAVE_WINDOW.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

#[cfg(test)]
fn run_after_persist_hook() {
    if let Some(hook) = AFTER_PERSIST.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// A plaintext-lane header: the flag is set and the header verifies under the
/// public key. A flag bit rotted on an encrypted vault fails the MAC check.
fn plaintext_lane_header(header_bytes: &[u8]) -> bool {
    VaultHeaderV3::from_bytes(header_bytes)
        .ok()
        .filter(|h| h.flags & FLAG_PLAINTEXT_CONTENT != 0)
        .is_some_and(|h| aerovz_mac_key().is_ok_and(|k| h.verify_mac(&k).is_ok()))
}

pub(super) fn open_vault_under_guard(
    path: impl Into<PathBuf>,
    password: &str,
    lock: &WriteLock,
    limits: VaultV3Limits,
) -> Result<OpenVaultV3, String> {
    let path = path.into();
    let guard = lock.covers_namespace(&path).then_some(lock);
    open_vault_with_guard(path, password, false, guard, limits)
}

fn retry_open_for_recovery(
    path: &Path,
    password: &str,
    encrypted_only: bool,
    limits: VaultV3Limits,
) -> Result<OpenVaultV3, String> {
    // Healthy reads stay lock-free. Before using detached recovery, reopen the
    // source under the same guard that excludes paired rotation and stripping.
    // This also recovers a journal published after the first optimistic check.
    let real = std::fs::canonicalize(path).map_err(|e| format!("Resolve recovery source: {e}"))?;
    let guard = crate::lock::acquire_for_export(&real).map_err(|e| e.to_string())?;
    open_vault_with_guard(
        path.to_path_buf(),
        password,
        encrypted_only,
        Some(&guard),
        limits,
    )
}

pub(super) fn recovery_namespace(path: &Path) -> Result<PathBuf, String> {
    let path = crate::lock::anchored(path).map_err(|e| format!("Resolve vault parent: {e}"))?;
    // A regular Windows leaf can be an 8.3 alias. Retain the long namespace
    // spelling for recovery reads and later default-sidecar writes. A symbolic
    // leaf remains symbolic so a later replacing write still refuses it.
    #[cfg(windows)]
    let path = if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
        std::fs::canonicalize(&path).map_err(|e| format!("Resolve vault leaf: {e}"))?
    } else {
        path
    };
    Ok(path)
}

fn open_vault_with_guard(
    path: impl Into<PathBuf>,
    password: &str,
    encrypted_only: bool,
    recovery_guard: Option<&WriteLock>,
    limits: VaultV3Limits,
) -> Result<OpenVaultV3, String> {
    let path = recovery_namespace(&path.into())?;
    if let Some(guard) = recovery_guard {
        super::strip_transaction::recover_under_guard(guard)?;
    } else {
        super::strip_transaction::recover_if_pending(&path)?;
    }
    #[cfg(test)]
    if let Some(hook) = AFTER_OPEN_RECOVERY_CHECK.with(|h| h.borrow_mut().take()) {
        hook();
    }
    // Once recovery takes a guard, read its pinned physical source, retaining
    // the supplied leaf namespace only for sidecar selection and the handle.
    let source = recovery_guard.map_or(path.as_path(), WriteLock::source_path);
    let mut file = crate::source::open_regular(source).map_err(|e| format!("Open vault: {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("Vault metadata: {e}"))?
        .len();
    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("Read header: {e}"))?;

    // Plaintext (`.aerovz`) lane: when the header parses and carries
    // FLAG_PLAINTEXT_CONTENT, there is no password — verify the header MAC under
    // the fixed PUBLIC integrity key and use an all-zero (public) master key for
    // the deterministic chunk-id derivation. The manifest is read as plaintext
    // below. EC header recovery stays on the encrypted path (the plaintext
    // header is still EC-protected by region; recovery for it is a follow-up).
    //
    // The flag byte is read before any MAC, so with a password (an encrypted
    // unlock) the flag alone is not enough: the header must also verify under
    // the public key. A flag bit rotted on an encrypted vault then fails that
    // check and goes down the encrypted path, where the real MAC fails and the
    // sidecar header recovery runs. With no password (open_plaintext) a header
    // that carries the flag stays on this lane and reports its own MAC error.
    let plaintext_header = if !encrypted_only && password.is_empty() {
        VaultHeaderV3::from_bytes(&header_bytes)
            .is_ok_and(|h| h.flags & FLAG_PLAINTEXT_CONTENT != 0)
    } else {
        plaintext_lane_header(&header_bytes)
    };
    if encrypted_only && plaintext_header {
        return Err(PLAINTEXT_NOT_A_VAULT.to_string());
    }

    // HEADER parity (rev. 4): the on-disk header is the happy path. If it fails
    // to parse or its MAC does not verify (bit-rot / bad sector), fall back to
    // rebuilding it from the detached sidecar's header parity. A missing sidecar
    // / no header parity / a rebuild that still does not unlock keeps the
    // original error. The MAC verify inside `open_header_bytes` is the proof.
    let (header, mac_key, master_key, header_repaired_on_open) = if plaintext_header {
        let header = VaultHeaderV3::from_bytes(&header_bytes)?;
        let mac_key = Zeroizing::new(aerovz_mac_key()?);
        header.verify_mac(&mac_key)?;
        if header.wrapper_header_version != SUPPORTED_WRAPPER_HEADER_VERSION {
            return Err(format!(
                "Unsupported AeroVault v3 wrapper-header version: {} (expected {})",
                header.wrapper_header_version, SUPPORTED_WRAPPER_HEADER_VERSION
            ));
        }
        (header, mac_key, Zeroizing::new([0u8; KEY_SIZE]), false)
    } else {
        match open_header_bytes(&header_bytes, password) {
            Ok((h, mac, master)) => (h, mac, master, false),
            Err(orig) => {
                if recovery_guard.is_none() {
                    let physical = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
                    if !super::ec::header_recovery_candidate(&path)
                        && !super::strip_transaction::journal_path(&physical).exists()
                    {
                        return Err(orig);
                    }
                    drop(file);
                    return retry_open_for_recovery(&path, password, encrypted_only, limits);
                }
                match super::ec::recover_header_from_sidecar(&path, &header_bytes, password)? {
                    Some((h, mac, master)) => (h, mac, master, true),
                    None => return Err(orig),
                }
            }
        }
    };

    // Reject impossible ranges before reading any payload for the baseline.
    validate_ranges(&header, file_len)?;

    limits.check_data_len(header.data_len)?;
    let data_size =
        usize::try_from(header.data_len).map_err(|_| "Data section exceeds address space")?;
    if data_size > isize::MAX as usize {
        return Err("Data section exceeds address space".into());
    }

    // The generation is taken once the header is checked, so a wrong password
    // or a file that is not a vault costs no extra read, and before the
    // payload is decoded. A writer that rewrites the file in place while it is
    // decoded (one that does not take the lock) then leaves a baseline older
    // than the file, and the next save is refused; taken after the decoding,
    // the baseline could be that writer's file, which the save would then
    // overwrite with this state. The hashed file must still start with the
    // header checked above and have the length measured above.
    #[cfg(test)]
    if let Some(hook) = BEFORE_OPEN_GENERATION.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let opened_hash = file_generation_starting_with(&mut file, &header_bytes, file_len)?;
    let encrypted_manifest = read_capped(
        &mut file,
        header.manifest_offset,
        header.manifest_len,
        MAX_MANIFEST_SIZE,
        "manifest",
    )?;

    // Read, parse and VALIDATE the extension directory up front (audit M4) so a forged
    // directory is rejected at open BEFORE the manifest-recovery block below can consume
    // it (`reconstruct_encrypted_manifest` reads its own copy of the directory region to
    // locate the EC parity extension). `read_capped` seeks per call, so this read does
    // not perturb the later reads. Reject critical / duplicate / out-of-range entries.
    let extension_json = read_capped(
        &mut file,
        header.extension_dir_offset,
        header.extension_dir_len,
        MAX_EXTENSION_DIR_SIZE,
        "extension directory",
    )?;
    let extensions: Vec<ExtensionEntryV3> = serde_json::from_slice(&extension_json)
        .map_err(|e| format!("Extension directory parse: {e}"))?;
    validate_extension_dir(&extensions, header.extension_payload_len)?;

    // GAP-4 (rev. 4): the manifest region may be corrupted (bit-rot, bad
    // sector). Rebuild the encrypted manifest from parity and retry. Try the
    // embedded metadata extension first (auto-fresh on the embedded path), then
    // the detached sidecar's manifest parity (the only copy a pure-detached
    // vault keeps). A successful AEAD decrypt on the rebuilt bytes is the
    // correctness proof; otherwise keep the original error.
    // Decode the stored manifest blob: AEAD-decrypt on the encrypted lane, parse
    // plaintext JSON on the `.aerovz` lane. Either way, on a parse/decrypt
    // failure rebuild the blob from Error-Correction parity (embedded metadata
    // extension first, then the detached sidecar) and retry — the manifest is
    // EC-protected by region regardless of whether it is encrypted.
    let decode_manifest = |blob: &[u8]| -> Result<VaultManifestV3, String> {
        if plaintext_header {
            parse_manifest_plaintext(blob)
        } else {
            decrypt_manifest(&master_key, blob)
        }
    };
    let (manifest, manifest_repaired_on_open) = match decode_manifest(&encrypted_manifest) {
        Ok(m) => (m, false),
        Err(orig) => {
            let embedded_metadata = extensions.iter().any(|e| {
                e.extension_id == super::constants::ERROR_CORRECTION_META_EXTENSION_ID
                    && e.length > 0
            });
            let detached_metadata = super::ec::recovery_sidecar_path(&path).exists();
            // Journals belong to the physical source even when recovery data
            // selection deliberately retains a symbolic alias namespace.
            let journal_source = std::fs::canonicalize(source)
                .map_err(|e| format!("Resolve recovery journal source: {e}"))?;
            let pending_pair = super::strip_transaction::journal_path(&journal_source).exists();
            if recovery_guard.is_none() && !embedded_metadata && !detached_metadata && !pending_pair
            {
                return Err(orig);
            }
            if recovery_guard.is_none() {
                // Release this attempt's metadata before acquiring/reopening.
                drop(encrypted_manifest);
                drop(extension_json);
                drop(extensions);
                drop(file);
                return retry_open_for_recovery(&path, password, encrypted_only, limits);
            }
            let embedded = super::ec::reconstruct_encrypted_manifest(&mut file, &header, file_len)?;
            let rebuilt = match embedded {
                Some(r) if r != encrypted_manifest => Some(r),
                _ => super::ec::reconstruct_manifest_from_sidecar(&path, &encrypted_manifest)?,
            };
            match rebuilt {
                Some(r) if r != encrypted_manifest => (decode_manifest(&r)?, true),
                _ => return Err(orig),
            }
        }
    };
    if manifest.format != VERSION {
        return Err(format!(
            "Unsupported AeroVault manifest version: {}",
            manifest.format
        ));
    }
    validate_supported_wrappers(&manifest.wrappers)?;
    // The header flag and the manifest `crypt` wrapper are two views of the same
    // lane; reject a container whose header claims one lane and manifest the
    // other (a forged/corrupt mismatch would otherwise decode under the wrong
    // key path).
    if plaintext_header != manifest_is_plaintext(&manifest) {
        return Err("AeroVault v3 header/manifest encryption-lane mismatch".to_string());
    }
    validate_manifest_paths(&manifest)?;
    validate_chunk_identities(&manifest)?;
    #[cfg(test)]
    crate::lock::trace("decode");

    // Validate the protected metadata before allocating the data section.
    // If the read fails, wipe any plaintext already read from a plaintext vault.
    let mut data = Zeroizing::new(Vec::new());
    data.try_reserve_exact(data_size)
        .map_err(|e| format!("Cannot allocate vault data section: {e}"))?;
    data.resize(data_size, 0);
    file.seek(std::io::SeekFrom::Start(header.data_offset))
        .map_err(|e| format!("Seek data section: {e}"))?;
    file.read_exact(&mut data)
        .map_err(|e| format!("Read data section: {e}"))?;

    // Do not round-trip the EC metadata-parity extension; build_file_bytes is
    // its sole author and recomputes it on every seal from the freshly
    // encrypted manifest. (No-op when no EC extension is present.)
    let extensions: Vec<ExtensionEntryV3> = extensions
        .into_iter()
        .filter(|e| e.extension_id != super::constants::ERROR_CORRECTION_META_EXTENSION_ID)
        .collect();

    #[cfg(test)]
    if let Some(hook) = AFTER_OPEN_DECODE.with(|h| h.borrow_mut().take()) {
        hook();
    }
    Ok(OpenVaultV3 {
        path,
        opened_file_len: file_len,
        opened_hash,
        limits,
        header,
        // Copied into the handle, whose Drop wipes them; the wrapped copies
        // are wiped here.
        master_key: *master_key,
        mac_key: *mac_key,
        manifest,
        extensions,
        data: std::mem::take(&mut *data),
        manifest_repaired_on_open,
        header_repaired_on_open,
        telemetry: None,
    })
}

fn validate_ranges(header: &VaultHeaderV3, file_len: u64) -> Result<(), String> {
    if header.data_offset != DATA_OFFSET {
        return Err("Invalid AeroVault v3 data offset".to_string());
    }
    if header.manifest_len > MAX_MANIFEST_SIZE {
        return Err("manifest exceeds size limit".to_string());
    }
    if header.extension_dir_len > MAX_EXTENSION_DIR_SIZE {
        return Err("extension directory exceeds size limit".to_string());
    }
    let ranges = [
        (header.data_offset, header.data_len, "data"),
        (header.manifest_offset, header.manifest_len, "manifest"),
        (
            header.extension_dir_offset,
            header.extension_dir_len,
            "extension directory",
        ),
        (
            header.extension_payload_offset,
            header.extension_payload_len,
            "extension payload",
        ),
    ];
    for (offset, len, label) in ranges {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| format!("{label} range overflows"))?;
        if end > file_len {
            return Err(format!("{label} range exceeds file size"));
        }
    }
    Ok(())
}

/// Staleness guard: refuse to seal if the on-disk vault changed since open
/// (concurrent writer), comparing the recorded whole-file length and BLAKE3 hash.
pub(super) fn assert_vault_generation_current(vault: &OpenVaultV3) -> Result<(), String> {
    assert_vault_generation_at(vault, &vault.path)
}

pub(super) fn assert_vault_generation_at(vault: &OpenVaultV3, path: &Path) -> Result<(), String> {
    let mut file = crate::source::open_regular(path).map_err(|e| format!("Open vault: {e}"))?;
    if file_generation(&mut file, vault.opened_file_len)? != vault.opened_hash {
        return Err("Vault changed while this write was in progress; retry operation".to_string());
    }
    Ok(())
}

/// A writer that passes bytes through and keeps their count and BLAKE3 hash,
/// so a save gets the generation of what it wrote without reading it back.
struct HashingWriter<'a> {
    inner: &'a mut std::fs::File,
    hasher: blake3::Hasher,
    len: u64,
}

impl<'a> HashingWriter<'a> {
    fn new(inner: &'a mut std::fs::File) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            len: 0,
        }
    }

    /// Length and hash of everything written, as [`file_generation`] would
    /// read them back from the start of a fresh file.
    fn finish(self) -> (u64, [u8; 32]) {
        (self.len, *self.hasher.finalize().as_bytes())
    }
}

impl std::io::Write for HashingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = std::io::Write::write(self.inner, buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.inner)
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: how many whole-file reads [`file_generation`] made on this thread.
    pub(super) static GENERATION_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Hash the original extent and reject a replacement of a different size
/// before scanning its bytes.
fn file_generation(file: &mut std::fs::File, expected_len: u64) -> Result<[u8; 32], String> {
    let len = file
        .metadata()
        .map_err(|e| format!("Stat vault: {e}"))?
        .len();
    if len != expected_len {
        return Err("Vault changed while this write was in progress; retry operation".into());
    }
    file_generation_starting_with(file, &[], len)
}

/// Hash exactly the observed file length, checking the header prefix and EOF.
/// Hashing streams in a fixed-size buffer regardless of container size.
fn file_generation_starting_with(
    file: &mut std::fs::File,
    prefix: &[u8],
    len: u64,
) -> Result<[u8; 32], String> {
    #[cfg(test)]
    GENERATION_READS.with(|n| n.set(n.get() + 1));
    #[cfg(test)]
    crate::lock::trace("generation");
    let changed = || "vault changed while it was being read; open it again".to_string();
    let expected = len.checked_sub(prefix.len() as u64).ok_or_else(changed)?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| format!("Read vault: {e}"))?;
    let mut head = vec![0u8; prefix.len()];
    file.read_exact(&mut head)
        .map_err(|e| format!("Read vault: {e}"))?;
    if head != prefix {
        return Err(changed());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&head);
    let rest = std::io::copy(&mut Read::by_ref(file).take(expected), &mut hasher)
        .map_err(|e| format!("Read vault: {e}"))?;
    if rest != expected
        || std::io::copy(&mut file.take(1), &mut std::io::sink())
            .map_err(|e| format!("Read vault: {e}"))?
            != 0
    {
        return Err(changed());
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Persist the in-memory vault back to disk with an atomic single-rename seal.
///
/// Concurrency contract (audit M6): the save holds the vault's cross-process write
/// lock (`<vault>.aerolock`, see [`crate::lock`]) from the generation check to the
/// rename, so two writers cannot both pass the check and overwrite each other.
/// The generation check ([`assert_vault_generation_current`]: the file is byte
/// for byte the one this handle read or last wrote) refuses a handle that
/// another writer has made stale, including a writer that does not take the
/// lock when its change landed before the check.
pub(super) fn save_open_vault(vault: &mut OpenVaultV3) -> Result<(), String> {
    let lock = write_lock(&vault.path)?;
    save_locked(vault, &lock)
}

/// Take the vault's cross-process write lock (see [`crate::lock`]).
pub(super) fn write_lock(path: &Path) -> Result<WriteLock, String> {
    crate::lock::acquire(path).map_err(|e| e.to_string())
}

/// [`save_open_vault`] for a caller that already holds the write lock, from
/// the generation check to the rename, so no other writer can save between.
pub(super) fn save_locked(vault: &mut OpenVaultV3, lock: &WriteLock) -> Result<(), String> {
    let target = vault.path.clone();
    save_locked_to(vault, lock, &target)
}

/// Seal to a private staging path without replacing the source. Used only by
/// the two-file strip transaction; all generation checks still concern source.
pub(super) fn save_locked_to(
    vault: &mut OpenVaultV3,
    lock: &WriteLock,
    target: &Path,
) -> Result<(), String> {
    vault.limits.check_data_len(vault.data.len() as u64)?;
    if !lock.covers_namespace(&vault.path) {
        return Err("source lock namespace changed; retry operation".to_string());
    }
    validate_chunk_identities(&vault.manifest)?;
    assert_vault_generation_current(vault)?;
    // Writers refuse damaged blocks before mutating (`write_op`); repair saves
    // only a fully verified reconstruction.

    let mut extensions = vault.extensions.clone();
    let mut ext_payloads = vec![];
    let mut ec_stats: Option<(u64, u64, f64)> = None;

    // rev. 4: if the Error-Correction extension is present, recompute the shards
    // over the current data section and update the entry + payload. Recompute on
    // every seal (cost is acceptable for the EC use case; most vaults won't have
    // it enabled).
    if let Some(error_correction_idx) = extensions
        .iter()
        .position(|e| e.extension_id == super::constants::ERROR_CORRECTION_EXTENSION_ID)
    {
        // On-disk blocks in data-section order (sorted by data_offset). Each
        // full block is [u64 len][ciphertext of that len]. Offset arithmetic is
        // checked so a manifest record near usize::MAX yields an empty slice
        // instead of panicking (matches collect_live_block_refs / scrub_vault).
        let mut chunk_records: Vec<_> = vault.manifest.chunks.values().cloned().collect();
        chunk_records.sort_by_key(|r| r.data_offset);

        let blocks: Vec<&[u8]> = chunk_records
            .iter()
            .map(|rec| {
                let start = rec.data_offset as usize;
                let end = (rec.block_len as usize)
                    .checked_add(8)
                    .and_then(|full| start.checked_add(full));
                match end {
                    Some(end) if end <= vault.data.len() => &vault.data[start..end],
                    _ => &[] as &[u8],
                }
            })
            .collect();

        let (k, p) = crate::error_correction::manifest_error_correction_grid(
            vault.manifest.error_correction_pct,
        );
        let (payload, shards, protected, overhead) =
            crate::error_correction::compute_error_correction_shards_grid(&blocks, k, p);

        let entry = &mut extensions[error_correction_idx];
        entry.offset = 0;
        entry.length = payload.len() as u64;

        ext_payloads = payload;
        if shards > 0 || protected > 0 {
            ec_stats = Some((shards, protected, overhead));
        }
    }
    // Surface Error Correction telemetry once the data borrow above is released.
    if let Some((shards, protected, overhead)) = ec_stats {
        vault.emit(|s| s.set_error_correction(shards, protected, overhead));
    }

    // Stream the container straight to the temp file: the data section (already
    // in RAM on `OpenVaultV3.data`) is written directly rather than copied into a
    // second whole-file buffer, so the seal no longer doubles peak memory
    // (T5 sub-task #2). Same atomic temp + sync + persist + dir-fsync discipline
    // as `atomic_write`, via the shared helpers.
    let ((file_len, file_hash), header) = {
        use std::io::Write;
        let parent = output_parent_dir(target);
        std::fs::create_dir_all(parent).map_err(|e| format!("Create parent dir: {e}"))?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".aerovault-v3-")
            .tempfile_in(parent)
            .map_err(|e| format!("Create temp file: {e}"))?;
        // Hash the bytes as they are written: the generation baseline of the
        // sealed file, without reading it back.
        let mut sealed = HashingWriter::new(tmp.as_file_mut());
        {
            let mut w = std::io::BufWriter::new(&mut sealed);
            write_container(
                &mut w,
                vault.header.clone(),
                &vault.mac_key,
                &vault.master_key,
                &vault.manifest,
                &extensions,
                &ext_payloads,
                &vault.data,
            )?;
            w.flush().map_err(|e| format!("Flush temp file: {e}"))?;
        }
        let generation = sealed.finish();
        tmp.as_file_mut()
            .sync_all()
            .map_err(|e| format!("Sync temp file: {e}"))?;
        // Take the staleness baseline from the bytes this writer sealed, not
        // from a later read of the path, which may already show another
        // writer's generation.
        let file = tmp.as_file_mut();
        let mut header_bytes = [0u8; HEADER_SIZE];
        file.seek(std::io::SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut header_bytes))
            .map_err(|e| format!("Read header: {e}"))?;
        #[cfg(test)]
        if FAIL_SAVED_HEADER_PARSE.with(|fail| fail.replace(false)) {
            header_bytes[0] ^= 1;
        }
        let header = VaultHeaderV3::from_bytes(&header_bytes)?;
        #[cfg(test)]
        run_in_save_window_hook();
        if !lock.covers_namespace(&vault.path) {
            return Err("source lock namespace changed; retry operation".to_string());
        }
        persist_over(tmp, target).map_err(|e| format!("Persist vault: {e}"))?;
        fsync_parent_dir(parent);
        #[cfg(test)]
        if target == vault.path {
            run_after_persist_hook();
        }
        (generation, header)
    };

    // Refresh the staleness baseline so a second save in the same session does
    // not trip the generation guard against the bytes we just wrote.
    vault.opened_file_len = file_len;
    vault.opened_hash = file_hash;
    vault.header = header;
    vault.header_repaired_on_open = false;
    vault.manifest_repaired_on_open = false;
    Ok(())
}

fn extract_entry(
    vault: &OpenVaultV3,
    entry_name: &str,
    dest_path: &Path,
) -> Result<PathBuf, String> {
    let entry_name = normalize_vault_relative_path(entry_name)?;
    match entry_kind(&vault.manifest, &entry_name) {
        Some(EntryKindV3::File) => {
            let entry = vault
                .manifest
                .entries
                .iter()
                .find(|entry| entry.path == entry_name)
                .ok_or_else(|| format!("Entry not found: {entry_name}"))?;
            if dest_path.is_dir() {
                // Extracting into an existing directory: contain under it.
                let output_path = dest_path.join(&entry.path);
                extract_file_entry(vault, entry, &output_path, dest_path)
            } else {
                // Caller named an EXACT output file path (not manifest-derived); the
                // single leaf is replaced by the temp file's rename (never when it
                // names a lock file, see `extract_file_entry`). The destination is
                // the caller's own choice, so its parent is a trust boundary the caller
                // owns (no manifest-controlled component is appended here).
                let parent = dest_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                std::fs::create_dir_all(parent).map_err(|e| format!("Create output dir: {e}"))?;
                extract_file_entry(vault, entry, dest_path, parent)
            }
        }
        Some(EntryKindV3::Directory) => {
            // Containment root is the user's chosen destination. When it already exists
            // we extract the subtree under `dest/<basename>`, and the manifest-derived
            // `<basename>` component is created through create_contained_dirs so a
            // pre-planted junction there is refused (audit M2 residual) rather than
            // followed; the subtree is then contained under the REAL `dest` (`root`),
            // not under a possibly-redirected `output_root`. When dest does not exist
            // we create it fresh and it is its own root.
            let (root, output_root) = if dest_path.exists() {
                if !dest_path.is_dir() {
                    return Err(
                        "Destination for directory extraction must be a directory".to_string()
                    );
                }
                let basename = path_basename(&entry_name);
                create_contained_dirs(dest_path, Path::new(basename))?;
                (dest_path.to_path_buf(), dest_path.join(basename))
            } else {
                std::fs::create_dir_all(dest_path)
                    .map_err(|e| format!("Create output dir: {e}"))?;
                (dest_path.to_path_buf(), dest_path.to_path_buf())
            };

            let prefix = format!("{entry_name}/");
            let mut descendants: Vec<&ManifestEntryV3> = vault
                .manifest
                .entries
                .iter()
                .filter(|entry| entry.path == entry_name || entry.path.starts_with(&prefix))
                .collect();
            sort_extraction_entries(&mut descendants);

            for entry in descendants {
                normalize_vault_relative_path(&entry.path)?;
                let rel = if entry.path == entry_name {
                    String::new()
                } else {
                    entry.path[entry_name.len() + 1..].to_string()
                };
                if !rel.is_empty() {
                    normalize_vault_relative_path(&rel)?;
                }
                let child_output = if rel.is_empty() {
                    output_root.clone()
                } else {
                    output_root.join(&rel)
                };
                if entry.is_dir {
                    // Contain every created directory under the REAL root (dest), which
                    // includes the basename component, so a planted reparse point
                    // anywhere on the path is refused.
                    let rel_from_root = child_output.strip_prefix(&root).map_err(|_| {
                        format!(
                            "Refusing extraction: {} escapes destination root {}",
                            child_output.display(),
                            root.display()
                        )
                    })?;
                    if !rel_from_root.as_os_str().is_empty() {
                        create_contained_dirs(&root, rel_from_root)?;
                    }
                } else {
                    extract_file_entry(vault, entry, &child_output, &root)?;
                }
            }

            Ok(output_root)
        }
        None => Err(format!("Entry not found: {entry_name}")),
    }
}

/// Extract the whole vault tree into `dest_root`, recreating every entry's path
/// under it. Returns the number of files written. Every entry path is
/// normalized first, so a crafted manifest cannot escape `dest_root`.
fn extract_all_entries(vault: &OpenVaultV3, dest_root: &Path) -> Result<u64, String> {
    extract_all_entries_with_progress(vault, dest_root, &mut |_, _| {})
}

fn sort_extraction_entries(entries: &mut [&ManifestEntryV3]) {
    // Extract named lock-file entries first. The later guarded writes can
    // then share those lock files without creating an empty placeholder over
    // an entry the user is trying to restore.
    entries.sort_by_cached_key(|&entry| {
        let lock_entry =
            !entry.is_dir && crate::lock::is_lock_file_name(path_basename(&entry.path));
        (!lock_entry, entry.path.as_str())
    });
}

/// `extract_all_entries` with a `(bytes_done, bytes_total)` progress callback
/// invoked after each file is written (#5: progress for extract). `bytes_total`
/// is the sum of file-entry plaintext sizes; directory entries do not move it.
fn extract_all_entries_with_progress(
    vault: &OpenVaultV3,
    dest_root: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<u64, String> {
    std::fs::create_dir_all(dest_root).map_err(|e| format!("Create output dir: {e}"))?;
    let mut entries: Vec<&ManifestEntryV3> = vault.manifest.entries.iter().collect();
    sort_extraction_entries(&mut entries);
    let total = progress_total(&entries);
    let mut done = 0u64;
    let mut files_written = 0u64;
    for entry in entries {
        let rel = normalize_vault_relative_path(&entry.path)?;
        let output = dest_root.join(&rel);
        if entry.is_dir {
            // Create directory entries through the same reparse-point-refusing path
            // as file parents, so a planted intermediate junction cannot redirect them.
            create_contained_dirs(dest_root, Path::new(&rel))?;
        } else {
            extract_file_entry(vault, entry, &output, dest_root)?;
            files_written += 1;
            done = done.saturating_add(entry.size);
            progress(done, total);
        }
    }
    Ok(files_written)
}

/// Recursive directory add (the byte-affecting part of the app command, minus
/// the Tauri progress emit). Returns `(added_files, added_dirs)`.
fn add_directory_into(
    vault: &mut OpenVaultV3,
    source_dir: &Path,
    target_prefix: Option<&str>,
    lock: &WriteLock,
    sidecar_lock: Option<&WriteLock>,
) -> Result<(usize, usize), String> {
    let source = source_dir
        .canonicalize()
        .map_err(|e| format!("Failed to resolve directory: {e}"))?;
    if !source.is_dir() {
        return Err(format!("Not a directory: {}", source_dir.display()));
    }

    struct DirEntry {
        rel_path: String,
        is_dir: bool,
        abs_path: PathBuf,
        depth: usize,
    }

    let normalized_prefix = target_prefix
        .map(|prefix| prefix.trim_matches('/'))
        .filter(|prefix| !prefix.is_empty())
        .map(normalize_vault_relative_path)
        .transpose()?;

    let mut all_entries: Vec<DirEntry> = Vec::new();
    for entry in walkdir::WalkDir::new(&source)
        .follow_links(false)
        .max_depth(100)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path() == source {
            continue;
        }
        #[cfg(test)]
        if entry.file_type().is_file() {
            if let Some(hook) = BEFORE_IMPORT_IDENTITY.with(|h| h.borrow_mut().take()) {
                hook();
            }
        }
        if (entry.file_type().is_file() || entry.file_type().is_symlink())
            && (lock.holds_file(entry.path()).map_err(|e| e.to_string())?
                || sidecar_lock
                    .map(|guard| guard.holds_file(entry.path()))
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .unwrap_or(false))
        {
            continue;
        }
        if all_entries.len() >= 500_000 {
            return Err("Directory exceeds maximum entry limit (500000)".to_string());
        }

        let rel_path = entry
            .path()
            .strip_prefix(&source)
            .map_err(|_| "Failed to compute relative path".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let full_rel = if let Some(prefix) = &normalized_prefix {
            join_vault_path(prefix, &rel_path)
        } else {
            rel_path
        };
        let full_rel = normalize_vault_relative_path(&full_rel)?;

        all_entries.push(DirEntry {
            rel_path: full_rel,
            is_dir: entry.file_type().is_dir(),
            abs_path: entry.path().to_path_buf(),
            depth: entry.depth(),
        });
    }

    let mut dirs: Vec<&DirEntry> = all_entries.iter().filter(|entry| entry.is_dir).collect();
    let files: Vec<&DirEntry> = all_entries.iter().filter(|entry| !entry.is_dir).collect();
    dirs.sort_by_key(|entry| entry.depth);

    let mut added_dirs = 0usize;
    for dir_entry in dirs {
        if create_directory_in_manifest(&mut vault.manifest, &dir_entry.rel_path)? {
            added_dirs += 1;
        }
    }

    let total_files = files.len();
    let sources: Vec<(PathBuf, String)> = files
        .iter()
        .map(|f| (f.abs_path.clone(), f.rel_path.clone()))
        .collect();
    append_sources_batched(vault, &sources)?;

    save_locked(vault, lock)?;
    Ok((total_files, added_dirs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "test-password-123";

    fn vault_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("av3-test-{}.aerovault", rand::random::<u64>()));
        p
    }

    fn scratch_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("av3-scratch-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Encrypted vault with one file and an exported detached sidecar.
    fn vault_with_sidecar() -> (PathBuf, PathBuf) {
        use super::super::ec::{default_sidecar_path, RecoveryPlacement};
        let vp = vault_path();
        let opts = CreateOptionsV3::new(&vp, PW);
        VaultV3::create_with_error_correction(&opts, RecoveryPlacement::Detached, 20).unwrap();
        let src = scratch_dir();
        let file = src.join("a.txt");
        std::fs::write(&file, b"sidecar test content").unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(&mut vault, &[(file, "a.txt".to_string())]).unwrap();
        drop(vault);
        std::fs::remove_dir_all(&src).ok();
        VaultV3::export_parity(&vp, PW, None).unwrap();
        let sidecar = default_sidecar_path(&vp);
        (vp, sidecar)
    }

    #[test]
    fn review_password_checks_absent_sidecar_under_destination_lock() {
        const PW_A: &str = "password-a-12345";
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotation.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let sidecar = super::super::ec::default_sidecar_path(&path);
        let held = crate::lock::acquire(&sidecar).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        assert!(VaultV3::change_password(&mut vault, PW_A)
            .unwrap_err()
            .contains("locked"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // An exporter from a separate copy wins before rotation gets the lock.
        drop(held);
        let copy = dir.path().join("copy.aerovault");
        std::fs::copy(&path, &copy).unwrap();
        VaultV3::export_parity(&copy, PW, Some(&sidecar)).unwrap();
        VaultV3::change_password(&mut vault, PW_A).unwrap();
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(VaultV3::open(&path, PW).is_err());
        assert!(VaultV3::open(&path, PW_A).unwrap().header_repaired_on_open);
    }

    #[test]
    fn round11_contended_fresh_extraction_cannot_publish_after_rotation_releases_lock() {
        const NEW: &str = "replacement-password-123";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotation.aerovault");
        let sidecar = super::super::ec::default_sidecar_path(&path);
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let backup = dir.path().join("backup.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&backup)).unwrap();
        let mut archived = VaultV3::open_plaintext(&backup).unwrap();
        VaultV3::add_files(&mut archived, &[(sidecar.clone(), "old-parity".into())]).unwrap();
        std::fs::remove_file(&sidecar).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        let output = sidecar.clone();
        let (start, started) = std::sync::mpsc::channel();
        let (contention, contended) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let timeout = std::time::Duration::from_secs(5);
        let extract = std::thread::spawn(move || {
            started.recv_timeout(timeout).unwrap();
            crate::lock::ON_LOCK_CONTENTION.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    contention.send(()).unwrap();
                    released.recv_timeout(timeout).unwrap();
                }));
            });
            VaultV3::extract_entry(&archived, "old-parity", &output)
        });
        IN_SAVE_WINDOW.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                start.send(()).unwrap();
                contended.recv_timeout(timeout).unwrap();
            }));
        });
        VaultV3::change_password(&mut vault, NEW).unwrap();
        release.send(()).unwrap();
        let error = extract.join().unwrap().unwrap_err();
        assert!(error.contains("locked by another writer"), "{error}");
        assert!(!sidecar.exists());
        assert!(VaultV3::open(&path, PW).is_err());
        assert!(VaultV3::open(&path, NEW).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn review_long_detached_create_refuses_before_replacing_vault() {
        const PW_A: &str = "password-a-12345";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v".repeat(255));
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let before = std::fs::read(&path).unwrap();
        for placement in [
            super::super::ec::RecoveryPlacement::Detached,
            super::super::ec::RecoveryPlacement::Both,
        ] {
            assert!(VaultV3::create_with_error_correction(
                &CreateOptionsV3::new_plaintext(&path),
                placement,
                20
            )
            .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        // A normal long encrypted vault still rotates without a possible default sidecar.
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        VaultV3::change_password(&mut vault, PW_A).unwrap();
        assert!(VaultV3::open(&path, PW_A).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn failed_save_does_not_leave_the_change_in_the_handle() {
        // The add and the delete succeed in memory but the save fails
        // (read-only folder). A later write on the same handle must not
        // persist either of them.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir();
        let vp = dir.join("v.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let (old, new) = (dir.join("old.txt"), dir.join("new.txt"));
        std::fs::write(&old, b"original").unwrap();
        std::fs::write(&new, b"replacement").unwrap();
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        VaultV3::add_files(&mut vault, &[(old, "f.txt".to_string())]).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            // Running as a user that ignores permissions: nothing to test.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let failed = VaultV3::add_files(&mut vault, &[(new, "f.txt".to_string())]);
        // Delete compacts the data section before the save: it must come back too.
        let failed_delete = VaultV3::delete_entry(&mut vault, "f.txt");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(failed.is_err());
        assert!(failed_delete.is_err());

        VaultV3::create_directory(&mut vault, "later").unwrap();
        drop(vault);
        let vault = VaultV3::open_plaintext(&vp).unwrap();
        let out = VaultV3::extract_entry(&vault, "f.txt", &dir.join("out")).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"original");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn progress_total_saturates_on_manifest_sizes() {
        let entry = |size| ManifestEntryV3 {
            path: "f".to_string(),
            size,
            modified: String::new(),
            is_dir: false,
            chunks: Vec::new(),
            pack_offset: None,
        };
        let (a, b) = (entry(u64::MAX), entry(2));
        assert_eq!(progress_total(&[&a, &b]), u64::MAX);
    }

    #[test]
    fn writer_is_held_off_while_a_password_change_refreshes_the_sidecar() {
        // B runs inside A's lock on this thread and must give up.
        crate::lock::set_short_wait_for_this_thread();
        // During pair publication A has replaced the vault but not the sidecar.
        // A pre-opened B must give up at the source lock. A reader must also
        // refuse while the journal needs that held lock for recovery.
        const PW_A: &str = "password-a-12345";
        const PW_B: &str = "password-b-12345";
        let (vp, sidecar) = vault_with_sidecar();
        let b_result = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (path, seen) = (vp.clone(), b_result.clone());
        let mut b = VaultV3::open(&vp, PW).unwrap();
        super::super::strip_transaction::AFTER_STRIP_VAULT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let error = VaultV3::open(&path, PW_A).unwrap_err();
                assert!(error.contains("locked by another writer"), "{error}");
                *seen.borrow_mut() = Some(VaultV3::change_password(&mut b, PW_B));
            }));
        });
        let mut a = VaultV3::open(&vp, PW).unwrap();
        VaultV3::change_password(&mut a, PW_A).unwrap();
        drop(a);
        let b_err = b_result.borrow_mut().take().unwrap().unwrap_err();
        assert!(b_err.contains("locked by another writer"), "{b_err}");
        assert!(VaultV3::open(&vp, PW_B).is_err());

        // The published sidecar rebuilds A's header: with the header MAC
        // damaged, PW_A still opens through recovery and PW does not.
        let mut bytes = std::fs::read(&vp).unwrap();
        let mac = super::super::constants::HEADER_MAC_OFFSET;
        bytes[mac] ^= 0xff;
        std::fs::write(&vp, &bytes).unwrap();
        let vault = VaultV3::open(&vp, PW_A).unwrap();
        assert!(vault.header_repaired_on_open);
        drop(vault);
        assert!(VaultV3::open(&vp, PW).is_err());

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn sidecar_exported_while_a_password_change_waits_is_refreshed() {
        // Another writer holds the lock and publishes a sidecar of the current
        // (old-password) header while A's password change waits for the lock.
        // A must see that sidecar once it holds the lock and refresh it, or
        // header recovery would bring the old password back.
        const PW_A: &str = "password-a-12345";
        let (vp, sidecar) = vault_with_sidecar();
        std::fs::remove_file(&sidecar).unwrap();
        let mut a = VaultV3::open(&vp, PW).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = vp.clone();
        let other = std::thread::spawn(move || {
            let lock = write_lock(&path).unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
            super::super::ec::export_parity_locked(
                &path,
                &path,
                PW,
                &super::super::ec::default_sidecar_path(&path),
                true,
                &lock,
                VaultV3Limits::default(),
            )
            .unwrap();
        });
        rx.recv().unwrap();
        VaultV3::change_password(&mut a, PW_A).unwrap();
        other.join().unwrap();
        drop(a);

        let mut bytes = std::fs::read(&vp).unwrap();
        bytes[super::super::constants::HEADER_MAC_OFFSET] ^= 0xff;
        std::fs::write(&vp, &bytes).unwrap();
        assert!(VaultV3::open(&vp, PW).is_err(), "old password recovered");
        assert!(VaultV3::open(&vp, PW_A).unwrap().header_repaired_on_open);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn create_waits_for_another_writer_then_refuses() {
        crate::lock::set_short_wait_for_this_thread();
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let before = std::fs::read(&vp).unwrap();
        let held = write_lock(&vp).unwrap();
        crate::lock::take_trace();
        let err = VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap_err();
        assert!(err.contains("locked by another writer"), "{err}");
        // Refused before any key was derived.
        assert!(!crate::lock::take_trace().contains(&"derive"));
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        drop(held);
        crate::lock::remove_vault_and_lock(&vp);
    }

    #[test]
    fn a_create_with_bad_options_leaves_nothing_behind() {
        // A short password or invalid CDC bounds are refused before the
        // create makes the missing folder or the lock file.
        let dir = scratch_dir();
        let vp = dir.join("new").join("sub").join("v.aerovault");
        let err = VaultV3::create(&CreateOptionsV3::new(&vp, "short")).unwrap_err();
        assert!(err.contains("at least 8"), "{err}");
        let bad = CdcBounds {
            min: 8192,
            avg: 4096,
            max: 65536,
        };
        let err = VaultV3::create(&CreateOptionsV3::new(&vp, PW).with_cdc_bounds(bad)).unwrap_err();
        assert!(err.contains("CDC bounds"), "{err}");
        assert!(!dir.join("new").exists(), "a refused create made a folder");
        assert!(!crate::lock::lock_path(&vp).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_short_new_password_is_refused_before_the_lock() {
        crate::lock::set_short_wait_for_this_thread();
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let mut v = VaultV3::open(&vp, PW).unwrap();
        let held = write_lock(&vp).unwrap();
        let err = VaultV3::change_password(&mut v, "short").unwrap_err();
        assert!(err.contains("at least 8"), "{err}");
        drop((held, v));
        crate::lock::remove_vault_and_lock(&vp);
    }

    #[test]
    fn create_takes_the_lock_before_it_derives_a_key() {
        let vp = vault_path();
        for _ in 0..2 {
            crate::lock::take_trace();
            VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
            let trace = crate::lock::take_trace();
            assert_eq!(trace.first(), Some(&"lock"), "{trace:?}");
            assert!(trace.contains(&"derive"), "{trace:?}");
        }
        crate::lock::remove_vault_and_lock(&vp);
    }

    #[test]
    fn review_invalid_ranges_fail_before_generation_scan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let mut header = VaultHeaderV3::from_bytes(&bytes[..HEADER_SIZE]).unwrap();
        header.data_len = bytes.len() as u64 + 1;
        header.header_mac = header.compute_mac(&aerovz_mac_key().unwrap()).unwrap();
        bytes[..HEADER_SIZE].copy_from_slice(&header.to_bytes());
        std::fs::write(&path, bytes).unwrap();
        crate::lock::take_trace();
        assert!(VaultV3::open_plaintext(&path).is_err());
        let events = crate::lock::take_trace();
        assert!(!events.contains(&"generation"), "{events:?}");
    }

    #[cfg(unix)]
    #[test]
    fn review_long_vault_names_remain_writable() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"long filename content").unwrap();
        for name in ["x".repeat(246), "x".repeat(255), "é".repeat(127)] {
            let path = dir.path().join(name);
            VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
            let mut v = VaultV3::open_plaintext(&path).unwrap();
            VaultV3::add_files(&mut v, &[(source.clone(), "item".into())]).unwrap();
            let reopened = VaultV3::open_plaintext(&path).unwrap();
            assert_eq!(VaultV3::summary(&reopened).entries.len(), 1);
        }
    }

    #[test]
    fn review_default_sidecar_destination_obeys_its_own_lock() {
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("source.bin");
        let enc = dir.path().join("source.aerovault");
        std::fs::write(&plain, vec![7u8; 5000]).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&enc, PW)).unwrap();
        for source in [&plain, &enc] {
            let dest = super::super::ec::default_sidecar_path(source);
            VaultV3::create(&CreateOptionsV3::new_plaintext(&dest)).unwrap();
            let before = std::fs::read(&dest).unwrap();
            let held = crate::lock::acquire(&dest).unwrap();
            for explicit in [false, true] {
                let result = if source == &enc {
                    VaultV3::export_parity(source, PW, explicit.then_some(dest.as_path())).map(drop)
                } else {
                    crate::error_correction::correct_generate(
                        source.to_str().unwrap(),
                        10,
                        if explicit { dest.to_str() } else { None },
                    )
                    .map(drop)
                };
                let err = result.unwrap_err();
                assert!(err.contains("locked by another writer"), "{err}");
                assert_eq!(std::fs::read(&dest).unwrap(), before);
            }
            drop(held);
        }
    }

    #[test]
    fn review_seed_and_password_refresh_obey_destination_lock() {
        use super::super::ec::{default_sidecar_path, RecoveryPlacement};
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.aerovault");
        let sidecar = default_sidecar_path(&path);
        VaultV3::create(&CreateOptionsV3::new_plaintext(&sidecar)).unwrap();
        let before = std::fs::read(&sidecar).unwrap();
        let held = crate::lock::acquire(&sidecar).unwrap();
        let result = VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        );
        assert!(result.unwrap_err().contains("locked by another writer"));
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        assert!(!path.exists(), "failed creation replaced the source first");
        drop(held);
        // Releasing the lock is not permission to overwrite the foreign vault.
        let error = VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap_err();
        assert!(error.contains("contains a vault"), "{error}");
        assert_eq!(std::fs::read(&sidecar).unwrap(), before);
        assert!(!path.exists());
        // Explicit fixture cleanup allows a normal seed/export for the rotation check.
        std::fs::remove_file(&sidecar).unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let before = std::fs::read(&path).unwrap();
        let old_sidecar = std::fs::read(&sidecar).unwrap();
        let held = crate::lock::acquire(&sidecar).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        let err = VaultV3::change_password(&mut vault, "new-password-123").unwrap_err();
        assert!(err.contains("locked by another writer"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read(&sidecar).unwrap(), old_sidecar);
        drop(held);
        assert!(VaultV3::open(&path, PW).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn review_fifo_replacement_cannot_stall_a_locked_reader() {
        use crate::source::fifo_test;
        use std::os::unix::ffi::OsStrExt;
        if let Some(dir) = fifo_test::child_path() {
            let path = dir.join("source.aerovault");
            let site = std::env::var("AEROVAULT_FIFO_TEST_SITE").unwrap();
            let mut v3 = (site == "v3-save").then(|| VaultV3::open_plaintext(&path).unwrap());
            let legacy = (site == "legacy").then(|| crate::Vault::open(&path, PW).unwrap());
            fifo_test::ready(&dir);
            let result = match site.as_str() {
                "v3-save" => VaultV3::create_directory(v3.as_mut().unwrap(), "during").map(drop),
                "legacy" => legacy
                    .as_ref()
                    .unwrap()
                    .create_directory("during")
                    .map(drop)
                    .map_err(|e| e.to_string()),
                "export" => VaultV3::export_parity(&path, PW, None).map(drop),
                "sidecar" => {
                    crate::lock::take_trace();
                    let result = VaultV3::open(&path, PW).map(drop);
                    assert!(crate::lock::take_trace().contains(&"open correction sidecar"));
                    result
                }
                "hash" => crate::error_correction::sync::write_if_unchanged(
                    &path,
                    0,
                    &[0; 32],
                    |_| Ok(()),
                ),
                _ => unreachable!(),
            };
            assert!(result.is_err(), "non-regular input accepted");
            return;
        }
        for site in ["v3-save", "legacy", "export", "hash", "sidecar"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("source.aerovault");
            if site == "legacy" {
                crate::Vault::create(crate::CreateOptions::new(&path, PW)).unwrap();
            } else if matches!(site, "export" | "sidecar") {
                VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
            } else {
                VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let fifo = if site == "sidecar" {
                super::super::ec::default_sidecar_path(&path)
            } else {
                path.clone()
            };
            let completed = fifo_test::run(
                "v3::vault::tests::review_fifo_replacement_cannot_stall_a_locked_reader",
                dir.path(),
                site,
                || {
                    if site == "sidecar" {
                        let mut damaged = before.clone();
                        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
                        std::fs::write(&path, damaged).unwrap();
                    } else {
                        std::fs::remove_file(&path).unwrap();
                    }
                    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                },
            );
            std::fs::remove_file(&fifo).unwrap();
            std::fs::write(&path, &before).unwrap();
            assert!(completed, "{site}: FIFO child failed or exceeded deadline");
            if site == "legacy" {
                crate::Vault::open(&path, PW)
                    .unwrap()
                    .create_directory("after")
                    .unwrap();
            } else {
                let mut vault = if matches!(site, "export" | "sidecar") {
                    VaultV3::open(&path, PW).unwrap()
                } else {
                    VaultV3::open_plaintext(&path).unwrap()
                };
                VaultV3::create_directory(&mut vault, "after").unwrap();
            }
        }
    }

    #[test]
    fn a_failed_open_does_not_read_the_whole_file() {
        // Wrong password, a plaintext container under `open`, a file that is
        // not a vault: each fails at the header, before the file is hashed.
        let dir = scratch_dir();
        let enc = dir.join("e.aerovault");
        let plain = dir.join("p.aerozip");
        let other = dir.join("o.bin");
        VaultV3::create(&CreateOptionsV3::new(&enc, PW)).unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&plain)).unwrap();
        std::fs::write(&other, vec![0x5Au8; 200_000]).unwrap();
        crate::lock::take_trace();
        assert!(VaultV3::open(&enc, "not-the-password").is_err());
        assert!(VaultV3::open(&plain, PW).is_err());
        assert!(VaultV3::open(&other, PW).is_err());
        assert!(VaultV3::open_plaintext(&other).is_err());
        let trace = crate::lock::take_trace();
        assert!(!trace.contains(&"generation"), "{trace:?}");
        // A good open hashes the file once.
        VaultV3::open(&enc, PW).unwrap();
        let trace = crate::lock::take_trace();
        assert_eq!(trace.iter().filter(|e| **e == "generation").count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_changed_between_the_header_check_and_the_hash_is_refused() {
        // Another writer (one that does not take the lock) replaces the bytes
        // in place after the header was checked: with another vault of the
        // same length (other header), and by appending (same header).
        let dir = scratch_dir();
        let ours = dir.join("ours.aerovault");
        let theirs = dir.join("theirs.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&ours, PW)).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&theirs, PW)).unwrap();
        let ours_bytes = std::fs::read(&ours).unwrap();
        let their_bytes = std::fs::read(&theirs).unwrap();
        assert_eq!(ours_bytes.len(), their_bytes.len());
        assert_ne!(ours_bytes[..HEADER_SIZE], their_bytes[..HEADER_SIZE]);
        let mut appended = ours_bytes.clone();
        appended.extend_from_slice(&[0u8; 10]);
        for replacement in [their_bytes, appended] {
            std::fs::write(&ours, &ours_bytes).unwrap();
            let (path, bytes) = (ours.clone(), replacement.clone());
            BEFORE_OPEN_GENERATION.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&path)
                        .unwrap();
                    std::io::Write::write_all(&mut f, &bytes).unwrap();
                }))
            });
            let err = VaultV3::open(&ours, PW).map(drop).unwrap_err();
            assert!(err.contains("changed while it was being"), "{err}");
            assert!(
                BEFORE_OPEN_GENERATION.with(|h| h.borrow().is_none()),
                "hook ran"
            );
            assert_eq!(std::fs::read(&ours).unwrap(), replacement);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_writer_cannot_slip_into_the_save_window() {
        // B runs inside A's lock on this thread and must give up.
        crate::lock::set_short_wait_for_this_thread();
        // A has passed its generation check and is about to rename. Without a
        // lock, B (same generation) could save an add that A's rename then
        // overwrites while both report success. B must be refused instead.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let src = scratch_dir();
        let (fa, fb) = (src.join("a.txt"), src.join("b.txt"));
        std::fs::write(&fa, b"from a").unwrap();
        std::fs::write(&fb, b"from b").unwrap();
        let b_result = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (path, seen, fb2) = (vp.clone(), b_result.clone(), fb.clone());
        IN_SAVE_WINDOW.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let mut b = VaultV3::open(&path, PW).unwrap();
                *seen.borrow_mut() =
                    Some(VaultV3::add_files(&mut b, &[(fb2, "b.txt".to_string())]));
            }));
        });
        let mut a = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(&mut a, &[(fa, "a.txt".to_string())]).unwrap();
        drop(a);

        let b_result = b_result.borrow_mut().take().unwrap();
        let vault = VaultV3::open(&vp, PW).unwrap();
        let paths: Vec<&str> = vault
            .manifest
            .entries
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        if b_result.is_ok() {
            assert!(
                paths.contains(&"b.txt"),
                "B's add was reported saved but is lost"
            );
        }
        let b_err = b_result.unwrap_err();
        assert!(b_err.contains("locked by another writer"), "{b_err}");
        assert_eq!(paths, ["a.txt"]);
        drop(vault);

        // Once A is done, B's retry goes through.
        let mut b = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(&mut b, &[(fb, "b.txt".to_string())]).unwrap();
        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn stale_handle_is_refused_when_only_the_body_changed() {
        // A rename to a name of the same length leaves the file length and
        // header bytes as they were; only the body differs. A handle opened
        // before such a change must still be refused, not overwrite it.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let src = scratch_dir();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        let mut a = VaultV3::open_plaintext(&vp).unwrap();
        let mut bytes = std::fs::read(&vp).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&vp, &bytes).unwrap();
        let err =
            VaultV3::add_files(&mut a, &[(src.join("a.txt"), "a.txt".to_string())]).unwrap_err();
        assert!(err.contains("Vault changed"), "{err}");
        assert_eq!(std::fs::read(&vp).unwrap(), bytes);
        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn a_file_rewritten_in_place_during_the_open_is_not_overwritten() {
        // A writer that does not take the lock rewrites the vault in place
        // (same inode) after the open decoded it. The handle's baseline must
        // be the file it decoded, so its next save is refused and the other
        // writer's file is kept.
        let vp = vault_path();
        let other = vault_path();
        let src = scratch_dir();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        for (path, name) in [(&vp, "a.txt"), (&other, "b.txt")] {
            VaultV3::create(&CreateOptionsV3::new_plaintext(path)).unwrap();
            let mut v = VaultV3::open_plaintext(path).unwrap();
            VaultV3::add_files(&mut v, &[(src.join("a.txt"), name.to_string())]).unwrap();
        }
        let theirs = std::fs::read(&other).unwrap();
        let (path, bytes) = (vp.clone(), theirs.clone());
        AFTER_OPEN_DECODE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .unwrap();
                std::io::Write::write_all(&mut f, &bytes).unwrap();
            }))
        });
        crate::lock::take_trace();
        let mut v = VaultV3::open_plaintext(&vp).unwrap();
        assert!(AFTER_OPEN_DECODE.with(|h| h.borrow().is_none()), "hook ran");
        // The baseline is taken before the decode, not only before the hook.
        assert_eq!(crate::lock::take_trace(), ["generation", "decode"]);
        let err =
            VaultV3::add_files(&mut v, &[(src.join("a.txt"), "c.txt".to_string())]).unwrap_err();
        assert!(err.contains("changed"), "{err}");
        drop(v);
        assert_eq!(std::fs::read(&vp).unwrap(), theirs);
        crate::lock::remove_vault_and_lock(&vp);
        crate::lock::remove_vault_and_lock(&other);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn open_and_save_each_read_the_whole_file_once_more() {
        // Open hashes the file it decoded; a save hashes the file on disk for
        // its check and the sealed bytes as it writes them, without reading
        // the new file back.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let src = scratch_dir();
        std::fs::write(src.join("a.txt"), vec![3u8; 100_000]).unwrap();
        let reads = || GENERATION_READS.with(|n| n.replace(0));
        reads();
        let mut v = VaultV3::open_plaintext(&vp).unwrap();
        assert_eq!(reads(), 1, "open");
        VaultV3::add_files(&mut v, &[(src.join("a.txt"), "a.txt".to_string())]).unwrap();
        assert_eq!(reads(), 1, "save");
        // The baseline the save kept is the file now on disk.
        let mut file = std::fs::File::open(&vp).unwrap();
        assert_eq!(
            file_generation(&mut file, v.opened_file_len).unwrap(),
            v.opened_hash
        );
        drop(file);
        VaultV3::add_files(&mut v, &[(src.join("a.txt"), "b.txt".to_string())]).unwrap();
        drop(v);
        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn a_chosen_output_is_replaced_only_under_its_own_lock() {
        // `export-parity --out` and `correct gen --out` name a path that may be
        // another vault (B): while a writer of B holds B's lock, B is kept.
        crate::lock::set_short_wait_for_this_thread();
        let dir = scratch_dir();
        let b = dir.join("b.aerozip");
        let c = dir.join("c.aerovault");
        let plain = dir.join("plain.bin");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&b)).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&c, PW)).unwrap();
        std::fs::write(&plain, vec![9u8; 20_000]).unwrap();
        let b_before = std::fs::read(&b).unwrap();
        let held = write_lock(&b).unwrap();
        let err =
            crate::error_correction::correct_generate(plain.to_str().unwrap(), 10, b.to_str())
                .map(drop)
                .unwrap_err();
        assert!(err.contains("locked by another writer"), "gen: {err}");
        let err = VaultV3::export_parity(&c, PW, Some(&b))
            .map(drop)
            .unwrap_err();
        assert!(err.contains("locked by another writer"), "export: {err}");
        assert_eq!(std::fs::read(&b).unwrap(), b_before);
        drop(held);
        // Without another writer the chosen output is written, as before,
        // including into a missing parent folder.
        VaultV3::export_parity(&c, PW, Some(&b)).unwrap();
        assert_ne!(std::fs::read(&b).unwrap(), b_before);
        let new_export = dir.join("new_a").join("sub").join("c.aerocorrect");
        let new_gen = dir.join("new_b").join("sub").join("plain.aerocorrect");
        VaultV3::export_parity(&c, PW, Some(&new_export)).unwrap();
        crate::error_correction::correct_generate(plain.to_str().unwrap(), 10, new_gen.to_str())
            .unwrap();
        assert!(new_export.exists() && new_gen.exists());
        // A refused `--out` makes no folder, takes no lock and derives no key.
        std::fs::remove_file(crate::lock::lock_path(&c)).unwrap();
        crate::lock::take_trace();
        for bad in [&c, &dir.join("new_bad").join("sub").join("x.aerolock")] {
            let err = VaultV3::export_parity(&c, PW, Some(bad))
                .map(drop)
                .unwrap_err();
            assert!(
                err.contains("the file it is built from") || err.contains("vault lock file"),
                "{err}"
            );
        }
        assert!(crate::lock::take_trace().is_empty());
        assert!(!crate::lock::lock_path(&c).exists());
        assert!(!dir.join("new_bad").exists());
        // An output that is the file it is built from is refused at once.
        let err =
            crate::error_correction::correct_generate(plain.to_str().unwrap(), 10, plain.to_str())
                .map(drop)
                .unwrap_err();
        assert!(err.contains("the file it is built from"), "{err}");
        assert_eq!(std::fs::read(&plain).unwrap(), vec![9u8; 20_000]);
        #[cfg(unix)]
        {
            let link = dir.join("link.bin");
            std::os::unix::fs::symlink(&plain, &link).unwrap();
            let err = crate::error_correction::correct_generate(
                link.to_str().unwrap(),
                10,
                link.to_str(),
            )
            .map(drop)
            .unwrap_err();
            assert!(err.contains("the file it is built from"), "{err}");
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_output_that_is_another_name_of_the_source_is_refused_at_once() {
        // A hard link of the source (or, on a case-insensitive file system, the
        // source in another case) is a path the name check cannot match: it is
        // refused by file identity, before the source is read or locked.
        let dir = scratch_dir();
        let plain = dir.join("plain.bin");
        let plain_link = dir.join("plain-other-name.bin");
        let c = dir.join("c.aerovault");
        let c_link = dir.join("c-other-name.aerovault");
        std::fs::write(&plain, vec![7u8; 20_000]).unwrap();
        std::fs::hard_link(&plain, &plain_link).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&c, PW)).unwrap();
        std::fs::hard_link(&c, &c_link).unwrap();
        std::fs::remove_file(crate::lock::lock_path(&c)).unwrap();
        let c_before = std::fs::read(&c).unwrap();
        crate::lock::take_trace();
        let mut read = false;
        let err = crate::error_correction::correct_generate_with_progress(
            plain.to_str().unwrap(),
            10,
            plain_link.to_str(),
            &mut |_, _| read = true,
        )
        .map(drop)
        .unwrap_err();
        assert!(err.contains("the file it is built from"), "gen: {err}");
        assert!(!read, "the source was read before the refusal");
        let err = VaultV3::export_parity(&c, PW, Some(&c_link))
            .map(drop)
            .unwrap_err();
        assert!(err.contains("the file it is built from"), "export: {err}");
        assert!(
            crate::lock::take_trace().is_empty(),
            "locked or derived before the refusal"
        );
        for p in [&plain, &plain_link, &c, &c_link] {
            assert!(!crate::lock::lock_path(p).exists(), "{}", p.display());
        }
        assert_eq!(std::fs::read(&plain_link).unwrap(), vec![7u8; 20_000]);
        assert_eq!(std::fs::read(&c_link).unwrap(), c_before);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vault_lock_file_is_never_written_over() {
        // Vault paths `p` and `p.aerolock`: while writer A holds the lock of
        // `p`, nothing may replace `p.aerolock` (A's lock file), or a second
        // writer could lock the new file and save `p` at the same time.
        crate::lock::set_short_wait_for_this_thread();
        let dir = scratch_dir();
        let p = dir.join("p.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&p)).unwrap();
        let lock_file = crate::lock::lock_path(&p);
        let held = write_lock(&p).unwrap();
        #[cfg(unix)]
        let inode = || std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&lock_file).unwrap());
        #[cfg(unix)]
        let before = inode();
        let refused = |what: &str, err: String| {
            assert!(err.contains("vault lock file"), "{what}: {err}");
        };
        refused(
            "v3 create",
            VaultV3::create(&CreateOptionsV3::new_plaintext(&lock_file)).unwrap_err(),
        );
        refused(
            "legacy create",
            crate::vault::Vault::create(crate::vault::CreateOptions::new(
                &lock_file,
                "test-password-123",
            ))
            .map(drop)
            .unwrap_err()
            .to_string(),
        );
        let plain = dir.join("plain.bin");
        std::fs::write(&plain, vec![5u8; 10_000]).unwrap();
        refused(
            "correct gen --out the lock file",
            crate::error_correction::correct_generate(
                plain.to_str().unwrap(),
                10,
                lock_file.to_str(),
            )
            .map(drop)
            .unwrap_err(),
        );
        // Size from the metadata, not a read: on Windows the held lock
        // (LockFileEx) refuses reads of the file to other handles.
        assert_eq!(std::fs::metadata(&lock_file).unwrap().len(), 0);
        #[cfg(unix)]
        assert_eq!(inode(), before, "the lock file was replaced");
        let err = write_lock(&p).map(drop).unwrap_err();
        assert!(err.contains("locked by another writer"), "{err}");
        drop(held);

        // An entry named like that lock file is extracted only where no file is.
        let src = scratch_dir();
        let named = src.join("payload");
        std::fs::write(&named, b"payload").unwrap();
        let q = dir.join("q.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&q)).unwrap();
        let mut v = VaultV3::open_plaintext(&q).unwrap();
        VaultV3::add_files(&mut v, &[(named, "p.aerozip.aerolock".to_string())]).unwrap();
        let err = VaultV3::extract_entry(&v, "p.aerozip.aerolock", &dir).unwrap_err();
        assert!(err.contains("p.aerozip.aerolock"), "{err}");
        assert_eq!(std::fs::read(&lock_file).unwrap(), b"");
        let out = VaultV3::extract_entry(&v, "p.aerozip.aerolock", &src.join("out")).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"payload");
        drop(v);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&src).unwrap();
    }

    #[test]
    fn extracting_a_folder_again_keeps_its_empty_lock_files() {
        // A folder of vaults added to a vault carries their empty lock files.
        // Extracting it twice into the same place works: an empty lock-named
        // entry over an empty file has nothing to write.
        let dir = scratch_dir();
        let src = dir.join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("x.txt"), b"x").unwrap();
        std::fs::write(src.join("v.aerovault.aerolock"), b"").unwrap();
        let p = dir.join("p.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&p)).unwrap();
        let mut v = VaultV3::open_plaintext(&p).unwrap();
        VaultV3::add_files(
            &mut v,
            &[
                (src.join("x.txt"), "x.txt".to_string()),
                (
                    src.join("v.aerovault.aerolock"),
                    "v.aerovault.aerolock".to_string(),
                ),
            ],
        )
        .unwrap();
        let out = dir.join("out");
        for _ in 0..2 {
            VaultV3::extract_all(&v, &out).unwrap();
            assert_eq!(std::fs::read(out.join("x.txt")).unwrap(), b"x");
            assert_eq!(
                std::fs::read(out.join("v.aerovault.aerolock")).unwrap(),
                b""
            );
        }
        drop(v);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn extraction_never_creates_a_directory_named_like_a_lock_file() {
        // A folder at `<vault>.aerolock` would block every write of that vault,
        // so no folder named by a vault entry takes a lock file name: v3 folder
        // entries, v3 file entries' parents, legacy folder entries.
        let dir = scratch_dir();
        let src = dir.join("payload");
        std::fs::write(&src, b"payload").unwrap();
        let p = dir.join("p.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&p)).unwrap();
        let mut v = VaultV3::open_plaintext(&p).unwrap();
        VaultV3::create_directory(&mut v, "d.aerolock").unwrap();
        VaultV3::add_files(&mut v, &[(src.clone(), "e.AeroLock/f.txt".to_string())]).unwrap();
        let out = dir.join("out");
        std::fs::create_dir(&out).unwrap();
        for entry in ["d.aerolock", "e.AeroLock/f.txt"] {
            let err = VaultV3::extract_entry(&v, entry, &out).unwrap_err();
            assert!(err.contains("vault lock file name"), "{entry}: {err}");
        }
        let err = VaultV3::extract_all(&v, &out).unwrap_err();
        assert!(err.contains("vault lock file name"), "{err}");
        assert!(!out.join("d.aerolock").exists());
        assert!(!out.join("e.AeroLock").exists());
        drop(v);

        let legacy = dir.join("l.aerovault");
        let lv = crate::vault::Vault::create(crate::vault::CreateOptions::new(
            &legacy,
            "test-password-123",
        ))
        .unwrap();
        lv.create_directory("g.aerolock").unwrap();
        let err = lv.extract("g.aerolock", &out).unwrap_err();
        assert!(err.to_string().contains("vault lock file name"), "{err}");
        assert!(!out.join("g.aerolock").exists());
        // Folders with other names are created as before.
        lv.create_directory("h").unwrap();
        assert!(lv.extract("h", &out).unwrap().is_dir());
        drop(lv);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_through_a_symlinked_vault_path_is_refused() {
        // The link and its target would lock two different `.aerolock` files, and
        // the rename would replace the link, not the vault that was read.
        crate::lock::set_short_wait_for_this_thread();
        let dir = scratch_dir();
        let real = dir.join("real.aerozip");
        let alias = dir.join("alias.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&real)).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        std::fs::write(dir.join("a.txt"), b"alpha").unwrap();
        let add = |v: &mut OpenVaultV3| {
            VaultV3::add_files(v, &[(dir.join("a.txt"), "a.txt".to_string())])
        };
        let real_before = std::fs::read(&real).unwrap();
        let mut through_alias = VaultV3::open_plaintext(&alias).unwrap();
        for held in [true, false] {
            let lock = held.then(|| write_lock(&real).unwrap());
            let err = add(&mut through_alias).unwrap_err();
            assert!(err.contains("is a symbolic link"), "{err}");
            drop(lock);
            assert!(std::fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(std::fs::read(&real).unwrap(), real_before);
            assert!(!crate::lock::lock_path(&alias).exists());
        }
        // Through the target path the same add works.
        let mut v = VaultV3::open_plaintext(&real).unwrap();
        add(&mut v).unwrap();
        assert_eq!(VaultV3::summary(&v).entries.len(), 1);
        drop((v, through_alias));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn create_makes_a_missing_parent_folder() {
        let root = scratch_dir();
        let vp = root.join("new").join("sub").join("v.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        VaultV3::open_plaintext(&vp).unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn save_succeeds_while_a_reader_has_the_vault_open() {
        // On Windows a plain MoveFileExW replace fails while another handle
        // has the destination open; readers take no lock, so a save must not.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let src = scratch_dir();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        let reader = std::fs::File::open(&vp).unwrap();
        let mut v = VaultV3::open_plaintext(&vp).unwrap();
        VaultV3::add_files(&mut v, &[(src.join("a.txt"), "a.txt".to_string())]).unwrap();
        drop(reader);
        drop(v);
        assert_eq!(
            VaultV3::summary(&VaultV3::open_plaintext(&vp).unwrap())
                .entries
                .len(),
            1
        );
        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn strip_parity_checks_the_sidecar_under_the_lock() {
        // Another writer holds the lock and removes the sidecar (as a failed
        // password-change refresh does) while strip-parity waits. Once it holds
        // the lock, strip-parity must see the sidecar gone and keep the parity.
        use super::super::ec::{default_sidecar_path, RecoveryPlacement};
        let vp = vault_path();
        let opts = CreateOptionsV3::new(&vp, PW);
        VaultV3::create_with_error_correction(&opts, RecoveryPlacement::Both, 20).unwrap();
        let sidecar = default_sidecar_path(&vp);
        assert!(sidecar.exists());
        let (tx, rx) = std::sync::mpsc::channel();
        let (path, side) = (vp.clone(), sidecar.clone());
        let other = std::thread::spawn(move || {
            let _lock = write_lock(&path).unwrap();
            tx.send(()).unwrap();
            // Longer than the key derivation strip-parity runs before its check.
            std::thread::sleep(std::time::Duration::from_secs(3));
            std::fs::remove_file(&side).unwrap();
        });
        rx.recv().unwrap();
        let res = VaultV3::strip_parity(&vp, PW, false);
        other.join().unwrap();
        let err = res.unwrap_err();
        assert!(err.contains("no detached recovery file"), "{err}");
        assert!(has_embedded_parity(&VaultV3::open(&vp, PW).unwrap()));
        crate::lock::remove_vault_and_lock(&vp);
    }

    #[cfg(unix)]
    #[test]
    fn export_to_another_folder_works_from_a_read_only_folder() {
        // A vault on read-only media (no lock file, none can be created) can
        // still be read to export its parity elsewhere.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir();
        let vp = dir.join("v.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        std::fs::remove_file(crate::lock::lock_path(&vp)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            // Running as root: the folder is writable anyway.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let out_dir = scratch_dir();
        let out = out_dir.join("v.aerocorrect");
        let res = VaultV3::export_parity(&vp, PW, Some(&out));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        res.unwrap();
        assert!(out.exists());
        assert!(!crate::lock::lock_path(&vp).exists());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn save_baseline_is_the_generation_this_writer_sealed() {
        // A writer that does not take the lock (an older version, a manual
        // copy) replaces the vault right after A's rename, before A records
        // its baseline. A's baseline must still be A's own header, so A's
        // next write sees the change instead of overwriting it.
        let (vp, sidecar) = vault_with_sidecar();
        let other = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&other, PW)).unwrap();
        let other_bytes = std::fs::read(&other).unwrap();
        let mut a = VaultV3::open(&vp, PW).unwrap();
        change_password_in_place(&mut a, "password-a-12345").unwrap();
        let path = vp.clone();
        AFTER_PERSIST.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::write(&path, &other_bytes).unwrap();
            }));
        });
        save_open_vault(&mut a).unwrap();
        let err = VaultV3::create_directory(&mut a, "later").unwrap_err();
        assert!(err.contains("Vault changed"), "{err}");

        crate::lock::remove_vault_and_lock(&vp);
        crate::lock::remove_vault_and_lock(&other);
        std::fs::remove_file(&sidecar).ok();
    }

    #[cfg(unix)]
    #[test]
    fn password_change_refuses_a_sidecar_directory_before_saving() {
        // An existing directory is rejected before the password is committed.
        // Preserve both the vault bytes and the unrelated directory contents.
        const NEW_PW: &str = "new-password-12345";
        let (vp, sidecar) = vault_with_sidecar();
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::create_dir(&sidecar).unwrap();
        std::fs::write(sidecar.join("keep"), b"x").unwrap();
        let before = std::fs::read(&vp).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let err = VaultV3::change_password(&mut vault, NEW_PW).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        assert_eq!(std::fs::read(sidecar.join("keep")).unwrap(), b"x");
        drop(vault);
        assert!(VaultV3::open(&vp, PW).is_ok());
        assert!(VaultV3::open(&vp, NEW_PW).is_err());

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&sidecar).ok();
    }

    #[test]
    fn password_change_reports_committed_pair_after_final_sync_failure() {
        const NEW_PW: &str = "new-password-12345";
        let (vp, sidecar) = vault_with_sidecar();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        super::super::strip_transaction::FAIL_FINAL_SYNC.with(|f| f.set(true));
        let err = VaultV3::change_password(&mut vault, NEW_PW).unwrap_err();
        assert!(err.starts_with("Password changed on disk"), "{err}");
        assert!(!super::super::strip_transaction::journal_path(&vp).exists());
        assert!(VaultV3::open(&vp, NEW_PW).is_ok());
        assert!(VaultV3::open(&vp, PW).is_err());
        VaultV3::create_directory(&mut vault, "after-sync-failure").unwrap();
        drop(vault);
        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn create_open_wrong_password_and_full_round_trip() {
        // One create + a couple opens to keep Argon2id calls modest.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        assert!(VaultV3::is_vault_v3(&vp));

        // Wrong password fails.
        assert!(VaultV3::open(&vp, "wrong-password").is_err());

        // Peek without password.
        let info = VaultV3::peek(&vp).unwrap();
        assert_eq!(info.version, VERSION);

        // Build a tree: several small files (packed), one large file (CDC path),
        // and a subdirectory.
        let src = scratch_dir();
        let small1 = src.join("a.txt");
        let small2 = src.join("b.txt");
        let small3 = src.join("c.txt");
        std::fs::write(&small1, b"alpha contents").unwrap();
        std::fs::write(&small2, b"beta contents which differ").unwrap();
        std::fs::write(&small3, vec![0x5au8; 4096]).unwrap();

        // Large file > PACK_SMALL_FILE_THRESHOLD to force the CDC per-file path.
        let large = src.join("big.bin");
        let mut payload = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 600_000];
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&large, &payload).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::create_directory(&mut vault, "docs/sub").unwrap();
        VaultV3::add_files(
            &mut vault,
            &[
                (small1.clone(), "a.txt".to_string()),
                (small2.clone(), "b.txt".to_string()),
                (small3.clone(), "docs/sub/c.txt".to_string()),
                (large.clone(), "big.bin".to_string()),
            ],
        )
        .unwrap();

        let listed = VaultV3::list(&vault);
        assert!(listed.iter().any(|e| e.path == "a.txt" && !e.is_dir));
        assert!(listed.iter().any(|e| e.path == "docs/sub" && e.is_dir));
        assert!(listed
            .iter()
            .any(|e| e.path == "big.bin" && e.size == payload.len() as u64));

        // Extract all and verify byte-identity.
        let out = scratch_dir();
        let written = VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(written, 4);
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha contents");
        assert_eq!(
            std::fs::read(out.join("b.txt")).unwrap(),
            b"beta contents which differ"
        );
        assert_eq!(
            std::fs::read(out.join("docs/sub/c.txt")).unwrap(),
            vec![0x5au8; 4096]
        );
        assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), payload);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn streaming_multi_megabyte_round_trip_is_byte_identical() {
        // T5 headline: a multi-MB file is ingested through the bounded-buffer
        // StreamingChunker (many CDC windows + several reader refills) and
        // re-extracted block-by-block, and must come back byte-for-byte. This
        // exercises the streaming add + streaming extract paths end to end,
        // across both the incompressible (stored-raw) and the zstd lanes.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

        let src = scratch_dir();

        // 12 MiB pseudo-random => incompressible (stored_raw) and split into
        // several CDC chunks (min 256 KiB / max 4 MiB => at least 3 chunks).
        let mut random = vec![0u8; 12 * 1024 * 1024 + 7];
        let mut x = 0xd1b54a32d192ed03u64;
        for b in random.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        let rnd_path = src.join("random.bin");
        std::fs::write(&rnd_path, &random).unwrap();

        // 12 MiB highly compressible => the zstd lane, decoded windowed on extract.
        let pattern = b"AeroVault v3 streaming round-trip payload block. ";
        let mut text = Vec::with_capacity(12 * 1024 * 1024);
        while text.len() < 12 * 1024 * 1024 {
            text.extend_from_slice(pattern);
        }
        let txt_path = src.join("text.bin");
        std::fs::write(&txt_path, &text).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[
                (rnd_path.clone(), "random.bin".to_string()),
                (txt_path.clone(), "text.bin".to_string()),
            ],
        )
        .unwrap();

        // Both files must have been split into multiple CDC chunks, i.e. the
        // streaming chunker actually crossed window boundaries (not one big read).
        let rnd_entry = vault
            .manifest
            .entries
            .iter()
            .find(|e| e.path == "random.bin")
            .unwrap();
        assert!(
            rnd_entry.chunks.len() >= 3,
            "12 MiB random file should split into multiple CDC chunks, got {}",
            rnd_entry.chunks.len()
        );

        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("random.bin")).unwrap(),
            random,
            "incompressible multi-chunk file must round-trip byte-identically"
        );
        assert_eq!(
            std::fs::read(out.join("text.bin")).unwrap(),
            text,
            "compressible multi-chunk file must round-trip byte-identically"
        );

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn streaming_packed_small_files_cross_chunk_round_trip() {
        // Exercises the windowed streaming extract with offset > 0 AND a file
        // straddling a CDC chunk boundary: many sub-threshold files are batched
        // into one pack, the pack is chunked (>= 2 chunks), and each member's
        // [pack_offset, pack_offset+size) slice is reassembled block-by-block.
        // This is the most error-prone new arithmetic (w_start/w_end clamp) and
        // the old offset==0 round-trip tests do not cover it.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

        let src = scratch_dir();
        // 48 distinct ~100 KiB files => ~4.8 MiB packed, which the CDC (avg 1 MiB,
        // max 4 MiB) splits into several chunks, so members straddle boundaries.
        // Each file gets unique pseudo-random content (no dedup collapse, so the
        // per-file byte comparison is meaningful).
        let mut files: Vec<(PathBuf, String, Vec<u8>)> = Vec::new();
        for i in 0..48u64 {
            let len = 100 * 1024 + (i as usize); // vary length so boundaries shift
            let mut data = vec![0u8; len];
            let mut x = 0xa5a5_0000_0000_0001u64.wrapping_add(i.wrapping_mul(0x9e3779b97f4a7c15));
            for b in data.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x & 0xff) as u8;
            }
            let name = format!("packed/file_{i:03}.bin");
            let path = src.join(format!("file_{i:03}.bin"));
            std::fs::write(&path, &data).unwrap();
            files.push((path, name, data));
        }

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let sources: Vec<(PathBuf, String)> = files
            .iter()
            .map(|(p, n, _)| (p.clone(), n.clone()))
            .collect();
        VaultV3::add_files(&mut vault, &sources).unwrap();

        // The pack must have split into multiple chunks AND at least one member
        // must span >1 chunk (i.e. a real cross-boundary windowed extract).
        assert!(
            vault.manifest.chunks.len() >= 2,
            "packed set should chunk into >= 2 blocks, got {}",
            vault.manifest.chunks.len()
        );
        assert!(
            vault.manifest.entries.iter().any(|e| e.chunks.len() >= 2),
            "at least one packed file must straddle a chunk boundary"
        );

        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        for (_, name, data) in &files {
            assert_eq!(
                &std::fs::read(out.join(name)).unwrap(),
                data,
                "packed cross-chunk file {name} must round-trip byte-identically"
            );
        }

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn probe_classifies_compressible_and_random() {
        // Highly repetitive text shrinks well past the threshold.
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(4096);
        assert!(!probe_incompressible(&text));

        // High-entropy bytes do not shrink: stored raw.
        let mut noise = vec![0u8; 256 * 1024];
        let mut x = 0x243f6a8885a308d3u64;
        for b in noise.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        assert!(probe_incompressible(&noise));

        // Empty input is never "incompressible".
        assert!(!probe_incompressible(&[]));
    }

    #[test]
    fn probe_does_not_let_noisy_prefix_hide_large_compressible_chunk() {
        let mut chunk = b"AeroVault representative probe body. ".repeat(80_000);
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in chunk[..INCOMPRESSIBLE_PROBE_SAMPLE].iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }

        assert!(chunk.len() > INCOMPRESSIBLE_PROBE_MAX_SAMPLE);
        assert!(
            !probe_incompressible(&chunk),
            "a noisy prefix must not force a large compressible chunk to raw"
        );
    }

    #[test]
    fn probe_still_stores_large_high_entropy_chunks_raw() {
        let mut noise = vec![0u8; INCOMPRESSIBLE_PROBE_MAX_SAMPLE * 2];
        let mut x = 0x6a09e667f3bcc909u64;
        for b in noise.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }

        assert!(probe_incompressible(&noise));
    }

    #[test]
    fn incompressible_chunks_store_raw_and_round_trip() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let src = scratch_dir();

        // Compressible file (>CDC threshold so it takes the per-file path).
        let text = src.join("text.txt");
        let text_payload = b"AeroVault incompressible-skip round trip. ".repeat(12_000);
        std::fs::write(&text, &text_payload).unwrap();

        // Incompressible file: high-entropy, also above the threshold.
        let noise = src.join("noise.bin");
        let mut noise_payload = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 500_000];
        let mut x = 0xdeadbeefcafef00du64;
        for b in noise_payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&noise, &noise_payload).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[
                (text.clone(), "text.txt".to_string()),
                (noise.clone(), "noise.bin".to_string()),
            ],
        )
        .unwrap();

        // Both representations must be present: the noise chunks are stored raw,
        // the text chunks are compressed.
        let any_raw = vault.manifest.chunks.values().any(|c| c.stored_raw);
        let any_compressed = vault.manifest.chunks.values().any(|c| !c.stored_raw);
        assert!(
            any_raw,
            "incompressible file should store at least one raw chunk"
        );
        assert!(
            any_compressed,
            "compressible file should store at least one zstd chunk"
        );
        // A raw chunk never stores more than its plaintext.
        for c in vault.manifest.chunks.values().filter(|c| c.stored_raw) {
            assert_eq!(c.compressed_len, c.plaintext_len);
        }

        // Decode honours the flag: both files come back byte-identical.
        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(std::fs::read(out.join("text.txt")).unwrap(), text_payload);
        assert_eq!(std::fs::read(out.join("noise.bin")).unwrap(), noise_payload);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn plaintext_lane_round_trip_and_unencrypted_storage() {
        // `.aerovz` (#7): no password, content + manifest stored unencrypted,
        // still compressed (+ EC available). create_empty_vault + add + extract.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        assert!(VaultV3::is_vault_v3(&vp));

        let src = scratch_dir();
        // A small (packed) file and a large compressible file (per-file CDC path).
        let small = src.join("note.txt");
        std::fs::write(&small, b"plaintext archive note").unwrap();
        let big = src.join("big.txt");
        let big_payload = b"Aerovz plaintext compressible body. ".repeat(20_000);
        std::fs::write(&big, &big_payload).unwrap();

        // Opens without any password (auto-detected via the header flag).
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        assert!(vault.header.flags & FLAG_PLAINTEXT_CONTENT != 0);
        assert!(manifest_is_plaintext(&vault.manifest));
        VaultV3::add_files(
            &mut vault,
            &[
                (small.clone(), "note.txt".to_string()),
                (big.clone(), "big.txt".to_string()),
            ],
        )
        .unwrap();
        drop(vault);

        // Reopen and extract byte-identical.
        let vault = VaultV3::open_plaintext(&vp).unwrap();
        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("note.txt")).unwrap(),
            b"plaintext archive note"
        );
        assert_eq!(std::fs::read(out.join("big.txt")).unwrap(), big_payload);

        // The data section is genuinely unencrypted: the compressed body of the
        // large file zstd-decodes straight off disk WITHOUT any key. We find the
        // big file's first stored block and decompress it.
        let raw = std::fs::read(&vp).unwrap();
        let big_entry = vault
            .manifest
            .entries
            .iter()
            .find(|e| e.path == "big.txt")
            .unwrap();
        let first_id = big_entry.chunks.first().unwrap();
        let rec = vault.manifest.chunks.get(first_id).unwrap();
        // `data_offset` is relative to the data section, which starts at
        // DATA_OFFSET in the file; +8 skips the block length prefix.
        let start = DATA_OFFSET as usize + rec.data_offset as usize + 8;
        let block = &raw[start..start + rec.block_len as usize];
        let decoded = zstd::stream::decode_all(block).unwrap();
        assert!(
            big_payload.starts_with(&decoded),
            "plaintext-lane block must zstd-decode off disk with no key"
        );

        // A plaintext archive has no password to change.
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        assert!(VaultV3::change_password(&mut vault, "irrelevant-pw-123").is_err());

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn open_with_password_refuses_plaintext_from_header_alone() {
        // A hostile plaintext container can declare a data section as large as
        // a sparse file, so the refusal must come before any payload is read.
        // Undecodable payload bytes show the header alone decided.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let mut bytes = std::fs::read(&vp).unwrap();
        bytes[HEADER_SIZE..].fill(0xA5);
        std::fs::write(&vp, &bytes).unwrap();
        assert_eq!(VaultV3::open(&vp, PW).unwrap_err(), PLAINTEXT_NOT_A_VAULT);
        crate::lock::remove_vault_and_lock(&vp);
    }

    #[test]
    fn open_with_password_rejects_plaintext_container() {
        // Someone who can replace the vault file swaps in a plaintext container
        // built with the public API. A password unlock must refuse it, whatever
        // the password, and leave the file untouched; only open_plaintext opens it.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        std::fs::remove_file(&vp).unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let before = std::fs::read(&vp).unwrap();

        for pw in [PW, "any other password", ""] {
            let err = VaultV3::open(&vp, pw).unwrap_err();
            assert_eq!(err, PLAINTEXT_NOT_A_VAULT);
        }
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        assert!(VaultV3::open_plaintext(&vp).is_ok());

        // An encrypted vault still opens with its password and only with it.
        let enc = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&enc, PW)).unwrap();
        assert!(VaultV3::open(&enc, PW).is_ok());
        assert!(VaultV3::open(&enc, "wrong-password-123").is_err());
        assert!(VaultV3::open_plaintext(&enc).is_err());

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_file(&enc).ok();
    }

    #[test]
    fn oversized_block_is_refused_at_write_not_sealed_unreadable() {
        // Custom CDC bounds may exceed MAX_BLOCK_SIZE, which readers refuse.
        // The write must fail and leave the vault as it was.
        let vp = vault_path();
        // min above the file size: the whole file is one chunk.
        let bounds = CdcBounds {
            min: 96 * 1024 * 1024,
            avg: 128 * 1024 * 1024,
            max: 128 * 1024 * 1024,
        };
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp).with_cdc_bounds(bounds)).unwrap();
        let src = scratch_dir();
        let big = src.join("big.bin");
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let data: Vec<u8> = (0..(MAX_BLOCK_SIZE as usize + 1024 * 1024))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        std::fs::write(&big, &data).unwrap();
        drop(data);
        let small = src.join("small.bin");
        std::fs::write(&small, b"original").unwrap();
        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        VaultV3::add_files(&mut vault, &[(small, "big.bin".to_string())]).unwrap();
        let before = std::fs::read(&vp).unwrap();

        // The rejected replacement leaves the file and the open handle intact:
        // a later write on the same handle must not persist a removal.
        let err = VaultV3::add_files(&mut vault, &[(big, "big.bin".to_string())]).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
        assert_eq!(std::fs::read(&vp).unwrap(), before);
        VaultV3::create_directory(&mut vault, "after").unwrap();
        drop(vault);
        let vault = VaultV3::open_plaintext(&vp).unwrap();
        let out = VaultV3::extract_entry(&vault, "big.bin", &src.join("out")).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"original");

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn create_options_decouple_zstd_level_from_cdc_bounds() {
        let vp = vault_path();
        let opts = CreateOptionsV3::new_plaintext(&vp)
            .with_zstd_level(19)
            .with_cdc_bounds(CdcBounds::defaults());
        VaultV3::create(&opts).unwrap();

        let vault = VaultV3::open_plaintext(&vp).unwrap();
        let bounds = manifest_cdc_bounds(&vault.manifest).unwrap();
        let defaults = CdcBounds::defaults();
        assert_eq!(manifest_zstd_level(&vault.manifest), 19);
        assert_eq!(bounds.min, defaults.min);
        assert_eq!(bounds.avg, defaults.avg);
        assert_eq!(bounds.max, defaults.max);

        crate::lock::remove_vault_and_lock(&vp);
    }

    #[test]
    fn plaintext_lane_stored_raw_composition() {
        // stored_raw (#10-B) composes with the plaintext lane: an incompressible
        // chunk is stored BOTH raw AND unencrypted, and still round-trips.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let src = scratch_dir();
        let noise = src.join("noise.bin");
        let mut noise_payload = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 400_000];
        let mut x = 0x1234_5678_9abc_def0u64;
        for b in noise_payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&noise, &noise_payload).unwrap();

        let mut vault = VaultV3::open_plaintext(&vp).unwrap();
        VaultV3::add_files(&mut vault, &[(noise.clone(), "noise.bin".to_string())]).unwrap();
        assert!(
            vault.manifest.chunks.values().any(|c| c.stored_raw),
            "incompressible input should store raw chunks"
        );
        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(std::fs::read(out.join("noise.bin")).unwrap(), noise_payload);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    #[cfg(feature = "test-vectors")]
    fn plaintext_empty_archive_is_deterministic() {
        // The plaintext lane has zero randomness (no salt, no random keys, fixed
        // public MAC key) and, under `test-vectors`, a fixed timestamp — so an
        // empty `.aerovz` is byte-deterministic. Freeze its digest to catch any
        // accidental layout drift in the plaintext header/manifest path.
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp)).unwrap();
        let bytes = std::fs::read(&vp).unwrap();
        let digest = blake3::hash(&bytes).to_hex().to_string();
        let vp2 = vault_path();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&vp2)).unwrap();
        assert_eq!(
            digest,
            blake3::hash(&std::fs::read(&vp2).unwrap())
                .to_hex()
                .to_string(),
            "empty plaintext archive must be byte-deterministic"
        );
        crate::lock::remove_vault_and_lock(&vp);
        crate::lock::remove_vault_and_lock(&vp2);
    }

    #[derive(Default)]
    struct CountingSink {
        chunks_new: u64,
        chunks_dedup: u64,
        files_packed: u64,
        files_unpacked: u64,
        packs: u64,
        cdc_set: bool,
        steps: Vec<String>,
        plaintext: u64,
    }

    impl super::super::telemetry::VaultTelemetrySink
        for std::sync::Arc<std::sync::Mutex<CountingSink>>
    {
        fn on_chunk(&mut self, is_new: bool, plaintext: u64, _c: u64, _e: u64) {
            let mut g = self.lock().unwrap();
            if is_new {
                g.chunks_new += 1;
            } else {
                g.chunks_dedup += 1;
            }
            g.plaintext += plaintext;
        }
        fn on_file(&mut self, packed: bool) {
            let mut g = self.lock().unwrap();
            if packed {
                g.files_packed += 1;
            } else {
                g.files_unpacked += 1;
            }
        }
        fn on_pack(&mut self) {
            self.lock().unwrap().packs += 1;
        }
        fn set_cdc(&mut self, _min: usize, _avg: usize, _max: usize) {
            self.lock().unwrap().cdc_set = true;
        }
        fn step(&mut self, message: &str) {
            self.lock().unwrap().steps.push(message.to_string());
        }
    }

    #[test]
    fn telemetry_sink_receives_content_pipeline_events() {
        // An attached sink must observe the same events the app historically
        // inlined: per-chunk, per-file (packed vs per-file), per-pack, CDC bounds,
        // and step lines. With no sink the bytes are unchanged (T5 golden).
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let src = scratch_dir();
        // Two small files (packed path) + one large file (per-file CDC path).
        std::fs::write(src.join("s1.txt"), b"small one").unwrap();
        std::fs::write(src.join("s2.txt"), b"small two differs").unwrap();
        let large = src.join("big.bin");
        let mut payload = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 200_000];
        let mut x = 0xfeed_face_dead_beefu64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        std::fs::write(&large, &payload).unwrap();

        let sink = std::sync::Arc::new(std::sync::Mutex::new(CountingSink::default()));
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        vault.set_telemetry_sink(Box::new(sink.clone()));
        VaultV3::add_files(
            &mut vault,
            &[
                (src.join("s1.txt"), "s1.txt".to_string()),
                (src.join("s2.txt"), "s2.txt".to_string()),
                (large.clone(), "big.bin".to_string()),
            ],
        )
        .unwrap();
        drop(vault);

        let g = sink.lock().unwrap();
        assert!(g.cdc_set, "CDC bounds reported");
        assert_eq!(g.packs, 1, "one pack for the two small files");
        assert_eq!(g.files_packed, 2, "two small files via the packed path");
        assert_eq!(g.files_unpacked, 1, "one large file via the per-file path");
        assert!(
            g.chunks_new >= 2,
            "at least the pack chunk + a large-file chunk"
        );
        assert!(
            g.steps.iter().any(|s| s.starts_with("scan:"))
                && g.steps.iter().any(|s| s.starts_with("partition:"))
                && g.steps.iter().any(|s| s.starts_with("pack:")),
            "scan / partition / pack step lines present: {:?}",
            g.steps
        );
        assert!(g.plaintext > 0);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn dedup_same_content_stored_once() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let src = scratch_dir();
        // Large identical content under two names -> CDC path -> deduped chunks.
        let mut payload = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 300_000];
        let mut x = 0x1234_5678_9abc_def0u64;
        for b in payload.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        let f1 = src.join("one.bin");
        let f2 = src.join("two.bin");
        std::fs::write(&f1, &payload).unwrap();
        std::fs::write(&f2, &payload).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[
                (f1.clone(), "one.bin".to_string()),
                (f2.clone(), "two.bin".to_string()),
            ],
        )
        .unwrap();

        // Two entries, but the logical chunk references exceed the stored chunks.
        let entries = &vault.manifest.entries;
        let total_refs: usize = entries.iter().map(|e| e.chunks.len()).sum();
        let stored = vault.manifest.chunks.len();
        assert!(total_refs > stored, "dedup must collapse identical content");
        // Both files reference the exact same chunk id set.
        let c1: Vec<&String> = entries
            .iter()
            .find(|e| e.path == "one.bin")
            .unwrap()
            .chunks
            .iter()
            .collect();
        let c2: Vec<&String> = entries
            .iter()
            .find(|e| e.path == "two.bin")
            .unwrap()
            .chunks
            .iter()
            .collect();
        assert_eq!(c1, c2);

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn copy_reuses_chunks_move_rename_delete() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let src = scratch_dir();
        std::fs::write(src.join("doc.txt"), b"hello world copy").unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::create_directory(&mut vault, "src").unwrap();
        VaultV3::add_files(
            &mut vault,
            &[(src.join("doc.txt"), "src/doc.txt".to_string())],
        )
        .unwrap();

        let chunks_before = vault.manifest.chunks.len();
        VaultV3::copy_entry(&mut vault, "src/doc.txt", "src/doc-copy.txt").unwrap();
        // Copy reuses chunk records: no new chunks stored.
        assert_eq!(vault.manifest.chunks.len(), chunks_before);
        assert!(VaultV3::list(&vault)
            .iter()
            .any(|e| e.path == "src/doc-copy.txt"));

        // Move directory updates descendants.
        VaultV3::move_entry(&mut vault, "src", "moved").unwrap();
        let paths: Vec<String> = VaultV3::list(&vault).into_iter().map(|e| e.path).collect();
        assert!(paths.contains(&"moved".to_string()));
        assert!(paths.contains(&"moved/doc.txt".to_string()));
        assert!(!paths.iter().any(|p| p.starts_with("src")));

        // Rename within parent.
        VaultV3::rename_entry(&mut vault, "moved/doc.txt", "renamed.txt").unwrap();
        assert!(VaultV3::list(&vault)
            .iter()
            .any(|e| e.path == "moved/renamed.txt"));

        // Delete then re-open round-trips.
        VaultV3::delete_entries(&mut vault, &["moved".to_string()], true).unwrap();
        assert!(VaultV3::list(&vault).is_empty());
        drop(vault);

        let reopened = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::list(&reopened).is_empty());

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn change_password_old_fails_new_opens() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, "old-password-123")).unwrap();
        let src = scratch_dir();
        std::fs::write(src.join("x.txt"), b"keep me").unwrap();

        let mut vault = VaultV3::open(&vp, "old-password-123").unwrap();
        VaultV3::add_files(&mut vault, &[(src.join("x.txt"), "x.txt".to_string())]).unwrap();
        VaultV3::change_password(&mut vault, "new-password-456").unwrap();
        drop(vault);

        assert!(VaultV3::open(&vp, "old-password-123").is_err());
        let v2 = VaultV3::open(&vp, "new-password-456").unwrap();
        assert!(VaultV3::list(&v2).iter().any(|e| e.path == "x.txt"));

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn add_directory_recursive_round_trip() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let tree = scratch_dir();
        std::fs::create_dir_all(tree.join("nested/deep")).unwrap();
        std::fs::write(tree.join("top.txt"), b"top file").unwrap();
        std::fs::write(tree.join("nested/mid.txt"), b"mid file").unwrap();
        std::fs::write(tree.join("nested/deep/bottom.txt"), b"bottom file").unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let (files, _dirs) = VaultV3::add_directory(&mut vault, &tree, Some("imported")).unwrap();
        assert_eq!(files, 3);

        let out = scratch_dir();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("imported/top.txt")).unwrap(),
            b"top file"
        );
        assert_eq!(
            std::fs::read(out.join("imported/nested/deep/bottom.txt")).unwrap(),
            b"bottom file"
        );

        crate::lock::remove_vault_and_lock(&vp);
        std::fs::remove_dir_all(&tree).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn path_normalization_rejects_traversal() {
        assert!(normalize_vault_relative_path("..").is_err());
        assert!(normalize_vault_relative_path("../etc/passwd").is_err());
        assert!(normalize_vault_relative_path("a/../b").is_err());
        assert!(normalize_vault_relative_path("a/./b").is_err());
        assert!(normalize_vault_relative_path("a\\b").is_err());
        assert!(normalize_vault_relative_path("C:\\x").is_err());
        assert!(normalize_vault_relative_path("a/b/c").is_ok());
        // Faithful to the app: leading '/' is trimmed, not rejected, so an
        // absolute-looking path normalizes to a vault-relative one.
        assert_eq!(
            normalize_vault_relative_path("/etc/passwd").unwrap(),
            "etc/passwd"
        );
    }

    #[test]
    fn extract_rejects_crafted_traversal_entry() {
        // No crypto / no Argon2: craft an OpenVaultV3 by hand with a malicious
        // manifest path and prove extract refuses it via normalization.
        let mut manifest = empty_manifest(DEFAULT_ZSTD_LEVEL);
        manifest.entries.push(ManifestEntryV3 {
            path: "../escape.txt".to_string(),
            size: 0,
            modified: now_iso(),
            is_dir: false,
            chunks: Vec::new(),
            pack_offset: None,
        });
        let vault = OpenVaultV3 {
            path: PathBuf::from("/tmp/none.aerovault"),
            header: VaultHeaderV3 {
                flags: 0,
                salt: [0u8; SALT_SIZE],
                wrapped_master_key: [0u8; crate::aerocrypt::WRAPPED_KEY_SIZE],
                wrapped_mac_key: [0u8; crate::aerocrypt::WRAPPED_KEY_SIZE],
                data_offset: DATA_OFFSET,
                data_len: 0,
                manifest_offset: DATA_OFFSET,
                manifest_len: 0,
                extension_dir_offset: DATA_OFFSET,
                extension_dir_len: 0,
                extension_payload_offset: DATA_OFFSET,
                extension_payload_len: 0,
                wrapper_header_version: 1,
                header_mac: [0u8; MAC_SIZE],
            },
            opened_file_len: 0,
            opened_hash: [0u8; 32],
            limits: VaultV3Limits::default(),
            master_key: [0u8; KEY_SIZE],
            mac_key: [0u8; KEY_SIZE],
            manifest,
            extensions: Vec::new(),
            data: Vec::new(),
            manifest_repaired_on_open: false,
            header_repaired_on_open: false,
            telemetry: None,
        };
        let out = scratch_dir();
        assert!(VaultV3::extract_entry(&vault, "../escape.txt", &out).is_err());
        std::fs::remove_dir_all(&out).ok();
    }

    /// Audit M2 regression: a pre-planted intermediate reparse point in the
    /// destination (a directory that is really a junction/symlink to a sibling
    /// "victim") must not let extraction write decrypted plaintext outside the
    /// chosen root. Build a real sealed vault with a nested entry `sub/secret.txt`,
    /// plant `dest/sub -> victim`, then assert `extract_all` fails closed and the
    /// victim directory stays empty. (Junctions need no admin on Windows.)
    #[test]
    fn extract_refuses_planted_reparse_point_parent() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

        let src = scratch_dir();
        let secret = src.join("secret.txt");
        let secret_bytes = b"TOP SECRET PLAINTEXT THAT MUST STAY CONTAINED";
        std::fs::write(&secret, secret_bytes).unwrap();

        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[(secret.clone(), "sub/secret.txt".to_string())],
        )
        .unwrap();

        let dest = scratch_dir();
        let victim = scratch_dir();
        // Plant `dest/sub` as a reparse point pointing at `victim`.
        let link = dest.join("sub");
        let planted = plant_dir_reparse_point(&link, &victim);
        if !planted {
            // Environment cannot create a junction/symlink (e.g. Developer Mode off and
            // no junction support); skip rather than give a false pass.
            eprintln!("skipping extract_refuses_planted_reparse_point_parent: no reparse support");
            std::fs::remove_dir_all(&dest).ok();
            std::fs::remove_dir_all(&victim).ok();
            crate::lock::remove_vault_and_lock(&vp);
            return;
        }

        let result = VaultV3::extract_all(&vault, &dest);
        assert!(
            result.is_err(),
            "extract must fail closed on a planted reparse-point parent, got {result:?}"
        );
        // The decrypted plaintext must NOT have been written through the junction.
        assert!(
            !victim.join("secret.txt").exists(),
            "plaintext escaped the destination root into the victim directory"
        );

        std::fs::remove_dir_all(&dest).ok();
        std::fs::remove_dir_all(&victim).ok();
        std::fs::remove_dir_all(&src).ok();
        crate::lock::remove_vault_and_lock(&vp);
    }

    /// Audit M4: a forged extension directory (duplicate id, or a payload slice that
    /// escapes the authenticated extension payload, or a critical extension) must be
    /// rejected at validation time. The header MAC covers the directory offset/len but
    /// not its bytes, so this is the open-time fail-closed gate.
    #[test]
    fn validate_extension_dir_rejects_forged_entries() {
        let ok = ExtensionEntryV3 {
            extension_id: "error-correction.reed-solomon".to_string(),
            algorithm_id: "rs".to_string(),
            algorithm_version: 1,
            critical: false,
            offset: 0,
            length: 100,
        };
        assert!(validate_extension_dir(std::slice::from_ref(&ok), 100).is_ok());

        // Payload slice escapes the declared extension-payload length.
        let mut oob = ok.clone();
        oob.length = 101;
        assert!(validate_extension_dir(std::slice::from_ref(&oob), 100).is_err());

        // offset + length overflow.
        let mut overflow = ok.clone();
        overflow.offset = u64::MAX;
        overflow.length = 1;
        assert!(validate_extension_dir(std::slice::from_ref(&overflow), 100).is_err());

        // Duplicate extension ids.
        assert!(validate_extension_dir(&[ok.clone(), ok.clone()], 1000).is_err());

        // Critical (unknown) extension is rejected.
        let mut critical = ok.clone();
        critical.critical = true;
        assert!(validate_extension_dir(std::slice::from_ref(&critical), 100).is_err());
    }

    /// Audit M2 residual (controaudit): the single-entry `extract_entry` directory
    /// path builds its subtree root from a manifest-derived basename. A pre-planted
    /// junction at `dest/<basename>` must be refused, not followed into a victim.
    #[test]
    fn extract_entry_dir_refuses_planted_output_root_junction() {
        let vp = vault_path();
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

        let src = scratch_dir();
        let secret = src.join("secret.txt");
        std::fs::write(&secret, b"TOP SECRET PLAINTEXT THAT MUST STAY CONTAINED").unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        VaultV3::add_files(
            &mut vault,
            &[(secret.clone(), "sub/secret.txt".to_string())],
        )
        .unwrap();

        let dest = scratch_dir(); // exists & is a dir -> output_root = dest/sub
        let victim = scratch_dir();
        let link = dest.join("sub"); // the manifest-derived basename component
        if !plant_dir_reparse_point(&link, &victim) {
            eprintln!("skipping extract_entry_dir_refuses_planted_output_root_junction: no reparse support");
            std::fs::remove_dir_all(&dest).ok();
            std::fs::remove_dir_all(&victim).ok();
            crate::lock::remove_vault_and_lock(&vp);
            return;
        }

        let result = VaultV3::extract_entry(&vault, "sub", &dest);
        assert!(
            result.is_err(),
            "extract_entry must fail closed on a planted output_root junction, got {result:?}"
        );
        assert!(
            !victim.join("secret.txt").exists(),
            "plaintext escaped into the victim via extract_entry"
        );

        std::fs::remove_dir_all(&dest).ok();
        std::fs::remove_dir_all(&victim).ok();
        std::fs::remove_dir_all(&src).ok();
        crate::lock::remove_vault_and_lock(&vp);
    }

    /// Plant `link` as a directory reparse point targeting `target`. Returns false
    /// if the platform/environment cannot create one (caller then skips).
    #[cfg(windows)]
    fn plant_dir_reparse_point(link: &Path, target: &Path) -> bool {
        // `mklink /J` creates a directory junction and needs no admin / Developer Mode.
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        matches!(status, Ok(s) if s.success()) && link.exists()
    }

    #[cfg(not(windows))]
    fn plant_dir_reparse_point(link: &Path, target: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok() && link.exists()
    }

    #[test]
    fn review_detached_parity_published_before_mutation_lock_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            crate::v3::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let source = dir.path().join("data");
        std::fs::write(&source, vec![7u8; 200_000]).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        VaultV3::add_files(&mut vault, &[(source.clone(), "first".to_string())]).unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let sidecar = super::super::ec::default_sidecar_path(&path);
        let recovery = std::fs::read(&sidecar).unwrap();
        std::fs::remove_file(&sidecar).unwrap();
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[DATA_OFFSET as usize + 20] ^= 1;
        std::fs::write(&path, &damaged).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        let out = sidecar.clone();
        let bytes = recovery.clone();
        BEFORE_MUTATION_SIDECAR_LOCK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let _publisher = crate::lock::acquire(&out).unwrap();
                atomic_write(&out, &bytes).unwrap();
            }))
        });
        let error = VaultV3::add_files(&mut vault, &[(source, "second".to_string())]).unwrap_err();
        assert!(error.contains("damaged blocks"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
        assert_eq!(std::fs::read(&sidecar).unwrap(), recovery);
        assert!(VaultV3::repair(&mut vault, false, None).unwrap().0 > 0);
    }

    #[test]
    fn review_default_sidecar_cannot_be_published_during_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staged.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        let sidecar = super::super::ec::default_sidecar_path(&path);
        IN_SAVE_WINDOW.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let error = std::thread::spawn(move || {
                    crate::lock::set_short_wait_for_this_thread();
                    crate::lock::acquire(&sidecar).unwrap_err().to_string()
                })
                .join()
                .unwrap();
                assert!(error.contains("locked by another writer"), "{error}");
            }))
        });
        VaultV3::create_directory(&mut vault, "committed").unwrap();
    }
    #[test]
    fn review_chunk_identity_is_rejected_at_open_and_seal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"identity content").unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut vault, &[(source, "item".to_string())]).unwrap();
        let before = std::fs::read(&path).unwrap();
        let record = vault.manifest.chunks.values_mut().next().unwrap();
        let mut id = record.id.clone().into_bytes();
        id[0] = if id[0] == b'a' { b'b' } else { b'a' };
        record.id = String::from_utf8(id).unwrap();
        let guard = write_lock(&path).unwrap();
        assert!(save_locked(&mut vault, &guard)
            .unwrap_err()
            .contains("identity"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(guard);
        let altered = serde_json::to_vec(&vault.manifest).unwrap();
        assert_eq!(altered.len() as u64, vault.header.manifest_len);
        let mut bytes = before;
        let offset = vault.header.manifest_offset as usize;
        bytes[offset..offset + altered.len()].copy_from_slice(&altered);
        std::fs::write(&path, bytes).unwrap();
        assert!(VaultV3::open_plaintext(&path)
            .unwrap_err()
            .contains("identity"));
    }
    #[test]
    fn review_create_and_rotate_refuse_automatic_sidecar_collisions() {
        use super::super::ec::{default_sidecar_path, RecoveryPlacement};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.aerovault");
        let sidecar = default_sidecar_path(&path);
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let original = std::fs::read(&path).unwrap();
        std::fs::create_dir(&sidecar).unwrap();
        for placement in [RecoveryPlacement::Detached, RecoveryPlacement::Both] {
            assert!(VaultV3::create_with_error_correction(
                &CreateOptionsV3::new(&path, PW),
                placement,
                20
            )
            .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        std::fs::remove_dir(&sidecar).unwrap();
        VaultV3::create(&CreateOptionsV3::new(&sidecar, PW)).unwrap();
        let foreign = std::fs::read(&sidecar).unwrap();
        assert!(VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Both,
            20
        )
        .is_err());
        let mut vault = VaultV3::open(&path, PW).unwrap();
        assert!(VaultV3::change_password(&mut vault, "new-password-123").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read(&sidecar).unwrap(), foreign);
        assert!(VaultV3::open(&path, PW).is_ok());
        assert!(VaultV3::open(&sidecar, PW).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn review_windows_short_name_rotation_refreshes_long_name_sidecar() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetShortPathNameW(long: *const u16, short: *mut u16, capacity: u32) -> u32;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("long-owned-vault-namespace.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            super::super::ec::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let long = std::fs::canonicalize(&path).unwrap();
        let wide: Vec<u16> = long.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut buf = vec![0u16; 32768];
        let len = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
            as usize;
        assert!(
            len > 0 && len < buf.len(),
            "GetShortPathNameW failed: {}",
            std::io::Error::last_os_error()
        );
        let short = PathBuf::from(std::ffi::OsString::from_wide(&buf[..len]));
        let short_leaf = short.file_name().unwrap();
        if short_leaf
            .to_string_lossy()
            .eq_ignore_ascii_case(&long.file_name().unwrap().to_string_lossy())
        {
            eprintln!("8.3 vault leaf unavailable on this volume; native alias case skipped");
            return;
        }
        // Keep the long parent so this regression must exercise an aliased
        // vault leaf, independently of any short name on a parent directory.
        let short = long.with_file_name(short_leaf);
        VaultV3::export_parity(&long, PW, None).unwrap();
        let status = VaultV3::recovery_status(&short).unwrap();
        let long_status = VaultV3::recovery_status(&long).unwrap();
        assert!(
            long_status.detached && long_status.manifest_parity && long_status.header_parity,
            "{long_status:?}"
        );
        assert_eq!(status, long_status);
        let sidecar = super::super::ec::default_sidecar_path(&long);
        let before = std::fs::read(&sidecar).unwrap();
        let mut vault = VaultV3::open(&short, PW).unwrap();
        assert_eq!(vault.path, long);
        VaultV3::change_password(&mut vault, "new-password-123").unwrap();
        assert_ne!(std::fs::read(&sidecar).unwrap(), before);
        let mut damaged = std::fs::read(&long).unwrap();
        damaged[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&long, damaged).unwrap();
        assert!(VaultV3::open(&long, PW).is_err());
        assert!(
            VaultV3::open(&long, "new-password-123")
                .unwrap()
                .header_repaired_on_open
        );
        eprintln!(
            "8.3 vault leaf exercised: {short_leaf:?}; sidecar and password recovery verified"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_manifest_recovery_retry_releases_first_data_buffer_under_memory_limit() {
        const KEY: &str = "AEROVAULT_MANIFEST_RETRY_MEMORY_PATH";
        const DATA_LEN: usize = 768 * 1024 * 1024;
        if let Some(path) = std::env::var_os(KEY) {
            crate::source::memory_test::limit();
            let opened = VaultV3::open_plaintext(PathBuf::from(path)).unwrap();
            assert!(opened.manifest_repaired_on_open);
            assert_eq!(opened.data.len(), DATA_LEN);
            assert_eq!(opened.data[0], 0);
            assert_eq!(opened.data[DATA_LEN - 1], 0);
            crate::source::memory_test::complete();
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-manifest.aerozip");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new_plaintext(&path),
            super::super::ec::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        vault.data.resize(DATA_LEN, 0);
        save_open_vault(&mut vault).unwrap();
        let manifest_at = vault.header.manifest_offset;
        drop(vault);
        VaultV3::export_parity(&path, "", None).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut byte = [0];
        file.seek(std::io::SeekFrom::Start(manifest_at)).unwrap();
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xff;
        file.seek(std::io::SeekFrom::Start(manifest_at)).unwrap();
        std::io::Write::write_all(&mut file, &byte).unwrap();
        drop(file);
        crate::source::memory_test::run(
            "v3::vault::tests::review_manifest_recovery_retry_releases_first_data_buffer_under_memory_limit", KEY, &path,
        );
    }

    #[test]
    fn review_reader_past_journal_check_cannot_recover_old_password_mid_rotation() {
        use super::super::ec::RecoveryPlacement;
        for placement in [RecoveryPlacement::Detached, RecoveryPlacement::Both] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("reader-race.aerovault");
            VaultV3::create_with_error_correction(&CreateOptionsV3::new(&path, PW), placement, 20)
                .unwrap();
            VaultV3::export_parity(&path, PW, None).unwrap();
            let mut vault = VaultV3::open(&path, PW).unwrap();
            std::thread::scope(|scope| {
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let (resume_tx, resume_rx) = std::sync::mpsc::channel();
                let (result_tx, result_rx) = std::sync::mpsc::channel();
                let reader_path = path.clone();
                let reader = scope.spawn(move || {
                    crate::lock::set_short_wait_for_this_thread();
                    AFTER_OPEN_RECOVERY_CHECK.with(|h| {
                        *h.borrow_mut() = Some(Box::new(move || {
                            ready_tx.send(()).unwrap();
                            resume_rx
                                .recv_timeout(std::time::Duration::from_secs(10))
                                .unwrap();
                        }));
                    });
                    let result = VaultV3::open(&reader_path, PW).map(|v| v.header_repaired_on_open);
                    result_tx.send(result.clone()).unwrap();
                    result
                });
                ready_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
                super::super::strip_transaction::AFTER_STRIP_VAULT.with(|h| {
                    *h.borrow_mut() = Some(Box::new(move || {
                        resume_tx.send(()).unwrap();
                        let error = result_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .unwrap()
                            .unwrap_err();
                        assert!(error.contains("locked by another writer"), "{error}");
                    }));
                });
                VaultV3::change_password(&mut vault, "new-password-123").unwrap();
                assert!(reader.join().unwrap().is_err());
            });
            assert!(VaultV3::open(&path, PW).is_err());
            assert!(VaultV3::open(&path, "new-password-123").is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn round7d_alias_manifest_failure_checks_late_physical_journal() {
        use super::super::{ec, strip_transaction as tx};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("physical.aerovault");
        let alias = dir.path().join("alias.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            ec::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let at = VaultV3::open(&path, PW).unwrap().header.manifest_offset as usize;
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[at] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        let mut rotating = VaultV3::open(&path, PW).unwrap();
        assert!(rotating.manifest_repaired_on_open);
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(!ec::recovery_sidecar_path(&alias).exists());
        assert_ne!(tx::journal_path(&alias), tx::journal_path(&path));
        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let reader_alias = alias.clone();
            let reader = scope.spawn(move || {
                crate::lock::set_short_wait_for_this_thread();
                AFTER_OPEN_RECOVERY_CHECK.with(|h| {
                    *h.borrow_mut() = Some(Box::new(move || {
                        ready_tx.send(()).unwrap();
                        resume_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .unwrap();
                    }));
                });
                let result = VaultV3::open(&reader_alias, PW).map(|_| ());
                result_tx.send(result.clone()).unwrap();
                result
            });
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            let pending = tx::journal_path(&path);
            tx::AFTER_STRIP_JOURNAL.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || {
                    assert!(pending.is_dir());
                    resume_tx.send(()).unwrap();
                    let error = result_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .unwrap()
                        .unwrap_err();
                    assert!(error.contains("locked by another writer"), "{error}");
                }));
            });
            VaultV3::change_password(&mut rotating, "new-password-123").unwrap();
            assert!(reader.join().unwrap().is_err());
        });
        assert!(VaultV3::open(&alias, PW).is_err());
        assert!(VaultV3::open(&alias, "new-password-123").is_ok());
        assert!(!tx::journal_path(&path).exists());
    }

    #[test]
    fn review_plaintext_specific_error_requires_public_mac_even_for_empty_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        for password in ["", PW] {
            assert_eq!(
                VaultV3::open(&path, password).unwrap_err(),
                PLAINTEXT_NOT_A_VAULT
            );
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        for password in ["", PW] {
            assert_ne!(
                VaultV3::open(&path, password).unwrap_err(),
                PLAINTEXT_NOT_A_VAULT
            );
        }
        assert!(VaultV3::open_plaintext(&path).unwrap_err().contains("MAC"));
    }

    #[test]
    fn review_section_caps_reject_in_file_ranges_before_generation_scan() {
        let dir = tempfile::tempdir().unwrap();
        for (name, cap) in [
            ("manifest", MAX_MANIFEST_SIZE),
            ("extension", MAX_EXTENSION_DIR_SIZE),
        ] {
            let path = dir.path().join(format!("{name}.aerozip"));
            VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let mut header = VaultHeaderV3::from_bytes(&bytes[..HEADER_SIZE]).unwrap();
            if name == "manifest" {
                header.manifest_len = cap + 1;
            } else {
                header.extension_dir_len = cap + 1;
            }
            let len =
                header.manifest_offset + header.manifest_len + header.extension_dir_len + 4096;
            header.header_mac = header.compute_mac(&aerovz_mac_key().unwrap()).unwrap();
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(len).unwrap();
            std::io::Write::write_all(&mut file, &header.to_bytes()).unwrap();
            drop(file);
            crate::lock::take_trace();
            assert!(VaultV3::open_plaintext(&path)
                .unwrap_err()
                .contains("size limit"));
            assert!(!crate::lock::take_trace().contains(&"generation"));
        }
    }

    #[test]
    fn review_password_rotation_recovers_after_first_pair_replacement() {
        const KEY: &str = "AEROVAULT_PASSWORD_RESTART_DIR";
        const NEW_PW: &str = "new-password-restart-123";
        if let Some(root) = std::env::var_os(KEY) {
            let path = PathBuf::from(root).join("restart.aerovault");
            super::super::strip_transaction::AFTER_STRIP_VAULT
                .with(|h| *h.borrow_mut() = Some(Box::new(|| std::process::exit(77))));
            let mut vault = VaultV3::open(&path, PW).unwrap();
            VaultV3::change_password(&mut vault, NEW_PW).unwrap();
            panic!("rotation interruption hook was not reached");
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                self.0.kill().ok();
                self.0.wait().ok();
            }
        }
        for placement in [
            super::super::ec::RecoveryPlacement::Detached,
            super::super::ec::RecoveryPlacement::Both,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("restart.aerovault");
            VaultV3::create_with_error_correction(&CreateOptionsV3::new(&path, PW), placement, 20)
                .unwrap();
            let payload = dir.path().join("payload");
            std::fs::write(&payload, b"protected content").unwrap();
            let mut vault = VaultV3::open(&path, PW).unwrap();
            VaultV3::add_files(&mut vault, &[(payload, "payload".into())]).unwrap();
            drop(vault);
            VaultV3::export_parity(&path, PW, None).unwrap();
            let sidecar = super::super::ec::default_sidecar_path(&path);
            let old_vault = std::fs::read(&path).unwrap();
            let old_sidecar = std::fs::read(&sidecar).unwrap();
            let mut child = Child(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "v3::vault::tests::review_password_rotation_recovers_after_first_pair_replacement", "--nocapture"])
                .env(KEY, dir.path()).spawn().unwrap());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "rotation child timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(77));
            assert!(super::super::strip_transaction::journal_path(&path).exists());
            assert_eq!(std::fs::read(&sidecar).unwrap(), old_sidecar);
            // An interrupted rotation rolls back before any password is tried.
            let mut recovered = VaultV3::open(&path, PW).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), old_vault);
            assert!(!super::super::strip_transaction::journal_path(&path).exists());
            assert!(VaultV3::open(&path, NEW_PW).is_err());
            VaultV3::change_password(&mut recovered, NEW_PW).unwrap();
            drop(recovered);
            // A completed rotation cannot resurrect the old password through parity.
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[super::super::constants::HEADER_MAC_OFFSET] ^= 1;
            std::fs::write(&path, bytes).unwrap();
            assert!(VaultV3::open(&path, PW).is_err());
            assert!(
                VaultV3::open(&path, NEW_PW)
                    .unwrap()
                    .header_repaired_on_open
            );
        }
    }

    #[test]
    fn round6_wrong_password_without_recovery_does_not_wait_for_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-recovery.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let expected = VaultV3::open(&path, "wrong-password-123").err().unwrap();
        let _guard = crate::lock::acquire(&path).unwrap();
        crate::lock::set_short_wait_for_this_thread();
        crate::lock::take_trace();
        let actual = VaultV3::open(&path, "wrong-password-123").err().unwrap();
        assert_eq!(actual, expected);
        assert!(!actual.contains("locked"));
        let events = crate::lock::take_trace();
        assert!(!events.contains(&"lock"), "{events:?}");
        assert_eq!(
            events.iter().filter(|&&e| e == "derive").count(),
            1,
            "{events:?}"
        );
    }

    #[test]
    fn round6_directory_import_excludes_only_held_lock_identities() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let path = source.join("inside.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        std::fs::write(source.join("ordinary.txt"), b"ordinary data").unwrap();
        std::fs::write(source.join("unrelated.aerolock"), b"ordinary named file").unwrap();
        let held = crate::lock::lock_path(&path);
        let add_links = |link: fn(&Path, &Path) -> std::io::Result<()>| {
            link(&held, &source.join("held-alias"))?;
            link(&source.join("ordinary.txt"), &source.join("ordinary-alias"))
        };
        #[cfg(unix)]
        let tested_links = {
            add_links(|from, to| std::os::unix::fs::symlink(from, to)).unwrap();
            true
        };
        #[cfg(windows)]
        let tested_links = match add_links(|from, to| std::os::windows::fs::symlink_file(from, to))
        {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!("Windows symlink creation unavailable: {e}");
                false
            }
            Err(e) => panic!("Create Windows import symlinks: {e}"),
        };
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_directory(&mut vault, &source, None).unwrap();
        let reopened = VaultV3::open_plaintext(&path).unwrap();
        let entries = VaultV3::list(&reopened);
        assert!(entries.iter().any(|e| e.path == "ordinary.txt"));
        assert!(entries.iter().any(|e| e.path == "unrelated.aerolock"));
        assert!(!entries.iter().any(|e| e.path == "held-alias"));
        if tested_links {
            assert!(entries.iter().any(|e| e.path == "ordinary-alias"));
        }
        for held in [&path, &super::super::ec::default_sidecar_path(&path)] {
            let name = crate::lock::lock_path(held).file_name().unwrap().to_owned();
            assert!(!entries.iter().any(|e| e.path == name.to_string_lossy()));
        }
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let dest = VaultV3::extract_entry(&reopened, "ordinary.txt", &out).unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), b"ordinary data");
    }

    #[test]
    fn round6_detached_create_failure_restores_original_pair_or_absence() {
        use super::super::ec::{default_sidecar_path, RecoveryPlacement};
        for placement in [RecoveryPlacement::Detached, RecoveryPlacement::Both] {
            for existing in [false, true] {
                for had_sidecar in [false, true] {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("create.aerovault");
                    let sidecar = default_sidecar_path(&path);
                    if existing {
                        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
                        let input = dir.path().join("input");
                        std::fs::write(&input, b"keep original").unwrap();
                        let mut v = VaultV3::open(&path, PW).unwrap();
                        VaultV3::add_files(&mut v, &[(input, "original".into())]).unwrap();
                    }
                    if had_sidecar {
                        let seed = super::super::ec::empty_sidecar_bytes(b"prior source");
                        std::fs::write(&sidecar, seed).unwrap();
                    }
                    let old_vault = std::fs::read(&path).ok();
                    let old_sidecar = std::fs::read(&sidecar).ok();
                    let source = path.clone();
                    super::super::strip_transaction::AFTER_STRIP_VAULT.with(|h| {
                        *h.borrow_mut() = Some(Box::new(move || {
                            let journal = super::super::strip_transaction::journal_path(&source);
                            std::fs::remove_file(journal.join("new-sidecar")).unwrap();
                        }));
                    });
                    let error = VaultV3::create_with_error_correction(
                        &CreateOptionsV3::new(&path, "new-password-123"),
                        placement,
                        20,
                    )
                    .unwrap_err();
                    assert!(error.contains("original vault restored"), "{error}");
                    assert_eq!(std::fs::read(&path).ok(), old_vault);
                    assert_eq!(std::fs::read(&sidecar).ok(), old_sidecar);
                    if existing {
                        assert!(VaultV3::list(&VaultV3::open(&path, PW).unwrap())
                            .iter()
                            .any(|e| e.path == "original"));
                    }
                    VaultV3::create_with_error_correction(
                        &CreateOptionsV3::new(&path, "new-password-123"),
                        placement,
                        20,
                    )
                    .unwrap();
                    assert!(VaultV3::open(&path, "new-password-123").is_ok());
                    assert!(sidecar.is_file());
                }
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn round7_import_retyped_fifo_is_rejected_on_deadline() {
        use crate::source::fifo_test;
        if let Some(dir) = fifo_test::child_path() {
            let path = dir.join("vault.aerozip");
            VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
            let mut v = VaultV3::open_plaintext(&path).unwrap();
            let ready = dir.clone();
            BEFORE_IMPORT_IDENTITY
                .with(|h| *h.borrow_mut() = Some(Box::new(move || fifo_test::ready(&ready))));
            let error = VaultV3::add_directory(&mut v, &dir.join("input"), None).unwrap_err();
            assert!(error.contains("Not a regular file"), "{error}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        std::fs::create_dir(&input).unwrap();
        let file = input.join("candidate");
        std::fs::write(&file, b"before type change").unwrap();
        let name = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        assert!(fifo_test::run(
            "v3::vault::tests::round7_import_retyped_fifo_is_rejected_on_deadline",
            dir.path(),
            "identity",
            || {
                std::fs::remove_file(&file).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        ));
    }

    #[test]
    fn round7_manifest_without_recovery_does_not_retry_under_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-recovery.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&path, PW)).unwrap();
        let v = VaultV3::open(&path, PW).unwrap();
        let at = v.header.manifest_offset as usize;
        drop(v);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[at + 4] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let original = VaultV3::open(&path, PW).unwrap_err();
        let guard = crate::lock::acquire(&path).unwrap();
        crate::lock::set_short_wait_for_this_thread();
        crate::lock::take_trace();
        GENERATION_READS.with(|n| n.set(0));
        assert_eq!(VaultV3::open(&path, PW).unwrap_err(), original);
        assert_eq!(GENERATION_READS.with(|n| n.get()), 1);
        assert!(!crate::lock::take_trace().contains(&"lock"));
        drop(guard);
    }

    #[test]
    fn round8_extraction_guards_outputs_and_refuses_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.aerozip");
        let input = dir.path().join("input");
        std::fs::write(&input, b"ordinary content").unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut opened = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(&mut opened, &[(input, "victim.aerovault".into())]).unwrap();
        let output = dir.path().join("out");
        std::fs::create_dir(&output).unwrap();
        let victim = output.join("victim.aerovault");
        VaultV3::create(&CreateOptionsV3::new(&victim, PW)).unwrap();
        let bytes = std::fs::read(&victim).unwrap();
        let guard = crate::lock::acquire(&victim).unwrap();
        crate::lock::set_short_wait_for_this_thread();
        assert!(VaultV3::extract_entry(&opened, "victim.aerovault", &output)
            .unwrap_err()
            .contains("locked by another writer"));
        assert_eq!(std::fs::read(&victim).unwrap(), bytes);
        drop(guard);
        assert!(VaultV3::extract_entry(&opened, "victim.aerovault", &output)
            .unwrap_err()
            .contains("existing vault"));
        assert_eq!(std::fs::read(&victim).unwrap(), bytes);
        VaultV3::export_parity(&victim, PW, None).unwrap();
        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        std::fs::write(&victim, &damaged).unwrap();
        assert!(VaultV3::open(&victim, PW).is_ok());
        assert!(VaultV3::extract_entry(&opened, "victim.aerovault", &output)
            .unwrap_err()
            .contains("recovery material"));
        assert_eq!(std::fs::read(&victim).unwrap(), damaged);
        std::fs::remove_file(super::super::ec::default_sidecar_path(&victim)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&victim, &bytes).unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o000)).unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert!(VaultV3::extract_entry(&opened, "victim.aerovault", &output)
                    .unwrap_err()
                    .contains("inspect extraction destination"));
            }
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(std::fs::read(&victim).unwrap(), bytes);
        }
        std::fs::write(&victim, b"ordinary prior file").unwrap();
        assert!(VaultV3::extract_entry(&opened, "victim.aerovault", &output).is_ok());
        assert_eq!(std::fs::read(victim).unwrap(), b"ordinary content");
    }

    #[test]
    fn round9_fresh_extraction_does_not_create_conflicting_lock_entries() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.aerozip");
        let plain = dir.path().join("plain");
        let sibling = dir.path().join("sibling");
        std::fs::write(&plain, b"ordinary content").unwrap();
        std::fs::write(&sibling, b"requested lock-name entry").unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut opened = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(
            &mut opened,
            &[
                (plain, "report.txt".into()),
                (sibling, "report.txt.aerolock".into()),
            ],
        )
        .unwrap();
        let output = dir.path().join("out");
        std::fs::create_dir(&output).unwrap();
        assert_eq!(VaultV3::extract_all(&opened, &output).unwrap(), 2);
        assert_eq!(
            std::fs::read(output.join("report.txt")).unwrap(),
            b"ordinary content"
        );
        let lock = output.join("report.txt.aerolock");
        assert_eq!(std::fs::read(&lock).unwrap(), b"requested lock-name entry");
        assert!(VaultV3::extract_entry(&opened, "report.txt.aerolock", &output).is_err());
        assert_eq!(std::fs::read(lock).unwrap(), b"requested lock-name entry");
    }

    #[test]
    fn round14_extraction_preserves_an_existing_vault_recovery_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            super::super::ec::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        VaultV3::export_parity(&path, PW, None).unwrap();
        let output = super::super::ec::default_sidecar_path(&path);
        let before = std::fs::read(&output).unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, b"ordinary archived bytes").unwrap();
        let archive = dir.path().join("archive.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut vault = VaultV3::open_plaintext(&archive).unwrap();
        let name = output.file_name().unwrap().to_str().unwrap();
        VaultV3::add_files(&mut vault, &[(source, name.to_owned())]).unwrap();
        let error = VaultV3::extract_all(&vault, dir.path()).unwrap_err();
        assert!(error.contains("existing recovery sidecar"), "{error}");
        assert_eq!(std::fs::read(output).unwrap(), before);
        assert!(VaultV3::open(&path, PW).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round14_extraction_replaces_an_ordinary_max_length_basename() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("x".repeat(255));
        std::fs::write(&input, b"extracted bytes").unwrap();
        std::fs::write(&output, b"ordinary existing file").unwrap();
        let archive = dir.path().join("archive.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut vault = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(&mut vault, &[(input, "input".into())]).unwrap();
        VaultV3::extract_entry(&vault, "input", &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), b"extracted bytes");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extraction_works_without_directory_listing_permission() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("write-and-search");
        let input = fixture.path().join("input");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(&input, b"extract without listing").unwrap();
        let archive = fixture.path().join("archive.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut vault = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(&mut vault, &[(input, "output".into())]).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o300)).unwrap();
        let listing = std::fs::read_dir(&root);
        let result = VaultV3::extract_all(&vault, &root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(
                listing.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        result.unwrap();
        assert_eq!(
            std::fs::read(root.join("output")).unwrap(),
            b"extract without listing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn round14_extraction_refuses_a_replaced_validated_parent() {
        for hook in [
            &AFTER_EXTRACTION_PARENT,
            &AFTER_EXTRACTION_STAGE,
            &BEFORE_EXTRACTION_PUBLISH,
        ] {
            assert_extraction_rejects_moved_parent(Some(hook), false);
        }
    }

    #[cfg(unix)]
    #[test]
    fn extraction_rolls_back_a_parent_move_after_the_publication_check() {
        for overwrite in [false, true] {
            assert_extraction_rejects_moved_parent(None, overwrite);
        }
    }

    #[cfg(unix)]
    fn assert_extraction_rejects_moved_parent(
        hook: Option<&'static std::thread::LocalKey<ExtractionHook>>,
        overwrite: bool,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let input = dir.path().join("input");
        std::fs::write(&input, b"plaintext inside the archive").unwrap();
        let archive = dir.path().join("archive.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut vault = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(&mut vault, &[(input, "subdir/file".into())]).unwrap();
        let subdir = root.join("subdir");
        let original_bytes = b"existing output to preserve";
        let original = overwrite.then(|| {
            std::fs::create_dir(&subdir).unwrap();
            let path = subdir.join("file");
            std::fs::write(&path, original_bytes).unwrap();
            same_file::Handle::from_path(path).unwrap()
        });
        let moved = outside.join("moved");
        let moved_destination = moved.clone();
        let redirect = outside.clone();
        let move_parent = Box::new(move || {
            std::fs::rename(&subdir, moved_destination).unwrap();
            std::os::unix::fs::symlink(redirect, subdir).unwrap();
        });
        if let Some(hook) = hook {
            hook.with(|slot| *slot.borrow_mut() = Some(move_parent));
        } else {
            AFTER_EXTRACTION_PUBLICATION_CHECK
                .with(|slot| *slot.borrow_mut() = Some((overwrite, move_parent)));
        }
        let error = VaultV3::extract_all(&vault, &root).unwrap_err();
        assert!(
            error.contains("validated output directory changed"),
            "{error}"
        );
        let outside_entries: Vec<_> = std::fs::read_dir(outside)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(outside_entries, std::slice::from_ref(&moved));
        let moved_output = moved.join("file");
        if let Some(original) = original {
            assert_eq!(std::fs::read(&moved_output).unwrap(), original_bytes);
            assert!(same_file::Handle::from_path(&moved_output).unwrap() == original);
        } else {
            assert!(!moved_output.exists());
        }
        for entry in std::fs::read_dir(moved).unwrap() {
            let entry = entry.unwrap();
            if overwrite && entry.path() == moved_output {
                continue;
            }
            assert_eq!(entry.file_name(), "file.aerolock");
            assert_eq!(entry.metadata().unwrap().len(), 0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn round14_extraction_prevents_parent_rename_while_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let subdir = root.join("subdir");
        let moved = dir.path().join("moved");
        std::fs::create_dir(&root).unwrap();
        let input = dir.path().join("input");
        let payload = b"plaintext inside the archive";
        std::fs::write(&input, payload).unwrap();
        let archive = dir.path().join("archive.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
        let mut vault = VaultV3::open_plaintext(&archive).unwrap();
        VaultV3::add_files(&mut vault, &[(input, "subdir/file".into())]).unwrap();
        let move_source = subdir.clone();
        let move_destination = moved.clone();
        BEFORE_EXTRACTION_PUBLISH.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let error = std::fs::rename(move_source, move_destination).unwrap_err();
                assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
            }));
        });
        VaultV3::extract_all(&vault, &root).unwrap();
        assert_eq!(std::fs::read(subdir.join("file")).unwrap(), payload);
        assert!(!moved.exists());
        std::fs::rename(subdir, moved).unwrap();
    }

    #[test]
    fn round14_failed_plaintext_add_wipes_the_rejected_range() {
        use rand::RngCore;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.aerozip");
        let original = dir.path().join("original");
        let large = dir.path().join("large");
        let larger = dir.path().join("larger");
        std::fs::write(&original, b"keep this entry").unwrap();
        let mut random = vec![0u8; PACK_SMALL_FILE_THRESHOLD + 1];
        rand::rngs::OsRng.fill_bytes(&mut random);
        std::fs::write(&large, &random).unwrap();
        random.resize(random.len() * 8, 0);
        rand::rngs::OsRng.fill_bytes(&mut random);
        std::fs::write(&larger, random).unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut vault, &[(original, "kept".into())]).unwrap();
        vault.data.shrink_to_fit();
        let prefix = vault.data.clone();
        let before = std::fs::read(&path).unwrap();
        let observed = std::rc::Rc::new(std::cell::Cell::new(false));
        let done = observed.clone();
        INSPECT_REJECTED_ADD.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |appended| {
                assert!(!appended.is_empty());
                assert!(appended.iter().all(|&b| b == 0));
                done.set(true);
            }));
        });
        crate::secret::WIPED_GROWTH.set(0);
        assert!(VaultV3::add_files(
            &mut vault,
            &[
                (large, "discarded".into()),
                (larger, "discarded-too".into()),
                (dir.path().join("missing"), "missing".into()),
            ]
        )
        .is_err());
        assert!(crate::secret::WIPED_GROWTH.get() >= 2);
        assert!(observed.get());
        assert_eq!(vault.data, prefix);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn round9_saved_header_failure_keeps_the_vault_and_handle_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let mut opened = VaultV3::open_plaintext(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let baseline = (
            opened.opened_file_len,
            opened.opened_hash,
            opened.header.to_bytes(),
        );
        FAIL_SAVED_HEADER_PARSE.with(|fail| fail.set(true));
        assert!(save_open_vault(&mut opened).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            (
                opened.opened_file_len,
                opened.opened_hash,
                opened.header.to_bytes()
            ),
            baseline
        );
        assert!(save_open_vault(&mut opened).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_sparse_tail_above_four_gib_can_be_resealed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerozip");
        let input = dir.path().join("input");
        std::fs::write(&input, b"valid 0.6.8 payload").unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut vault, &[(input.clone(), "input".into())]).unwrap();
        drop(vault);
        let original_extent = 4 * 1024 * 1024 * 1024 + 1;
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(original_extent).unwrap();
        drop(file);

        let mut opened = VaultV3::open_plaintext(&path).unwrap();
        assert_eq!(opened.opened_file_len, original_extent);
        let output = dir.path().join("output");
        VaultV3::extract_entry(&opened, "input", &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), b"valid 0.6.8 payload");
        VaultV3::add_files(&mut opened, &[(input, "new".into())]).unwrap();
        assert_eq!(VaultV3::list(&opened).len(), 2);
        assert!(opened.opened_file_len < original_extent);
        assert_vault_generation_current(&opened).unwrap();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    #[ignore = "requires a 64-bit host with room for multiple 4 GiB allocations and file extents"]
    fn legacy_sparse_data_section_over_four_gib_can_be_resealed() {
        use super::super::manifest::serialize_manifest_plaintext;
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerozip");
        let input = dir.path().join("input");
        let payload = b"referenced block beyond 4 GiB";
        std::fs::write(&input, payload).unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let mut vault = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut vault, &[(input.clone(), "input".into())]).unwrap();

        // Write the ordinary v3 layout accepted by 0.6.8. The data section
        // is sparse, with a live block past 4 GiB and the manifest after it.
        let block_offset = 4 * 1024 * 1024 * 1024 + 4096;
        assert_eq!(vault.manifest.chunks.len(), 1);
        vault
            .manifest
            .chunks
            .values_mut()
            .next()
            .unwrap()
            .data_offset = block_offset;
        let manifest = serialize_manifest_plaintext(&vault.manifest).unwrap();
        let mut header = vault.header.clone();
        header.data_len = block_offset + vault.data.len() as u64;
        header.manifest_offset = header.data_offset + header.data_len;
        header.manifest_len = manifest.len() as u64;
        header.extension_dir_offset = header.manifest_offset + header.manifest_len;
        header.extension_dir_len = 2;
        header.extension_payload_offset = header.extension_dir_offset + header.extension_dir_len;
        header.extension_payload_len = 0;
        header.header_mac = header.compute_mac(&vault.mac_key).unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&header.to_bytes()).unwrap();
        file.seek(std::io::SeekFrom::Start(header.data_offset + block_offset))
            .unwrap();
        file.write_all(&vault.data).unwrap();
        file.write_all(&manifest).unwrap();
        file.write_all(b"[]").unwrap();
        drop(file);
        drop(vault);

        let mut opened = VaultV3::open_plaintext(&path).unwrap();
        assert_eq!(opened.data.len() as u64, header.data_len);
        let output = dir.path().join("output");
        VaultV3::extract_entry(&opened, "input", &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), payload);
        VaultV3::add_files(&mut opened, &[(input, "new".into())]).unwrap();
        assert_vault_generation_current(&opened).unwrap();
        assert_eq!(VaultV3::list(&opened).len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round9_paired_password_rotation_keeps_one_large_data_buffer() {
        const KEY: &str = "AEROVAULT_ROTATION_MEMORY_PATH";
        const DATA_LEN: usize = 768 * 1024 * 1024;
        const NEW: &str = "replacement-password-123";
        if let Some(path) = std::env::var_os(KEY).map(PathBuf::from) {
            crate::source::memory_test::limit();
            let mut vault = VaultV3::open(&path, PW).unwrap();
            assert_eq!(vault.data.len(), DATA_LEN);
            VaultV3::change_password(&mut vault, NEW).unwrap();
            assert_eq!(vault.data.len(), DATA_LEN);
            assert_vault_generation_current(&vault).unwrap();
            drop(vault);
            assert_eq!(VaultV3::open(&path, NEW).unwrap().data.len(), DATA_LEN);
            assert!(VaultV3::open(&path, PW).is_err());
            crate::source::memory_test::complete();
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-rotation.aerovault");
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            super::super::ec::RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        vault.data.resize(DATA_LEN, 0);
        save_open_vault(&mut vault).unwrap();
        drop(vault);
        crate::source::memory_test::run(
            "v3::vault::tests::round9_paired_password_rotation_keeps_one_large_data_buffer",
            KEY,
            &path,
        );
    }

    #[test]
    fn round9_v3_data_budget_refuses_public_add_without_mutating_handle_or_disk() {
        use rand::{RngCore, SeedableRng};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerozip");
        let input = dir.path().join("input");
        let mut random = [0u8; 1024];
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        rng.fill_bytes(&mut random);
        std::fs::write(&input, random).unwrap();
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let tight = VaultV3Limits::default().with_max_data_bytes(512);
        let mut opened = VaultV3::open_plaintext_with_limits(&path, tight).unwrap();
        let before = std::fs::read(&path).unwrap();
        let failed = VaultV3::add_files(&mut opened, &[(input.clone(), "input".into())]);
        assert!(failed
            .unwrap_err()
            .contains("configured 512-byte data budget"));
        assert!(opened.data.is_empty());
        assert!(VaultV3::list(&opened).is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut unlimited = VaultV3::open_plaintext(&path).unwrap();
        VaultV3::add_files(&mut unlimited, &[(input, "input".into())]).unwrap();
        assert!(VaultV3::open_plaintext_with_limits(&path, tight)
            .unwrap_err()
            .contains("configured 512-byte data budget"));
        let reopened = VaultV3::open_plaintext_with_limits(
            &path,
            VaultV3Limits::default().with_max_data_bytes(2048),
        )
        .unwrap();
        assert_eq!(VaultV3::list(&reopened).len(), 1);
    }

    #[test]
    fn a_data_budget_refusal_preserves_the_vault_and_its_sidecar() {
        use super::super::ec::RecoveryPlacement;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerovault");
        let sidecar = super::super::ec::default_sidecar_path(&path);
        let input = dir.path().join("input");
        std::fs::write(&input, b"stored bytes").unwrap();
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&path, PW),
            RecoveryPlacement::Embedded,
            20,
        )
        .unwrap();
        let mut vault = VaultV3::open(&path, PW).unwrap();
        VaultV3::add_files(&mut vault, &[(input, "input".into())]).unwrap();
        drop(vault);
        VaultV3::export_parity(&path, PW, None).unwrap();

        let original = std::fs::read(&path).unwrap();
        let recovery = std::fs::read(&sidecar).unwrap();
        let limits = VaultV3Limits::default().with_max_data_bytes(0);
        for error in [
            VaultV3::open_with_limits(&path, PW, limits).unwrap_err(),
            VaultV3::export_parity_with_limits(&path, PW, None, limits).unwrap_err(),
            VaultV3::strip_parity_with_limits(&path, PW, false, limits).unwrap_err(),
        ] {
            assert!(error.contains("configured 0-byte data budget"), "{error}");
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(std::fs::read(&sidecar).unwrap(), recovery);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn round8_plaintext_sparse_data_refused_before_scan_under_memory_limit() {
        const KEY: &str = "AEROVAULT_ROUND8_MEMORY";
        if let Some(path) = std::env::var_os(KEY) {
            crate::source::memory_test::limit();
            let limits = VaultV3Limits::default().with_max_data_bytes(1024 * 1024 * 1024);
            crate::lock::take_trace();
            let err = VaultV3::open_plaintext_with_limits(PathBuf::from(path), limits).unwrap_err();
            assert!(
                err.contains("configured 1073741824-byte data budget"),
                "{err}"
            );
            assert!(!crate::lock::take_trace().contains(&"generation"));
            crate::source::memory_test::complete();
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.aerozip");
        VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut header = VaultHeaderV3::from_bytes(&bytes[..HEADER_SIZE]).unwrap();
        header.data_len = 2 * 1024 * 1024 * 1024;
        header.manifest_offset = header.data_offset + header.data_len;
        header.extension_dir_offset = header.manifest_offset + header.manifest_len;
        header.extension_payload_offset = header.extension_dir_offset + header.extension_dir_len;
        header.header_mac = header.compute_mac(&aerovz_mac_key().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(header.extension_payload_offset + header.extension_payload_len)
            .unwrap();
        std::io::Write::write_all(&mut file, &header.to_bytes()).unwrap();
        drop(file);
        crate::source::memory_test::run(
            "v3::vault::tests::round8_plaintext_sparse_data_refused_before_scan_under_memory_limit",
            KEY,
            &path,
        );
    }
}
