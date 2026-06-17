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

// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use super::block::build_file_bytes;
use super::chunking::{chunk_ranges_with, keyed_chunk_id, CdcBounds};
use super::constants::{
    CDC_MAX, DATA_OFFSET, DEFAULT_ZSTD_LEVEL, HEADER_SIZE, HKDF_CHUNK_ID, MAC_SIZE, MAGIC,
    MAX_BLOCK_SIZE, MAX_EXTENSION_DIR_SIZE, MAX_MANIFEST_SIZE, MAX_PLAINTEXT_BLOCK_SIZE,
    MIN_PASSWORD_LEN, PACK_SMALL_FILE_THRESHOLD, PACK_TARGET, SUPPORTED_WRAPPER_HEADER_VERSION,
    VERSION,
};
use super::format::{derive_keks, VaultHeaderV3};
use super::manifest::{
    block_aad, decrypt_manifest, empty_manifest, manifest_cdc_bounds, manifest_zstd_level,
    next_block_index, now_iso, AlgorithmSpec, ChunkRecordV3, ExtensionEntryV3, ManifestEntryV3,
    VaultManifestV3, WrapperManifest,
};
use crate::aerocrypt::{
    decrypt_with_aad, derive_base_kek, encrypt_with_aad, hkdf_expand, random_array, unwrap_key,
    wrap_key, KEY_SIZE, SALT_SIZE,
};

/// Options for creating an AEROVAULT3 container. Without an Error-Correction
/// placement this produces a plain rev. 3 container; setting one (see
/// [`VaultV3::create_with_error_correction`]) opts into rev. 4.
pub struct CreateOptionsV3 {
    /// Destination path for the `.aerovault` container.
    pub path: PathBuf,
    /// Master password (>= [`MIN_PASSWORD_LEN`] characters).
    pub password: String,
    /// zstd compression level recorded on the `compression` wrapper.
    pub zstd_level: i32,
    /// rev. 4 Error-Correction placement. `None` keeps the container plain rev. 3.
    pub(super) error_correction: Option<super::ec::RecoveryPlacement>,
    /// QR-style EC overhead percentage; only meaningful when
    /// `error_correction` is `Some`. Defaults to the original K=10/P=2 grid.
    pub(super) error_correction_pct: u32,
}

impl CreateOptionsV3 {
    /// New options with the default ([`DEFAULT_ZSTD_LEVEL`]) compression level.
    pub fn new(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: password.into(),
            zstd_level: DEFAULT_ZSTD_LEVEL,
            error_correction: None,
            error_correction_pct:
                crate::error_correction::ERROR_CORRECTION_DEFAULT_PCT,
        }
    }

    /// Override the zstd compression level.
    pub fn with_zstd_level(mut self, level: i32) -> Self {
        self.zstd_level = level;
        self
    }
}

/// An unlocked, fully in-memory AEROVAULT3 container.
///
/// Holds the decrypted master and MAC keys plus the whole data section in RAM.
/// Drop it when done: the [`Drop`] impl zeroizes the key material.
#[derive(Debug)]
pub struct OpenVaultV3 {
    pub(super) path: PathBuf,
    pub(super) header: VaultHeaderV3,
    pub(super) opened_file_len: u64,
    pub(super) opened_header_mac: [u8; MAC_SIZE],
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
        super::ec::export_parity(vault_path, password, out)
    }

    /// Drop the embedded Error-Correction extension on the next seal. Refuses
    /// unless a detached sidecar already exists or `force` is set, so a vault is
    /// never silently left with zero recovery.
    pub fn strip_parity(
        vault_path: &Path,
        password: &str,
        force: bool,
    ) -> Result<super::ec::StripParityResult, String> {
        super::ec::strip_parity(vault_path, password, force)
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
    /// written. Returns `(repaired_block_count, parity_source)`.
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

    /// Recovery surfaces available for a vault without the password.
    pub fn recovery_status(path: &Path) -> Result<super::ec::RecoveryStatus, String> {
        super::ec::recovery_status(path)
    }

    /// True if `path` begins with the AEROVAULT3 magic + version.
    pub fn is_vault_v3(path: impl AsRef<Path>) -> bool {
        let Ok(mut file) = std::fs::File::open(path.as_ref()) else {
            return false;
        };
        let mut buf = [0u8; 11];
        if file.read_exact(&mut buf).is_err() {
            return false;
        }
        &buf[..10] == MAGIC && buf[10] == VERSION
    }

    /// Open and unlock a container with `password`.
    pub fn open(path: impl Into<PathBuf>, password: &str) -> Result<OpenVaultV3, String> {
        open_vault(path, password)
    }

    /// Read header-only info without a password.
    pub fn peek(path: impl AsRef<Path>) -> Result<PeekInfo, String> {
        let mut file =
            std::fs::File::open(path.as_ref()).map_err(|e| format!("Open vault: {e}"))?;
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
            })
            .collect()
    }

    /// Add files into the vault at the given vault-relative paths, then persist.
    pub fn add_files(
        vault: &mut OpenVaultV3,
        sources: &[(PathBuf, String)],
    ) -> Result<(), String> {
        append_sources_batched(vault, sources)?;
        save_open_vault(vault)
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
        if !target.is_empty() {
            create_directory_in_manifest(&mut vault.manifest, target)?;
        }
        append_sources_batched(vault, &mapped)?;
        save_open_vault(vault)
    }

    /// Create a directory (and any missing parents) inside the vault, persist.
    pub fn create_directory(vault: &mut OpenVaultV3, dir_path: &str) -> Result<(), String> {
        create_directory_in_manifest(&mut vault.manifest, dir_path)?;
        save_open_vault(vault)
    }

    /// Recursively add `source_dir` (depth <= 100, <= 500000 entries) under
    /// `target_prefix` (or the root when `None`), then persist.
    pub fn add_directory(
        vault: &mut OpenVaultV3,
        source_dir: &Path,
        target_prefix: Option<&str>,
    ) -> Result<(usize, usize), String> {
        add_directory_into(vault, source_dir, target_prefix)
    }

    /// Delete a single entry (file or empty directory), then persist.
    pub fn delete_entry(vault: &mut OpenVaultV3, entry_name: &str) -> Result<usize, String> {
        let removed =
            delete_entries_from_manifest(vault, std::slice::from_ref(&entry_name.to_string()), false)?;
        save_open_vault(vault)?;
        Ok(removed)
    }

    /// Delete entries; with `recursive` a directory drops its whole subtree.
    pub fn delete_entries(
        vault: &mut OpenVaultV3,
        entry_names: &[String],
        recursive: bool,
    ) -> Result<usize, String> {
        let removed = delete_entries_from_manifest(vault, entry_names, recursive)?;
        save_open_vault(vault)?;
        Ok(removed)
    }

    /// Move (or rename across directories) an entry/subtree, then persist.
    pub fn move_entry(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
        move_entry_in_manifest(vault, from, to)?;
        save_open_vault(vault)
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
        move_entry_in_manifest(vault, &current, &target)?;
        save_open_vault(vault)
    }

    /// Copy an entry/subtree (reusing the same content chunks), then persist.
    pub fn copy_entry(vault: &mut OpenVaultV3, from: &str, to: &str) -> Result<(), String> {
        copy_entry_in_manifest(vault, from, to)?;
        save_open_vault(vault)
    }

    /// Re-wrap the keys under a new password (new salt + KEKs), then persist.
    pub fn change_password(vault: &mut OpenVaultV3, new_password: &str) -> Result<(), String> {
        change_password_in_place(vault, new_password)?;
        save_open_vault(vault)
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
}

// --- Internal port of the app sync core ---------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKindV3 {
    File,
    Directory,
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
    if trimmed.split('/').any(|part| part.is_empty() || part == ".") {
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
            return Err(format!("Duplicate AeroVault path in manifest: {}", entry.path));
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

/// Compress + encrypt + dedup one already-delimited plaintext chunk; returns the
/// chunk id. Shared by the per-file and pack paths. (Telemetry dropped.)
fn ingest_chunk(
    vault: &mut OpenVaultV3,
    chunk: &[u8],
    chunk_key: &[u8; KEY_SIZE],
    level: i32,
) -> Result<String, String> {
    let chunk_id = keyed_chunk_id(chunk_key, chunk);
    if !vault.manifest.chunks.contains_key(&chunk_id) {
        let compressed = zstd::stream::encode_all(chunk, level)
            .map_err(|e| format!("zstd compress failed: {e}"))?;
        let block_index = next_block_index(&vault.manifest);
        let aad = block_aad(block_index, &chunk_id);
        let encrypted = encrypt_with_aad(&vault.master_key, &compressed, &aad)?;
        let cipher_hash = blake3::hash(&encrypted).to_hex().to_string();
        let data_offset = vault.data.len() as u64;
        vault
            .data
            .extend_from_slice(&(encrypted.len() as u64).to_le_bytes());
        vault.data.extend_from_slice(&encrypted);
        let (pt, cz, enc) = (
            chunk.len() as u64,
            compressed.len() as u64,
            encrypted.len() as u64,
        );
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
            },
        );
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

    let mut plaintext =
        std::fs::read(source).map_err(|e| format!("Read {}: {e}", source.display()))?;
    let size = plaintext.len() as u64;
    let chunk_key = hkdf_expand::<KEY_SIZE>(&vault.master_key, HKDF_CHUNK_ID)?;
    let level = manifest_zstd_level(&vault.manifest);
    let bounds = manifest_cdc_bounds(&vault.manifest)?;
    let mut entry_chunks = Vec::new();

    let ranges = chunk_ranges_with(&plaintext, &bounds);
    for (start, end) in ranges {
        let chunk_id = ingest_chunk(vault, &plaintext[start..end], &chunk_key, level)?;
        entry_chunks.push(chunk_id);
    }
    plaintext.zeroize();

    vault.manifest.entries.push(ManifestEntryV3 {
        path: entry_path,
        size,
        modified: now_iso(),
        is_dir: false,
        chunks: entry_chunks,
        pack_offset: None,
    });
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

    let ranges = chunk_ranges_with(pack, bounds);
    let mut chunks: Vec<(String, u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in &ranges {
        let id = ingest_chunk(vault, &pack[*start..*end], chunk_key, level)?;
        chunks.push((id, *start as u64, *end as u64));
    }

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
    }
    Ok(())
}

/// Add a set of sources, batching sub-threshold files into shared packs before
/// chunking and routing large files through the per-file path. Deterministic
/// path ordering keeps packs (and therefore dedup) stable across identical adds.
fn append_sources_batched(
    vault: &mut OpenVaultV3,
    sources: &[(PathBuf, String)],
) -> Result<(), String> {
    let chunk_key = hkdf_expand::<KEY_SIZE>(&vault.master_key, HKDF_CHUNK_ID)?;
    let level = manifest_zstd_level(&vault.manifest);
    let bounds = manifest_cdc_bounds(&vault.manifest)?;

    let mut small_meta: Vec<(PathBuf, String)> = Vec::new();
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
            append_file_at(vault, source, &entry_path)?;
        }
    }

    if !small_meta.is_empty() {
        small_meta.sort_by(|a, b| a.1.cmp(&b.1));

        let mut pack: Vec<u8> = Vec::new();
        let mut members: Vec<(String, u64, u64)> = Vec::new();
        for (source, entry_path) in &small_meta {
            let mut data =
                std::fs::read(source).map_err(|e| format!("Read {}: {e}", source.display()))?;
            let start = pack.len() as u64;
            pack.extend_from_slice(&data);
            let len = data.len() as u64;
            data.zeroize();
            members.push((entry_path.clone(), start, len));
            if pack.len() >= PACK_TARGET {
                flush_pack(vault, &pack, &members, &chunk_key, level, &bounds)?;
                pack.zeroize();
                pack.clear();
                members.clear();
            }
        }
        if !members.is_empty() {
            flush_pack(vault, &pack, &members, &chunk_key, level, &bounds)?;
            pack.zeroize();
        }
    }

    sort_entries(&mut vault.manifest);
    vault.manifest.modified = now_iso();
    Ok(())
}

/// Garbage-collect orphaned chunks: keep only chunk records still referenced by
/// a live entry, rewrite the data section in block-index order, and remap each
/// surviving record's `data_offset`.
fn compact_live_chunks(vault: &mut OpenVaultV3) -> Result<(), String> {
    let live_chunk_ids: HashSet<String> = vault
        .manifest
        .entries
        .iter()
        .flat_map(|entry| entry.chunks.iter().cloned())
        .collect();

    if live_chunk_ids.is_empty() {
        vault.manifest.chunks.clear();
        vault.data.clear();
        return Ok(());
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

    vault.data = new_data;
    vault.manifest.chunks = new_chunks;
    Ok(())
}

fn delete_entries_from_manifest(
    vault: &mut OpenVaultV3,
    entry_names: &[String],
    recursive: bool,
) -> Result<usize, String> {
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

    if removed > 0 {
        compact_live_chunks(vault)?;
        sort_entries(&mut vault.manifest);
        vault.manifest.modified = now_iso();
    }

    Ok(removed)
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
    if new_password.len() < MIN_PASSWORD_LEN {
        return Err("Password must be at least 8 characters".to_string());
    }
    let salt = random_array::<SALT_SIZE>();
    let mut base_kek = derive_base_kek(new_password, &salt)?;
    let (kek_master, kek_mac) = derive_keks(&base_kek)?;
    base_kek.zeroize();
    vault.header.salt = salt;
    vault.header.wrapped_master_key = wrap_key(&kek_master, &vault.master_key)?;
    vault.header.wrapped_mac_key = wrap_key(&kek_mac, &vault.mac_key)?;
    vault.manifest.modified = now_iso();
    Ok(())
}

fn extract_file_entry(
    vault: &OpenVaultV3,
    entry: &ManifestEntryV3,
    output_path: &Path,
) -> Result<PathBuf, String> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create output dir: {e}"))?;
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

    let mut out = Vec::with_capacity(end.min(32 * 1024 * 1024));
    for chunk_id in &entry.chunks {
        if out.len() >= end {
            // Everything this entry slices is already decoded; ignore the rest
            // (a hostile pack may list extra/duplicate chunks past this point).
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
        let mut compressed = decrypt_with_aad(&vault.master_key, encrypted, &aad)?;
        // Bound the decompressor output to `plaintext_len + 1`: with the cap
        // above this is at most one chunk, so a zstd bomb cannot materialise
        // more than that before the length mismatch is detected.
        let mut decoder = zstd::stream::read::Decoder::new(&compressed[..])
            .map_err(|e| format!("zstd decompress init failed: {e}"))?;
        let mut plaintext = Vec::with_capacity(record.plaintext_len as usize);
        decoder
            .by_ref()
            .take(record.plaintext_len + 1)
            .read_to_end(&mut plaintext)
            .map_err(|e| format!("zstd decompress failed: {e}"))?;
        compressed.zeroize();
        if plaintext.len() as u64 != record.plaintext_len {
            plaintext.zeroize();
            return Err(format!("Plaintext length mismatch for chunk {chunk_id}"));
        }
        out.extend_from_slice(&plaintext);
        plaintext.zeroize();
    }
    if end > out.len() {
        return Err(format!(
            "Entry slice [{offset}..{end}] exceeds decoded data ({})",
            out.len()
        ));
    }
    let mut sliced = out[offset..end].to_vec();
    out.zeroize();
    atomic_write(output_path, &sliced)?;
    sliced.zeroize();
    Ok(output_path.to_path_buf())
}

pub(super) fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
    tmp.persist(target)
        .map_err(|e| format!("Persist vault: {}", e.error))?;
    #[cfg(unix)]
    {
        if let Some(parent) = target.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

pub(super) fn read_capped(
    file: &mut std::fs::File,
    offset: u64,
    len: u64,
    cap: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    use std::io::Seek;
    if len > cap {
        return Err(format!("{label} too large: {len} bytes"));
    }
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| format!("Seek {label}: {e}"))?;
    let mut buf = vec![0u8; len as usize];
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
    check_wrapper("crypt", &w.crypt, "aes-256-gcm-siv", 1)?;
    check_wrapper("cipher_hash", &w.cipher_hash, "blake3-256", 1)?;
    Ok(())
}

pub(super) fn open_header_bytes(
    header_bytes: &[u8],
    password: &str,
) -> Result<(VaultHeaderV3, [u8; KEY_SIZE], [u8; KEY_SIZE]), String> {
    let header = VaultHeaderV3::from_bytes(header_bytes)?;
    let mut base_kek = derive_base_kek(password, &header.salt)?;
    let (kek_master, kek_mac) = derive_keks(&base_kek)?;
    base_kek.zeroize();
    let mac_key = unwrap_key(&kek_mac, &header.wrapped_mac_key)?;
    header.verify_mac(&mac_key)?;
    if header.wrapper_header_version != SUPPORTED_WRAPPER_HEADER_VERSION {
        return Err(format!(
            "Unsupported AeroVault v3 wrapper-header version: {} (expected {})",
            header.wrapper_header_version, SUPPORTED_WRAPPER_HEADER_VERSION
        ));
    }
    let master_key = unwrap_key(&kek_master, &header.wrapped_master_key)?;
    Ok((header, mac_key, master_key))
}

fn create_empty_vault(
    path: &Path,
    password: &str,
    level: i32,
    error_correction: Option<super::ec::RecoveryPlacement>,
    error_correction_pct: u32,
) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err("Password must be at least 8 characters".to_string());
    }

    let salt = random_array::<SALT_SIZE>();
    let mut base_kek = derive_base_kek(password, &salt)?;
    let (kek_master, kek_mac) = derive_keks(&base_kek)?;
    base_kek.zeroize();

    let mut master_key = random_array::<KEY_SIZE>();
    let mut mac_key = random_array::<KEY_SIZE>();
    let wrapped_master_key = wrap_key(&kek_master, &master_key)?;
    let wrapped_mac_key = wrap_key(&kek_mac, &mac_key)?;

    let header = VaultHeaderV3 {
        flags: 0,
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

    let mut manifest = empty_manifest(level);
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
    master_key.zeroize();
    mac_key.zeroize();
    atomic_write(path, &bytes)?;

    // Detached/both placements seed the sidecar so the file exists from
    // creation. An empty vault has an empty parity payload; re-run
    // `export-parity` after adding files (par2 semantics).
    if error_correction.is_some_and(|p| p.writes_sidecar()) {
        super::ec::seed_empty_sidecar(path, &bytes)?;
    }
    Ok(())
}

pub(super) fn open_vault(path: impl Into<PathBuf>, password: &str) -> Result<OpenVaultV3, String> {
    let path = path.into();
    let mut file = std::fs::File::open(&path).map_err(|e| format!("Open vault: {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("Vault metadata: {e}"))?
        .len();
    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("Read header: {e}"))?;

    // HEADER parity (rev. 4): the on-disk header is the happy path. If it fails
    // to parse or its MAC does not verify (bit-rot / bad sector), fall back to
    // rebuilding it from the detached sidecar's header parity. A missing sidecar
    // / no header parity / a rebuild that still does not unlock keeps the
    // original error. The MAC verify inside `open_header_bytes` is the proof.
    let (header, mac_key, master_key, header_repaired_on_open) =
        match open_header_bytes(&header_bytes, password) {
            Ok((h, mac, master)) => (h, mac, master, false),
            Err(orig) => {
                match super::ec::recover_header_from_sidecar(&path, &header_bytes, password)? {
                    Some((h, mac, master)) => (h, mac, master, true),
                    None => return Err(orig),
                }
            }
        };

    validate_ranges(&header, file_len)?;

    let data = read_capped(
        &mut file,
        header.data_offset,
        header.data_len,
        // The data section is authenticated and validate_ranges has already
        // bounded it within the file; cap explicitly at file length.
        file_len,
        "data section",
    )?;
    let encrypted_manifest = read_capped(
        &mut file,
        header.manifest_offset,
        header.manifest_len,
        MAX_MANIFEST_SIZE,
        "manifest",
    )?;
    // GAP-4 (rev. 4): the manifest region may be corrupted (bit-rot, bad
    // sector). Rebuild the encrypted manifest from parity and retry. Try the
    // embedded metadata extension first (auto-fresh on the embedded path), then
    // the detached sidecar's manifest parity (the only copy a pure-detached
    // vault keeps). A successful AEAD decrypt on the rebuilt bytes is the
    // correctness proof; otherwise keep the original error.
    let (manifest, manifest_repaired_on_open) =
        match decrypt_manifest(&master_key, &encrypted_manifest) {
            Ok(m) => (m, false),
            Err(orig) => {
                let embedded = super::ec::reconstruct_encrypted_manifest(
                    &mut file, &header, file_len,
                )?;
                let rebuilt = match embedded {
                    Some(r) if r != encrypted_manifest => Some(r),
                    _ => super::ec::reconstruct_manifest_from_sidecar(
                        &path,
                        &encrypted_manifest,
                    )?,
                };
                match rebuilt {
                    Some(r) if r != encrypted_manifest => {
                        (decrypt_manifest(&master_key, &r)?, true)
                    }
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
    validate_manifest_paths(&manifest)?;

    let extension_json = read_capped(
        &mut file,
        header.extension_dir_offset,
        header.extension_dir_len,
        MAX_EXTENSION_DIR_SIZE,
        "extension directory",
    )?;
    let extensions: Vec<ExtensionEntryV3> = serde_json::from_slice(&extension_json)
        .map_err(|e| format!("Extension directory parse: {e}"))?;

    for ext in &extensions {
        // A rev. 3 reader rejects any critical extension; the rev. 4 EC layers
        // are deliberately non-critical so this stays a forward-compat skip.
        if ext.critical {
            return Err(format!(
                "Unsupported critical AeroVault v3 extension: {}",
                ext.extension_id
            ));
        }
    }

    // Do not round-trip the EC metadata-parity extension; build_file_bytes is
    // its sole author and recomputes it on every seal from the freshly
    // encrypted manifest. (No-op when no EC extension is present.)
    let extensions: Vec<ExtensionEntryV3> = extensions
        .into_iter()
        .filter(|e| e.extension_id != super::constants::ERROR_CORRECTION_META_EXTENSION_ID)
        .collect();

    Ok(OpenVaultV3 {
        path,
        opened_file_len: file_len,
        opened_header_mac: header.header_mac,
        header,
        master_key,
        mac_key,
        manifest,
        extensions,
        data,
        manifest_repaired_on_open,
        header_repaired_on_open,
    })
}

fn validate_ranges(header: &VaultHeaderV3, file_len: u64) -> Result<(), String> {
    if header.data_offset != DATA_OFFSET {
        return Err("Invalid AeroVault v3 data offset".to_string());
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
/// (concurrent writer), keyed on file length + header MAC.
fn assert_vault_generation_current(vault: &OpenVaultV3) -> Result<(), String> {
    let mut file = std::fs::File::open(&vault.path).map_err(|e| format!("Open vault: {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("Vault metadata: {e}"))?
        .len();
    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("Read header: {e}"))?;
    let header = VaultHeaderV3::from_bytes(&header_bytes)?;
    if file_len != vault.opened_file_len || header.header_mac != vault.opened_header_mac {
        return Err("Vault changed while this write was in progress; retry operation".to_string());
    }
    Ok(())
}

pub(super) fn save_open_vault(vault: &mut OpenVaultV3) -> Result<(), String> {
    assert_vault_generation_current(vault)?;

    let mut extensions = vault.extensions.clone();
    let mut ext_payloads = vec![];

    // rev. 4: if the Error-Correction extension is present, recompute the shards
    // over the current data section and update the entry + payload. Recompute on
    // every seal (cost is acceptable for the EC use case; most vaults won't have
    // it enabled).
    if let Some(error_correction_idx) = extensions
        .iter()
        .position(|e| e.extension_id == super::constants::ERROR_CORRECTION_EXTENSION_ID)
    {
        // On-disk blocks in data-section order (sorted by data_offset). Each
        // full block is [u64 len][ciphertext of that len].
        let mut chunk_records: Vec<_> = vault.manifest.chunks.values().cloned().collect();
        chunk_records.sort_by_key(|r| r.data_offset);

        let blocks: Vec<&[u8]> = chunk_records
            .iter()
            .map(|rec| {
                let start = rec.data_offset as usize;
                let full_len = 8 + rec.block_len as usize;
                if start + full_len <= vault.data.len() {
                    &vault.data[start..start + full_len]
                } else {
                    &[] as &[u8]
                }
            })
            .collect();

        let (k, p) = crate::error_correction::manifest_error_correction_grid(
            vault.manifest.error_correction_pct,
        );
        let (payload, _shards, _protected, _overhead) =
            crate::error_correction::compute_error_correction_shards_grid(&blocks, k, p);

        let entry = &mut extensions[error_correction_idx];
        entry.offset = 0;
        entry.length = payload.len() as u64;

        ext_payloads = payload;
    }

    let bytes = build_file_bytes(
        vault.header.clone(),
        &vault.mac_key,
        &vault.master_key,
        &vault.manifest,
        &extensions,
        &ext_payloads,
        &vault.data,
    )?;
    atomic_write(&vault.path, &bytes)?;

    // Refresh the staleness baseline so a second save in the same session does
    // not trip the generation guard against the bytes we just wrote.
    let mut file = std::fs::File::open(&vault.path).map_err(|e| format!("Open vault: {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("Vault metadata: {e}"))?
        .len();
    let mut header_bytes = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("Read header: {e}"))?;
    let header = VaultHeaderV3::from_bytes(&header_bytes)?;
    vault.opened_file_len = file_len;
    vault.opened_header_mac = header.header_mac;
    vault.header = header;
    Ok(())
}

fn extract_entry(vault: &OpenVaultV3, entry_name: &str, dest_path: &Path) -> Result<PathBuf, String> {
    let entry_name = normalize_vault_relative_path(entry_name)?;
    match entry_kind(&vault.manifest, &entry_name) {
        Some(EntryKindV3::File) => {
            let entry = vault
                .manifest
                .entries
                .iter()
                .find(|entry| entry.path == entry_name)
                .ok_or_else(|| format!("Entry not found: {entry_name}"))?;
            let output_path = if dest_path.is_dir() {
                dest_path.join(&entry.path)
            } else {
                dest_path.to_path_buf()
            };
            extract_file_entry(vault, entry, &output_path)
        }
        Some(EntryKindV3::Directory) => {
            let output_root = if dest_path.exists() {
                if !dest_path.is_dir() {
                    return Err(
                        "Destination for directory extraction must be a directory".to_string(),
                    );
                }
                dest_path.join(path_basename(&entry_name))
            } else {
                dest_path.to_path_buf()
            };
            std::fs::create_dir_all(&output_root).map_err(|e| format!("Create output dir: {e}"))?;

            let prefix = format!("{entry_name}/");
            let mut descendants: Vec<&ManifestEntryV3> = vault
                .manifest
                .entries
                .iter()
                .filter(|entry| entry.path == entry_name || entry.path.starts_with(&prefix))
                .collect();
            descendants.sort_by(|a, b| a.path.cmp(&b.path));

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
                    std::fs::create_dir_all(&child_output)
                        .map_err(|e| format!("Create output dir: {e}"))?;
                } else {
                    extract_file_entry(vault, entry, &child_output)?;
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
    std::fs::create_dir_all(dest_root).map_err(|e| format!("Create output dir: {e}"))?;
    let mut entries: Vec<&ManifestEntryV3> = vault.manifest.entries.iter().collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut files_written = 0u64;
    for entry in entries {
        let rel = normalize_vault_relative_path(&entry.path)?;
        let output = dest_root.join(&rel);
        if entry.is_dir {
            std::fs::create_dir_all(&output).map_err(|e| format!("Create output dir: {e}"))?;
        } else {
            extract_file_entry(vault, entry, &output)?;
            files_written += 1;
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

    save_open_vault(vault)?;
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
        assert!(listed.iter().any(|e| e.path == "big.bin" && e.size == payload.len() as u64));

        // Extract all and verify byte-identity.
        let out = scratch_dir();
        let written = VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(written, 4);
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha contents");
        assert_eq!(
            std::fs::read(out.join("b.txt")).unwrap(),
            b"beta contents which differ"
        );
        assert_eq!(std::fs::read(out.join("docs/sub/c.txt")).unwrap(), vec![0x5au8; 4096]);
        assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), payload);

        std::fs::remove_file(&vp).ok();
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
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
        let c1: Vec<&String> = entries.iter().find(|e| e.path == "one.bin").unwrap().chunks.iter().collect();
        let c2: Vec<&String> = entries.iter().find(|e| e.path == "two.bin").unwrap().chunks.iter().collect();
        assert_eq!(c1, c2);

        std::fs::remove_file(&vp).ok();
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
        VaultV3::add_files(&mut vault, &[(src.join("doc.txt"), "src/doc.txt".to_string())]).unwrap();

        let chunks_before = vault.manifest.chunks.len();
        VaultV3::copy_entry(&mut vault, "src/doc.txt", "src/doc-copy.txt").unwrap();
        // Copy reuses chunk records: no new chunks stored.
        assert_eq!(vault.manifest.chunks.len(), chunks_before);
        assert!(VaultV3::list(&vault).iter().any(|e| e.path == "src/doc-copy.txt"));

        // Move directory updates descendants.
        VaultV3::move_entry(&mut vault, "src", "moved").unwrap();
        let paths: Vec<String> = VaultV3::list(&vault).into_iter().map(|e| e.path).collect();
        assert!(paths.contains(&"moved".to_string()));
        assert!(paths.contains(&"moved/doc.txt".to_string()));
        assert!(!paths.iter().any(|p| p.starts_with("src")));

        // Rename within parent.
        VaultV3::rename_entry(&mut vault, "moved/doc.txt", "renamed.txt").unwrap();
        assert!(VaultV3::list(&vault).iter().any(|e| e.path == "moved/renamed.txt"));

        // Delete then re-open round-trips.
        VaultV3::delete_entries(&mut vault, &["moved".to_string()], true).unwrap();
        assert!(VaultV3::list(&vault).is_empty());
        drop(vault);

        let reopened = VaultV3::open(&vp, PW).unwrap();
        assert!(VaultV3::list(&reopened).is_empty());

        std::fs::remove_file(&vp).ok();
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

        std::fs::remove_file(&vp).ok();
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
        assert_eq!(std::fs::read(out.join("imported/top.txt")).unwrap(), b"top file");
        assert_eq!(
            std::fs::read(out.join("imported/nested/deep/bottom.txt")).unwrap(),
            b"bottom file"
        );

        std::fs::remove_file(&vp).ok();
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
            opened_header_mac: [0u8; MAC_SIZE],
            master_key: [0u8; KEY_SIZE],
            mac_key: [0u8; KEY_SIZE],
            manifest,
            extensions: Vec::new(),
            data: Vec::new(),
            manifest_repaired_on_open: false,
            header_repaired_on_open: false,
        };
        let out = scratch_dir();
        assert!(VaultV3::extract_entry(&vault, "../escape.txt", &out).is_err());
        std::fs::remove_dir_all(&out).ok();
    }
}
