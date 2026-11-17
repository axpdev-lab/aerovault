// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High-level vault operations.
//!
//! This module provides the public API for creating, opening, and manipulating
//! AeroVault v2 containers. All mutations use atomic writes (temp + fsync + rename)
//! to prevent data corruption on crash or power loss.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::*;
use crate::crypto;
use crate::error::{CryptoError, Error, FormatError};
use crate::format::*;

/// Minimum allowed chunk size (4 KiB).
const MIN_CHUNK_SIZE: u32 = 4 * 1024;

/// Maximum allowed chunk size (16 MiB).
const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Options for creating a new vault.
pub struct CreateOptions {
    path: PathBuf,
    password: SecretString,
    mode: EncryptionMode,
    chunk_size: u32,
    version: u8,
}

impl CreateOptions {
    /// Create new vault options with the given path and password.
    pub fn new(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: SecretString::from(password.into()),
            mode: EncryptionMode::Standard,
            chunk_size: DEFAULT_CHUNK_SIZE,
            version: VERSION,
        }
    }

    /// Select the on-disk container version to write.
    ///
    /// Defaults to the current [`VERSION`] (v3, file-id-bound chunk AAD).
    /// Pass [`LEGACY_VERSION`] (v2, chunk-index-only AAD) to write a legacy
    /// container, e.g. for migration tooling or backward-compat round-trip
    /// tests. Any other value is rejected at [`Vault::create`]. Readers accept
    /// both versions regardless of which one was written.
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set the encryption mode.
    pub fn with_mode(mut self, mode: EncryptionMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set a custom chunk size.
    ///
    /// Must be between 4 KiB and 16 MiB. Returns an error at vault creation
    /// if the value is out of range.
    pub fn with_chunk_size(mut self, size: u32) -> Self {
        self.chunk_size = size;
        self
    }
}

/// Decrypted entry information returned by listing operations.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Decrypted filename (may contain `/` for nested paths).
    pub name: String,
    /// Original file size in bytes.
    pub size: u64,
    /// Whether this is a directory entry.
    pub is_dir: bool,
    /// Last modification timestamp (ISO 8601).
    pub modified: String,
}

/// An unlocked AeroVault v2 container.
///
/// Created via [`Vault::create`] or [`Vault::open`]. Holds decrypted keys
/// in memory — drop the vault when done to zeroize secrets.
pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    master_key: SecretVec<u8>,
    mac_key: SecretVec<u8>,
}

impl Vault {
    /// Create a new empty vault at the specified path.
    ///
    /// # Errors
    ///
    /// Returns an error if the password is too short (< 8 chars), the chunk
    /// size is out of range, the file cannot be written, or the write lock is
    /// refused (another writer keeps it, the path is a symbolic link or names
    /// a lock file; see `crate::lock`).
    pub fn create(opts: CreateOptions) -> crate::Result<Self> {
        if opts.password.expose_secret().len() < MIN_PASSWORD_LENGTH {
            return Err(crate::Error::PasswordPolicy(format!(
                "password must be at least {MIN_PASSWORD_LENGTH} characters"
            )));
        }

        if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
            return Err(FormatError::InvalidChunkSize(opts.chunk_size).into());
        }

        if opts.version != VERSION && opts.version != LEGACY_VERSION {
            return Err(FormatError::UnsupportedVersion(opts.version).into());
        }

        // The lock first: the mode of an existing vault at this path is read
        // (for the replacement) only while no other writer can change it, and
        // a refused lock returns before any key exists.
        let lock = crate::lock::acquire(&opts.path)?;

        // Generate random salt
        let mut salt = [0u8; SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // Derive base KEK from password
        let base_kek = crypto::derive_key(&opts.password, &salt)?;
        let (kek_master, kek_mac) = crypto::derive_kek_pair(base_kek.expose_secret());

        // Generate random master and MAC keys (zeroized on every return)
        let mut master_key_raw = Zeroizing::new([0u8; KEY_SIZE]);
        let mut mac_key_raw = Zeroizing::new([0u8; KEY_SIZE]);
        rand::rngs::OsRng.fill_bytes(&mut master_key_raw[..]);
        rand::rngs::OsRng.fill_bytes(&mut mac_key_raw[..]);

        // Wrap keys
        let wrapped_master = crypto::wrap_key(&kek_master, &master_key_raw[..])?;
        let wrapped_mac = crypto::wrap_key(&kek_mac, &mac_key_raw[..])?;

        // kek_master and kek_mac are Zeroizing — auto-dropped

        // Build header
        let flags = HeaderFlags {
            cascade_mode: opts.mode == EncryptionMode::Cascade,
        };

        let mut header = VaultHeader {
            magic: *MAGIC,
            version: opts.version,
            flags,
            salt,
            wrapped_master_key: wrapped_master,
            wrapped_mac_key: wrapped_mac,
            chunk_size: opts.chunk_size,
            reserved: [0u8; 320],
            header_mac: [0u8; MAC_SIZE],
        };
        header.header_mac = header.compute_mac(&mac_key_raw[..]);

        // Create empty manifest
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let manifest = VaultManifest {
            created: now.clone(),
            modified: now,
            description: None,
            entries: Vec::new(),
        };

        let manifest_json =
            serde_json::to_string(&manifest).map_err(|e| crate::Error::Manifest(e.to_string()))?;
        let encrypted_manifest = crypto::encrypt_filename(&master_key_raw[..], &manifest_json)?;
        let manifest_bytes = encrypted_manifest.as_bytes();

        // Write vault file atomically via temp + fsync + rename
        let tmp = temporary_vault_file(&opts.path, "create")?;
        let mut writer = BufWriter::new(tmp.as_file());

        writer.write_all(&header.to_bytes())?;
        writer.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(manifest_bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);

        atomic_rename(tmp.path(), &opts.path)?;
        drop(lock);

        let master_key = SecretVec::new(master_key_raw.to_vec());
        let mac_key = SecretVec::new(mac_key_raw.to_vec());

        Ok(Self {
            path: opts.path,
            header,
            master_key,
            mac_key,
        })
    }

    /// Open an existing vault with the given password.
    ///
    /// Verifies the header MAC before unwrapping the master key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyUnwrap`] if the password is wrong, or
    /// [`CryptoError::HeaderMacMismatch`] if the header has been tampered with.
    pub fn open(path: impl Into<PathBuf>, password: impl Into<String>) -> crate::Result<Self> {
        let path = path.into();
        let pwd = SecretString::from(password.into());

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);

        // Read header
        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;
        let header = VaultHeader::from_bytes(&header_buf)?;

        // Derive keys
        let base_kek = crypto::derive_key(&pwd, &header.salt)?;
        let (kek_master, kek_mac) = crypto::derive_kek_pair(base_kek.expose_secret());

        // Unwrap MAC key first, verify header MAC, then unwrap master key
        let mac_key = crypto::unwrap_key(&kek_mac, &header.wrapped_mac_key)?;
        header.verify_mac(mac_key.expose_secret())?;
        let master_key = crypto::unwrap_key(&kek_master, &header.wrapped_master_key)?;

        // kek_master and kek_mac are Zeroizing — auto-dropped

        Ok(Self {
            path,
            header,
            master_key,
            mac_key,
        })
    }

    /// Check if a file is an AeroVault v2 container (reads only the first 11 bytes).
    pub fn is_vault(path: impl AsRef<Path>) -> bool {
        let Ok(file) = File::open(path.as_ref()) else {
            return false;
        };
        let mut buf = [0u8; 11];
        let mut reader = BufReader::new(file);
        if reader.read_exact(&mut buf).is_err() {
            return false;
        }
        &buf[..10] == MAGIC && (buf[10] == VERSION || buf[10] == LEGACY_VERSION)
    }

    /// Read vault header information without a password.
    ///
    /// Returns basic metadata (version, encryption mode, chunk size) that is
    /// stored unencrypted in the header. Useful for UI display before unlock.
    pub fn peek(path: impl AsRef<Path>) -> crate::Result<PeekInfo> {
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);
        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;
        let header = VaultHeader::from_bytes(&header_buf)?;

        let mode = if header.flags.cascade_mode {
            EncryptionMode::Cascade
        } else {
            EncryptionMode::Standard
        };

        Ok(PeekInfo {
            version: header.version,
            mode,
            chunk_size: header.chunk_size,
        })
    }

    /// Get the vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the encryption mode.
    pub fn mode(&self) -> EncryptionMode {
        if self.header.flags.cascade_mode {
            EncryptionMode::Cascade
        } else {
            EncryptionMode::Standard
        }
    }

    /// Get the chunk size.
    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size
    }

    /// Return security information about the vault.
    pub fn security_info(&self) -> SecurityInfo {
        SecurityInfo {
            version: self.header.version,
            mode: self.mode(),
            chunk_size: self.header.chunk_size,
            argon2_m_cost_kib: ARGON2_M_COST,
            argon2_t_cost: ARGON2_T_COST,
            argon2_p_cost: ARGON2_P_COST,
        }
    }

    /// List all entries in the vault with decrypted filenames.
    pub fn list(&self) -> crate::Result<Vec<EntryInfo>> {
        let manifest = self.read_manifest()?;
        let mut entries = Vec::with_capacity(manifest.entries.len());

        for entry in &manifest.entries {
            let name =
                crypto::decrypt_filename(self.master_key.expose_secret(), &entry.encrypted_name)?;
            entries.push(EntryInfo {
                name,
                size: entry.size,
                is_dir: entry.is_dir,
                modified: entry.modified.clone(),
            });
        }

        Ok(entries)
    }

    /// Add files from disk into the vault.
    ///
    /// Files are encrypted in chunks and appended to the data section.
    /// Duplicate filenames are silently skipped.
    pub fn add_files(&self, file_paths: &[impl AsRef<Path>]) -> crate::Result<u32> {
        self.add_files_to_dir(file_paths, "")
    }

    /// Add files to a specific directory inside the vault.
    ///
    /// The `target_dir` must already exist (or be empty for root).
    pub fn add_files_to_dir(
        &self,
        file_paths: &[impl AsRef<Path>],
        target_dir: &str,
    ) -> crate::Result<u32> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let target_dir = target_dir.trim().trim_matches('/');
        if target_dir.contains("..") {
            return Err(crate::Error::InvalidPath(
                "directory path cannot contain '..'".into(),
            ));
        }

        let cascade_mode = self.header.flags.cascade_mode;
        let chunk_size = self.header.chunk_size as usize;
        let bind_chunks = self.header.version >= VERSION;

        // Read current vault state
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        // Verify target directory exists (if non-empty)
        if !target_dir.is_empty() {
            let target_encrypted =
                crypto::encrypt_filename(self.master_key.expose_secret(), target_dir)?;
            let dir_exists = manifest
                .entries
                .iter()
                .any(|e| e.encrypted_name == target_encrypted && e.is_dir);
            if !dir_exists {
                return Err(crate::Error::EntryNotFound(format!(
                    "target directory '{target_dir}'"
                )));
            }
        }

        // Read existing data
        let mut existing_data = Vec::new();
        reader.read_to_end(&mut existing_data)?;

        let chacha_key = if cascade_mode {
            crypto::derive_chacha_key(self.master_key.expose_secret())
        } else {
            zeroize::Zeroizing::new([0u8; KEY_SIZE])
        };

        let mut data_offset = existing_data.len() as u64;
        let mut new_data = Vec::new();
        let mut added_count = 0u32;

        for file_path in file_paths {
            let file_path = file_path.as_ref();
            let source = File::open(file_path)?;
            let metadata = source.metadata()?;

            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| crate::Error::InvalidPath(format!("{}", file_path.display())))?;

            let vault_name = if target_dir.is_empty() {
                filename.to_string()
            } else {
                format!("{target_dir}/{filename}")
            };

            // Check for duplicate
            let encrypted_name =
                crypto::encrypt_filename(self.master_key.expose_secret(), &vault_name)?;
            if manifest
                .entries
                .iter()
                .any(|e| e.encrypted_name == encrypted_name)
            {
                continue;
            }

            let mut source_reader = BufReader::new(source);
            let mut chunk_count = 0u32;
            let chunk_total = if metadata.len() == 0 {
                0
            } else {
                metadata
                    .len()
                    .div_ceil(chunk_size as u64)
                    .try_into()
                    .map_err(|_| crate::Error::Manifest("chunk count overflow".into()))?
            };
            let file_id = if bind_chunks {
                let mut id = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut id);
                Some(id)
            } else {
                None
            };
            let entry_offset = data_offset;

            loop {
                let mut chunk = vec![0u8; chunk_size];
                let bytes_read = source_reader.read(&mut chunk)?;
                if bytes_read == 0 {
                    break;
                }
                chunk.truncate(bytes_read);

                let encrypted_chunk = if cascade_mode {
                    crypto::encrypt_chunk_cascade_bound(
                        self.master_key.expose_secret(),
                        &chacha_key,
                        &chunk,
                        chunk_count,
                        file_id.as_ref(),
                        chunk_total,
                    )?
                } else {
                    crypto::encrypt_chunk_bound(
                        self.master_key.expose_secret(),
                        &chunk,
                        chunk_count,
                        file_id.as_ref(),
                        chunk_total,
                    )?
                };

                let chunk_len = encrypted_chunk.len() as u32;
                new_data.extend_from_slice(&chunk_len.to_le_bytes());
                new_data.extend_from_slice(&encrypted_chunk);

                data_offset += 4 + encrypted_chunk.len() as u64;
                chunk_count = chunk_count
                    .checked_add(1)
                    .ok_or_else(|| crate::Error::Manifest("chunk count overflow".into()))?;

                chunk.zeroize();
            }

            // The v3+ chunk AAD binds `chunk_total`, derived from the pre-stream
            // `metadata.len()`. Extraction rebuilds the AAD from the manifest's
            // stored `chunk_count` (the actual number of chunks streamed). If the
            // source changed size between the stat and the read, the two diverge
            // and every chunk would fail AAD verification on extract: a silently
            // unrecoverable entry. Fail the add instead of persisting it. (Legacy
            // v2 binds only the chunk index, so the mismatch is harmless there.)
            if bind_chunks && chunk_count != chunk_total {
                return Err(crate::Error::Manifest(format!(
                    "source changed size during add (bound {chunk_total} chunks, streamed {chunk_count}); aborting to avoid an unrecoverable entry"
                )));
            }

            let modified = metadata
                .modified()
                .map(|t| {
                    let datetime: chrono::DateTime<chrono::Utc> = t.into();
                    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                })
                .unwrap_or_else(|_| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

            manifest.entries.push(ManifestEntry {
                encrypted_name,
                name: String::new(),
                size: metadata.len(),
                offset: entry_offset,
                chunk_count,
                file_id,
                is_dir: false,
                modified,
            });

            added_count += 1;
        }

        if added_count > 0 {
            manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            self.write_vault_atomic(&header_buf, &manifest, &existing_data, &new_data)?;
        }

        // chacha_key is Zeroizing — auto-dropped
        Ok(added_count)
    }

    /// Create a directory inside the vault.
    ///
    /// Intermediate directories are created automatically (like `mkdir -p`).
    pub fn create_directory(&self, dir_name: &str) -> crate::Result<u32> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let dir_name = dir_name.trim().trim_matches('/');
        if dir_name.is_empty() {
            return Err(crate::Error::InvalidPath(
                "directory name cannot be empty".into(),
            ));
        }
        if dir_name.contains("..") {
            return Err(crate::Error::InvalidPath(
                "directory name cannot contain '..'".into(),
            ));
        }
        if dir_name.len() > 4096 {
            return Err(crate::Error::InvalidPath("directory name too long".into()));
        }

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut existing_data = Vec::new();
        reader.read_to_end(&mut existing_data)?;

        // Collect directories to create (including intermediates)
        let mut dirs_to_create = Vec::new();
        let parts: Vec<&str> = dir_name.split('/').collect();
        for i in 1..=parts.len() {
            let partial = parts[..i].join("/");
            let encrypted = crypto::encrypt_filename(self.master_key.expose_secret(), &partial)?;
            if !manifest
                .entries
                .iter()
                .any(|e| e.encrypted_name == encrypted)
            {
                dirs_to_create.push((partial, encrypted));
            }
        }

        if dirs_to_create.is_empty() {
            return Ok(0);
        }

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for (_, encrypted_name) in &dirs_to_create {
            manifest.entries.push(ManifestEntry {
                encrypted_name: encrypted_name.clone(),
                name: String::new(),
                size: 0,
                offset: 0,
                chunk_count: 0,
                file_id: None,
                is_dir: true,
                modified: now.clone(),
            });
        }

        manifest.modified = now;
        let created = dirs_to_create.len() as u32;
        self.write_vault_atomic(&header_buf, &manifest, &existing_data, &[])?;

        Ok(created)
    }

    /// Extract a single entry to the specified output directory.
    ///
    /// Returns the full path of the extracted file. Validates that the output
    /// path stays within `output_dir` to prevent path traversal attacks.
    pub fn extract(
        &self,
        entry_name: &str,
        output_dir: impl AsRef<Path>,
    ) -> crate::Result<PathBuf> {
        let output_dir = output_dir.as_ref();

        // Validate entry name against path traversal
        validate_entry_name(entry_name)?;

        let manifest = self.read_manifest()?;

        // Find matching entry
        let entry = manifest
            .entries
            .iter()
            .find(|e| {
                crypto::decrypt_filename(self.master_key.expose_secret(), &e.encrypted_name)
                    .map(|name| name == entry_name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| crate::Error::EntryNotFound(entry_name.to_string()))?;

        if entry.is_dir {
            let dir_path = output_dir.join(entry_name);
            validate_output_path(&dir_path, output_dir)?;
            // Every folder this creates is named by the vault: none may take a
            // lock file name.
            let mut current = output_dir.to_path_buf();
            for part in Path::new(entry_name).components() {
                current.push(part);
                if !current.exists() {
                    crate::lock::refuse_lock_named_dir(&current)?;
                }
            }
            std::fs::create_dir_all(&dir_path)?;
            return Ok(dir_path);
        }

        let cascade_mode = self.header.flags.cascade_mode;

        let chacha_key = if cascade_mode {
            crypto::derive_chacha_key(self.master_key.expose_secret())
        } else {
            zeroize::Zeroizing::new([0u8; KEY_SIZE])
        };

        // Open vault and seek to data section
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        // Skip header
        let mut skip_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut skip_buf)?;

        // Skip manifest
        let (manifest_len, _manifest_data) = crypto::read_manifest_bounded(&mut reader)?;
        let data_start = HEADER_SIZE as u64 + 4 + manifest_len as u64;
        let vault_len = std::fs::metadata(&self.path)?.len();

        // Skip to entry offset
        let mut skipped = 0u64;
        while skipped < entry.offset {
            let to_skip = std::cmp::min(entry.offset - skipped, 8192) as usize;
            let mut skip = vec![0u8; to_skip];
            reader.read_exact(&mut skip)?;
            skipped += to_skip as u64;
        }

        // Determine safe output path
        let filename = Path::new(entry_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                crate::Error::InvalidPath(format!("invalid entry name: {entry_name}"))
            })?;
        let dest_path = output_dir.join(filename);
        validate_output_path(&dest_path, output_dir)?;

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let out_file = open_new_output_file(&dest_path, output_dir)?;
        let mut writer = BufWriter::new(out_file);

        // Read and decrypt chunks
        let mut entry_bytes_consumed = 0u64;
        for chunk_idx in 0..entry.chunk_count {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let chunk_len = u32::from_le_bytes(len_buf) as usize;
            let bytes_remaining =
                vault_len.saturating_sub(data_start + entry.offset + entry_bytes_consumed + 4);
            validate_encrypted_chunk_len(
                chunk_len,
                bytes_remaining,
                self.header.chunk_size,
                cascade_mode,
            )?;
            entry_bytes_consumed += 4 + chunk_len as u64;

            let mut encrypted_chunk = vec![0u8; chunk_len];
            reader.read_exact(&mut encrypted_chunk)?;

            let mut plaintext = if cascade_mode {
                crypto::decrypt_chunk_cascade_bound(
                    self.master_key.expose_secret(),
                    &chacha_key,
                    &encrypted_chunk,
                    chunk_idx,
                    entry.file_id.as_ref(),
                    entry.chunk_count,
                )?
            } else {
                crypto::decrypt_chunk_bound(
                    self.master_key.expose_secret(),
                    &encrypted_chunk,
                    chunk_idx,
                    entry.file_id.as_ref(),
                    entry.chunk_count,
                )?
            };

            writer.write_all(&plaintext)?;
            plaintext.zeroize();
            encrypted_chunk.zeroize();
        }

        writer.flush()?;
        // chacha_key is Zeroizing — auto-dropped

        Ok(dest_path)
    }

    /// Extract all entries to the specified output directory.
    ///
    /// Returns the number of entries extracted.
    pub fn extract_all(&self, output_dir: impl AsRef<Path>) -> crate::Result<u32> {
        let entries = self.list()?;
        let mut count = 0u32;
        for entry in &entries {
            self.extract(&entry.name, output_dir.as_ref())?;
            count += 1;
        }
        Ok(count)
    }

    /// Delete an entry from the vault manifest.
    ///
    /// The encrypted data remains in the file but becomes orphaned.
    /// Use [`Vault::compact`] (future) to reclaim space.
    pub fn delete_entry(&self, entry_name: &str) -> crate::Result<()> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut data_section = Vec::new();
        reader.read_to_end(&mut data_section)?;

        // Find and remove entry
        let mut found = false;
        manifest.entries.retain(|entry| {
            match crypto::decrypt_filename(self.master_key.expose_secret(), &entry.encrypted_name) {
                Ok(name) if name == entry_name => {
                    found = true;
                    false
                }
                _ => true,
            }
        });

        if !found {
            return Err(crate::Error::EntryNotFound(entry_name.to_string()));
        }

        manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        self.write_vault_atomic(&header_buf, &manifest, &data_section, &[])?;
        Ok(())
    }

    /// Delete multiple entries from the vault manifest in a single pass.
    ///
    /// If `recursive` is true, deleting a directory also removes all entries
    /// under it (e.g., deleting "docs" also removes "docs/file.txt").
    /// Returns the number of entries removed.
    pub fn delete_entries(&self, names: &[&str], recursive: bool) -> crate::Result<u32> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut data_section = Vec::new();
        reader.read_to_end(&mut data_section)?;

        let original_count = manifest.entries.len();

        manifest.entries.retain(|entry| {
            let decrypted =
                crypto::decrypt_filename(self.master_key.expose_secret(), &entry.encrypted_name);
            match decrypted {
                Ok(name) => {
                    // Direct name match
                    if names.contains(&name.as_str()) {
                        return false;
                    }
                    // Recursive: remove children of deleted directories
                    if recursive {
                        for target in names {
                            if name.starts_with(&format!("{target}/")) {
                                return false;
                            }
                        }
                    }
                    true
                }
                Err(_) => true,
            }
        });

        let removed = (original_count - manifest.entries.len()) as u32;
        if removed > 0 {
            manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            self.write_vault_atomic(&header_buf, &manifest, &data_section, &[])?;
        }

        Ok(removed)
    }

    /// Move or rename an entry inside the vault.
    ///
    /// Supports both file and directory moves. When moving a directory, all
    /// descendant entries are moved as a single atomic manifest update.
    pub fn move_entry(&self, from: &str, to: &str) -> crate::Result<()> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let from = from.trim().trim_matches('/');
        let to = to.trim().trim_matches('/');

        if from.is_empty() || to.is_empty() {
            return Err(crate::Error::InvalidPath(
                "source and destination cannot be empty".into(),
            ));
        }

        validate_entry_name(from)?;
        validate_entry_name(to)?;

        if from == to {
            return Ok(());
        }

        if to.starts_with(&format!("{from}/")) {
            return Err(crate::Error::InvalidPath(
                "cannot move an entry into its own subtree".into(),
            ));
        }

        if from.len() > 4096 || to.len() > 4096 {
            return Err(crate::Error::InvalidPath("path too long".into()));
        }

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut data_section = Vec::new();
        reader.read_to_end(&mut data_section)?;

        let mut names: Vec<String> = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            names.push(crypto::decrypt_filename(
                self.master_key.expose_secret(),
                &entry.encrypted_name,
            )?);
        }

        let src_index = names
            .iter()
            .position(|n| n == from)
            .ok_or_else(|| crate::Error::EntryNotFound(from.to_string()))?;
        let src_is_dir = manifest.entries[src_index].is_dir;

        let mut renames: Vec<(usize, String)> = Vec::new();
        for (idx, name) in names.iter().enumerate() {
            if src_is_dir {
                if name == from {
                    renames.push((idx, to.to_string()));
                } else if name.starts_with(&format!("{from}/")) {
                    renames.push((idx, format!("{to}{}", &name[from.len()..])));
                }
            } else if name == from {
                renames.push((idx, to.to_string()));
            }
        }

        if renames.is_empty() {
            return Err(crate::Error::EntryNotFound(from.to_string()));
        }

        // Build final entry map and validate uniqueness + parent directories.
        let mut final_map: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        for (idx, old_name) in names.iter().enumerate() {
            let resolved_name = renames
                .iter()
                .find(|(rename_idx, _)| *rename_idx == idx)
                .map(|(_, new_name)| new_name.as_str())
                .unwrap_or(old_name.as_str());

            if final_map
                .insert(resolved_name.to_string(), manifest.entries[idx].is_dir)
                .is_some()
            {
                return Err(crate::Error::Manifest(format!(
                    "target entry already exists: {resolved_name}"
                )));
            }
        }

        for name in final_map.keys() {
            if let Some((parent, _)) = name.rsplit_once('/') {
                if parent.is_empty() {
                    continue;
                }
                let parent_is_dir = final_map.get(parent).copied().unwrap_or(false);
                if !parent_is_dir {
                    return Err(crate::Error::EntryNotFound(format!(
                        "parent directory '{parent}'"
                    )));
                }
            }
        }

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for (idx, new_name) in &renames {
            manifest.entries[*idx].encrypted_name =
                crypto::encrypt_filename(self.master_key.expose_secret(), new_name)?;
            manifest.entries[*idx].modified = now.clone();
        }

        manifest.modified = now;
        self.write_vault_atomic(&header_buf, &manifest, &data_section, &[])?;
        Ok(())
    }

    /// Rename an entry while keeping it in the same parent directory.
    pub fn rename_entry(&self, current_name: &str, new_name: &str) -> crate::Result<()> {
        let current_name = current_name.trim().trim_matches('/');
        let new_name = new_name.trim().trim_matches('/');

        if new_name.is_empty() {
            return Err(crate::Error::InvalidPath("new name cannot be empty".into()));
        }
        if new_name.contains('/') || new_name.contains('\\') || new_name.contains('\0') {
            return Err(crate::Error::InvalidPath(
                "new name must be a single path segment".into(),
            ));
        }
        if new_name == "." || new_name == ".." {
            return Err(crate::Error::InvalidPath("invalid new name".into()));
        }

        let target = if let Some((parent, _)) = current_name.rsplit_once('/') {
            format!("{parent}/{new_name}")
        } else {
            new_name.to_string()
        };

        self.move_entry(current_name, &target)
    }

    /// Copy an entry (file or directory) inside the vault.
    ///
    /// The copied entries reuse the existing encrypted data chunk references;
    /// only manifest metadata is duplicated and re-encrypted names are written.
    pub fn copy_entry(&self, from: &str, to: &str) -> crate::Result<()> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        let from = from.trim().trim_matches('/');
        let to = to.trim().trim_matches('/');

        if from.is_empty() || to.is_empty() {
            return Err(crate::Error::InvalidPath(
                "source and destination cannot be empty".into(),
            ));
        }

        validate_entry_name(from)?;
        validate_entry_name(to)?;

        if from == to {
            return Err(crate::Error::Manifest("target entry already exists".into()));
        }

        if to.starts_with(&format!("{from}/")) {
            return Err(crate::Error::InvalidPath(
                "cannot copy an entry into its own subtree".into(),
            ));
        }

        if from.len() > 4096 || to.len() > 4096 {
            return Err(crate::Error::InvalidPath("path too long".into()));
        }

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut data_section = Vec::new();
        reader.read_to_end(&mut data_section)?;

        let mut names: Vec<String> = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            names.push(crypto::decrypt_filename(
                self.master_key.expose_secret(),
                &entry.encrypted_name,
            )?);
        }

        let src_index = names
            .iter()
            .position(|n| n == from)
            .ok_or_else(|| crate::Error::EntryNotFound(from.to_string()))?;
        let src_is_dir = manifest.entries[src_index].is_dir;

        let mut copies: Vec<(usize, String)> = Vec::new();
        for (idx, name) in names.iter().enumerate() {
            if src_is_dir {
                if name == from {
                    copies.push((idx, to.to_string()));
                } else if name.starts_with(&format!("{from}/")) {
                    copies.push((idx, format!("{to}{}", &name[from.len()..])));
                }
            } else if name == from {
                copies.push((idx, to.to_string()));
            }
        }

        if copies.is_empty() {
            return Err(crate::Error::EntryNotFound(from.to_string()));
        }

        let mut final_map: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        for (idx, name) in names.iter().enumerate() {
            final_map.insert(name.to_string(), manifest.entries[idx].is_dir);
        }
        for (src_idx, copied_name) in &copies {
            if final_map
                .insert(copied_name.clone(), manifest.entries[*src_idx].is_dir)
                .is_some()
            {
                return Err(crate::Error::Manifest(format!(
                    "target entry already exists: {copied_name}"
                )));
            }
        }

        for name in final_map.keys() {
            if let Some((parent, _)) = name.rsplit_once('/') {
                if parent.is_empty() {
                    continue;
                }
                let parent_is_dir = final_map.get(parent).copied().unwrap_or(false);
                if !parent_is_dir {
                    return Err(crate::Error::EntryNotFound(format!(
                        "parent directory '{parent}'"
                    )));
                }
            }
        }

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut new_entries: Vec<ManifestEntry> = Vec::with_capacity(copies.len());
        for (src_idx, copied_name) in copies {
            let mut cloned = manifest.entries[src_idx].clone();
            cloned.encrypted_name =
                crypto::encrypt_filename(self.master_key.expose_secret(), &copied_name)?;
            cloned.modified = now.clone();
            new_entries.push(cloned);
        }

        manifest.entries.extend(new_entries);
        manifest.modified = now;
        self.write_vault_atomic(&header_buf, &manifest, &data_section, &[])?;
        Ok(())
    }

    /// Compact the vault by removing orphaned data from deleted entries.
    ///
    /// Reads all surviving entries, decrypts and re-encrypts their chunks with
    /// fresh nonces, and writes a new vault file. Uses atomic temp+rename.
    ///
    /// Returns a [`CompactResult`] with size savings information.
    pub fn compact(&self) -> crate::Result<CompactResult> {
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;
        use std::io::Seek;

        let original_size = std::fs::metadata(&self.path)?.len();

        // Read header + manifest
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let data_start = HEADER_SIZE as u64 + 4 + manifest_len as u64;
        let cascade_mode = self.header.flags.cascade_mode;
        let file_count = manifest.entries.len();
        drop(reader);

        let chacha_key = if cascade_mode {
            crypto::derive_chacha_key(self.master_key.expose_secret())
        } else {
            zeroize::Zeroizing::new([0u8; KEY_SIZE])
        };

        // Re-open for seek-based reads
        let orig_file = File::open(&self.path)?;
        let mut orig_reader = BufReader::new(orig_file);

        let mut compacted_data: Vec<u8> = Vec::new();
        let mut new_data_offset: u64 = 0;

        for entry in &mut manifest.entries {
            if entry.is_dir || entry.chunk_count == 0 {
                entry.offset = 0;
                continue;
            }

            let entry_new_offset = new_data_offset;
            orig_reader.seek(std::io::SeekFrom::Start(data_start + entry.offset))?;

            let mut entry_bytes_consumed = 0u64;
            for chunk_idx in 0..entry.chunk_count {
                let mut len_buf = [0u8; 4];
                orig_reader.read_exact(&mut len_buf)?;
                let encrypted_chunk_len = u32::from_le_bytes(len_buf) as usize;
                let bytes_remaining = original_size
                    .saturating_sub(data_start + entry.offset + entry_bytes_consumed + 4);
                validate_encrypted_chunk_len(
                    encrypted_chunk_len,
                    bytes_remaining,
                    self.header.chunk_size,
                    cascade_mode,
                )?;
                entry_bytes_consumed += 4 + encrypted_chunk_len as u64;

                let mut encrypted_chunk = vec![0u8; encrypted_chunk_len];
                orig_reader.read_exact(&mut encrypted_chunk)?;

                let mut plaintext = if cascade_mode {
                    crypto::decrypt_chunk_cascade_bound(
                        self.master_key.expose_secret(),
                        &chacha_key,
                        &encrypted_chunk,
                        chunk_idx,
                        entry.file_id.as_ref(),
                        entry.chunk_count,
                    )?
                } else {
                    crypto::decrypt_chunk_bound(
                        self.master_key.expose_secret(),
                        &encrypted_chunk,
                        chunk_idx,
                        entry.file_id.as_ref(),
                        entry.chunk_count,
                    )?
                };

                encrypted_chunk.zeroize();

                let new_encrypted = if cascade_mode {
                    crypto::encrypt_chunk_cascade_bound(
                        self.master_key.expose_secret(),
                        &chacha_key,
                        &plaintext,
                        chunk_idx,
                        entry.file_id.as_ref(),
                        entry.chunk_count,
                    )?
                } else {
                    crypto::encrypt_chunk_bound(
                        self.master_key.expose_secret(),
                        &plaintext,
                        chunk_idx,
                        entry.file_id.as_ref(),
                        entry.chunk_count,
                    )?
                };

                plaintext.zeroize();

                let new_chunk_len = new_encrypted.len() as u32;
                compacted_data.extend_from_slice(&new_chunk_len.to_le_bytes());
                compacted_data.extend_from_slice(&new_encrypted);

                new_data_offset += 4 + new_encrypted.len() as u64;
            }

            entry.offset = entry_new_offset;
        }
        drop(orig_reader);

        manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Write compacted vault
        let manifest_json =
            serde_json::to_string(&manifest).map_err(|e| crate::Error::Manifest(e.to_string()))?;
        let encrypted_manifest =
            crypto::encrypt_filename(self.master_key.expose_secret(), &manifest_json)?;
        let manifest_bytes = encrypted_manifest.as_bytes();

        let tmp = temporary_vault_file(&self.path, "compact")?;
        let mut writer = BufWriter::new(tmp.as_file());

        writer.write_all(&header_buf)?;
        writer.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(manifest_bytes)?;
        writer.write_all(&compacted_data)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);

        atomic_rename(tmp.path(), &self.path)?;

        let compacted_size = std::fs::metadata(&self.path)?.len();

        Ok(CompactResult {
            original_size,
            compacted_size,
            saved_bytes: original_size.saturating_sub(compacted_size),
            file_count,
        })
    }

    /// Change the vault password.
    ///
    /// Re-wraps the master and MAC keys with a new KEK. The encrypted content
    /// remains unchanged — only the 512-byte header is modified.
    pub fn change_password(&mut self, new_password: impl Into<String>) -> crate::Result<()> {
        let new_pwd = SecretString::from(new_password.into());
        if new_pwd.expose_secret().len() < MIN_PASSWORD_LENGTH {
            return Err(crate::Error::PasswordPolicy(format!(
                "password must be at least {MIN_PASSWORD_LENGTH} characters"
            )));
        }
        // Held from the read of the vault to the rename (see `crate::lock`).
        let _lock = crate::lock::acquire(&self.path)?;

        let mut vault_data = std::fs::read(&self.path)?;

        if vault_data.len() < HEADER_SIZE {
            return Err(FormatError::TooSmall {
                actual: vault_data.len(),
                expected: HEADER_SIZE,
            }
            .into());
        }

        // The new header wraps this handle's keys over the content on disk, so
        // that content must be under these keys: `Vault::create` may have
        // replaced the vault since this handle opened it. The other writes find
        // out when the manifest does not decrypt; this one decrypts it here.
        // Only the content is checked, not the header on disk, which this
        // write replaces (a damaged header is rewritten, as before).
        if !self.manifest_decrypts(&vault_data[HEADER_SIZE..]) {
            vault_data.zeroize();
            return Err(crate::Error::Io(std::io::Error::other(format!(
                "{}: its manifest does not decrypt under this handle's key, so it is \
                 not the vault this handle opened (it was replaced since: open it \
                 again) or its manifest is damaged",
                self.path.display()
            ))));
        }

        // Generate new salt
        let mut new_salt = [0u8; SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);

        // Derive new KEKs
        let new_base_kek = crypto::derive_key(&new_pwd, &new_salt)?;
        let (new_kek_master, new_kek_mac) = crypto::derive_kek_pair(new_base_kek.expose_secret());

        // Re-wrap keys
        let new_wrapped_master =
            crypto::wrap_key(&new_kek_master, self.master_key.expose_secret())?;
        let new_wrapped_mac = crypto::wrap_key(&new_kek_mac, self.mac_key.expose_secret())?;

        // new_kek_master and new_kek_mac are Zeroizing — auto-dropped

        // Build new header
        let mut new_header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            flags: self.header.flags,
            salt: new_salt,
            wrapped_master_key: new_wrapped_master,
            wrapped_mac_key: new_wrapped_mac,
            chunk_size: self.header.chunk_size,
            reserved: [0u8; 320],
            header_mac: [0u8; MAC_SIZE],
        };
        new_header.header_mac = new_header.compute_mac(self.mac_key.expose_secret());

        // Write new header into vault data
        let header_bytes = new_header.to_bytes();
        vault_data[..HEADER_SIZE].copy_from_slice(&header_bytes);

        // Atomic write with fsync
        atomic_write(&self.path, &vault_data, "chpw")?;

        self.header = new_header;
        vault_data.zeroize();

        Ok(())
    }

    // --- Internal Helpers ---

    /// True if `body` (the bytes after the header) starts with a manifest that
    /// decrypts under this handle's master key. The decrypted manifest is only
    /// a proof and is wiped at once.
    fn manifest_decrypts(&self, mut body: &[u8]) -> bool {
        crypto::read_manifest_bounded(&mut body).is_ok_and(|(_, encrypted)| {
            std::str::from_utf8(&encrypted).is_ok_and(|text| {
                crypto::decrypt_filename(self.master_key.expose_secret(), text)
                    .map(|mut plain| plain.zeroize())
                    .is_ok()
            })
        })
    }

    /// Read and decrypt the vault manifest.
    fn read_manifest(&self) -> crate::Result<VaultManifest> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str =
            std::str::from_utf8(&manifest_encrypted).map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json =
            crypto::decrypt_filename(self.master_key.expose_secret(), manifest_str)?;

        serde_json::from_str(&manifest_json).map_err(|e| crate::Error::Manifest(e.to_string()))
    }

    /// Write vault atomically: header + manifest + data_old + data_new.
    fn write_vault_atomic(
        &self,
        header_buf: &[u8; HEADER_SIZE],
        manifest: &VaultManifest,
        existing_data: &[u8],
        new_data: &[u8],
    ) -> crate::Result<()> {
        let manifest_json =
            serde_json::to_string(manifest).map_err(|e| crate::Error::Manifest(e.to_string()))?;
        let encrypted_manifest =
            crypto::encrypt_filename(self.master_key.expose_secret(), &manifest_json)?;
        let manifest_bytes = encrypted_manifest.as_bytes();

        let tmp = temporary_vault_file(&self.path, "write")?;
        let mut writer = BufWriter::new(tmp.as_file());

        writer.write_all(header_buf)?;
        writer.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(manifest_bytes)?;
        writer.write_all(existing_data)?;
        writer.write_all(new_data)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);

        atomic_rename(tmp.path(), &self.path)?;
        Ok(())
    }
}

/// Header information available without a password.
#[derive(Debug, Clone)]
pub struct PeekInfo {
    /// Format version.
    pub version: u8,
    /// Encryption mode.
    pub mode: EncryptionMode,
    /// Chunk size in bytes.
    pub chunk_size: u32,
}

/// Result of a compact operation.
#[derive(Debug, Clone)]
pub struct CompactResult {
    /// Original vault file size in bytes.
    pub original_size: u64,
    /// Compacted vault file size in bytes.
    pub compacted_size: u64,
    /// Bytes saved.
    pub saved_bytes: u64,
    /// Number of entries in the vault.
    pub file_count: usize,
}

/// Security information about a vault.
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Format version.
    pub version: u8,
    /// Encryption mode.
    pub mode: EncryptionMode,
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Argon2id memory cost in KiB.
    pub argon2_m_cost_kib: u32,
    /// Argon2id time cost.
    pub argon2_t_cost: u32,
    /// Argon2id parallelism.
    pub argon2_p_cost: u32,
}

impl std::fmt::Display for SecurityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode_str = match self.mode {
            EncryptionMode::Standard => "AES-256-GCM-SIV",
            EncryptionMode::Cascade => "AES-256-GCM-SIV + ChaCha20-Poly1305",
        };
        write!(
            f,
            "Version: {}\n\
             Encryption: {}\n\
             Chunk size: {} bytes\n\
             KDF: Argon2id ({} MiB, t={}, p={})\n\
             Key wrapping: AES-256-KW (RFC 3394)\n\
             Filename encryption: AES-256-SIV\n\
             Header integrity: HMAC-SHA512",
            self.version,
            mode_str,
            self.chunk_size,
            self.argon2_m_cost_kib / 1024,
            self.argon2_t_cost,
            self.argon2_p_cost,
        )
    }
}

/// Validate that an entry name is safe (no path traversal, no absolute paths).
fn validate_entry_name(name: &str) -> crate::Result<()> {
    if name.contains("..") {
        return Err(crate::Error::InvalidPath(
            "entry name contains '..' (path traversal)".into(),
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(crate::Error::InvalidPath(
            "entry name is an absolute path".into(),
        ));
    }
    if name.contains('\0') {
        return Err(crate::Error::InvalidPath(
            "entry name contains null byte".into(),
        ));
    }
    Ok(())
}

/// Validate that a resolved output path stays within the output directory.
fn validate_output_path(path: &Path, output_dir: &Path) -> crate::Result<()> {
    // Canonicalize the output directory (it must exist)
    let canonical_dir = output_dir
        .canonicalize()
        .unwrap_or_else(|_| output_dir.to_path_buf());

    // For the file path, canonicalize the parent (which should exist after create_dir_all)
    // and append the filename
    let canonical_path = if let Some(parent) = path.parent() {
        let canon_parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if let Some(filename) = path.file_name() {
            canon_parent.join(filename)
        } else {
            canon_parent
        }
    } else {
        path.to_path_buf()
    };

    if !canonical_path.starts_with(&canonical_dir) {
        return Err(crate::Error::InvalidPath(format!(
            "output path escapes target directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_encrypted_chunk_len(
    chunk_len: usize,
    bytes_remaining: u64,
    header_chunk_size: u32,
    cascade_mode: bool,
) -> crate::Result<()> {
    let aead_overhead = NONCE_SIZE + TAG_SIZE;
    let max_len =
        header_chunk_size as usize + aead_overhead + if cascade_mode { aead_overhead } else { 0 };

    if chunk_len > max_len {
        return Err(Error::Format(FormatError::InvalidChunkSize(
            chunk_len as u32,
        )));
    }
    if chunk_len as u64 > bytes_remaining {
        return Err(Error::Format(FormatError::ManifestTruncated));
    }
    Ok(())
}

fn open_new_output_file(path: &Path, output_dir: &Path) -> crate::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    validate_output_path(path, output_dir)?;

    let canonical_dir = output_dir.canonicalize()?;
    let canonical_parent = path
        .parent()
        .ok_or_else(|| Error::InvalidPath(format!("missing parent for {}", path.display())))?
        .canonicalize()?;
    if !canonical_parent.starts_with(&canonical_dir) {
        return Err(Error::InvalidPath(format!(
            "output path escapes target directory: {}",
            path.display()
        )));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let fd_meta = file.metadata()?;
        let path_meta = std::fs::symlink_metadata(path)?;
        if !path_meta.file_type().is_file()
            || fd_meta.dev() != path_meta.dev()
            || fd_meta.ino() != path_meta.ino()
        {
            return Err(Error::InvalidPath(format!(
                "output path is not the newly-created regular file: {}",
                path.display()
            )));
        }
        let canonical_path = path.canonicalize()?;
        if !canonical_path.starts_with(&canonical_dir) {
            return Err(Error::InvalidPath(format!(
                "output path escapes target directory: {}",
                path.display()
            )));
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        let file = options.open(path)?;
        let canonical_path = path.canonicalize()?;
        if !canonical_path.starts_with(&canonical_dir) {
            return Err(Error::InvalidPath(format!(
                "output path escapes target directory: {}",
                path.display()
            )));
        }
        Ok(file)
    }
}

#[cfg(unix)]
fn fsync_parent_dir(path: &Path) -> crate::Result<()> {
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) -> crate::Result<()> {
    Ok(())
}

fn temporary_vault_file(path: &Path, suffix: &str) -> crate::Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::Builder::new()
        .prefix(&format!(".aerovault-{suffix}-"))
        .tempfile_in(parent)?;
    // The rename replaces the vault's mode with the temp file's 0600. Keep the
    // mode of an existing regular vault (special bits dropped); a symlink's
    // 0777 is never lent, and a new vault stays 0600.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_file() {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(
                    meta.permissions().mode() & 0o777,
                ))?;
        }
    }
    #[cfg(test)]
    crate::lock::trace("temp");
    Ok(tmp)
}

/// Atomic rename: tmp -> final as the single visible commit point.
fn atomic_rename(tmp_path: &Path, final_path: &Path) -> crate::Result<()> {
    rename_into_place(tmp_path, final_path)?;
    fsync_parent_dir(final_path)?;
    Ok(())
}

/// The single commit point of every write. `std::fs::rename` replaces an
/// existing file on Windows too, so the vault is never deleted before its
/// replacement is in place: if the rename fails, the old vault is untouched.
fn rename_into_place(tmp_path: &Path, final_path: &Path) -> std::io::Result<()> {
    crate::lock::refuse_lock_file_name(final_path)?;
    #[cfg(test)]
    if FAIL_NEXT_RENAME.with(|f| f.replace(false)) {
        return Err(std::io::Error::other("injected rename failure"));
    }
    std::fs::rename(tmp_path, final_path)
}

#[cfg(test)]
thread_local! {
    /// Test seam: makes the next commit rename fail.
    static FAIL_NEXT_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Atomic write: write to temp file with fsync, then rename.
fn atomic_write(path: &Path, data: &[u8], suffix: &str) -> crate::Result<()> {
    let tmp = temporary_vault_file(path, suffix)?;
    let mut writer = BufWriter::new(tmp.as_file());
    writer.write_all(data)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    rename_into_place(tmp.path(), path)?;
    fsync_parent_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_vault_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "aerovault-test-{}.aerovault",
            rand::random::<u64>()
        ));
        path
    }

    #[test]
    fn write_waits_for_another_writer_then_refuses() {
        crate::lock::set_short_wait_for_this_thread();
        // Each write holds the vault lock from its read to its rename; while
        // another writer holds it, a write must give up, not interleave.
        let path = temp_vault_path();
        let vault = Vault::create(CreateOptions::new(&path, "test-password-123")).unwrap();
        let before = std::fs::read(&path).unwrap();
        let held = crate::lock::acquire(&path).unwrap();
        let err = vault.create_directory("blocked").unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        crate::lock::take_trace();
        let Err(err) = Vault::create(CreateOptions::new(&path, "test-password-123")) else {
            panic!("create must refuse while another writer holds the lock");
        };
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        // Refused before any key was derived or any temp file made.
        assert_eq!(crate::lock::take_trace(), Vec::<&str>::new());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(held);
        vault.create_directory("after").unwrap();
        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn create_takes_the_lock_before_any_key_or_temp_file() {
        // The lock comes first, so a refused create derives no key, and the
        // mode of the vault it replaces is read (with the temp file) only while
        // no other writer can change it. Checked for a new vault and for a
        // replacement.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.aerovault");
        for _ in 0..2 {
            crate::lock::take_trace();
            Vault::create(CreateOptions::new(&path, "test-password-123")).unwrap();
            assert_eq!(crate::lock::take_trace(), ["lock", "derive", "temp"]);
        }
    }

    #[test]
    fn change_password_refuses_a_vault_replaced_since_the_open() {
        // `Vault::create` replaces the vault while an old handle is open. The
        // old handle's password change must not wrap its keys over the new
        // vault's content: refused, the new vault unchanged and readable.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.aerovault");
        let mut old = Vault::create(CreateOptions::new(&path, "first-password-1")).unwrap();
        let input = dir.path().join("a.txt");
        std::fs::write(&input, b"second vault's file").unwrap();
        let new = Vault::create(CreateOptions::new(&path, "second-password-2")).unwrap();
        new.add_files(&[&input]).unwrap();
        let replaced = std::fs::read(&path).unwrap();

        let err = old.change_password("third-password-3").unwrap_err();
        assert!(
            err.to_string().contains("not the vault this handle opened"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), replaced);
        let reopened = Vault::open(&path, "second-password-2").unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let got = reopened.extract("a.txt", &out).unwrap();
        assert_eq!(std::fs::read(got).unwrap(), b"second vault's file");

        // A handle of the same vault (same keys) still changes the password.
        let mut again = Vault::open(&path, "second-password-2").unwrap();
        again.change_password("fourth-password-4").unwrap();
        assert!(Vault::open(&path, "fourth-password-4").is_ok());
    }

    #[test]
    fn a_short_new_password_is_refused_before_the_lock() {
        // The policy error comes at once, not after waiting for another writer.
        crate::lock::set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.aerovault");
        let mut vault = Vault::create(CreateOptions::new(&path, "first-password-1")).unwrap();
        let held = crate::lock::acquire(&path).unwrap();
        let err = vault.change_password("short").unwrap_err();
        assert!(matches!(err, crate::Error::PasswordPolicy(_)), "{err}");
        drop(held);
    }

    #[test]
    fn change_password_rewrites_a_damaged_header_of_its_own_vault() {
        // The check is on the content, not the header: an open handle whose
        // vault header was damaged on disk still writes a new, valid header.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.aerovault");
        let mut vault = Vault::create(CreateOptions::new(&path, "first-password-1")).unwrap();
        let input = dir.path().join("a.txt");
        std::fs::write(&input, b"kept").unwrap();
        vault.add_files(&[&input]).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER_SIZE - 1] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        assert!(Vault::open(&path, "first-password-1").is_err());

        vault.change_password("second-password-2").unwrap();
        let reopened = Vault::open(&path, "second-password-2").unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let got = reopened.extract("a.txt", &out).unwrap();
        assert_eq!(std::fs::read(got).unwrap(), b"kept");
    }

    #[test]
    fn failed_commit_rename_leaves_the_old_vault_intact() {
        // Each write commits by one rename over the vault. When that rename
        // fails, the original must still be there and open, on every platform.
        let path = temp_vault_path();
        let vault = Vault::create(CreateOptions::new(&path, "test-password-123")).unwrap();
        let input =
            std::env::temp_dir().join(format!("aerovault-rename-{}.txt", rand::random::<u64>()));
        std::fs::write(&input, b"kept").unwrap();
        vault.add_files(&[&input]).unwrap();
        let before = std::fs::read(&path).unwrap();

        FAIL_NEXT_RENAME.with(|f| f.set(true));
        assert!(vault.create_directory("later").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let mut vault = Vault::open(&path, "test-password-123").unwrap();
        FAIL_NEXT_RENAME.with(|f| f.set(true));
        assert!(vault.change_password("other-password-456").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let vault = Vault::open(&path, "test-password-123").unwrap();
        assert_eq!(vault.list().unwrap().len(), 1);
        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&input).ok();
    }

    #[test]
    fn test_create_and_open() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let _vault = Vault::create(opts).unwrap();

        assert!(Vault::is_vault(&path));

        let vault = Vault::open(&path, "test-password-123").unwrap();
        let entries = vault.list().unwrap();
        assert!(entries.is_empty());

        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_wrong_password() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "correct-password");
        let _vault = Vault::create(opts).unwrap();

        let result = Vault::open(&path, "wrong-password");
        assert!(result.is_err());

        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_password_too_short() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "short");
        let result = Vault::create(opts);
        assert!(result.is_err());
        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_chunk_size_validation() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123").with_chunk_size(1); // too small
        assert!(Vault::create(opts).is_err());

        let opts = CreateOptions::new(&path, "test-password-123").with_chunk_size(32 * 1024 * 1024); // too large
        assert!(Vault::create(opts).is_err());

        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_add_and_extract() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        // Create a test file
        let test_file = std::env::temp_dir().join("aerovault-test-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"Hello from AeroVault!").unwrap();

        // Add file
        let added = vault.add_files(&[&test_file]).unwrap();
        assert_eq!(added, 1);

        // List
        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "aerovault-test-input.txt");
        assert_eq!(entries[0].size, 21);
        assert!(!entries[0].is_dir);

        // Extract
        let out_dir = std::env::temp_dir().join("aerovault-test-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault.extract("aerovault-test-input.txt", &out_dir).unwrap();
        let content = std::fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "Hello from AeroVault!");

        // Cleanup
        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_legacy_v2_roundtrip_and_version_dispatch() {
        // A v2 (LEGACY_VERSION) container must round-trip byte-identically with
        // the chunk-index-only AAD, and a default v3 container must round-trip
        // with the file-id-bound AAD. Both must reopen and extract correctly.
        // Locks the backward-compat read path against future refactors.
        let v2_path = temp_vault_path();
        let v3_path = temp_vault_path();

        // Multi-chunk payload (> one default chunk) to exercise chunk indexing.
        let input = std::env::temp_dir().join(format!(
            "aerovault-legacy-input-{}.bin",
            v2_path.file_stem().unwrap().to_string_lossy()
        ));
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&input, &payload).unwrap();
        let entry = input.file_name().unwrap().to_string_lossy().to_string();

        // --- v2 legacy container ---
        let v2 = Vault::create(
            CreateOptions::new(&v2_path, "legacy-password-123").with_version(LEGACY_VERSION),
        )
        .unwrap();
        v2.add_files(&[&input]).unwrap();
        assert_eq!(Vault::peek(&v2_path).unwrap().version, LEGACY_VERSION);

        let v2r = Vault::open(&v2_path, "legacy-password-123").unwrap();
        let out2 = std::env::temp_dir().join(format!("av-legacy-out-{}", std::process::id()));
        std::fs::create_dir_all(&out2).ok();
        let ex2 = v2r.extract(&entry, &out2).unwrap();
        assert_eq!(
            std::fs::read(&ex2).unwrap(),
            payload,
            "v2 legacy round-trip"
        );

        // --- v3 default container ---
        let v3 = Vault::create(CreateOptions::new(&v3_path, "modern-password-123")).unwrap();
        v3.add_files(&[&input]).unwrap();
        assert_eq!(Vault::peek(&v3_path).unwrap().version, VERSION);

        let v3r = Vault::open(&v3_path, "modern-password-123").unwrap();
        let out3 = std::env::temp_dir().join(format!("av-v3-out-{}", std::process::id()));
        std::fs::create_dir_all(&out3).ok();
        let ex3 = v3r.extract(&entry, &out3).unwrap();
        assert_eq!(std::fs::read(&ex3).unwrap(), payload, "v3 round-trip");

        // An unsupported version is rejected at create time.
        assert!(Vault::create(
            CreateOptions::new(temp_vault_path(), "x-password-123").with_version(9)
        )
        .is_err());

        crate::lock::remove_vault_and_lock(&v2_path);
        crate::lock::remove_vault_and_lock(&v3_path);
        std::fs::remove_file(&input).ok();
        std::fs::remove_dir_all(&out2).ok();
        std::fs::remove_dir_all(&out3).ok();
    }

    #[test]
    fn test_cascade_mode() {
        let path = temp_vault_path();
        let opts =
            CreateOptions::new(&path, "test-password-123").with_mode(EncryptionMode::Cascade);
        let vault = Vault::create(opts).unwrap();

        assert_eq!(vault.mode(), EncryptionMode::Cascade);

        let test_file = std::env::temp_dir().join("aerovault-cascade-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"Cascade mode test").unwrap();

        vault.add_files(&[&test_file]).unwrap();

        // Re-open and extract
        let vault2 = Vault::open(&path, "test-password-123").unwrap();
        let out_dir = std::env::temp_dir().join("aerovault-cascade-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault2
            .extract("aerovault-cascade-input.txt", &out_dir)
            .unwrap();
        let content = std::fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "Cascade mode test");

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_create_directory() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        // Create nested directory
        let created = vault.create_directory("docs/notes").unwrap();
        assert_eq!(created, 2); // "docs" + "docs/notes"

        // Creating again should return 0
        let created = vault.create_directory("docs/notes").unwrap();
        assert_eq!(created, 0);

        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_dir));

        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_delete_entry() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-delete-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"to be deleted").unwrap();

        vault.add_files(&[&test_file]).unwrap();
        assert_eq!(vault.list().unwrap().len(), 1);

        vault.delete_entry("aerovault-delete-input.txt").unwrap();
        assert_eq!(vault.list().unwrap().len(), 0);

        // Deleting again should fail
        assert!(vault.delete_entry("aerovault-delete-input.txt").is_err());

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_change_password() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "old-password-123");
        let mut vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-chpw-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"password change test").unwrap();
        vault.add_files(&[&test_file]).unwrap();

        vault.change_password("new-password-456").unwrap();

        // Old password should fail
        assert!(Vault::open(&path, "old-password-123").is_err());

        // New password should work and data should be intact
        let vault2 = Vault::open(&path, "new-password-456").unwrap();
        let entries = vault2.list().unwrap();
        assert_eq!(entries.len(), 1);

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_is_vault_negative() {
        let path = std::env::temp_dir().join("not-a-vault.txt");
        std::fs::write(&path, b"just text").ok();
        assert!(!Vault::is_vault(&path));
        crate::lock::remove_vault_and_lock(&path);

        assert!(!Vault::is_vault("/nonexistent/path"));
    }

    #[test]
    fn test_security_info_display() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();
        let info = vault.security_info();
        let display = format!("{info}");
        assert!(display.contains("AES-256-GCM-SIV"));
        assert!(display.contains("128 MiB"));
        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_path_traversal_rejected() {
        assert!(validate_entry_name("../etc/passwd").is_err());
        assert!(validate_entry_name("/etc/passwd").is_err());
        assert!(validate_entry_name("foo\0bar").is_err());
        assert!(validate_entry_name("normal/file.txt").is_ok());
    }

    #[test]
    fn test_rename_entry() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-rename-input.txt");
        std::fs::write(&test_file, b"rename me").unwrap();
        vault.add_files(&[&test_file]).unwrap();

        vault
            .rename_entry("aerovault-rename-input.txt", "renamed.txt")
            .unwrap();

        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "renamed.txt");

        let out_dir = std::env::temp_dir().join("aerovault-rename-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault.extract("renamed.txt", &out_dir).unwrap();
        assert!(extracted.ends_with("renamed.txt"));

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_move_directory_recursive() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        vault.create_directory("docs/old").unwrap();

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("aerovault-move-input.txt");
        std::fs::write(&test_file, b"move me").unwrap();
        vault.add_files_to_dir(&[&test_file], "docs/old").unwrap();

        vault.create_directory("archive").unwrap();
        vault.move_entry("docs/old", "archive/old").unwrap();

        let names: Vec<String> = vault.list().unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.iter().any(|n| n == "archive/old"));
        assert!(names
            .iter()
            .any(|n| n == "archive/old/aerovault-move-input.txt"));
        assert!(!names.iter().any(|n| n == "docs/old"));

        let out_dir = temp_dir.join("aerovault-move-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault
            .extract("archive/old/aerovault-move-input.txt", &out_dir)
            .unwrap();
        let content = std::fs::read_to_string(extracted).unwrap();
        assert_eq!(content, "move me");

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_move_entry_rejects_self_subtree() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        vault.create_directory("docs/old").unwrap();
        assert!(vault.move_entry("docs", "docs/archive").is_err());

        crate::lock::remove_vault_and_lock(&path);
    }

    #[test]
    fn test_copy_entry_file() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-copy-input.txt");
        std::fs::write(&test_file, b"copy me").unwrap();
        vault.add_files(&[&test_file]).unwrap();

        vault
            .copy_entry("aerovault-copy-input.txt", "aerovault-copy-output.txt")
            .unwrap();

        let names: Vec<String> = vault.list().unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.iter().any(|n| n == "aerovault-copy-input.txt"));
        assert!(names.iter().any(|n| n == "aerovault-copy-output.txt"));

        let out_dir = std::env::temp_dir().join("aerovault-copy-output-dir");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault
            .extract("aerovault-copy-output.txt", &out_dir)
            .unwrap();
        let content = std::fs::read_to_string(extracted).unwrap();
        assert_eq!(content, "copy me");

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_copy_entry_directory_recursive() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        vault.create_directory("docs/original").unwrap();

        let test_file = std::env::temp_dir().join("aerovault-copy-tree-input.txt");
        std::fs::write(&test_file, b"tree copy").unwrap();
        vault
            .add_files_to_dir(&[&test_file], "docs/original")
            .unwrap();

        vault.create_directory("archive").unwrap();
        vault
            .copy_entry("docs/original", "archive/original-copy")
            .unwrap();

        let names: Vec<String> = vault.list().unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.iter().any(|n| n == "docs/original"));
        assert!(names.iter().any(|n| n == "archive/original-copy"));
        assert!(names
            .iter()
            .any(|n| n == "archive/original-copy/aerovault-copy-tree-input.txt"));

        crate::lock::remove_vault_and_lock(&path);
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_copy_entry_rejects_self_subtree() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        vault.create_directory("docs/original").unwrap();
        assert!(vault.copy_entry("docs", "docs/archive").is_err());

        crate::lock::remove_vault_and_lock(&path);
    }

    #[cfg(unix)]
    #[test]
    fn test_legacy_temp_symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerovault");
        let victim = dir.path().join("outside.txt");
        std::fs::write(&victim, b"outside-vault-target").unwrap();

        let plant = |name: &str| {
            let temp = PathBuf::from(format!("{}.{}", path.display(), name));
            symlink(&victim, &temp).unwrap();
            temp
        };
        let assert_victim_intact = || {
            assert_eq!(std::fs::read(&victim).unwrap(), b"outside-vault-target");
        };

        let create_tmp = plant("create.tmp");
        let mut vault = Vault::create(CreateOptions::new(&path, "old-password-123")).unwrap();
        assert_victim_intact();
        assert!(create_tmp
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let input = dir.path().join("input.txt");
        std::fs::write(&input, b"vault payload").unwrap();
        let write_tmp = plant("tmp");
        vault.add_files(&[&input]).unwrap();
        assert_victim_intact();
        assert!(write_tmp
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let chpw_tmp = plant("chpw.tmp");
        vault.change_password("new-password-456").unwrap();
        assert_victim_intact();
        assert!(chpw_tmp
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        vault.delete_entry("input.txt").unwrap();
        let compact_tmp = plant("compact.tmp");
        vault.compact().unwrap();
        assert_victim_intact();
        assert!(compact_tmp
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let reopened = Vault::open(&path, "new-password-456").unwrap();
        assert!(reopened.list().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_replacement_preserves_existing_vault_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.aerovault");
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        let mut vault = Vault::create(CreateOptions::new(&path, "old-password-123")).unwrap();
        assert_eq!(mode(&path), 0o600, "a new vault stays private");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let input = dir.path().join("input.txt");
        std::fs::write(&input, b"vault payload").unwrap();
        vault.add_files(&[&input]).unwrap();
        assert_eq!(mode(&path), 0o640, "manifest update");
        vault.compact().unwrap();
        assert_eq!(mode(&path), 0o640, "compaction");
        vault.change_password("new-password-456").unwrap();
        assert_eq!(mode(&path), 0o640, "password change");

        // Special bits are never carried over.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4640)).unwrap();
        let second = dir.path().join("second.txt");
        std::fs::write(&second, b"second payload").unwrap();
        vault.add_files(&[&second]).unwrap();
        assert_eq!(mode(&path), 0o640, "setuid dropped");
        // A write through a symlinked vault path is refused (0.6.9): it would
        // replace the link, not the vault behind it. Link and vault stay as
        // they were.
        let target = dir.path().join("real.aerovault");
        std::fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        let before = std::fs::read(&target).unwrap();
        let reopened = Vault::open(&path, "new-password-456").unwrap();
        let third = dir.path().join("third.txt");
        std::fs::write(&third, b"third payload").unwrap();
        let err = reopened.add_files(&[&third]).unwrap_err().to_string();
        assert!(err.contains("is a symbolic link"), "{err}");
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert_eq!(mode(&target), 0o640);
    }
}
