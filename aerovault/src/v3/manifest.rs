//! AEROVAULT3 manifest: the encrypted JSON index of wrappers, entries, and
//! chunk records, plus the extension directory entry type. Byte-for-byte port
//! of the AeroFTP app structs and their serde shape (field names + order +
//! skip-if-none) so an app-written manifest deserializes here and vice versa.

// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::chunking::CdcBounds;
use super::constants::{
    BLOCK_AAD_PREFIX, CRYPT_ALGORITHM_ENCRYPTED, CRYPT_ALGORITHM_NONE, DEFAULT_ZSTD_LEVEL,
    MANIFEST_AAD, VERSION,
};
use crate::aerocrypt::{decrypt_with_aad, encrypt_with_aad, KEY_SIZE};

/// One wrapper-stack layer: an algorithm id + version, optional zstd level,
/// optional CDC bounds (only on the `chunking` wrapper).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmSpec {
    pub algorithm_id: String,
    pub algorithm_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds: Option<CdcBounds>,
}

/// The ordered wrapper stack recorded in every manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperManifest {
    pub packing: AlgorithmSpec,
    pub chunking: AlgorithmSpec,
    pub chunk_id: AlgorithmSpec,
    pub compression: AlgorithmSpec,
    pub crypt: AlgorithmSpec,
    pub cipher_hash: AlgorithmSpec,
}

/// One file or directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntryV3 {
    pub path: String,
    pub size: u64,
    pub modified: String,
    pub is_dir: bool,
    pub chunks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_offset: Option<u64>,
}

/// One stored content block (deduplicated by `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRecordV3 {
    pub id: String,
    pub block_index: u64,
    pub data_offset: u64,
    pub block_len: u64,
    pub plaintext_len: u64,
    pub compressed_len: u64,
    pub cipher_hash: String,
    /// `true` when the block stores the raw plaintext (still encrypted) because
    /// the chunk was incompressible: the zstd pass was skipped at ingest and
    /// must be skipped on decode. Absent (false) in pre-T3 manifests and for
    /// every compressible chunk, so it costs no bytes there and the on-disk
    /// major stays 3.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stored_raw: bool,
}

/// The full manifest, encrypted as one AEAD blob under `MANIFEST_AAD`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifestV3 {
    pub format: u8,
    pub created: String,
    pub modified: String,
    pub wrappers: WrapperManifest,
    pub entries: Vec<ManifestEntryV3>,
    pub chunks: BTreeMap<String, ChunkRecordV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_correction_pct: Option<u32>,
}

/// One extension-directory record (JSON array). Offsets are relative to the
/// extension payload area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionEntryV3 {
    pub extension_id: String,
    pub algorithm_id: String,
    pub algorithm_version: u32,
    pub critical: bool,
    pub offset: u64,
    pub length: u64,
}

/// UTC timestamp in the app's exact `%Y-%m-%dT%H:%M:%SZ` form.
#[cfg(not(feature = "test-vectors"))]
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Fixed timestamp under the `test-vectors` feature so deterministic golden
/// containers are reproducible. MUST match the app's test-vector timestamp.
#[cfg(feature = "test-vectors")]
pub fn now_iso() -> String {
    "2026-06-17T00:00:00Z".to_string()
}

/// The default wrapper stack for the encrypted lane (`crypt = aes-256-gcm-siv`).
pub fn default_wrappers(level: i32) -> WrapperManifest {
    default_wrappers_for_crypt(level, CRYPT_ALGORITHM_ENCRYPTED)
}

/// The default wrapper stack for the plaintext (`.aerovz`) lane: identical to
/// the encrypted stack except the `crypt` wrapper records `none` — content
/// blocks and the manifest are stored unencrypted (#7).
pub fn default_wrappers_plaintext(level: i32) -> WrapperManifest {
    default_wrappers_for_crypt(level, CRYPT_ALGORITHM_NONE)
}

fn default_wrappers_for_crypt(level: i32, crypt_id: &str) -> WrapperManifest {
    WrapperManifest {
        packing: AlgorithmSpec {
            algorithm_id: "small-file-batching".to_string(),
            algorithm_version: 1,
            level: None,
            bounds: None,
        },
        chunking: AlgorithmSpec {
            algorithm_id: "gear-cdc".to_string(),
            algorithm_version: 1,
            level: None,
            bounds: Some(CdcBounds::for_level(level)),
        },
        chunk_id: AlgorithmSpec {
            algorithm_id: "blake3-keyed-128".to_string(),
            algorithm_version: 1,
            level: None,
            bounds: None,
        },
        compression: AlgorithmSpec {
            algorithm_id: "zstd".to_string(),
            algorithm_version: 1,
            level: Some(level),
            bounds: None,
        },
        crypt: AlgorithmSpec {
            algorithm_id: crypt_id.to_string(),
            algorithm_version: 1,
            level: None,
            bounds: None,
        },
        cipher_hash: AlgorithmSpec {
            algorithm_id: "blake3-256".to_string(),
            algorithm_version: 1,
            level: None,
            bounds: None,
        },
    }
}

/// `true` when this manifest describes the plaintext (`.aerovz`) lane: the
/// single source of truth for whether content blocks and the manifest itself
/// are stored unencrypted. Mirrored cheaply by [`FLAG_PLAINTEXT_CONTENT`] in the
/// header so the open path can branch before it can read the manifest.
pub fn manifest_is_plaintext(manifest: &VaultManifestV3) -> bool {
    manifest.wrappers.crypt.algorithm_id == CRYPT_ALGORITHM_NONE
}

pub fn empty_manifest(level: i32) -> VaultManifestV3 {
    empty_manifest_with_wrappers(level, default_wrappers(level))
}

/// An empty manifest for the plaintext (`.aerovz`) lane.
pub fn empty_manifest_plaintext(level: i32) -> VaultManifestV3 {
    empty_manifest_with_wrappers(level, default_wrappers_plaintext(level))
}

fn empty_manifest_with_wrappers(_level: i32, wrappers: WrapperManifest) -> VaultManifestV3 {
    let now = now_iso();
    VaultManifestV3 {
        format: VERSION,
        created: now.clone(),
        modified: now,
        wrappers,
        entries: Vec::new(),
        chunks: BTreeMap::new(),
        error_correction_pct: None,
    }
}

/// Effective CDC bounds for a manifest: the recorded `chunking.bounds` if
/// present and valid, otherwise the const defaults (pre-GAP-5 vaults).
pub fn manifest_cdc_bounds(manifest: &VaultManifestV3) -> Result<CdcBounds, String> {
    match manifest.wrappers.chunking.bounds {
        Some(b) => {
            b.validate()?;
            Ok(b)
        }
        None => Ok(CdcBounds::defaults()),
    }
}

pub fn manifest_zstd_level(manifest: &VaultManifestV3) -> i32 {
    manifest
        .wrappers
        .compression
        .level
        .unwrap_or(DEFAULT_ZSTD_LEVEL)
}

/// AAD bound on a content block: prefix + block_index (LE) + chunk id bytes.
pub fn block_aad(block_index: u64, chunk_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BLOCK_AAD_PREFIX.len() + 8 + chunk_id.len());
    aad.extend_from_slice(BLOCK_AAD_PREFIX);
    aad.extend_from_slice(&block_index.to_le_bytes());
    aad.extend_from_slice(chunk_id.as_bytes());
    aad
}

pub fn encrypt_manifest(
    key: &[u8; KEY_SIZE],
    manifest: &VaultManifestV3,
) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(manifest).map_err(|e| format!("Manifest serialize: {e}"))?;
    encrypt_with_aad(key, &json, MANIFEST_AAD)
}

pub fn decrypt_manifest(key: &[u8; KEY_SIZE], encrypted: &[u8]) -> Result<VaultManifestV3, String> {
    let json = decrypt_with_aad(key, encrypted, MANIFEST_AAD)?;
    serde_json::from_slice(&json).map_err(|e| format!("Manifest parse: {e}"))
}

/// Serialize the manifest as plaintext JSON for the `.aerovz` lane (no AEAD).
/// The stored bytes are the manifest blob the header offsets address and that
/// Error Correction protects, exactly like the encrypted blob but unencrypted.
pub fn serialize_manifest_plaintext(manifest: &VaultManifestV3) -> Result<Vec<u8>, String> {
    serde_json::to_vec(manifest).map_err(|e| format!("Manifest serialize: {e}"))
}

/// Parse a plaintext (`.aerovz`) manifest blob.
pub fn parse_manifest_plaintext(bytes: &[u8]) -> Result<VaultManifestV3, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("Manifest parse: {e}"))
}

/// Next free block index = max existing + 1 (0 for an empty manifest).
pub fn next_block_index(manifest: &VaultManifestV3) -> u64 {
    manifest
        .chunks
        .values()
        .map(|record| record.block_index)
        .max()
        .map(|max| max + 1)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_encrypt_decrypt_round_trip() {
        let key = [0x44u8; KEY_SIZE];
        let m = empty_manifest(9);
        let enc = encrypt_manifest(&key, &m).unwrap();
        let back = decrypt_manifest(&key, &enc).unwrap();
        assert_eq!(back.format, VERSION);
        assert_eq!(back.wrappers.compression.level, Some(9));
        assert_eq!(back.wrappers.chunking.algorithm_id, "gear-cdc");
        // Wrong key fails closed.
        assert!(decrypt_manifest(&[0x45u8; KEY_SIZE], &enc).is_err());
    }

    #[test]
    fn block_aad_is_prefix_index_id() {
        let aad = block_aad(7, "deadbeef");
        let mut expected = b"AeroVault v3 block".to_vec();
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(b"deadbeef");
        assert_eq!(aad, expected);
    }

    #[test]
    fn next_block_index_increments() {
        let mut m = empty_manifest(9);
        assert_eq!(next_block_index(&m), 0);
        m.chunks.insert(
            "a".to_string(),
            ChunkRecordV3 {
                id: "a".to_string(),
                block_index: 5,
                data_offset: 0,
                block_len: 1,
                plaintext_len: 1,
                compressed_len: 1,
                cipher_hash: "x".to_string(),
                stored_raw: false,
            },
        );
        assert_eq!(next_block_index(&m), 6);
    }

    #[test]
    fn empty_extension_dir_serializes_to_brackets() {
        // Byte-critical: an empty extension list is the 2-byte JSON "[]", not 0.
        let empty: Vec<ExtensionEntryV3> = Vec::new();
        assert_eq!(serde_json::to_vec(&empty).unwrap(), b"[]");
    }
}
