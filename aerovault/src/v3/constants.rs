//! AEROVAULT3 container constants, mirrored byte-for-byte from the AeroFTP app
//! reference implementation (`src-tauri/src/aerovault_v3.rs`). Changing any of
//! these changes the on-disk format and breaks the T5 cross-open contract.

// SPDX-License-Identifier: GPL-3.0-only

/// Container magic. Distinct from the legacy `AEROVAULT2` lineage.
pub const MAGIC: &[u8; 10] = b"AEROVAULT3";
/// On-disk format major.
pub const VERSION: u8 = 3;
/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 1024;
/// Offset of the 64-byte HMAC-SHA512 trailer inside the header.
pub const HEADER_MAC_OFFSET: usize = 960;
/// HMAC-SHA512 output size.
pub const MAC_SIZE: usize = 64;
/// Minimum password length enforced at create time.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum encrypted-manifest size (DoS guard).
pub const MAX_MANIFEST_SIZE: u64 = 128 * 1024 * 1024;
/// Maximum extension-directory JSON size.
pub const MAX_EXTENSION_DIR_SIZE: u64 = 16 * 1024 * 1024;
/// Maximum stored (encrypted) block size.
pub const MAX_BLOCK_SIZE: u64 = 64 * 1024 * 1024;
/// Absolute ceiling on decompressed plaintext of a single content block, equal
/// to the largest `max` a `CdcBounds` may declare. The effective cap is the
/// vault's recorded chunking `max` clamped to this, so a decompression bomb
/// cannot expand a block past one legitimate chunk of RAM (CLAUDE-AV-005).
pub const MAX_PLAINTEXT_BLOCK_SIZE: u64 = 256 * 1024 * 1024;

/// Data section starts immediately after the fixed header.
pub const DATA_OFFSET: u64 = HEADER_SIZE as u64;

/// Header `flags` bit (byte 11) marking the unencrypted `.aerozip` plaintext
/// lane (#7): content blocks AND the manifest are stored in the clear (still
/// compressed + Error-Correction-protected), there is no password, and the
/// header HMAC is keyed by the fixed PUBLIC integrity key below. This lane is
/// integrity + recovery, NOT confidentiality — the data is readable by anyone.
/// Absent (0) on every encrypted `.aerovault`, so those containers are
/// byte-identical and old readers fail closed on an unknown crypt id.
pub const FLAG_PLAINTEXT_CONTENT: u8 = 0x01;

/// `crypt` wrapper algorithm id recorded for the encrypted lane.
pub const CRYPT_ALGORITHM_ENCRYPTED: &str = "aes-256-gcm-siv";
/// `crypt` wrapper algorithm id recorded for the plaintext (`.aerozip`) lane.
pub const CRYPT_ALGORITHM_NONE: &str = "none";

/// Public, fixed input keying material for the plaintext lane's header HMAC.
/// Public by design: it authenticates the header against bit-rot / accidental
/// tampering; it provides NO confidentiality (the lane has none).
pub const AEROZIP_MAC_IKM: &[u8] = b"AeroVault v3 aerozip public container";
/// HKDF-SHA256 label deriving the plaintext-lane header-integrity MAC key.
pub const HKDF_AEROZIP_MAC: &[u8] = b"AeroVault v3 aerozip header integrity key";
/// Default zstd compression level (`balanced` profile).
pub const DEFAULT_ZSTD_LEVEL: i32 = 9;
/// The only wrapper-header layout this build understands.
pub const SUPPORTED_WRAPPER_HEADER_VERSION: u16 = 1;

/// Incompressible-skip probe (#10-B): size of each representative window that
/// is trial-compressed at a fast level to decide whether the full, possibly
/// expensive, zstd pass is worth running.
pub const INCOMPRESSIBLE_PROBE_SAMPLE: usize = 64 * 1024;
/// Maximum bytes sampled by the incompressibility probe. Chunks at or below
/// this size are probed as a whole; larger chunks are sampled with windows
/// spread across the chunk so a noisy prefix cannot force a compressible block
/// to be stored raw.
pub const INCOMPRESSIBLE_PROBE_MAX_SAMPLE: usize = 1024 * 1024;
/// zstd level used for the cheap probe (fast, just enough signal).
pub const INCOMPRESSIBLE_PROBE_LEVEL: i32 = 3;
/// A chunk is treated as incompressible when the probe leaves the sample at or
/// above this percentage of its original size (i.e. it shrank by less than
/// 3 %): the chunk is then stored raw (still encrypted) and the full pass is
/// skipped. Media/already-compressed data lands here; text/code shrinks well
/// past it and takes the normal compression path.
pub const INCOMPRESSIBLE_RATIO_PCT: u64 = 97;

/// CDC minimum chunk size (256 KiB).
pub const CDC_MIN: usize = 256 * 1024;
/// CDC average (target) chunk size (1 MiB). Must be a power of two.
pub const CDC_AVG: usize = 1024 * 1024;
/// CDC maximum chunk size (4 MiB).
pub const CDC_MAX: usize = 4 * 1024 * 1024;

/// Files strictly smaller than this are batched into shared packs before CDC.
pub const PACK_SMALL_FILE_THRESHOLD: usize = CDC_MIN;
/// A pack is flushed once it reaches this size.
pub const PACK_TARGET: usize = CDC_MAX;

/// HKDF-SHA256 label deriving the master KEK from the base KEK.
pub const HKDF_MASTER: &[u8] = b"AeroVault v3 KEK for master key";
/// HKDF-SHA256 label deriving the MAC KEK from the base KEK.
pub const HKDF_MAC: &[u8] = b"AeroVault v3 KEK for MAC key";
/// HKDF-SHA256 label deriving the keyed-BLAKE3 chunk-id key from the master key.
pub const HKDF_CHUNK_ID: &[u8] = b"AeroVault v3 keyed BLAKE3 chunk ids";
/// AAD bound on the encrypted manifest.
pub const MANIFEST_AAD: &[u8] = b"AeroVault v3 manifest";
/// AAD prefix bound on each content block (followed by block_index LE + chunk id).
pub const BLOCK_AAD_PREFIX: &[u8] = b"AeroVault v3 block";

/// Extension ID for the rev. 4 Error Correction (Reed-Solomon) data layer.
pub const ERROR_CORRECTION_EXTENSION_ID: &str = "error-correction.reed-solomon";
/// Extension ID for parity over the encrypted manifest (the scrub locator).
pub const ERROR_CORRECTION_META_EXTENSION_ID: &str = "error-correction-metadata.reed-solomon";
/// Algorithm ID recorded for both EC extensions.
pub const ERROR_CORRECTION_ALGORITHM_ID: &str = "reed-solomon";
/// Algorithm version recorded for both EC extensions.
pub const ERROR_CORRECTION_ALGORITHM_VERSION: u32 = 1;
