//! # AeroVault v2
//!
//! Military-grade encrypted vault format with defense-in-depth cryptography.
//!
//! AeroVault v2 provides a single-file encrypted container format designed for
//! maximum security while maintaining practical usability. It combines multiple
//! cryptographic primitives in a layered architecture that remains secure even
//! if individual algorithms are compromised.
//!
//! ## Cryptographic Stack
//!
//! | Layer | Algorithm | Purpose |
//! |-------|-----------|---------|
//! | KDF | Argon2id (128 MiB, t=4, p=4) | Password-based key derivation |
//! | Key Wrapping | AES-256-KW (RFC 3394) | Master key protection |
//! | Content Encryption | AES-256-GCM-SIV (RFC 8452) | Nonce misuse-resistant AEAD |
//! | Cascade Mode | ChaCha20-Poly1305 | Optional second encryption layer |
//! | Filename Encryption | AES-256-SIV | Deterministic authenticated encryption |
//! | Header Integrity | HMAC-SHA512 | Header tamper detection |
//! | Key Separation | HKDF-SHA256 | Domain separation for key purposes |
//!
//! ## Quick Start
//!
//! ```no_run
//! use aerovault::{Vault, CreateOptions, EncryptionMode};
//!
//! // Create a new vault
//! let opts = CreateOptions::new("my-vault.aerovault", "strong-password-here")
//!     .with_mode(EncryptionMode::Standard);
//! let vault = Vault::create(opts)?;
//!
//! // Add files
//! vault.add_files(&["document.pdf", "photo.jpg"])?;
//!
//! // Open existing vault
//! let vault = Vault::open("my-vault.aerovault", "strong-password-here")?;
//!
//! // List contents
//! for entry in vault.list()? {
//!     println!("{} ({} bytes)", entry.name, entry.size);
//! }
//!
//! // Extract a file
//! vault.extract("document.pdf", "/tmp/output/")?;
//! # Ok::<(), aerovault::Error>(())
//! ```
//!
//! ## File Format
//!
//! An `.aerovault` file consists of three sections:
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │          Header (512 bytes)      │
//! │  magic, version, flags, salt,    │
//! │  wrapped keys, chunk size, MAC   │
//! ├──────────────────────────────────┤
//! │     Manifest Length (4 bytes)    │
//! ├──────────────────────────────────┤
//! │   AES-SIV Encrypted Manifest    │
//! │  (JSON: entries, timestamps)    │
//! ├──────────────────────────────────┤
//! │       Encrypted Data Chunks     │
//! │  [len:4][encrypted_chunk:len]   │
//! │  [len:4][encrypted_chunk:len]   │
//! │            ...                  │
//! └──────────────────────────────────┘
//! ```
//!
//! See [`AEROVAULT-V2-SPEC.md`](https://github.com/axpdev-lab/aerovault/blob/main/docs/AEROVAULT-V2-SPEC.md)
//! for the complete format specification.

pub mod aerocrypt;
pub(crate) mod constants;
pub(crate) mod crypto;
pub mod error;
pub mod error_correction;
pub mod format;
pub mod v3;
pub mod vault;

// Re-export primary API
pub use error::Error;
pub use error_correction::{
    aerocorrect_sidecar_path_for, correct_generate, correct_repair, correct_repair_anchored,
    correct_verify, AeroCorrectSegment, AeroCorrectSidecar, CorrectGenerateReport,
    CorrectRepairReport, CorrectVerifyReport, ShardHealth, AEROCORRECT_EXTENSION,
    AEROCORRECT_MAGIC, AEROCORRECT_VERSION,
};
// AeroSync windowed-sidecar error-correction API: windowed `.aerocorrect` generation
// (from a path or from bytes, with cap + minimum-benefit gate) and verify/repair against
// an out-of-band expected SHA-256. This is the single implementation; the AeroFTP app
// routes its AeroSync download EC and standalone `correct` here (M7 convergence).
pub use error_correction::sync::{
    estimate_aerorec_sidecar_len, generate_sync_sidecar_for_bytes,
    generate_sync_sidecar_for_bytes_capped, generate_sync_sidecar_for_file_capped,
    parse_sha256_hex, sync_error_correction_sidecar_path, verify_repair_sync_bytes,
    verify_repair_sync_file, verify_repair_sync_file_streamed, SyncEcGenerateResult,
    SyncEcGeneratedSidecar, SyncEcRepairResult, AEROSYNC_EC_MAX_FILE_SIZE,
};
pub use error_correction::{
    ERROR_CORRECTION_DEFAULT_PCT, ERROR_CORRECTION_MAX_PCT, ERROR_CORRECTION_MIN_PCT,
};
pub use format::{EncryptionMode, HeaderFlags, ManifestEntry, VaultHeader, VaultManifest};
pub use vault::{CompactResult, CreateOptions, EntryInfo, PeekInfo, Vault};

/// Result type alias for AeroVault operations.
pub type Result<T> = std::result::Result<T, Error>;

/// MIME type for `.aerovault` files.
///
/// Register this in your OS integration (freedesktop shared-mime-info, Windows Registry, etc.).
pub const MIME_TYPE: &str = "application/x-aerovault";

/// SVG icon for the `.aerovault` MIME type (shield with lock, emerald color scheme).
///
/// Embedders can use this to register the file type icon without shipping separate assets.
/// The icon follows the freedesktop naming convention `application-x-aerovault`.
pub const ICON_SVG: &str = include_str!("aerovault-icon.svg");
