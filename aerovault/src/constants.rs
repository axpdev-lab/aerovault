// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Vault format constants and cryptographic parameters.
//!
//! All constants are derived from the AeroVault v2 specification.
//! Changing these values will produce incompatible vault files.

/// Magic bytes identifying an AeroVault v2 file.
pub const MAGIC: &[u8; 10] = b"AEROVAULT2";

/// Legacy v2 format version. Chunk AAD binds only the per-file chunk index.
pub const LEGACY_VERSION: u8 = 2;

/// Current format version. Chunk AAD binds file id, chunk count, and chunk index.
pub const VERSION: u8 = 3;

/// Total header size in bytes.
pub const HEADER_SIZE: usize = 512;

/// Default plaintext chunk size (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// AES-GCM-SIV nonce size in bytes.
pub const NONCE_SIZE: usize = 12;

/// AES-GCM-SIV authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Master key and MAC key size in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Argon2id salt size in bytes (256-bit).
pub const SALT_SIZE: usize = 32;

/// AES-256-KW wrapped key size (32-byte key + 8-byte integrity check).
pub const WRAPPED_KEY_SIZE: usize = 40;

/// HMAC-SHA512 output size in bytes.
pub const MAC_SIZE: usize = 64;

/// Maximum manifest size to prevent denial-of-service (64 MiB).
pub const MAX_MANIFEST_SIZE: usize = 64 * 1024 * 1024;

/// Minimum password length enforced at the API level.
pub const MIN_PASSWORD_LENGTH: usize = 8;

// --- Argon2id Parameters ---
// These exceed OWASP 2024 recommendations (64 MiB / t=3 / p=1).

/// The audited Argon2id memory cost in KiB (128 MiB).
pub const AUDITED_ARGON2_M_COST: u32 = 128 * 1024;

/// The audited Argon2id time cost (iterations).
pub const AUDITED_ARGON2_T_COST: u32 = 4;

/// Argon2id memory cost in KiB used by every derivation: the audited 128 MiB,
/// or 8 MiB under the test-only `fast-kdf-for-tests` feature (see Cargo.toml).
#[cfg(not(feature = "fast-kdf-for-tests"))]
pub const ARGON2_M_COST: u32 = AUDITED_ARGON2_M_COST;
#[cfg(feature = "fast-kdf-for-tests")]
pub const ARGON2_M_COST: u32 = 8 * 1024;

/// Argon2id time cost (iterations): the audited 4, or 1 under
/// `fast-kdf-for-tests`.
#[cfg(not(feature = "fast-kdf-for-tests"))]
pub const ARGON2_T_COST: u32 = AUDITED_ARGON2_T_COST;
#[cfg(feature = "fast-kdf-for-tests")]
pub const ARGON2_T_COST: u32 = 1;

/// Argon2id parallelism degree.
pub const ARGON2_P_COST: u32 = 4;

// --- HKDF Domain Separation Labels ---

/// HKDF info label for the master KEK derivation.
pub const HKDF_LABEL_MASTER: &[u8] = b"AeroVault v2 KEK for master key";

/// HKDF info label for the MAC KEK derivation.
pub const HKDF_LABEL_MAC: &[u8] = b"AeroVault v2 KEK for MAC key";

/// HKDF info label for the ChaCha20-Poly1305 cascade key.
pub const HKDF_LABEL_CHACHA: &[u8] = b"AeroVault v2 ChaCha20-Poly1305 cascade";

/// HKDF info label for the AES-SIV filename encryption key.
pub const HKDF_LABEL_SIV: &[u8] = b"AeroVault v2 AES-SIV filename encryption";

#[cfg(test)]
mod kdf_profile_tests {
    use super::*;

    /// The audited profile is what every build derives with unless the
    /// test-only feature is on; a silent change to the numbers shows here.
    #[cfg(not(feature = "fast-kdf-for-tests"))]
    #[test]
    fn every_derivation_uses_the_audited_profile() {
        assert_eq!(
            (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST),
            (128 * 1024, 4, 4)
        );
        assert_eq!(ARGON2_M_COST, AUDITED_ARGON2_M_COST);
        assert_eq!(ARGON2_T_COST, AUDITED_ARGON2_T_COST);
    }

    /// Under the feature the profile is the floor, and the audited numbers
    /// are still reachable by name so a consumer can describe the real vault.
    #[cfg(feature = "fast-kdf-for-tests")]
    #[test]
    fn the_test_feature_derives_at_the_floor_and_keeps_the_audited_numbers_by_name() {
        assert_eq!(
            (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST),
            (8 * 1024, 1, 4)
        );
        assert_eq!(
            (AUDITED_ARGON2_M_COST, AUDITED_ARGON2_T_COST),
            (128 * 1024, 4)
        );
    }
}
