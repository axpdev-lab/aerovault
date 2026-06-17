//! AEROVAULT3 content pipeline: content-defined chunking (gear-CDC), keyed
//! BLAKE3 chunk ids, per-chunk zstd. Byte-for-byte port of the AeroFTP app
//! (`aerovault_v3.rs`): the gear seed string, rolling-hash formula, break
//! condition, chunk-id truncation, and zstd level must all match exactly or a
//! container will not cross-open with the app (T5 contract).

// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

use super::constants::{CDC_AVG, CDC_MAX, CDC_MIN};
use crate::aerocrypt::KEY_SIZE;

/// Content-defined-chunking bounds, recorded on the `chunking` wrapper so a
/// reader uses the exact bounds the writer used. Absent in pre-GAP-5 vaults and
/// non-`chunking` wrappers, where callers fall back to the const defaults.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CdcBounds {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl CdcBounds {
    pub fn defaults() -> Self {
        Self {
            min: CDC_MIN,
            avg: CDC_AVG,
            max: CDC_MAX,
        }
    }

    /// Profile-driven defaults. `archive` (level >= 19) widens the per-chunk
    /// zstd window for ratio at the cost of finer-grained dedup.
    pub fn for_level(level: i32) -> Self {
        if level >= 19 {
            Self {
                min: 1024 * 1024,
                avg: 4 * 1024 * 1024,
                max: 16 * 1024 * 1024,
            }
        } else {
            Self::defaults()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.min < 4096
            || self.min > self.avg
            || self.avg > self.max
            || self.max > 256 * 1024 * 1024
            || !self.avg.is_power_of_two()
        {
            return Err(format!(
                "Invalid AeroVault v3 CDC bounds: min={} avg={} max={}",
                self.min, self.avg, self.max
            ));
        }
        Ok(())
    }
}

/// Keyed-BLAKE3 chunk id: hex of the first 16 bytes (128 bits) of
/// `blake3::keyed_hash(key, plaintext)`. Used for content addressing + dedup.
pub fn keyed_chunk_id(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> String {
    let hash = blake3::keyed_hash(key, plaintext);
    hex::encode(&hash.as_bytes()[..16])
}

/// 256-entry gear-CDC table, each slot = first 8 bytes (LE) of
/// `BLAKE3(b"AeroVault v3 gear-cdc table" + byte(i))`.
pub fn gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    for (idx, slot) in table.iter_mut().enumerate() {
        let mut input = b"AeroVault v3 gear-cdc table".to_vec();
        input.push(idx as u8);
        let hash = blake3::hash(&input);
        *slot = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().expect("slice length"));
    }
    table
}

/// Compute chunk boundaries `(start, end)` over `data` for the given bounds.
/// Rolling hash: `rolling = rolling.rotate_left(1).wrapping_add(table[byte])`;
/// break when `len >= min && ((rolling & (avg-1)) == 0 || len >= max)`.
pub fn chunk_ranges_with(data: &[u8], bounds: &CdcBounds) -> Vec<(usize, usize)> {
    if data.is_empty() {
        return Vec::new();
    }
    if data.len() <= bounds.min {
        return vec![(0, data.len())];
    }

    let table = gear_table();
    let mask = (bounds.avg as u64) - 1;
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut rolling = 0u64;

    for (idx, byte) in data.iter().enumerate() {
        rolling = rolling.rotate_left(1).wrapping_add(table[*byte as usize]);
        let len = idx + 1 - start;
        if len >= bounds.min && ((rolling & mask) == 0 || len >= bounds.max) {
            ranges.push((start, idx + 1));
            start = idx + 1;
            rolling = 0;
        }
    }
    if start < data.len() {
        ranges.push((start, data.len()));
    }
    ranges
}

/// Per-chunk zstd compression at `level` (matches the app's
/// `zstd::stream::encode_all`). Frames are byte-identical when the linked
/// libzstd version matches (this crate and the app both pin zstd 0.13.x).
pub fn zstd_compress(chunk: &[u8], level: i32) -> Result<Vec<u8>, String> {
    zstd::stream::encode_all(chunk, level).map_err(|e| format!("zstd compress failed: {e}"))
}

/// Bounded per-chunk zstd decompression. Reads at most `plaintext_len + 1`
/// bytes so a malicious frame cannot expand past one legitimate chunk
/// (CLAUDE-AV-005); the caller verifies the exact length afterwards.
pub fn zstd_decompress_bounded(compressed: &[u8], plaintext_len: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|e| format!("zstd decoder init failed: {e}"))?;
    let mut out = Vec::with_capacity(plaintext_len.min(1 << 20) as usize);
    decoder
        .take(plaintext_len + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("zstd decompress failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdc_bounds_validate_and_profiles() {
        assert!(CdcBounds::defaults().validate().is_ok());
        assert!(CdcBounds::for_level(19).validate().is_ok());
        assert_eq!(CdcBounds::for_level(9).avg, CDC_AVG);
        assert_eq!(CdcBounds::for_level(19).avg, 4 * 1024 * 1024);
        // avg not power of two -> invalid.
        assert!(CdcBounds {
            min: 4096,
            avg: 3000,
            max: 4096
        }
        .validate()
        .is_err());
        // min > avg -> invalid.
        assert!(CdcBounds {
            min: 8192,
            avg: 4096,
            max: 8192
        }
        .validate()
        .is_err());
    }

    #[test]
    fn empty_and_small_inputs() {
        let b = CdcBounds::defaults();
        assert!(chunk_ranges_with(&[], &b).is_empty());
        // <= min stays a single chunk.
        let small = vec![0u8; 1024];
        assert_eq!(chunk_ranges_with(&small, &b), vec![(0, 1024)]);
    }

    #[test]
    fn chunk_ranges_cover_and_are_contiguous() {
        // Deterministic pseudo-random data large enough to split.
        let mut data = vec![0u8; 8 * 1024 * 1024];
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        let bounds = CdcBounds::defaults();
        let ranges = chunk_ranges_with(&data, &bounds);
        assert!(ranges.len() > 1, "large input must split");
        // contiguous, non-overlapping, full cover.
        assert_eq!(ranges.first().unwrap().0, 0);
        assert_eq!(ranges.last().unwrap().1, data.len());
        for w in ranges.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
        // every chunk except the last respects min; none exceeds max.
        for (i, (s, e)) in ranges.iter().enumerate() {
            let len = e - s;
            assert!(len <= bounds.max, "chunk over max");
            if i + 1 < ranges.len() {
                assert!(len >= bounds.min, "non-final chunk under min");
            }
        }
    }

    #[test]
    fn gear_table_is_deterministic_known_answer() {
        let t = gear_table();
        // Recompute independently to confirm the verbatim seed + formula. A
        // drift here means a different gear seed -> different chunk boundaries
        // -> no cross-open.
        let mut input = b"AeroVault v3 gear-cdc table".to_vec();
        input.push(42u8);
        let h = blake3::hash(&input);
        assert_eq!(
            t[42],
            u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap())
        );
    }

    #[test]
    fn keyed_chunk_id_known_answer() {
        let key = [0x11u8; KEY_SIZE];
        let id = keyed_chunk_id(&key, b"the quick brown fox");
        assert_eq!(id.len(), 32, "16 bytes hex");
        // Recompute independently.
        let h = blake3::keyed_hash(&key, b"the quick brown fox");
        assert_eq!(id, hex::encode(&h.as_bytes()[..16]));
        // Different plaintext -> different id (dedup correctness).
        assert_ne!(id, keyed_chunk_id(&key, b"the quick brown foy"));
    }

    #[test]
    fn zstd_round_trip_bounded() {
        let data = b"AeroVault zstd round-trip payload".repeat(4096);
        let c = zstd_compress(&data, DEFAULT_LEVEL).unwrap();
        let back = zstd_decompress_bounded(&c, data.len() as u64).unwrap();
        assert_eq!(back, data);
    }

    const DEFAULT_LEVEL: i32 = 9;
}
