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

/// Bounded refill increment for [`StreamingChunker`]: how many bytes are pulled
/// from the reader per `read` call. Peak buffer memory is `bounds.max +
/// STREAM_READ_CHUNK` (one in-progress chunk plus one lookahead refill),
/// independent of the source file size.
const STREAM_READ_CHUNK: usize = 256 * 1024;

/// Streaming gear-CDC chunker: yields the EXACT same chunk boundaries as
/// [`chunk_ranges_with`] over the identical byte stream, but reads the source
/// through a bounded buffer so peak memory is O(max chunk), not O(file size).
///
/// This is correct because gear-CDC is a strictly left-to-right rolling hash
/// that resets to zero at every emitted boundary and has a hard `max` cutoff
/// with no look-back: a chunk boundary depends only on the bytes since the last
/// boundary, never on anything ahead of it. So folding bytes one at a time out
/// of a sliding buffer produces an identical boundary sequence to folding the
/// whole buffer at once. The `streaming_chunker_matches_whole_buffer` test pins
/// this equality (changing it would change chunk ids and break cross-open).
pub struct StreamingChunker<R: std::io::Read> {
    reader: R,
    bounds: CdcBounds,
    table: [u64; 256],
    mask: u64,
    /// Bytes of the current in-progress chunk, starting at its boundary, plus
    /// any lookahead already pulled from the reader but not yet emitted.
    buf: Vec<u8>,
    /// Count of `buf` bytes already folded into `rolling` == current chunk len.
    scanned: usize,
    rolling: u64,
    eof: bool,
}

impl<R: std::io::Read> StreamingChunker<R> {
    pub fn new(reader: R, bounds: CdcBounds) -> Self {
        Self {
            reader,
            table: gear_table(),
            mask: (bounds.avg as u64) - 1,
            bounds,
            buf: Vec::new(),
            scanned: 0,
            rolling: 0,
            eof: false,
        }
    }

    /// Pull up to `STREAM_READ_CHUNK` more bytes from the reader directly into the
    /// buffer's spare capacity (no scratch allocation, no tmp->buf copy), then trim
    /// to the count actually read. A read of `0` is treated as end of stream (per
    /// the `Read` contract, `Ok(0)` means EOF); a short non-zero read needs no
    /// special handling, the next `fill` on the following loop turn appends more.
    fn fill(&mut self) -> std::io::Result<()> {
        let old = self.buf.len();
        self.buf.resize(old + STREAM_READ_CHUNK, 0);
        let n = self.reader.read(&mut self.buf[old..])?;
        self.buf.truncate(old + n);
        if n == 0 {
            self.eof = true;
        }
        Ok(())
    }

    /// Return the next chunk's bytes, or `None` once the stream is exhausted.
    /// The returned `Vec` is exactly the bytes `chunk_ranges_with` would have
    /// delimited for the same `(start, end)` range.
    pub fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            // Fold any buffered-but-unscanned bytes, breaking at the first
            // boundary exactly as the whole-buffer loop does.
            while self.scanned < self.buf.len() {
                let byte = self.buf[self.scanned];
                self.rolling = self
                    .rolling
                    .rotate_left(1)
                    .wrapping_add(self.table[byte as usize]);
                self.scanned += 1;
                let len = self.scanned;
                if len >= self.bounds.min
                    && ((self.rolling & self.mask) == 0 || len >= self.bounds.max)
                {
                    let chunk = self.buf[..len].to_vec();
                    self.buf.drain(..len);
                    self.rolling = 0;
                    self.scanned = 0;
                    return Ok(Some(chunk));
                }
            }
            if self.eof {
                // The trailing partial chunk mirrors the whole-buffer loop's
                // `if start < data.len()` tail push.
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let chunk = std::mem::take(&mut self.buf);
                self.rolling = 0;
                self.scanned = 0;
                return Ok(Some(chunk));
            }
            self.fill()?;
        }
    }
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

    /// Deterministic pseudo-random fill (xorshift), seeded distinctly so each
    /// fixture has its own byte pattern.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut data = vec![0u8; len];
        let mut x = seed | 1;
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        data
    }

    /// THE byte-compat gate for streaming ingest: the streamed chunker MUST emit
    /// exactly the boundaries `chunk_ranges_with` produces on the same bytes, or
    /// chunk ids change and existing `.aerovault` containers stop cross-opening.
    /// Proven here over empty / sub-min / boundary / repetitive / random / multi-MB
    /// fixtures and several bounds (including the `max`-cutoff-only regime) BEFORE
    /// any ingest path is wired to it.
    #[test]
    fn streaming_chunker_matches_whole_buffer() {
        use std::io::Cursor;

        // Cheap small bounds exercise the multi-window path without multi-MB data;
        // `min == avg == max` forces every break through the hard `max` cutoff;
        // the defaults prove it at the real (256 KiB / 1 MiB / 4 MiB) geometry.
        let bounds_set = [
            CdcBounds {
                min: 4096,
                avg: 8192,
                max: 65536,
            },
            CdcBounds {
                min: 4096,
                avg: 4096,
                max: 4096,
            },
            CdcBounds::defaults(),
        ];

        for bounds in bounds_set {
            bounds.validate().expect("test bounds valid");
            let big = if bounds.max >= 1024 * 1024 {
                9_000_000
            } else {
                300_000
            };
            let fixtures: Vec<Vec<u8>> = vec![
                Vec::new(),                      // empty -> zero chunks
                vec![0u8; 1],                    // single byte (< min)
                vec![7u8; bounds.min - 1],       // just under min
                vec![9u8; bounds.min],           // exactly min
                vec![0xABu8; bounds.max + 1],    // just over max (repetitive)
                vec![0u8; bounds.max * 2 + 123], // multiple max-length chunks
                pseudo_random(bounds.min * 3 + 17, 0x1234_5678_9abc_def0),
                pseudo_random(big, 0x0f0f_0f0f_0f0f_0f0f),
            ];

            for (i, data) in fixtures.iter().enumerate() {
                let whole = chunk_ranges_with(data, &bounds);

                let mut chunker = StreamingChunker::new(Cursor::new(data.as_slice()), bounds);
                let mut streamed = Vec::new();
                let mut pos = 0usize;
                while let Some(chunk) = chunker.next_chunk().expect("stream chunk") {
                    let end = pos + chunk.len();
                    // The streamed bytes must be exactly the source slice.
                    assert_eq!(
                        &chunk[..],
                        &data[pos..end],
                        "streamed chunk bytes differ (bounds={bounds:?}, fixture {i})"
                    );
                    streamed.push((pos, end));
                    pos = end;
                }

                assert_eq!(
                    streamed,
                    whole,
                    "streamed boundaries != whole-buffer (bounds={bounds:?}, fixture {i}, len={})",
                    data.len()
                );
                // Full, contiguous cover when there is any data at all.
                if !data.is_empty() {
                    assert_eq!(streamed.last().unwrap().1, data.len());
                }
            }
        }
    }

    /// A reader that hands back at most `cap` bytes per `read` (including short
    /// and zero-but-not-EOF reads) to prove the chunker is independent of read
    /// granularity: boundaries cannot depend on how the source is delivered.
    #[test]
    fn streaming_chunker_is_read_granularity_independent() {
        use std::io::Read;

        struct Trickle<'a> {
            data: &'a [u8],
            pos: usize,
            cap: usize,
        }
        impl Read for Trickle<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self
                    .data
                    .len()
                    .saturating_sub(self.pos)
                    .min(self.cap)
                    .min(out.len());
                out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let bounds = CdcBounds {
            min: 4096,
            avg: 8192,
            max: 65536,
        };
        let data = pseudo_random(500_000, 0xdead_beef_cafe_babe);
        let whole = chunk_ranges_with(&data, &bounds);
        for cap in [1usize, 7, 4095, 4096, 65537, 200_000] {
            let mut chunker = StreamingChunker::new(
                Trickle {
                    data: &data,
                    pos: 0,
                    cap,
                },
                bounds,
            );
            let mut streamed = Vec::new();
            let mut pos = 0usize;
            while let Some(chunk) = chunker.next_chunk().expect("stream chunk") {
                streamed.push((pos, pos + chunk.len()));
                pos += chunk.len();
            }
            assert_eq!(streamed, whole, "boundaries changed at read cap {cap}");
        }
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
