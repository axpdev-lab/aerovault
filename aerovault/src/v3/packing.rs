//! AEROVAULT3 small-file packing layout (the byte-affecting part of the app's
//! `append_sources_batched` / `flush_pack`). Files strictly smaller than
//! `PACK_SMALL_FILE_THRESHOLD` are sorted by vault path, concatenated, and
//! flushed into packs at `PACK_TARGET`; each member records the chunks that
//! cover its byte span plus `pack_offset` (its first byte's offset inside the
//! first covering chunk). Files at or above the threshold take the per-file
//! path. This module models the pure layout so it can be unit-tested without
//! crypto; `v3::VaultV3` wires it to chunking + encryption (T4).

// SPDX-License-Identifier: GPL-3.0-only

use super::constants::{PACK_SMALL_FILE_THRESHOLD, PACK_TARGET};

/// One assembled pack: the concatenated bytes plus per-member `(path, start,
/// len)` spans into those bytes.
#[derive(Debug, Clone)]
pub struct Pack {
    pub data: Vec<u8>,
    pub members: Vec<(String, u64, u64)>,
}

/// True if `len` routes through the small-file pack path rather than per-file.
pub fn is_small(len: u64) -> bool {
    (len as usize) < PACK_SMALL_FILE_THRESHOLD
}

/// Assemble small files into packs exactly as the app does: stable sort by
/// vault path, concatenate, flush once a pack reaches `PACK_TARGET`, and flush
/// the trailing remainder. Input is `(vault_path, bytes)`; large files must be
/// filtered out by the caller (they are per-file, not packed).
pub fn assemble_packs(mut small: Vec<(String, Vec<u8>)>) -> Vec<Pack> {
    small.sort_by(|a, b| a.0.cmp(&b.0));

    let mut packs = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    let mut members: Vec<(String, u64, u64)> = Vec::new();

    for (path, bytes) in &small {
        let start = data.len() as u64;
        data.extend_from_slice(bytes);
        let len = bytes.len() as u64;
        members.push((path.clone(), start, len));
        if data.len() >= PACK_TARGET {
            packs.push(Pack {
                data: std::mem::take(&mut data),
                members: std::mem::take(&mut members),
            });
        }
    }
    if !members.is_empty() {
        packs.push(Pack { data, members });
    }
    packs
}

/// Map a member's `[fstart, fstart+flen)` span onto the pack's chunk ranges,
/// returning the indices of covering chunks and the member's `pack_offset`
/// (its first byte's offset inside the first covering chunk). Mirrors
/// `flush_pack`: a zero-length file covers nothing with `pack_offset = 0`.
pub fn cover(
    chunk_ranges: &[(usize, usize)],
    fstart: u64,
    flen: u64,
) -> Result<(Vec<usize>, u64), String> {
    if flen == 0 {
        return Ok((Vec::new(), 0));
    }
    let fend = fstart + flen;
    let mut cov = Vec::new();
    let mut first: Option<u64> = None;
    for (i, (cstart, cend)) in chunk_ranges.iter().enumerate() {
        let (cs, ce) = (*cstart as u64, *cend as u64);
        if cs < fend && fstart < ce {
            if first.is_none() {
                first = Some(cs);
            }
            cov.push(i);
        }
    }
    let fc = first.ok_or_else(|| "Packing failed to cover file".to_string())?;
    Ok((cov, fstart - fc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::chunking::{chunk_ranges_with, CdcBounds};

    #[test]
    fn small_threshold() {
        assert!(is_small(0));
        assert!(is_small((PACK_SMALL_FILE_THRESHOLD - 1) as u64));
        assert!(!is_small(PACK_SMALL_FILE_THRESHOLD as u64));
    }

    #[test]
    fn packs_are_path_sorted_and_offsets_contiguous() {
        let small = vec![
            ("b.txt".to_string(), vec![1u8; 10]),
            ("a.txt".to_string(), vec![2u8; 20]),
            ("c.txt".to_string(), vec![3u8; 5]),
        ];
        let packs = assemble_packs(small);
        assert_eq!(packs.len(), 1, "well under PACK_TARGET -> one pack");
        let p = &packs[0];
        // sorted by path: a, b, c
        assert_eq!(p.members[0].0, "a.txt");
        assert_eq!(p.members[1].0, "b.txt");
        assert_eq!(p.members[2].0, "c.txt");
        // contiguous spans: a[0,20) b[20,30) c[30,35)
        assert_eq!(p.members[0], ("a.txt".to_string(), 0, 20));
        assert_eq!(p.members[1], ("b.txt".to_string(), 20, 10));
        assert_eq!(p.members[2], ("c.txt".to_string(), 30, 5));
        assert_eq!(p.data.len(), 35);
    }

    #[test]
    fn pack_flushes_at_target() {
        // Three ~half-target small files -> flush after the first crosses target
        // would need >= PACK_TARGET; build members each just under threshold.
        let chunk = (PACK_SMALL_FILE_THRESHOLD - 1) as usize; // < threshold => small
        let small = vec![
            ("a".to_string(), vec![0u8; chunk]),
            ("b".to_string(), vec![0u8; chunk]),
            ("c".to_string(), vec![0u8; chunk]),
        ];
        let total = 3 * chunk;
        let packs = assemble_packs(small);
        let summed: usize = packs.iter().map(|p| p.data.len()).sum();
        assert_eq!(summed, total, "no bytes lost across flush boundary");
        // At least one pack reached >= PACK_TARGET except possibly the last.
        for p in &packs[..packs.len() - 1] {
            assert!(p.data.len() >= PACK_TARGET);
        }
    }

    #[test]
    fn cover_maps_spans_to_chunks() {
        // Build a deterministic pack and chunk it, then check each member maps
        // to covering chunks with a correct pack_offset.
        let mut data = vec![0u8; 6 * 1024 * 1024];
        let mut x = 0x1234_5678_9abc_def0u64;
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        let ranges = chunk_ranges_with(&data, &CdcBounds::defaults());
        assert!(ranges.len() > 1);

        // zero-length member.
        assert_eq!(cover(&ranges, 100, 0).unwrap(), (Vec::new(), 0));

        // A member fully inside the first chunk.
        let (first_s, first_e) = ranges[0];
        let fstart = (first_s + 10) as u64;
        let flen = ((first_e - first_s) / 4) as u64;
        let (cov, off) = cover(&ranges, fstart, flen).unwrap();
        assert_eq!(cov, vec![0]);
        assert_eq!(off, 10);

        // A member spanning the first two chunks.
        let fstart2 = (first_e - 5) as u64;
        let flen2 = 10u64;
        let (cov2, off2) = cover(&ranges, fstart2, flen2).unwrap();
        assert_eq!(cov2, vec![0, 1]);
        assert_eq!(off2, fstart2 - first_s as u64);
    }
}
