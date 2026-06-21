//! Experimental zstd-dictionary proxy for the plaintext compression lane.
//!
//! This does not write an AeroVault container. It applies the same CDC chunking
//! bounds to every input file, trains one per-archive zstd dictionary from those
//! chunks, then compresses each chunk independently with that dictionary. The
//! reported output includes dictionary bytes, which a real format would need to
//! store or reference.
//!
//! Usage:
//! cargo run --release --example bench_dict_proxy --manifest-path aerovault/Cargo.toml -- <dir> <level> <profile> <dict_bytes>
//! Use dict_bytes=0 for the no-dictionary proxy baseline.

use std::path::{Path, PathBuf};

use aerovault::v3::{chunk_ranges_with, CdcBounds};

const TRAIN_SAMPLE: usize = 32 * 1024;
const TRAIN_STRIDE: usize = 256 * 1024;

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn parse_size(s: &str) -> usize {
    let (digits, multiplier) = match s.as_bytes().last().copied() {
        Some(b'K') | Some(b'k') => (&s[..s.len() - 1], 1024usize),
        Some(b'M') | Some(b'm') => (&s[..s.len() - 1], 1024usize * 1024),
        _ => (s, 1usize),
    };
    digits.parse::<usize>().unwrap() * multiplier
}

fn parse_bounds(profile: &str, level: i32) -> CdcBounds {
    match profile {
        "auto" => CdcBounds::for_level(level),
        "balanced" => CdcBounds::defaults(),
        "archive" => CdcBounds::for_level(19),
        custom => {
            let parts: Vec<&str> = custom.split(':').collect();
            if parts.len() != 3 {
                panic!("unknown chunk profile {custom:?}; use auto, balanced, archive, or <min>:<avg>:<max>");
            }
            CdcBounds {
                min: parse_size(parts[0]),
                avg: parse_size(parts[1]),
                max: parse_size(parts[2]),
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(&args[1]);
    let level: i32 = args[2].parse().unwrap();
    let profile = args[3].as_str();
    let dict_size = parse_size(&args[4]);
    let bounds = parse_bounds(profile, level);
    bounds.validate().unwrap();

    let mut files = Vec::new();
    collect(&dir, &mut files);
    files.sort();

    let mut chunks = Vec::new();
    let mut input_bytes = 0u64;
    for file in &files {
        let data = std::fs::read(file).unwrap();
        input_bytes += data.len() as u64;
        for (start, end) in chunk_ranges_with(&data, &bounds) {
            chunks.push(data[start..end].to_vec());
        }
    }

    let mut samples = Vec::new();
    for chunk in &chunks {
        if chunk.len() <= TRAIN_SAMPLE {
            samples.push(chunk.clone());
            continue;
        }
        let mut offset = 0usize;
        while offset < chunk.len() {
            let end = (offset + TRAIN_SAMPLE).min(chunk.len());
            samples.push(chunk[offset..end].to_vec());
            offset += TRAIN_STRIDE;
        }
    }

    let dict = if dict_size == 0 {
        Vec::new()
    } else {
        zstd::dict::from_samples(&samples, dict_size).unwrap()
    };
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, &dict).unwrap();
    let mut compressed_bytes = dict.len() as u64;
    for chunk in &chunks {
        let compressed = compressor.compress(chunk).unwrap();
        compressed_bytes += compressed.len().min(chunk.len()) as u64;
    }

    let ratio = input_bytes as f64 / compressed_bytes as f64;
    println!(
        "zstd-dict-proxy,{level},{profile},{},{},{compressed_bytes},{ratio:.3},dict={},samples={}",
        chunks.len(),
        input_bytes,
        dict.len(),
        samples.len()
    );
}
