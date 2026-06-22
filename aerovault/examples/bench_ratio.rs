//! Compression-ratio benchmark for the .aerozip (plaintext, EC-off) lane.
//! Creates an .aerozip from every regular file under a directory at a given zstd
//! level and reports the container size, so it can be compared apples-to-apples
//! with tar.bz2 / tar.xz / tar.zst of the same files.
//!
//! Usage: cargo run --release --example bench_ratio --manifest-path aerovault/Cargo.toml -- <dir> <level> [auto|balanced|archive|<min>:<avg>:<max>]
//! Custom bounds accept K/M suffixes, e.g. 512K:2M:8M.
//! Prints CSV: codec,level,chunk_profile,input_bytes,output_bytes,ratio

use std::path::{Path, PathBuf};

use aerovault::v3::{CdcBounds, CreateOptionsV3, VaultV3};

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

fn parse_bounds(profile: &str) -> Option<CdcBounds> {
    let parts: Vec<&str> = profile.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    Some(CdcBounds {
        min: parse_size(parts[0]),
        avg: parse_size(parts[1]),
        max: parse_size(parts[2]),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(&args[1]);
    let level: i32 = args[2].parse().unwrap();
    let chunk_profile = args.get(3).map(String::as_str).unwrap_or("auto");

    let mut files = Vec::new();
    collect(&dir, &mut files);
    files.sort();
    let input_bytes: u64 = files
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .sum();

    // map each file to a vault-relative path under the corpus root
    let sources: Vec<(PathBuf, String)> = files
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (p.clone(), rel)
        })
        .collect();

    let tmp = std::env::temp_dir().join(format!(
        "bench-{}-{}-{}.aerozip",
        level,
        chunk_profile,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    // plaintext (.aerozip) lane, EC OFF (default), at the requested zstd level.
    let base = CreateOptionsV3::new_plaintext(&tmp).with_zstd_level(level);
    let opts = match chunk_profile {
        "auto" => base,
        "balanced" => base.with_cdc_bounds(CdcBounds::defaults()),
        "archive" => base.with_cdc_bounds(CdcBounds::for_level(19)),
        custom => {
            let bounds = parse_bounds(custom)
                .unwrap_or_else(|| panic!("unknown chunk profile {custom:?}; use auto, balanced, archive, or <min>:<avg>:<max>"));
            base.with_cdc_bounds(bounds)
        }
    };
    VaultV3::create(&opts).unwrap();
    let mut vault = VaultV3::open_plaintext(&tmp).unwrap();
    VaultV3::add_files(&mut vault, &sources).unwrap();
    drop(vault);

    let output_bytes = std::fs::metadata(&tmp).unwrap().len();
    let _ = std::fs::remove_file(&tmp);
    let ratio = input_bytes as f64 / output_bytes as f64;
    println!("aerozip,{level},{chunk_profile},{input_bytes},{output_bytes},{ratio:.3}");
}
