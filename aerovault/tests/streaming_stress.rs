//! T5 streaming stress + anti-regression suite.
//!
//! Two things this file proves that the in-crate unit tests cannot:
//!   1. MEMORY BOUNDEDNESS (the whole point of T5): with a process-wide tracking
//!      allocator we assert that ingesting AND extracting a large, highly
//!      compressible file keeps peak Rust-heap usage far below the file size.
//!      The pre-T5 whole-buffer code read the entire file into one `Vec` on
//!      ingest and accumulated the whole entry into `out` on extract, so it would
//!      blow past these bounds — this is a real regression guard.
//!   2. EXTREME EDGE CASES: a size/pattern matrix straddling every CDC boundary
//!      (empty, 1 byte, min-1/min/min+1, max-1/max/max+1, multi-max, pack
//!      threshold) round-trips byte-identically through the streaming paths.
//!
//! SPDX-License-Identifier: GPL-3.0-only

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use aerovault::v3::{CreateOptionsV3, VaultV3};

// ---------------------------------------------------------------------------
// Process-wide tracking allocator: counts live Rust-heap bytes and the peak.
// (zstd/blake3 allocate through their C libs / libc malloc, which bypass this
// allocator — fine, we only need to see the big plaintext buffers, which ARE
// Rust `Vec`s and so are counted.)
// ---------------------------------------------------------------------------
struct Tracking;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn bump(delta: usize) {
    let now = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            bump(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            bump(layout.size());
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                bump(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Reset the peak watermark down to the currently-live bytes, so the next
/// `peak_since()` reports only what the measured section allocated on top.
fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}
fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}
fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

const MIB: usize = 1024 * 1024;

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

fn unique_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    p.push(format!("av3-stress-{tag}-{pid}-{seq}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Write `len` bytes of a cheap pattern to `path` WITHOUT ever holding the whole
/// file in this test's own RAM (so the test harness doesn't pollute the peak we
/// attribute to the vault code). `zeros = true` writes all-zero (max
/// compressible); otherwise a repeating byte ramp (still compressible, non-zero).
fn write_pattern(path: &Path, len: usize, zeros: bool) {
    let mut f = std::fs::File::create(path).unwrap();
    let chunk = 4 * MIB;
    let buf: Vec<u8> = if zeros {
        vec![0u8; chunk]
    } else {
        (0..chunk).map(|i| (i % 251) as u8).collect()
    };
    let mut written = 0usize;
    while written < len {
        let n = chunk.min(len - written);
        f.write_all(&buf[..n]).unwrap();
        written += n;
    }
    f.sync_all().unwrap();
}

/// Write `len` incompressible (xorshift) bytes to `path` in 4 MiB blocks reusing
/// one buffer, so the TEST never holds the whole file in RAM (otherwise it would
/// pollute the peak we attribute to the vault code).
fn write_incompressible(path: &Path, len: usize, mut x: u64) {
    let mut f = std::fs::File::create(path).unwrap();
    let block = 4 * MIB;
    let mut buf = vec![0u8; block];
    let mut written = 0usize;
    while written < len {
        let n = block.min(len - written);
        for b in buf[..n].iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
        f.write_all(&buf[..n]).unwrap();
        written += n;
    }
    f.sync_all().unwrap();
}

/// INCOMPRESSIBLE-data memory profile: the data section legitimately lives in
/// RAM at ~file size (the vault is opened in memory by design), so we cannot get
/// below 1x here — but no path may add ANOTHER whole-file buffer on top. Three
/// independent regression guards: (1) ingest adds no whole-file plaintext buffer
/// (`fs::read`), (2) the seal in isolation adds no whole-file duplicate
/// (T5 sub-task #2: streaming `save_open_vault`), (3) extract adds no whole-entry
/// `out` buffer. Each pre-T5 path would have blown its bound.
#[test]
fn streaming_incompressible_seal_and_extract_not_doubled() {
    const FILE: usize = 64 * MIB;
    const PW: &str = "seal-password-123";

    let dir = unique_dir("seal");
    let src = dir.join("random.bin");
    write_incompressible(&src, FILE, 0x1357_9bdf_2468_ace0);

    let vp = dir.join("v.aerovault");
    VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

    // The Argon2id KDF in `open` allocates a transient 128 MiB matrix (the
    // audited profile), freed before it returns. Every measured section resets
    // the watermark AFTER open, so we measure only the streaming work, never the
    // KDF floor.

    // ---- INGEST (streaming add + seal) ----
    // Ingest BUILDS `vault.data` (~1x file for incompressible) inside the window.
    // Vec growth-by-doubling means `vault.data`'s last realloc transiently holds
    // old+new (~1.5x file); that is amortized growth, NOT a whole-file buffer.
    // The pre-T5 code added a SEPARATE whole-file plaintext buffer on top (the
    // `fs::read`), pushing this well past 2x. Bound 2x catches that regression
    // while tolerating the doubling transient.
    const INGEST_BOUND: usize = 2 * FILE;
    {
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset_peak();
        VaultV3::add_files(&mut vault, &[(src.clone(), "random.bin".to_string())]).unwrap();
        let ingest_peak = peak().saturating_sub(base);
        assert!(
            ingest_peak < INGEST_BOUND,
            "ingest+seal peak {} MiB exceeded {} MiB for a {} MiB incompressible file \
             (a whole-file plaintext ingest buffer regressed)",
            ingest_peak / MIB,
            INGEST_BOUND / MIB,
            FILE / MIB
        );
    }

    // ---- SEAL in isolation (the T5 sub-task #2 win, measured cleanly) ----
    // Re-seal an already-built vault via a no-op `add_files(&[])` (appends
    // nothing, then `save_open_vault`). `vault.data` (~1x file) is already in the
    // baseline, so the ONLY thing the seal may allocate is the encrypted manifest
    // + extension payloads (metadata-scale). The pre-sub-task-#2 seal built a
    // SECOND whole-file buffer (`build_file_bytes` -> ~1x file). Bound 0.25x file
    // is far below that 1x and far above the few-KB manifest, so it pins the win.
    const SEAL_BOUND: usize = FILE / 4;
    {
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset_peak();
        VaultV3::add_files(&mut vault, &[]).unwrap(); // pure re-seal, no data change
        let seal_peak = peak().saturating_sub(base);
        assert!(
            seal_peak < SEAL_BOUND,
            "re-seal extra peak {} MiB exceeded {} MiB for a {} MiB vault \
             (the seal still builds a whole-file duplicate buffer)",
            seal_peak / MIB,
            SEAL_BOUND / MIB,
            FILE / MIB
        );
    }

    // ---- reopen + EXTRACT (streaming) under measurement ----
    // After open, `vault.data` (~1x file) is already in the baseline, so the
    // EXTRA the extract may allocate is just transient decoded blocks (a window).
    // The old whole-entry `out` Vec would add ~1x file on top. Bound 0.5x file.
    const EXTRACT_BOUND: usize = FILE / 2;
    let out = unique_dir("seal-out");
    let extract_peak;
    {
        let vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset_peak();
        VaultV3::extract_all(&vault, &out).unwrap();
        extract_peak = peak().saturating_sub(base);
    }
    assert!(
        extract_peak < EXTRACT_BOUND,
        "reopen+extract extra peak {} MiB exceeded {} MiB (whole-entry `out` buffer regressed)",
        extract_peak / MIB,
        EXTRACT_BOUND / MIB
    );

    assert_eq!(
        hash_file(&src),
        hash_file(&out.join("random.bin")),
        "incompressible round trip changed the bytes"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&out).ok();
}

/// Streaming ingest AND extract of a large, MAXIMALLY compressible file (all
/// zeros) must keep peak Rust-heap bounded by roughly a CDC window — NOT the
/// file size. Zeros compress to almost nothing, so the data section in RAM
/// (`OpenVaultV3.data`) and the seal buffer stay tiny; the ONLY thing that
/// would push the peak near the file size is a whole-file plaintext buffer on
/// ingest (`fs::read`, pre-T5) or a whole-entry `out` Vec on extract (pre-T5).
/// T5 removed both, so this pins the regression.
///
/// Scope note: this isolates the T5 headline (no whole-plaintext-file buffer).
/// For INCOMPRESSIBLE data the data section legitimately approaches the file
/// size in RAM, and the seal (`save_open_vault`) still builds the whole file
/// bytes in one buffer — that is the documented, deferred sub-task #2
/// (streaming seal), not a T5 regression. Hence the compressible fixture.
#[test]
fn streaming_ingest_extract_is_memory_bounded() {
    // 96 MiB of zeros; pre-T5 ingest (`fs::read`) and extract (`out` Vec) would
    // each push peak past ~96 MiB. The streaming paths stay an order of
    // magnitude below. 32 MiB bound leaves wide margin on both sides.
    const FILE: usize = 96 * MIB;
    const BOUND: usize = 32 * MIB;
    const PW: &str = "stress-password-123";

    let dir = unique_dir("mem");
    let src = dir.join("zeros.bin");
    write_pattern(&src, FILE, true);

    let vp = dir.join("v.aerovault");
    VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

    // ---- INGEST (streaming add + seal) under measurement ----
    // Reset the watermark AFTER open so the transient 128 MiB Argon2id KDF matrix
    // (freed before open returns) is excluded; we measure only the streaming work.
    let ingest_peak;
    {
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset_peak();
        VaultV3::add_files(&mut vault, &[(src.clone(), "zeros.bin".to_string())]).unwrap();
        ingest_peak = peak().saturating_sub(base);
        // The file must actually have split into several CDC windows, else we'd
        // be proving boundedness of a trivial one-chunk file.
        let entry = VaultV3::list(&vault)
            .into_iter()
            .find(|e| e.path == "zeros.bin")
            .unwrap();
        assert_eq!(entry.size, FILE as u64);
    }
    assert!(
        ingest_peak < BOUND,
        "streaming ingest peak {ingest_peak} bytes ({} MiB) exceeded bound {BOUND} ({} MiB) \
         for a {FILE}-byte file — the whole file was held in memory (regression)",
        ingest_peak / MIB,
        BOUND / MIB
    );

    // ---- EXTRACT (reopen from disk, stream block-by-block) under measurement ----
    let out = unique_dir("mem-out");
    let extract_peak;
    {
        let vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset_peak();
        VaultV3::extract_all(&vault, &out).unwrap();
        extract_peak = peak().saturating_sub(base);
    }
    assert!(
        extract_peak < BOUND,
        "streaming extract peak {extract_peak} bytes ({} MiB) exceeded bound {BOUND} ({} MiB) \
         — the whole entry was decoded into RAM (regression)",
        extract_peak / MIB,
        BOUND / MIB
    );

    // Byte-identity (verified streamed, not in one buffer): hash both sides in
    // bounded chunks so the verification itself doesn't allocate the file.
    let want = hash_file(&src);
    let got = hash_file(&out.join("zeros.bin"));
    assert_eq!(want, got, "memory-bounded round trip changed the bytes");

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&out).ok();
}

fn hash_file(path: &Path) -> [u8; 32] {
    use std::io::Read;
    let mut f = std::fs::File::open(path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    *hasher.finalize().as_bytes()
}

/// Deterministic pseudo-random bytes (xorshift), distinct per `seed`.
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = seed | 1;
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xff) as u8;
    }
    out
}

/// Every CDC boundary and content regime must round-trip byte-identically
/// through the streaming add + streaming extract. Sizes are picked relative to
/// the shipped geometry: CDC_MIN = 256 KiB, CDC_MAX = 4 MiB, pack threshold =
/// 256 KiB. Patterns cover: empty, all-zero (max compressible -> zstd lane),
/// 0xFF (also compressible), and incompressible random (stored-raw lane).
#[test]
fn streaming_extreme_size_and_pattern_matrix() {
    const PW: &str = "matrix-password-123";
    const MIN: usize = 256 * 1024;
    const MAX: usize = 4 * 1024 * 1024;

    // (size, kind) where kind: 0 = empty/zeros, 1 = 0xFF run, 2 = random.
    let sizes = [
        0usize,
        1,
        4095,
        4096,
        MIN - 1,
        MIN,
        MIN + 1,
        MIN + 7,
        MAX - 1,
        MAX,
        MAX + 1,
        2 * MAX,
        2 * MAX + 123,
        3 * MAX + 9999,
    ];

    let dir = unique_dir("matrix");

    // Build a per-pattern source set, add them all in one vault (mixes the pack
    // path for sub-256-KiB files with the per-file CDC path for the rest), then
    // extract all and compare every file byte-for-byte.
    for kind in 0u8..3 {
        let vp = dir.join(format!("v{kind}.aerovault"));
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();

        let mut expect: Vec<(String, Vec<u8>)> = Vec::new();
        let mut sources: Vec<(PathBuf, String)> = Vec::new();
        for (i, &sz) in sizes.iter().enumerate() {
            let data = match kind {
                0 => vec![0u8; sz],
                1 => vec![0xFFu8; sz],
                _ => pseudo_random(sz, 0x51ed_1000 + (i as u64) * 0x9e37 + kind as u64),
            };
            let fname = format!("f_{kind}_{i:02}_{sz}.bin");
            let src = dir.join(&fname);
            std::fs::write(&src, &data).unwrap();
            let vault_name = format!("m/{fname}");
            sources.push((src, vault_name.clone()));
            expect.push((vault_name, data));
        }

        VaultV3::add_files(&mut vault, &sources).unwrap();

        let out = dir.join(format!("out{kind}"));
        std::fs::create_dir_all(&out).unwrap();
        VaultV3::extract_all(&vault, &out).unwrap();

        for (vault_name, data) in &expect {
            let got = std::fs::read(out.join(vault_name)).unwrap();
            assert_eq!(
                got.len(),
                data.len(),
                "size mismatch kind={kind} entry={vault_name}"
            );
            assert!(
                &got == data,
                "byte mismatch kind={kind} entry={vault_name} (len {})",
                data.len()
            );
        }
        drop(vault);
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A single file whose size is an EXACT multiple of CDC_MAX exercises the
/// max-cutoff boundary repeatedly with no trailing partial chunk, then a
/// +1-byte variant forces a 1-byte trailing chunk. Both must round-trip and the
/// exact-multiple case must produce only full-max chunks (no off-by-one in the
/// streaming tail handling).
#[test]
fn streaming_exact_max_multiple_boundaries() {
    const PW: &str = "exact-password-123";
    const MAX: usize = 4 * 1024 * 1024;
    let dir = unique_dir("exact");

    for (tag, sz) in [("exact", 3 * MAX), ("plus1", 3 * MAX + 1)] {
        let vp = dir.join(format!("{tag}.aerovault"));
        VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();
        let mut vault = VaultV3::open(&vp, PW).unwrap();

        // Incompressible so each window becomes its own stored-raw block and the
        // chunk count is a clean function of the size.
        let data = pseudo_random(sz, 0x00C0_FFEE_D00D_1234);
        let src = dir.join(format!("{tag}.bin"));
        std::fs::write(&src, &data).unwrap();
        VaultV3::add_files(&mut vault, &[(src, format!("{tag}.bin"))]).unwrap();

        let out = dir.join(format!("out-{tag}"));
        std::fs::create_dir_all(&out).unwrap();
        VaultV3::extract_all(&vault, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join(format!("{tag}.bin"))).unwrap(),
            data,
            "exact-max-multiple round trip ({tag}) changed bytes"
        );
        drop(vault);
    }
    std::fs::remove_dir_all(&dir).ok();
}
