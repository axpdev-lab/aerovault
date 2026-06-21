//! Peak-heap measurement harness for the T5 streaming work. Uses a process-wide
//! tracking allocator and ONLY the public `VaultV3` API, so it compiles and runs
//! identically on the pre-T5 commit (0545a82) and the streamed commit — giving a
//! REAL old-vs-new comparison rather than estimates.
//!
//! Output: one CSV line per (scenario,phase) with the measured peak-heap DELTA in
//! bytes, with the watermark reset AFTER `open` so the transient Argon2id KDF
//! matrix (128 MiB, freed before open returns) is excluded.
//!
//! Run: cargo run --release --example measure_mem --manifest-path aerovault/Cargo.toml

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use aerovault::v3::{CreateOptionsV3, VaultV3};

struct Tracking;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn bump(d: usize) {
    let now = LIVE.fetch_add(d, Ordering::Relaxed) + d;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            if n >= l.size() {
                bump(n - l.size());
            } else {
                LIVE.fetch_sub(l.size() - n, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

const MIB: usize = 1024 * 1024;
const PW: &str = "measure-password-123";

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}
fn reset() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}
fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

fn write_file(path: &Path, len: usize, zeros: bool, mut x: u64) {
    let mut f = std::fs::File::create(path).unwrap();
    let block = 4 * MIB;
    let mut buf = vec![0u8; block];
    if zeros {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    let mut written = 0usize;
    while written < len {
        let n = block.min(len - written);
        if !zeros {
            for b in buf[..n].iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x & 0xff) as u8;
            }
        }
        f.write_all(&buf[..n]).unwrap();
        written += n;
    }
    f.sync_all().unwrap();
}

fn measure(dir: &Path, tag: &str, len: usize, zeros: bool) {
    let src = dir.join(format!("{tag}.src"));
    write_file(&src, len, zeros, 0x1234_5678_9abc_def0);
    let vp = dir.join(format!("{tag}.aerovault"));
    VaultV3::create(&CreateOptionsV3::new(&vp, PW)).unwrap();

    // INGEST (add_files = streaming append + seal)
    {
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset();
        VaultV3::add_files(&mut vault, &[(src.clone(), "f.bin".to_string())]).unwrap();
        println!("{tag},ingest,{}", peak().saturating_sub(base));
    }
    // RESEAL in isolation (no data change)
    {
        let mut vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset();
        VaultV3::add_files(&mut vault, &[]).unwrap();
        println!("{tag},reseal,{}", peak().saturating_sub(base));
    }
    // EXTRACT (reopen + extract_all)
    {
        let out = dir.join(format!("{tag}-out"));
        std::fs::create_dir_all(&out).unwrap();
        let vault = VaultV3::open(&vp, PW).unwrap();
        let base = live();
        reset();
        VaultV3::extract_all(&vault, &out).unwrap();
        println!("{tag},extract,{}", peak().saturating_sub(base));
        std::fs::remove_dir_all(&out).ok();
    }
}

fn main() {
    let dir = std::env::temp_dir().join(format!("av3-measure-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    println!("scenario,phase,peak_bytes");
    measure(&dir, "zeros96", 96 * MIB, true);
    measure(&dir, "rand64", 64 * MIB, false);
    std::fs::remove_dir_all(&dir).ok();
}
