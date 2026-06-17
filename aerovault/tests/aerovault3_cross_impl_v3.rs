//! AEROVAULT3 (rev. 3) cross-impl byte-compat contract (T5 release gate).
//!
//! Proves the crate's AEROVAULT3 container is the same on-disk format as the
//! AeroFTP app's, both directions:
//!
//! 1. `golden_is_byte_reproducible` (feature `test-vectors`): with the
//!    deterministic CSPRNG + frozen timestamp seam, building the fixed fixture
//!    tree twice yields identical bytes, and those bytes equal the checked-in
//!    golden `fixtures/aerovault3_golden.av3`. The AeroFTP app, running the SAME
//!    seam over the SAME tree, asserts equality against this SAME golden in its
//!    own test suite, so crate output == app output, byte for byte (crate ->
//!    app direction).
//! 2. `crate_opens_and_extracts_golden` (always): opens the checked-in golden
//!    with the known password and extracts it, asserting the tree comes back
//!    byte-identical (app -> crate direction; the golden was produced under the
//!    shared seam, equivalently by either implementation).
//!
//! Regenerate the golden intentionally with:
//!   AEROVAULT3_WRITE_GOLDEN=1 cargo test -p aerovault --features test-vectors \
//!     --test aerovault3_cross_impl_v3 -- --nocapture
//! Doing so is a conscious format change, never a silent break.

use std::path::{Path, PathBuf};

use aerovault::v3::VaultV3;

/// Password baked into the golden. Fixed so the wrapped keys are deterministic.
const FIXTURE_PW: &str = "aerovault-fixture-pw";

/// The fixed tree the golden encodes: (vault path, bytes). Two small files
/// (packed), one >256 KiB file (the CDC per-file path, compressible so the
/// fixture stays small), plus an explicit empty directory.
fn fixture_tree() -> Vec<(String, Vec<u8>)> {
    let mut big = Vec::with_capacity(300_000);
    // A repeating, compressible pattern: large enough to take the CDC path
    // (>= PACK_SMALL_FILE_THRESHOLD = 256 KiB) but tiny once zstd'd.
    while big.len() < 300_000 {
        big.extend_from_slice(b"AeroVault v3 cross-impl big-file pattern block. ");
    }
    big.truncate(300_000);
    vec![
        (
            "readme.txt".to_string(),
            b"AeroVault v3 cross-impl fixture\n".to_vec(),
        ),
        ("data/small.bin".to_string(), vec![0xA5u8; 1000]),
        ("data/big.bin".to_string(), big),
    ]
}

#[cfg(feature = "test-vectors")]
fn write_tree_to_disk(root: &Path, tree: &[(String, Vec<u8>)]) -> Vec<(PathBuf, String)> {
    let mut sources = Vec::new();
    for (rel, bytes) in tree {
        let abs = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, bytes).unwrap();
        sources.push((abs, rel.clone()));
    }
    sources
}

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/aerovault3_golden.av3")
}

/// Build the fixture container deterministically (only meaningful under the
/// `test-vectors` feature, which makes salt/keys/nonces/timestamp fixed).
#[cfg(feature = "test-vectors")]
fn build_deterministic_container() -> Vec<u8> {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    let sources = write_tree_to_disk(&src, &fixture_tree());
    let vp = tmp.path().join("golden.aerovault");

    // Rewind the deterministic stream so every build starts from the same point.
    aerovault::aerocrypt::reset_test_vectors();
    VaultV3::create(&aerovault::v3::CreateOptionsV3::new(&vp, FIXTURE_PW)).unwrap();
    let mut vault = VaultV3::open(&vp, FIXTURE_PW).unwrap();
    VaultV3::create_directory(&mut vault, "emptydir").unwrap();
    VaultV3::add_files(&mut vault, &sources).unwrap();
    drop(vault);

    std::fs::read(&vp).unwrap()
}

#[cfg(feature = "test-vectors")]
#[test]
fn golden_is_byte_reproducible() {
    let a = build_deterministic_container();
    let b = build_deterministic_container();
    assert_eq!(
        a, b,
        "deterministic build must be byte-reproducible run to run"
    );

    if std::env::var("AEROVAULT3_WRITE_GOLDEN").is_ok() {
        std::fs::write(golden_path(), &a).unwrap();
        eprintln!(
            "wrote golden: {} bytes, blake3={}",
            a.len(),
            blake3::hash(&a).to_hex()
        );
        return;
    }

    let golden = std::fs::read(golden_path())
        .expect("checked-in golden missing; regenerate with AEROVAULT3_WRITE_GOLDEN=1");
    assert_eq!(
        a.len(),
        golden.len(),
        "container length drifted from the golden"
    );
    assert_eq!(
        a, golden,
        "AEROVAULT3 container bytes drifted from the cross-impl golden (crate != app or a deliberate format change needs a golden refresh)"
    );
}

/// app -> crate: open the checked-in golden and extract it, asserting the tree
/// is reproduced byte-identically. Runs without the seam (pure read path).
#[test]
fn crate_opens_and_extracts_golden() {
    let gp = golden_path();
    if !gp.exists() {
        // The golden is generated by the feature-gated test above; skip cleanly
        // if it has not been produced yet rather than failing the default run.
        eprintln!(
            "golden not present yet ({}); skipping read-path check",
            gp.display()
        );
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let vp = tmp.path().join("opened.aerovault");
    std::fs::copy(&gp, &vp).unwrap();

    assert!(VaultV3::is_vault_v3(&vp), "golden must be a v3 container");
    let vault = VaultV3::open(&vp, FIXTURE_PW).expect("crate must open the app/golden container");

    let out = tmp.path().join("out");
    let written = VaultV3::extract_all(&vault, &out).unwrap();
    assert_eq!(written, 3, "three files in the fixture tree");

    for (rel, bytes) in fixture_tree() {
        let got =
            std::fs::read(out.join(&rel)).unwrap_or_else(|_| panic!("missing extracted {rel}"));
        assert_eq!(got, bytes, "extracted {rel} is not byte-identical");
    }
    // The explicit empty directory survived.
    assert!(
        out.join("emptydir").is_dir(),
        "empty directory not extracted"
    );
}
