// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// SPDX-License-Identifier: MPL-2.0

//! An opt-in release-profile suite using vaults written by the published 0.6.8.
//! Run sequentially on a 64-bit host with room for a few vault-sized copies:
//! cargo test --release --manifest-path tests/large-vault-compat/Cargo.toml -- --ignored --test-threads=1

#![cfg(target_pointer_width = "64")]

use aerovault::v3::{block, constants, manifest, OpenVaultV3, VaultHeaderV3, VaultV3};
use aerovault_068::v3::{CreateOptionsV3 as LegacyOptions, VaultV3 as LegacyVault};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const PASSWORD: &str = "large-fixture-original-password";
const NEW_PASSWORD: &str = "large-fixture-rotated-password";

fn random_file(path: &Path, size_mib: u64, seed: u64) -> [u8; 32] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut file = File::create(path).unwrap();
    let mut digest = Sha256::new();
    let mut buf = vec![0; MIB as usize];
    for _ in 0..size_mib {
        rng.fill_bytes(&mut buf);
        file.write_all(&buf).unwrap();
        digest.update(&buf);
    }
    digest.finalize().into()
}

fn file_hash(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut buf = vec![0; MIB as usize];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            return digest.finalize().into();
        }
        digest.update(&buf[..n]);
    }
}

fn open(path: &Path, plaintext: bool) -> OpenVaultV3 {
    if plaintext {
        VaultV3::open_plaintext(path).unwrap()
    } else {
        VaultV3::open(path, PASSWORD).unwrap()
    }
}

fn verify_files(vault: &OpenVaultV3, destination: &Path, expected: &[(&str, [u8; 32])]) {
    std::fs::create_dir(destination).unwrap();
    for (name, hash) in expected {
        let output = VaultV3::extract_entry(vault, name, destination).unwrap();
        assert_eq!(file_hash(&output), *hash, "{name}");
    }
}

fn check_legacy(plain: bool, near_four: bool) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = root.join(if plain {
        "old.aerozip"
    } else {
        "old.aerovault"
    });
    let original = root.join("base.bin");
    let extra = root.join("extra.bin");
    let input_mib = if near_four { 4094 } else { 1024 };
    let extra_mib = if near_four { 4 } else { 1 };
    let hashes = [
        ("base.bin", random_file(&original, input_mib, 12)),
        ("extra.bin", random_file(&extra, extra_mib, 29)),
    ];

    let seed_started = Instant::now();
    let options = if plain {
        LegacyOptions::new_plaintext(&path)
    } else {
        LegacyOptions::new(&path, PASSWORD)
    };
    LegacyVault::create(&options).unwrap();
    let mut legacy = if plain {
        LegacyVault::open_plaintext(&path).unwrap()
    } else {
        LegacyVault::open(&path, PASSWORD).unwrap()
    };
    LegacyVault::add_files(&mut legacy, &[(original, hashes[0].0.into())]).unwrap();
    drop(legacy);
    let before = std::fs::metadata(&path).unwrap().len();
    if near_four {
        assert!(
            before < 4 * GIB,
            "legacy seed must be below 4 GiB: {before}"
        );
    }
    eprintln!(
        "0.6.8 seed {input_mib} MiB ({before} container bytes): {:.3?}",
        seed_started.elapsed()
    );

    let started = Instant::now();
    let mut vault = open(&path, plain);
    eprintln!("open plaintext={plain}: {:.3?}", started.elapsed());
    verify_files(&vault, &root.join("before"), &hashes[..1]);
    let started = Instant::now();
    VaultV3::add_files(&mut vault, &[(extra, hashes[1].0.into())]).unwrap();
    eprintln!(
        "add {extra_mib} MiB plaintext={plain}: {:.3?}",
        started.elapsed()
    );
    drop(vault);

    if near_four {
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(after > 4 * GIB, "replacement must cross 4 GiB: {after}");
        eprintln!("replacement container bytes: {after}");
    }
    let vault = open(&path, plain);
    verify_files(&vault, &root.join("after"), &hashes);
    drop(vault);

    if !near_four || !plain {
        let started = Instant::now();
        VaultV3::export_parity(&path, if plain { "" } else { PASSWORD }, None).unwrap();
        eprintln!("export parity plaintext={plain}: {:.3?}", started.elapsed());
        if !near_four && !plain {
            let mut vault = open(&path, false);
            let started = Instant::now();
            VaultV3::change_password(&mut vault, NEW_PASSWORD).unwrap();
            drop(vault);
            assert!(VaultV3::open(&path, PASSWORD).is_err());
            let reopened = VaultV3::open(&path, NEW_PASSWORD).unwrap();
            verify_files(&reopened, &root.join("rotated"), &hashes);
            eprintln!("rotate, reopen and verify: {:.3?}", started.elapsed());
        }
    }
}

#[test]
#[ignore = "requires several GiB of RAM and temporary disk space"]
fn encrypted_legacy_over_one_gib() {
    check_legacy(false, false);
}

#[test]
#[ignore = "requires several GiB of RAM and temporary disk space"]
fn plaintext_legacy_over_one_gib() {
    check_legacy(true, false);
}

#[test]
#[ignore = "requires a 64-bit host with room for a 4 GiB vault and source copies"]
fn encrypted_legacy_add_crosses_four_gib() {
    check_legacy(false, true);
}

#[test]
#[ignore = "requires a 64-bit host with room for a 4 GiB vault and source copies"]
fn plaintext_legacy_add_crosses_four_gib() {
    check_legacy(true, true);
}

#[test]
#[ignore = "requires a 64-bit host with room for a 4 GiB vault and source copies"]
fn plaintext_legacy_reads_live_block_beyond_four_gib() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = root.join("legacy.aerozip");
    let input = root.join("base.bin");
    let expected = random_file(&input, 4098, 74);

    LegacyVault::create(&LegacyOptions::new_plaintext(&path)).unwrap();
    let mut legacy = LegacyVault::open_plaintext(&path).unwrap();
    LegacyVault::add_files(&mut legacy, &[(input, "base.bin".into())]).unwrap();
    drop(legacy);

    // Verify the offset in the original 0.6.8 bytes, before opening with 0.7.0.
    let mut stored = File::open(&path).unwrap();
    let mut raw_header = [0; constants::HEADER_SIZE];
    stored.read_exact(&mut raw_header).unwrap();
    let header = VaultHeaderV3::from_bytes(&raw_header).unwrap();
    let index = block::read_section(
        &mut stored,
        header.manifest_offset,
        header.manifest_len,
        constants::MAX_MANIFEST_SIZE,
        "legacy manifest",
    )
    .unwrap();
    let index = manifest::parse_manifest_plaintext(&index).unwrap();
    let entry = index.entries.iter().find(|e| e.path == "base.bin").unwrap();
    let last_start = entry
        .chunks
        .iter()
        .map(|id| header.data_offset + index.chunks[id].data_offset)
        .max()
        .unwrap();
    assert!(
        last_start > 4 * GIB,
        "last live block starts at {last_start}"
    );
    eprintln!("0.6.8 last live block starts at byte {last_start}");
    drop(stored);

    let vault = VaultV3::open_plaintext(&path).unwrap();
    verify_files(&vault, &root.join("extracted"), &[("base.bin", expected)]);
}
