// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A vault created at a path while `correct repair` or `correct gen` is
//! reading that path must survive: the tool either refuses its write or
//! writes for the file it read, never over the new vault. Public API only.
//!
//! SPDX-License-Identifier: MPL-2.0

use std::path::Path;

use aerovault::v3::{CreateOptionsV3, VaultV3};
use aerovault::{
    aerocorrect_sidecar_path_for, correct_generate, correct_generate_with_progress,
    correct_repair_anchored_with_progress,
};

fn damage(path: &Path, range: std::ops::Range<usize>) {
    let mut bytes = std::fs::read(path).unwrap();
    for b in &mut bytes[range] {
        *b ^= 0xFF;
    }
    std::fs::write(path, bytes).unwrap();
}

/// Run `tool` with a progress callback that creates a vault at `file` the
/// first time it fires, then check that the created vault is what is left.
fn create_during(
    file: &Path,
    tool: impl FnOnce(&str, &mut dyn FnMut(u64, u64)) -> Result<(), String>,
) {
    let mut created = None;
    let mut progress = |_: u64, _: u64| {
        if created.is_none() {
            created = Some(VaultV3::create(&CreateOptionsV3::new_plaintext(file)));
        }
    };
    let result = tool(file.to_str().unwrap(), &mut progress);
    created
        .expect("the progress callback ran")
        .expect("creating the vault");
    let err = result.expect_err("the tool wrote although the file changed after it read it");
    assert!(err.contains("changed while it was being read"), "{err}");
    let vault = VaultV3::open_plaintext(file).expect("the created vault is still there");
    assert!(VaultV3::summary(&vault).entries.is_empty());
}

fn repair(file: &str, progress: &mut dyn FnMut(u64, u64)) -> Result<(), String> {
    correct_repair_anchored_with_progress(file, None, None, progress).map(drop)
}

#[test]
fn repair_of_a_plain_file_does_not_replace_a_vault_created_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("target.bin");
    std::fs::write(
        &file,
        (0..50_000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
    correct_generate(file.to_str().unwrap(), 25, None).unwrap();
    damage(&file, 100..1_000);
    create_during(&file, repair);
}

#[test]
fn repair_of_a_vault_with_damaged_magic_does_not_replace_a_vault_created_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("old.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&file)).unwrap();
    correct_generate(file.to_str().unwrap(), 25, None).unwrap();
    damage(&file, 0..10);
    create_during(&file, repair);
}

#[test]
fn gen_does_not_write_a_sidecar_for_a_vault_created_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("target.bin");
    std::fs::write(&file, vec![9u8; 50_000]).unwrap();
    create_during(&file, |f, progress| {
        correct_generate_with_progress(f, 25, None, progress).map(drop)
    });
    assert!(!Path::new(&aerocorrect_sidecar_path_for(file.to_str().unwrap())).exists());
}
