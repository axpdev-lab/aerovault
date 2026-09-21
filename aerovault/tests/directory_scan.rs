// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use aerovault::v3::{CreateOptionsV3, VaultV3};

#[cfg(unix)]
#[test]
fn unreadable_directory_fails_without_persisting_partial_archive() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    let denied = source.join("denied");
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::write(source.join("visible.txt"), b"visible").unwrap();
    std::fs::write(denied.join("hidden.txt"), b"must be archived").unwrap();
    let path = tmp.path().join("test.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
    let mut vault = VaultV3::open_plaintext(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root and hosts with DAC override do not reproduce this permission case.
    if std::fs::read_dir(&denied).is_ok() {
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipped: host can traverse a mode-000 directory");
        return;
    }
    let result = VaultV3::add_directory(&mut vault, &source, None);
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "a scan failure must not report success");
    assert!(VaultV3::list(&vault).is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn depth_overflow_fails_without_persisting_partial_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let mut nested = source.clone();
    for _ in 0..101 {
        nested.push("d");
        std::fs::create_dir(&nested).unwrap();
    }
    let path = tmp.path().join("test.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
    let mut vault = VaultV3::open_plaintext(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let error = VaultV3::add_directory(&mut vault, &source, None).unwrap_err();
    assert!(error.contains("maximum depth"));
    assert!(VaultV3::list(&vault).is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
