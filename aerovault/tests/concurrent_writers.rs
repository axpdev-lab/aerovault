// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Two handles write the same vault at once, through the public API only.
//! Every add that reports success must be in the vault afterwards.
//!
//! SPDX-License-Identifier: MPL-2.0

use std::path::Path;
use std::sync::mpsc;

use aerovault::v3::{CreateOptionsV3, VaultV3};

const TRIALS: usize = 40;
const WRITERS: usize = 2;
const ADDS: usize = 5;

fn documented_refusal(error: &str) -> bool {
    error == "Vault changed while this write was in progress; retry operation"
        || error.starts_with("vault is locked by another writer (")
            && error.ends_with("); retry when it has finished")
}

#[test]
fn same_generation_handles_preserve_each_successful_add() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directed.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
    let mut a = VaultV3::open_plaintext(&path).unwrap();
    let mut b = VaultV3::open_plaintext(&path).unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"directed data").unwrap();
    let first = VaultV3::add_files(&mut a, &[(source.clone(), "first".to_string())]);
    let second = VaultV3::add_files(&mut b, &[(source, "second".to_string())]);
    assert!(first.is_ok());
    let current = VaultV3::open_plaintext(&path).unwrap();
    let entries = VaultV3::summary(&current).entries;
    assert!(entries.iter().any(|e| e.path == "first"));
    match second {
        Ok(()) => assert!(entries.iter().any(|e| e.path == "second")),
        Err(error) => {
            assert!(documented_refusal(&error), "{error}");
            assert!(!entries.iter().any(|e| e.path == "second"));
        }
    }
}

#[test]
fn only_documented_refusals_are_expected() {
    assert!(documented_refusal(
        "vault is locked by another writer (x.aerolock); retry when it has finished"
    ));
    assert!(documented_refusal(
        "Vault changed while this write was in progress; retry operation"
    ));
    for error in [
        "writer lock setup blocked",
        "unlocked input",
        "changed password",
        "file changed unexpectedly",
    ] {
        assert!(!documented_refusal(error), "accepted: {error}");
    }
}

/// One trial: returns (adds reported Ok, adds refused, Ok adds missing).
fn trial(dir: &Path, t: usize) -> (usize, usize, usize) {
    let vault = dir.join(format!("t{t}.aerozip"));
    VaultV3::create(&CreateOptionsV3::new_plaintext(&vault)).unwrap();
    let src = dir.join(format!("src{t}.bin"));
    std::fs::write(&src, vec![7u8; 200_000]).unwrap();
    let (ok, refused) = std::thread::scope(|scope| {
        // If a later spawn panics, dropping these senders cancels every worker
        // already started before thread::scope waits for it.
        let mut gates = Vec::new();
        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let (vault, src) = (vault.clone(), src.clone());
                let (start, ready) = mpsc::channel();
                gates.push(start);
                scope.spawn(move || {
                    if ready.recv().is_err() {
                        return (Vec::new(), 0);
                    }
                    let (mut ok, mut refused) = (Vec::new(), 0);
                    for i in 0..ADDS {
                        let name = format!("w{w}-{i}.bin");
                        let res = VaultV3::open_plaintext(&vault).and_then(|mut v| {
                            VaultV3::add_files(&mut v, &[(src.clone(), name.clone())])
                        });
                        match res {
                            Ok(()) => ok.push(name),
                            // A refusal is a correct outcome; a lost update is not.
                            Err(e) if documented_refusal(&e) => refused += 1,
                            Err(e) => panic!("unexpected error: {e}"),
                        }
                    }
                    (ok, refused)
                })
            })
            .collect();
        for start in gates {
            start.send(()).unwrap();
        }
        let (mut ok, mut refused) = (Vec::new(), 0);
        for w in writers {
            let (o, r) = w.join().unwrap();
            ok.extend(o);
            refused += r;
        }
        (ok, refused)
    });
    let v = VaultV3::open_plaintext(&vault).unwrap();
    let present: Vec<String> = VaultV3::summary(&v)
        .entries
        .iter()
        .map(|e| e.path.clone())
        .collect();
    let lost = ok.iter().filter(|n| !present.contains(n)).count();
    (ok.len(), refused, lost)
}

#[test]
fn concurrent_writers_lose_no_update() {
    let dir = tempfile::tempdir().unwrap();
    let (mut ok, mut refused, mut lost) = (0, 0, 0);
    for t in 0..TRIALS {
        let (o, r, l) = trial(dir.path(), t);
        ok += o;
        refused += r;
        lost += l;
    }
    eprintln!(
        "{TRIALS} trials x {WRITERS} writers x {ADDS} adds: ok={ok} refused={refused} lost={lost}"
    );
    assert_eq!(ok + refused, TRIALS * WRITERS * ADDS);
    assert!(ok > 0, "every add was refused: the test proved nothing");
    assert_eq!(lost, 0, "an add reported success but is not in the vault");
}
