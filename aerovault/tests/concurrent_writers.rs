// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Two handles write the same vault at once, through the public API only.
//! Every add that reports success must be in the vault afterwards.
//!
//! SPDX-License-Identifier: MPL-2.0

use std::path::Path;
use std::sync::{Arc, Barrier};

use aerovault::v3::{CreateOptionsV3, VaultV3};

const TRIALS: usize = 40;
const WRITERS: usize = 2;
const ADDS: usize = 5;

/// One trial: returns (adds reported Ok, adds refused, Ok adds missing).
fn trial(dir: &Path, t: usize) -> (usize, usize, usize) {
    let vault = dir.join(format!("t{t}.aerozip"));
    VaultV3::create(&CreateOptionsV3::new_plaintext(&vault)).unwrap();
    let src = dir.join(format!("src{t}.bin"));
    std::fs::write(&src, vec![7u8; 200_000]).unwrap();
    let start = Arc::new(Barrier::new(WRITERS));
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (vault, src, start) = (vault.clone(), src.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                let (mut ok, mut refused) = (Vec::new(), 0);
                for i in 0..ADDS {
                    let name = format!("w{w}-{i}.bin");
                    let res = VaultV3::open_plaintext(&vault).and_then(|mut v| {
                        VaultV3::add_files(&mut v, &[(src.clone(), name.clone())])
                    });
                    match res {
                        Ok(()) => ok.push(name),
                        // A refusal is a correct outcome; a lost update is not.
                        Err(e) if e.contains("changed") || e.contains("locked") => refused += 1,
                        Err(e) => panic!("unexpected error: {e}"),
                    }
                }
                (ok, refused)
            })
        })
        .collect();
    let (mut ok, mut refused) = (Vec::new(), 0);
    for w in writers {
        let (o, r) = w.join().unwrap();
        ok.extend(o);
        refused += r;
    }
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
    let dir = std::env::temp_dir().join(format!(
        "aerovault-concurrent-writers-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (mut ok, mut refused, mut lost) = (0, 0, 0);
    for t in 0..TRIALS {
        let (o, r, l) = trial(&dir, t);
        ok += o;
        refused += r;
        lost += l;
    }
    std::fs::remove_dir_all(&dir).ok();
    eprintln!(
        "{TRIALS} trials x {WRITERS} writers x {ADDS} adds: ok={ok} refused={refused} lost={lost}"
    );
    assert_eq!(ok + refused, TRIALS * WRITERS * ADDS);
    assert!(ok > 0, "every add was refused: the test proved nothing");
    assert_eq!(lost, 0, "an add reported success but is not in the vault");
}
