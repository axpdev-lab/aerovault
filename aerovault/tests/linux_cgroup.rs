// SPDX-License-Identifier: MPL-2.0
#![cfg(target_os = "linux")]

use aerovault::v3::{CreateOptionsV3, VaultV3, VaultV3Limits};
use rand::{RngCore, SeedableRng};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

const VAULT: &str = "AEROVAULT_CGROUP_TEST_VAULT";
const MODE: &str = "AEROVAULT_CGROUP_TEST_MODE";
const MIB: u64 = 1024 * 1024;

fn memory_cgroup() -> PathBuf {
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap();
    let scope = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .unwrap();
    Path::new("/sys/fs/cgroup").join(scope)
}

fn open_in_scope(path: &Path, mode: &str) {
    let scope = memory_cgroup();
    let max = fs::read_to_string(scope.join("memory.max")).unwrap();
    let cap = max
        .trim()
        .parse::<u64>()
        .expect("test requires a finite memory limit");
    let len = path.metadata().unwrap().len();
    match mode {
        "ancestor" => {
            assert_eq!(cap, 48 * MIB);
            assert!(len > cap);
            let leaf = scope.join("leaf");
            fs::create_dir(&leaf).unwrap();
            fs::write(leaf.join("cgroup.procs"), std::process::id().to_string()).unwrap();
            fs::write(scope.join("cgroup.subtree_control"), "+memory").unwrap();
            assert_eq!(memory_cgroup(), leaf);
            assert_eq!(
                fs::read_to_string(leaf.join("memory.max")).unwrap().trim(),
                "max"
            );
            let error =
                VaultV3::open_plaintext_with_limits(path, VaultV3Limits::default()).unwrap_err();
            assert!(error.contains("the system reports"), "{error}");
            assert!(error.contains("AEROVAULT_V3_DATA_BUDGET_BYTES"), "{error}");
            println!("Unlimited leaf, {cap}-byte parent: {error}");
        }
        "cold" | "warm" => {
            assert_eq!(cap, 96 * MIB);
            assert!(
                len < cap && len * 2 > cap,
                "fixture must require cache reclaim"
            );
            if mode == "warm" {
                io::copy(&mut File::open(path).unwrap(), &mut io::sink()).unwrap();
            }
            let vault =
                VaultV3::open_plaintext_with_limits(path, VaultV3Limits::default()).unwrap();
            assert_eq!(VaultV3::list(&vault).len(), 1);
            println!("{mode} open: {len}-byte archive in a {cap}-byte cgroup");
        }
        _ => panic!("unexpected cgroup test mode"),
    }
}

#[test]
#[ignore = "requires a delegated systemd user session with cgroup v2 memory control"]
fn cold_and_warm_opens_reclaim_cache_and_obey_ancestor_limit() {
    if let Some(path) = std::env::var_os(VAULT) {
        open_in_scope(Path::new(&path), &std::env::var(MODE).unwrap());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("fixture.aerozip");
    let input = temp.path().join("input");
    let mut file = File::create(&input).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(600);
    let mut bytes = vec![0; MIB as usize];
    for _ in 0..64 {
        rng.fill_bytes(&mut bytes);
        file.write_all(&bytes).unwrap();
    }
    drop(file);
    VaultV3::create(&CreateOptionsV3::new_plaintext(&archive)).unwrap();
    let mut vault =
        VaultV3::open_plaintext_with_limits(&archive, VaultV3Limits::default()).unwrap();
    VaultV3::add_files(&mut vault, &[(input, "payload".into())]).unwrap();
    drop(vault);
    let file = File::open(&archive).unwrap();
    file.sync_all().unwrap();

    for (mode, cap) in [("cold", "96M"), ("warm", "96M"), ("ancestor", "48M")] {
        // SAFETY: the descriptor is live. Only the synthetic archive cache
        // is dropped, and the file stays available to the child.
        assert_eq!(
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) },
            0
        );
        let result = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--quiet",
                "-p",
                "Delegate=yes",
                "-p",
                "MemorySwapMax=0",
                "-p",
            ])
            .arg(format!("MemoryMax={cap}"))
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "cold_and_warm_opens_reclaim_cache_and_obey_ancestor_limit",
                "--nocapture",
            ])
            .env(VAULT, &archive)
            .env(MODE, mode)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(result.status.success(), "{mode}\n{stdout}{stderr}");
        print!("{stdout}");
    }
}
