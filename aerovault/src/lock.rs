// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-process write lock for a vault.
//!
//! Every write replaces the vault (or its `.aerocorrect` sidecar) by rename,
//! so a lock on the vault file itself would be lost with the file it locks.
//! Writers instead take an exclusive OS lock (`flock` / `LockFileEx`) on a
//! separate, stable `<vault>.lock` next to the vault, and hold it from the
//! moment they read the state they will write until the rename is done.
//! Readers never take it.
//!
//! The OS drops the lock when the holder exits or crashes, so there is no
//! stale-lock cleanup. The `<vault>.lock` file itself is left in place on
//! purpose: deleting it would let two writers lock two different files.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a writer waits for another writer before giving up.
#[cfg(not(test))]
const WAIT: Duration = Duration::from_secs(30);
#[cfg(test)]
const WAIT: Duration = Duration::from_secs(2);

const POLL: Duration = Duration::from_millis(10);

/// Held while a write is in progress; dropping it releases the lock.
#[derive(Debug)]
pub(crate) struct WriteLock {
    _file: File,
}

/// `<vault>.lock`: the vault's file name with `.lock` appended.
pub(crate) fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    vault.with_file_name(name)
}

/// Take the write lock of `vault`, waiting up to 30 seconds for another
/// writer. Errors say why: the lock file could not be created or opened,
/// the lock could not be taken, or another writer kept it too long.
pub(crate) fn acquire(vault: &Path) -> io::Result<WriteLock> {
    let path = lock_path(vault);
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::other(format!(
            "vault lock file {} is a symbolic link; remove it",
            path.display()
        )));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("open vault lock file {}: {e}", path.display()),
            )
        })?;
    let deadline = Instant::now() + WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(WriteLock { _file: file }),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "vault is locked by another writer ({}); retry when it has finished",
                        path.display()
                    ),
                ))
            }
            Err(TryLockError::Error(e)) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("lock vault lock file {}: {e}", path.display()),
                ))
            }
        }
    }
}

/// [`acquire`] when `path` is an AeroVault container (v2 or v3 magic), so a
/// generic tool that rewrites a file or its `.aerocorrect` (`correct repair`,
/// `correct gen`) cannot interleave with a vault writer. Any other file gets
/// no lock and no `.lock` file next to it.
pub(crate) fn acquire_if_container(path: &Path) -> io::Result<Option<WriteLock>> {
    let mut magic = [0u8; 10];
    let is_container = File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && (&magic == crate::constants::MAGIC || &magic == crate::v3::constants::MAGIC);
    if is_container {
        acquire(path).map(Some)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aerovault-lock-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn second_writer_waits_then_gets_a_clear_error() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let held = acquire(&vault).unwrap();
        let started = Instant::now();
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        assert!(started.elapsed() >= WAIT, "gave up before the wait");
        assert!(started.elapsed() < WAIT * 10, "hung");
        drop(held);
        acquire(&vault).unwrap();
        assert!(lock_path(&vault).exists(), "the lock file stays");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_folder_names_the_cause() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let err = acquire(&dir.join("v.aerovault")).unwrap_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.to_string().contains("open vault lock file"), "{err}");
        assert!(!err.to_string().contains("another writer"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_is_refused() {
        let dir = scratch();
        let target = dir.join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.join("v.aerovault.lock")).unwrap();
        let err = acquire(&dir.join("v.aerovault")).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!target.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
