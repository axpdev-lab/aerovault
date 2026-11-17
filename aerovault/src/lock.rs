// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-process write lock for a vault.
//!
//! Every write replaces the vault (or its `.aerocorrect` sidecar) by rename,
//! so a lock on the vault file itself would be lost with the file it locks.
//! Writers instead take an exclusive OS lock (`flock` / `LockFileEx`) on a
//! separate, stable `<vault>.lock` next to the vault, and hold it from the
//! moment they read the state they will write (for a v3 handle opened
//! earlier, from the check that the file is still the one it read) until the
//! rename is done. Readers never take it. Tools that rewrite any file or
//! write its `.aerocorrect` (`correct repair`, `correct gen`) read it without
//! the lock, then take the lock of that file, vault or not, for their write,
//! and write only if it still holds the bytes they read
//! (`error_correction::sync::write_if_unchanged`), so a vault created or saved
//! at that path meanwhile is not lost.
//!
//! The OS drops the lock when the holder exits or crashes, so there is no
//! stale-lock cleanup. The `<vault>.lock` file itself is left in place on
//! purpose: deleting it would let two writers lock two different files.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a writer waits for another writer before giving up.
const WAIT: Duration = Duration::from_secs(30);

const POLL: Duration = Duration::from_millis(10);

/// The wait a test sets with [`set_short_wait_for_this_thread`].
#[cfg(test)]
pub(crate) const TEST_SHORT_WAIT: Duration = Duration::from_millis(300);

#[cfg(test)]
thread_local! {
    static TEST_WAIT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Test seam: a test that expects a refusal makes this thread give up after
/// [`TEST_SHORT_WAIT`] instead of the full wait. Every other test keeps the
/// full wait, so slow work inside another holder's lock cannot time it out.
#[cfg(test)]
pub(crate) fn set_short_wait_for_this_thread() {
    TEST_WAIT.with(|w| w.set(Some(TEST_SHORT_WAIT)));
}

fn wait() -> Duration {
    #[cfg(test)]
    if let Some(wait) = TEST_WAIT.with(|w| w.get()) {
        return wait;
    }
    WAIT
}

/// Held while a write is in progress; dropping it releases the lock.
#[derive(Debug)]
pub(crate) struct WriteLock {
    /// `None` when there is nothing to lock (see [`acquire`]).
    _file: Option<File>,
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
///
/// When `<vault>.lock` does not exist and this process may not create files
/// in the vault's folder (read-only folder or media), it returns a lock that
/// holds nothing: such a process cannot rename anything over the vault
/// either, so only a read of it (an export to another folder) can follow, and
/// a write fails later with its own cause.
///
/// A `vault` path that is itself a symbolic link is refused: a writer going
/// through the link and one using its target would lock two different files,
/// and the rename would replace the link with a regular file, leaving two
/// diverging copies.
pub(crate) fn acquire(vault: &Path) -> io::Result<WriteLock> {
    if std::fs::symlink_metadata(vault).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::other(format!(
            "{} is a symbolic link: writing through it would replace the link and \
             lock a different file than a writer using its target; use the target path",
            vault.display()
        )));
    }
    let path = lock_path(vault);
    let Some(file) = open_lock_file(&path)? else {
        return Ok(WriteLock { _file: None });
    };
    let deadline = Instant::now() + wait();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(WriteLock { _file: Some(file) }),
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

/// Open (or create) the lock file without following a symbolic link (or, on
/// Windows, a reparse point) at its path, and refuse anything that is not a
/// regular file (a link, a directory, a FIFO, a device). The check is on the
/// opened handle, so nothing can be swapped in between the check and the open.
///
/// A lock file this process may not write (created by another user) is
/// opened read-only: an exclusive lock needs no write access. `None`: there
/// is no lock file and it cannot be created here.
fn open_lock_file(path: &Path) -> io::Result<Option<File>> {
    let file = match open_no_follow(path, true) {
        Ok(file) => file,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match open_no_follow(path, false) {
                Ok(file) => file,
                Err(missing) if missing.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(open_error(path, e)),
            }
        }
        Err(e) => return Err(open_error(path, e)),
    };
    let meta = file.metadata().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("inspect vault lock file {}: {e}", path.display()),
        )
    })?;
    // On Windows `is_file` is false for a symbolic link or junction (a
    // name-surrogate reparse point) and true for other reparse points such as
    // cloud-sync placeholders, which are ordinary files to lock.
    if !meta.is_file() {
        return Err(io::Error::other(format!(
            "vault lock file {}: is not a regular file; remove it",
            path.display()
        )));
    }
    Ok(Some(file))
}

/// Open `path` read-write (creating it) or read-only, never through a link.
fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(write)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: opening a FIFO planted at the path must not wait for a
        // peer (POSIX leaves O_RDWR on a FIFO undefined; Linux does not wait).
        // It has no effect on a regular file or on the lock itself.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// The open error, named; a symbolic link at the path (which the open
/// refused to follow) is said as such.
fn open_error(path: &Path, e: io::Error) -> io::Error {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        io::Error::other(format!(
            "vault lock file {}: is a symbolic link; remove it",
            path.display()
        ))
    } else {
        io::Error::new(
            e.kind(),
            format!("open vault lock file {}: {e}", path.display()),
        )
    }
}

/// Test cleanup: remove a vault and its lock file, and check both are gone.
#[cfg(test)]
pub(crate) fn remove_vault_and_lock(vault: &Path) {
    let _ = std::fs::remove_file(vault);
    let _ = std::fs::remove_file(lock_path(vault));
    assert!(!vault.exists(), "vault left behind: {}", vault.display());
    assert!(
        !lock_path(vault).exists(),
        "lock file left behind: {}",
        lock_path(vault).display()
    );
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
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let held = acquire(&vault).unwrap();
        let started = Instant::now();
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        assert!(
            started.elapsed() >= TEST_SHORT_WAIT,
            "gave up before the wait"
        );
        assert!(started.elapsed() < TEST_SHORT_WAIT * 20, "hung");
        drop(held);
        acquire(&vault).unwrap();
        assert!(lock_path(&vault).exists(), "the lock file stays");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_only_folder_without_a_lock_file_has_nothing_to_lock() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            // Running as root: the folder is writable anyway.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let res = acquire(&vault);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(res.unwrap()._file.is_none());
        assert!(!lock_path(&vault).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_this_user_cannot_write_is_still_locked() {
        // A lock file another user created (0644) must not lock this user out.
        use std::os::unix::fs::PermissionsExt;
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        drop(acquire(&vault).unwrap());
        let lock = lock_path(&vault);
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        if OpenOptions::new().write(true).open(&lock).is_ok() {
            // Running as root: the file is writable anyway.
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let held = acquire(&vault).unwrap();
        assert!(held._file.is_some());
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        drop(held);
        acquire(&vault).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_is_refused() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        // Dangling: following it would create the target.
        let target = dir.join("elsewhere");
        std::os::unix::fs::symlink(&target, lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!target.exists(), "the link was followed");
        // Pointing at an existing file: following it would lock that file.
        std::fs::remove_file(lock_path(&vault)).unwrap();
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vault_path_is_refused() {
        let dir = scratch();
        let target = dir.join("real.aerovault");
        std::fs::write(&target, b"vault").unwrap();
        let link = dir.join("link.aerovault");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = acquire(&link).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!lock_path(&link).exists());
        acquire(&target).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_at_the_lock_path_names_the_cause() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::create_dir(lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("vault lock file"), "{err}");
        assert!(!err.to_string().contains("another writer"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_at_the_lock_path_is_refused_without_hanging() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let fifo = CString::new(lock_path(&vault).as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let v = vault.clone();
        std::thread::spawn(move || tx.send(acquire(&v).map(drop)).ok());
        let res = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO at the lock path hung");
        let err = res.unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
