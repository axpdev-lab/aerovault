// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-process write lock for a vault.
//!
//! Every write replaces the vault (or its `.aerocorrect` sidecar) by rename,
//! so a lock on the vault file itself would be lost with the file it locks.
//! Writers instead take an exclusive OS lock (`flock` / `LockFileEx`) on a
//! separate, stable `<vault>.aerolock` next to the vault, and hold it from the
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
//! stale-lock cleanup. The `<vault>.aerolock` file itself is left in place on
//! purpose: deleting or replacing it would let two writers lock two different
//! files. So no write of this crate replaces a file whose name ends with
//! `.aerolock` ([`refuse_lock_file_name`], at every commit point), and on
//! Windows the lock file is opened without delete sharing, so no other program
//! can replace or delete it while a writer holds or waits for it.

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

#[cfg(test)]
thread_local! {
    static TRACE: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Test seam: record that `event` happened on this thread ("lock", "derive",
/// "temp", "generation", "decode"), so a test can check the order of steps.
#[cfg(test)]
pub(crate) fn trace(event: &'static str) {
    TRACE.with(|t| t.borrow_mut().push(event));
}

/// Test seam: the events recorded on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_trace() -> Vec<&'static str> {
    TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
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

/// The suffix of every lock file, reserved: no write replaces such a file.
const LOCK_SUFFIX: &str = ".aerolock";

/// `<vault>.aerolock`: the vault's file name with the lock suffix appended.
pub(crate) fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault.file_name().unwrap_or_default().to_os_string();
    name.push(LOCK_SUFFIX);
    vault.with_file_name(name)
}

/// Refuse a write that would replace `dest` when its name is the name of a
/// lock file: replacing the lock file of a vault while a writer holds it would
/// let a second writer lock the new file and save at the same time. On Windows
/// an existing `dest` is also checked under its real name, so a short (8.3)
/// name of a lock file is refused too.
pub(crate) fn refuse_lock_file_name(dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    let real_name = std::fs::canonicalize(dest)
        .ok()
        .and_then(|real| real.file_name().map(|n| n.to_os_string()));
    #[cfg(not(windows))]
    let real_name: Option<std::ffi::OsString> = None;
    let names_lock_file = [dest.file_name(), real_name.as_deref()]
        .into_iter()
        .flatten()
        .any(|name| is_lock_file_name(&name.to_string_lossy()));
    if names_lock_file {
        return Err(io::Error::other(format!(
            "{}: names a vault lock file (*{LOCK_SUFFIX}); it is never written over",
            dest.display()
        )));
    }
    Ok(())
}

/// Refuse to create the directory `dir` when its name is a lock file name: a
/// directory at a vault's lock path blocks every write of that vault. Used by
/// extraction, whose directory names come from the vault.
pub(crate) fn refuse_lock_named_dir(dir: &Path) -> io::Result<()> {
    if is_lock_file_name(&dir.file_name().unwrap_or_default().to_string_lossy()) {
        return Err(io::Error::other(format!(
            "{}: a directory cannot take a vault lock file name (*{LOCK_SUFFIX})",
            dir.display()
        )));
    }
    Ok(())
}

/// True if `name` ends with the lock suffix as a file system that ignores
/// case (Windows, macOS), trailing dots and spaces (Windows) or the
/// characters HFS+ ignores in names would see it, so no other spelling of a
/// lock file name gets through. Lowercasing with Unicode rules also maps the
/// Kelvin sign (U+212A), which macOS treats as `K`, to `k`.
fn is_lock_file_name(name: &str) -> bool {
    let visible: String = name.chars().filter(|&c| !ignored_in_names(c)).collect();
    visible
        .trim_end_matches(['.', ' '])
        .to_lowercase()
        .ends_with(LOCK_SUFFIX)
}

/// The characters HFS+ ignores in file names (and U+200B, zero width space).
fn ignored_in_names(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}')
}

/// The path whose name the lock file takes. On Unix, the vault path itself. On
/// Windows one file answers to several names: trailing dots and spaces are
/// dropped and a short (8.3) name stands for the long one (case needs nothing:
/// the lock file names differ only in case, so they are one file). So an
/// existing vault takes its lock name from its real name, and a path that does
/// not exist yet and ends in a dot or a space is refused: the file it would
/// create has another name. When the real name cannot be read (some network
/// or RAM-disk drivers do not report it), the given name is used without its
/// trailing dots and spaces (a short name then still locks its own file).
#[cfg(windows)]
fn lock_name_source(vault: &Path) -> io::Result<PathBuf> {
    match std::fs::canonicalize(vault) {
        Ok(real) => Ok(match real.file_name() {
            Some(name) => vault.with_file_name(name),
            None => vault.to_path_buf(),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let name = vault.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(['.', ' ']) {
                return Err(io::Error::other(format!(
                    "{}: a file name cannot end with a dot or a space on Windows",
                    vault.display()
                )));
            }
            Ok(vault.to_path_buf())
        }
        Err(_) => {
            let name = vault.file_name().unwrap_or_default().to_string_lossy();
            let trimmed = name.trim_end_matches(['.', ' ']);
            Ok(if trimmed.is_empty() {
                vault.to_path_buf()
            } else {
                vault.with_file_name(trimmed)
            })
        }
    }
}

#[cfg(not(windows))]
fn lock_name_source(vault: &Path) -> io::Result<PathBuf> {
    Ok(vault.to_path_buf())
}

/// Take the write lock of `vault`, waiting up to 30 seconds for another
/// writer. Errors say why: the lock file could not be created or opened,
/// the lock could not be taken, or another writer kept it too long.
///
/// When `<vault>.aerolock` does not exist and this process may not create files
/// in the vault's folder (read-only folder or media), it returns a lock that
/// holds nothing: such a process cannot rename anything over the vault
/// either, so only a read of it (an export to another folder) can follow, and
/// a write fails later with its own cause.
///
/// A `vault` path that is itself a symbolic link is refused: a writer going
/// through the link and one using its target would lock two different files,
/// and the rename would replace the link with a regular file, leaving two
/// diverging copies. So is a `vault` path that names a lock file
/// ([`refuse_lock_file_name`]) and, on Windows, a new path ending in a dot or
/// a space ([`lock_name_source`]). On Windows a lock file that another
/// program holds open with delete access is waited for like a held lock.
pub(crate) fn acquire(vault: &Path) -> io::Result<WriteLock> {
    refuse_lock_file_name(vault)?;
    if std::fs::symlink_metadata(vault).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::other(format!(
            "{} is a symbolic link: writing through it would replace the link and \
             lock a different file than a writer using its target; use the target path",
            vault.display()
        )));
    }
    let path = lock_path(&lock_name_source(vault)?);
    let deadline = Instant::now() + wait();
    let file = loop {
        match open_lock_file(&path) {
            Ok(Some(file)) => break file,
            Ok(None) => return Ok(WriteLock { _file: None }),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(POLL)
            }
            Err(e) => return Err(e),
        }
    };
    loop {
        match file.try_lock() {
            Ok(()) => {
                #[cfg(test)]
                trace("lock");
                return Ok(WriteLock { _file: Some(file) });
            }
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

/// Take the write lock of `out`, a destination the caller named for a file
/// built from `held` (already locked by the caller): `export-parity --out`,
/// `correct gen --out`. A vault at `out` is then replaced only while none of
/// its writers holds its lock. `None` when `out` is a symbolic link: the rename
/// replaces the link itself, never the file it names, so there is nothing of
/// a writer's to protect. Refused when `out` is `held` itself: the output would
/// replace the file it was built from (and this process would wait for its own
/// lock).
pub(crate) fn acquire_destination(out: &Path, held: &Path) -> io::Result<Option<WriteLock>> {
    if std::fs::symlink_metadata(out).is_ok_and(|m| m.file_type().is_symlink()) {
        return Ok(None);
    }
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(out), std::fs::canonicalize(held)) {
        if a == b {
            return Err(io::Error::other(format!(
                "{}: the output is the file it is built from; choose another output path",
                out.display()
            )));
        }
    }
    acquire(out).map(Some)
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
        Err(e) if is_sharing_violation(&e) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "vault lock file {} is in use by another program; retry when it has closed it",
                    path.display()
                ),
            ))
        }
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

/// True for the Windows error of an open refused by another handle's sharing
/// mode (ERROR_SHARING_VIOLATION): this process opens the lock file without
/// delete sharing, so a program holding it open with delete access (a sync or
/// backup tool) refuses the open until it closes it.
fn is_sharing_violation(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(32)
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
        // No FILE_SHARE_DELETE: while any writer has the lock file open
        // (holding or waiting), nothing can rename over it or delete it.
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
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
    fn lock_file_names_are_never_written_over() {
        for name in [
            "v.aerovault.aerolock",
            "V.AEROVAULT.AeroLock",
            "v.aerolock.",
            "v.aerolock . ",
            ".aerolock",
            // Kelvin sign for the final k (one file with `.aerolock` on macOS).
            "v.aeroloc\u{212A}",
            // Characters HFS+ ignores in names.
            "v.aero\u{200C}lock",
            "v.aerolock\u{FEFF}",
            "v.aerolock\u{200B}.",
        ] {
            let err = refuse_lock_file_name(Path::new(name)).unwrap_err();
            assert!(err.to_string().contains("vault lock file"), "{name}: {err}");
        }
        for name in ["Cargo.lock", "v.aerolock.bak", "v.aerovault", "aerolock"] {
            refuse_lock_file_name(Path::new(name)).unwrap();
        }
        // A write that would replace a lock file never takes a lock of its own.
        let dir = scratch();
        let lock_file = lock_path(&dir.join("v.aerovault"));
        let err = acquire(&lock_file).unwrap_err();
        assert!(err.to_string().contains("vault lock file"), "{err}");
        assert!(!lock_path(&lock_file).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn every_windows_name_of_a_vault_locks_one_lock_file() {
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::write(&vault, b"vault").unwrap();
        let held = acquire(&vault).unwrap();
        for alias in [
            "v.aerovault.",
            "v.aerovault ",
            "V.AEROVAULT",
            "v.aerovault. .",
        ] {
            let err = acquire(&dir.join(alias)).unwrap_err();
            assert!(
                err.to_string().contains("locked by another writer"),
                "{alias}: {err}"
            );
        }
        drop(held);
        // A new vault cannot be named with a trailing dot or space: the file
        // created would be `n.aerovault`, locked under another lock file name.
        let err = acquire(&dir.join("n.aerovault.")).unwrap_err();
        assert!(err.to_string().contains("dot or a space"), "{err}");
        // The real name of an existing lock file is a lock file name too.
        assert!(refuse_lock_file_name(&dir.join("v.aerovault.aerolock.")).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_lock_file_held_open_with_delete_access_is_waited_for() {
        // A sync or backup tool that holds the lock file open with delete
        // access makes the open fail with a sharing violation: the writer
        // waits as for a held lock, then says what is in the way.
        use std::os::windows::fs::OpenOptionsExt;
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        drop(acquire(&vault).unwrap());
        const DELETE: u32 = 0x0001_0000;
        const GENERIC_READ: u32 = 0x8000_0000;
        let tool = OpenOptions::new()
            .access_mode(DELETE | GENERIC_READ)
            .share_mode(0x1 | 0x2 | 0x4)
            .open(lock_path(&vault))
            .unwrap();
        let started = Instant::now();
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("in use by another program"),
            "{err}"
        );
        assert!(
            started.elapsed() >= TEST_SHORT_WAIT,
            "gave up before the wait"
        );
        drop(tool);
        acquire(&vault).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_held_lock_file_cannot_be_replaced_or_deleted() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let held = acquire(&vault).unwrap();
        let other = dir.join("other");
        std::fs::write(&other, b"x").unwrap();
        assert!(std::fs::rename(&other, lock_path(&vault)).is_err());
        assert!(std::fs::remove_file(lock_path(&vault)).is_err());
        drop(held);
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
