// SPDX-License-Identifier: MPL-2.0
//! Linux publication and restart recovery for a pair with no previous files.
//!
//! The private journal is durable before the detached sidecar is made visible.
//! The vault is linked into place last. Neither publication replaces an
//! existing name, so a crash never leaves an openable, partially created vault.

use super::state;
use crate::lock::WriteLock;
use crate::v3::ec::default_sidecar_path;
use crate::v3::strip_transaction::{
    generation, hash_generation, private_dir, private_options, sync_dir, validate_journal_ancestry,
    Generation, PrivateDir, TrustedJournal,
};
use crate::v3::vault::output_parent_dir;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const VERSION: u8 = 1;
const RECORD: &str = "fresh.json";
const MAX_RECORD: u64 = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    source_key: [u8; 32],
    parent_device: u64,
    parent_inode: u64,
    vault: Generation,
    sidecar: Generation,
}

pub(super) struct Destination {
    pub(super) path: PathBuf,
    pub(super) directory: File,
    pub(super) device: u64,
    pub(super) inode: u64,
}

impl Destination {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        // Do not follow a retargeted parent or grant new writes under a
        // foreign-owned or non-sticky, other-writable ancestry.
        let user = unsafe { libc::geteuid() };
        for component in path.ancestors() {
            let meta = fs::symlink_metadata(component)
                .map_err(|error| format!("Inspect vault ancestry: {error}"))?;
            if !meta.is_dir()
                || (meta.uid() != user && meta.uid() != 0)
                || (meta.mode() & 0o002 != 0 && meta.mode() & 0o1000 == 0)
            {
                return Err(
                    "Fresh vault destination ancestry is not suitable for publication".into(),
                );
            }
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| format!("Open vault destination: {error}"))?;
        let meta = directory.metadata().map_err(|error| error.to_string())?;
        let destination = Self {
            path: path.to_owned(),
            directory,
            device: meta.dev(),
            inode: meta.ino(),
        };
        destination.recheck()?;
        Ok(destination)
    }

    pub(super) fn recheck(&self) -> Result<(), String> {
        let meta = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("Recheck vault destination: {error}"))?;
        if !meta.is_dir() || (meta.dev(), meta.ino()) != (self.device, self.inode) {
            return Err("Vault destination directory changed during pair creation".into());
        }
        Ok(())
    }

    pub(super) fn leaf(&self, path: &Path) -> Result<CString, String> {
        if output_parent_dir(path) != self.path {
            return Err("Publication target is outside its pinned directory".into());
        }
        let name = path.file_name().ok_or("Missing publication basename")?;
        CString::new(name.as_bytes()).map_err(|error| error.to_string())
    }

    fn current(&self, path: &Path, expected: Generation) -> Result<Option<Generation>, String> {
        let leaf = self.leaf(path)?;
        // SAFETY: the directory and leaf are valid for the duration of openat.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        let file = match checked_fd(fd) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Inspect fresh pair destination: {error}")),
        };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() != expected.len {
            return Err("Fresh pair destination has an unexpected file type or generation".into());
        }
        let generation = hash_generation(file, expected.len)?;
        if generation != expected {
            return Err("Fresh pair destination has an unexpected generation".into());
        }
        Ok(Some(generation))
    }

    fn anonymous_file(&self) -> Result<File, String> {
        // SAFETY: the existing directory fd is live; O_TMPFILE opens an
        // unnamed inode in that filesystem with private permissions.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
            )
        };
        checked_fd(fd).map_err(|error| {
            format!("Cannot stage a fresh vault pair on the destination filesystem: {error}")
        })
    }

    fn stage_input(
        &self,
        journal: &TrustedJournal<'_>,
        input: &str,
        expected: Generation,
    ) -> Result<File, String> {
        let mut source = journal.open_input(input)?;
        if source.metadata().map_err(|error| error.to_string())?.len() != expected.len {
            return Err(format!("Private recovery input {input} has the wrong size"));
        }
        let mut stage = self.anonymous_file()?;
        let length = io::copy(
            &mut Read::by_ref(&mut source).take(expected.len),
            &mut stage,
        )
        .map_err(|error| format!("Stage {input}: {error}"))?;
        if length != expected.len || source.read(&mut [0]).map_err(|error| error.to_string())? != 0
        {
            return Err(format!("Private recovery input {input} changed length"));
        }
        stage
            .seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        if hash_generation(
            stage.try_clone().map_err(|error| error.to_string())?,
            expected.len,
        )? != expected
        {
            return Err(format!("Private recovery input {input} changed content"));
        }
        stage
            .sync_all()
            .map_err(|error| format!("Sync staged {input}: {error}"))?;
        Ok(stage)
    }

    fn link(&self, stage: &File, path: &Path) -> Result<(), String> {
        self.recheck()?;
        let leaf = self.leaf(path)?;
        // SAFETY: both fds and the destination leaf remain live. linkat only
        // publishes a missing name; it cannot replace an unexpected file.
        let code = unsafe {
            libc::linkat(
                stage.as_raw_fd(),
                c"".as_ptr(),
                self.directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if code != 0 {
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOENT | libc::EINVAL)
            ) {
                return Err(format!("Publish fresh pair file: {error}"));
            }
            // Unprivileged Linux callers may need the procfs name for an
            // O_TMPFILE inode instead of linkat with AT_EMPTY_PATH.
            let proc = CString::new(format!("/proc/self/fd/{}", stage.as_raw_fd()))
                .expect("numeric file descriptor has no NUL");
            let meta = fs::metadata(std::ffi::OsStr::from_bytes(proc.as_bytes()))
                .map_err(|error| format!("Resolve unnamed pair stage: {error}"))?;
            let expected = stage.metadata().map_err(|error| error.to_string())?;
            if (meta.dev(), meta.ino()) != (expected.dev(), expected.ino()) {
                return Err("Unnamed pair stage identity changed".into());
            }
            // SAFETY: the procfs name selects the verified, live fd.
            if unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    proc.as_ptr(),
                    self.directory.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            } != 0
            {
                return Err(format!(
                    "Publish fresh pair file: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        self.directory
            .sync_all()
            .map_err(|error| format!("Sync pair destination: {error}"))
    }
}

pub(super) fn checked_fd(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transfers ownership of a new fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn ensure_private_root(root: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                validate_journal_ancestry(ancestor)?;
                break;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => missing.push(ancestor),
            Err(error) => return Err(format!("Inspect AeroVault private state: {error}")),
        }
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(root)
        .map_err(|error| format!("Create AeroVault private state: {error}"))?;
    TrustedJournal::open(root)?;
    for directory in missing {
        sync_dir(output_parent_dir(directory))?;
    }
    Ok(())
}

pub(in crate::v3) struct Plan {
    destination: Destination,
    source: PathBuf,
    root: PathBuf,
    prepared: PrivateDir,
}

impl Plan {
    pub(in crate::v3) fn prepare(path: &Path) -> Result<Self, String> {
        let source = crate::lock::anchored(path).map_err(|error| error.to_string())?;
        if pending(&source).is_some() {
            // Normal recovery under the source lock uses the already prepared
            // generations. Never turn a retry into a new set of vault keys.
            let _lock = crate::lock::acquire(&source).map_err(|error| error.to_string())?;
            return Err("An earlier fresh pair creation was recovered or completed; open that vault with its original password".into());
        }
        let destination = Destination::open(output_parent_dir(&source))?;
        require_absent(&source, &default_sidecar_path(&source))?;
        let root = state::configured_root()?;
        ensure_private_root(&root)?;
        // Detect unsupported destination filesystems before creating locks or
        // committing a journal that cannot be published on this filesystem.
        drop(destination.anonymous_file()?);
        let prepared = private_dir(&root, ".pair-prepare-")
            .map_err(|error| format!("Cannot prepare a private fresh pair journal: {error}"))?;
        Ok(Self {
            source,
            root,
            destination,
            prepared,
        })
    }

    pub(in crate::v3) fn publish(
        self,
        lock: &WriteLock,
        sidecar_lock: &WriteLock,
        vault: &[u8],
        parity: &[u8],
    ) -> Result<(), String> {
        if self.source != lock.source_path() || !lock.covers_namespace(&self.source) {
            return Err("Fresh pair source namespace changed before publication".into());
        }
        self.destination.recheck()?;
        require_absent(&self.source, &default_sidecar_path(&self.source))?;
        let key = state::source_key(&self.source);
        let active = self.root.join(key.to_hex().as_str());
        let prepared = self.prepared;
        let vault = write_input(prepared.path(), "new-vault", vault)?;
        let sidecar = write_input(prepared.path(), "new-sidecar", parity)?;
        let record = Record {
            version: VERSION,
            source_key: *key.as_bytes(),
            parent_device: self.destination.device,
            parent_inode: self.destination.inode,
            vault,
            sidecar,
        };
        write_input(
            prepared.path(),
            RECORD,
            &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
        )?;
        sync_dir(prepared.path())?;
        publish_index(prepared.path(), &active)?;
        sync_dir(&self.root)?;
        #[cfg(test)]
        stop_after("journal");
        finish(&self.source, self.destination, &active, lock, sidecar_lock).map_err(|error| {
            format!(
                "Fresh pair recovery pending at {}: {error}",
                active.display()
            )
        })
    }
}

fn require_absent(source: &Path, sidecar: &Path) -> Result<(), String> {
    for path in [source, sidecar] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Inspect fresh pair target: {error}")),
            Ok(_) => {
                return Err(
                    "Fresh pair creation requires both destination names to be absent".into(),
                )
            }
        }
    }
    Ok(())
}

pub(super) fn write_input(parent: &Path, leaf: &str, bytes: &[u8]) -> Result<Generation, String> {
    let path = parent.join(leaf);
    let mut file = private_options()
        .open(&path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    generation(&path)
}

pub(super) fn publish_index(prepared: &Path, active: &Path) -> Result<(), String> {
    let path_name =
        |value: &Path| CString::new(value.as_os_str().as_bytes()).map_err(|e| e.to_string());
    let source = path_name(prepared)?;
    let target = path_name(active)?;
    // SAFETY: both C strings outlive the syscall. A second writer must not
    // replace an existing transaction entry, even if its namespace lock moved.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(format!(
            "Commit private fresh pair journal: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(in crate::v3) fn pending(source: &Path) -> Option<PathBuf> {
    let root = state::configured_root().ok()?;
    let path = root.join(state::source_key(source).to_hex().as_str());
    fs::symlink_metadata(path.join(RECORD)).ok()?;
    Some(path)
}

pub(in crate::v3) fn recover(lock: &WriteLock, active: &Path) -> Result<(), String> {
    let source = lock.source_path();
    if !lock.covers_namespace(source) {
        return Err("Fresh pair recovery requires a real vault namespace lock".into());
    }
    match fs::symlink_metadata(active.join(RECORD)) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("Inspect private fresh pair journal: {error}")),
    }
    let sidecar = default_sidecar_path(source);
    let sidecar_lock =
        crate::lock::acquire_without_recovery(&sidecar).map_err(|e| e.to_string())?;
    let destination = Destination::open(output_parent_dir(source))?;
    finish(source, destination, active, lock, &sidecar_lock).map_err(|error| {
        format!(
            "Fresh pair conflict; preserve the private journal {}: {error}",
            active.display()
        )
    })
}

fn finish(
    source: &Path,
    destination: Destination,
    active: &Path,
    lock: &WriteLock,
    sidecar_lock: &WriteLock,
) -> Result<(), String> {
    TrustedJournal::open(output_parent_dir(active))?;
    let journal = TrustedJournal::open(active)?;
    let mut metadata = Vec::new();
    let n = journal
        .open_input(RECORD)?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut metadata)
        .map_err(|error| error.to_string())?;
    if n as u64 > MAX_RECORD {
        return Err("Fresh private record exceeds its size limit".into());
    }
    let record: Record = serde_json::from_slice(&metadata).map_err(|error| error.to_string())?;
    if record.version != VERSION
        || record.source_key != *state::source_key(source).as_bytes()
        || (record.parent_device, record.parent_inode) != (destination.device, destination.inode)
    {
        return Err("Fresh private record does not match this destination".into());
    }
    let sidecar = default_sidecar_path(source);
    let check_locks = || {
        if !lock.covers_namespace(source) || !sidecar_lock.covers_namespace(&sidecar) {
            return Err("Fresh pair lock namespace changed".to_string());
        }
        Ok(())
    };
    check_locks()?;
    // A restarted process may be retrying a failed index sync. The durable
    // recovery record must precede any visible destination write.
    sync_dir(output_parent_dir(active))?;
    let visible_vault = destination.current(source, record.vault)?;
    let visible_sidecar = destination.current(&sidecar, record.sidecar)?;
    if visible_vault.is_some() && visible_sidecar.is_none() {
        return Err("Fresh vault appeared without its durable sidecar".into());
    }
    if visible_vault.is_none() {
        // Validate all required private bytes before publishing either file.
        let vault = destination.stage_input(&journal, "new-vault", record.vault)?;
        if visible_sidecar.is_none() {
            let staged = destination.stage_input(&journal, "new-sidecar", record.sidecar)?;
            check_locks()?;
            destination.link(&staged, &sidecar)?;
            #[cfg(test)]
            stop_after("sidecar");
        }
        if destination.current(&sidecar, record.sidecar)?.is_none() {
            return Err("Fresh sidecar disappeared before vault publication".into());
        }
        // The sidecar might have been linked by a process that exited
        // before syncing the directory. Persist it before linking the vault.
        destination
            .directory
            .sync_all()
            .map_err(|error| format!("Sync sidecar publication: {error}"))?;
        check_locks()?;
        destination.link(&vault, source)?;
        #[cfg(test)]
        stop_after("vault");
    }
    check_locks()?;
    destination.recheck()?;
    if destination.current(source, record.vault)?.is_none()
        || destination.current(&sidecar, record.sidecar)?.is_none()
    {
        return Err("The fresh pair changed before retirement".into());
    }
    // Recovery can observe both names after a crash before the final sync.
    // Persist the destination directory before retiring the recovery inputs.
    destination
        .directory
        .sync_all()
        .map_err(|error| format!("Sync completed fresh pair: {error}"))?;
    journal.retire()
}

#[cfg(test)]
fn stop_after(phase: &str) {
    FRESH_STOP.with(|stop| {
        if stop.get() == Some(phase) {
            std::process::exit(77);
        }
    });
}

#[cfg(test)]
thread_local! {
    static FRESH_STOP: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{CreateOptionsV3, RecoveryPlacement, VaultV3};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    const ACTION: &str = "AEROVAULT_TEST_FRESH_PAIR_ACTION";
    const TARGET: &str = "AEROVAULT_TEST_FRESH_PAIR_PATH";
    const PASSWORD: &str = "isolated-fixture-password";
    const TEST: &str = "v3::pending_pair::fresh::tests::fresh_pair_recovers_across_process_boundaries_without_overwriting";

    #[test]
    fn fresh_publication_preserves_a_file_that_appeared_during_staging() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap();
        let destination = Destination::open(&parent).unwrap();
        let path = parent.join("file.aerovault");
        let mut stage = destination.anonymous_file().unwrap();
        stage.write_all(b"candidate").unwrap();
        stage.sync_all().unwrap();

        fs::write(&path, b"another writer").unwrap();
        assert!(destination
            .link(&stage, &path)
            .unwrap_err()
            .contains("File exists"));
        assert_eq!(fs::read(path).unwrap(), b"another writer");
    }

    #[test]
    fn fresh_pair_recovers_across_process_boundaries_without_overwriting() {
        if let Some(path) = std::env::var_os(TARGET) {
            let path = PathBuf::from(path);
            let action = std::env::var(ACTION).unwrap();
            let create = |placement| {
                let options = if action == "plain-both" {
                    CreateOptionsV3::new_plaintext(&path)
                } else {
                    CreateOptionsV3::new(&path, PASSWORD)
                };
                VaultV3::create_with_error_correction(&options, placement, 20)
            };
            match action.as_str() {
                "detached" => create(RecoveryPlacement::Detached).unwrap(),
                "both" | "plain-both" => create(RecoveryPlacement::Both).unwrap(),
                "open-plaintext" => {
                    assert!(VaultV3::list(&VaultV3::open_plaintext(&path).unwrap()).is_empty())
                }
                "journal" | "sidecar" | "vault" => {
                    let phase = match action.as_str() {
                        "journal" => "journal",
                        "sidecar" => "sidecar",
                        _ => "vault",
                    };
                    FRESH_STOP.with(|stop| stop.set(Some(phase)));
                    create(RecoveryPlacement::Both).unwrap();
                    panic!("did not reach fresh pair boundary {phase}");
                }
                "open" => {
                    let vault = VaultV3::open(&path, PASSWORD).unwrap();
                    assert!(VaultV3::list(&vault).is_empty());
                }
                "conflict" => {
                    let error = VaultV3::open(&path, PASSWORD).unwrap_err();
                    assert!(error.contains("Fresh pair conflict"), "{error}");
                }
                "absent-state" => {
                    let error = create(RecoveryPlacement::Detached).unwrap_err();
                    assert!(error.contains("HOME"), "{error}");
                }
                "retry" => {
                    let error = create(RecoveryPlacement::Detached).unwrap_err();
                    assert!(
                        error.contains("earlier fresh pair creation was recovered"),
                        "{error}"
                    );
                }
                "readonly-state" => {
                    let error = create(RecoveryPlacement::Detached).unwrap_err();
                    assert!(error.contains("private fresh pair journal"), "{error}");
                }
                "occupied" => {
                    let error = create(RecoveryPlacement::Detached).unwrap_err();
                    assert!(
                        error.contains("both destination names to be absent"),
                        "{error}"
                    );
                }
                _ => panic!("unknown test action"),
            }
            return;
        }

        let fixture = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let state_home = fixture.path().join("state");
        let root = state_home.join("aerovault/journals");

        let run = |target: &Path, action: &str, expected: i32| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env(TARGET, target)
                .env(ACTION, action);
            if action == "absent-state" {
                command.env_remove("HOME").env_remove("XDG_STATE_HOME");
            } else if action == "readonly-state" {
                command.env("XDG_STATE_HOME", fixture.path().join("readonly-state-home"));
            } else {
                command.env("XDG_STATE_HOME", &state_home);
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{action}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        let fresh_target = |name: &str| {
            let directory = fixture.path().join(name);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).unwrap();
            directory.join("test.aerovault")
        };
        let journal = |source: &Path| root.join(state::source_key(source).to_hex().as_str());

        for placement in ["detached", "both"] {
            let target = fresh_target(placement);
            run(&target, placement, 0);
            assert!(target.is_file() && default_sidecar_path(&target).is_file());
            assert!(!journal(&target).exists());
            assert_eq!(
                target.parent().unwrap().metadata().unwrap().mode() & 0o777,
                0o775
            );
            run(&target, "open", 0);
        }
        let plaintext = fresh_target("plaintext").with_extension("aerozip");
        run(&plaintext, "plain-both", 0);
        run(&plaintext, "open-plaintext", 0);
        assert!(default_sidecar_path(&plaintext).is_file());
        assert!(!journal(&plaintext).exists());

        for phase in ["journal", "sidecar", "vault"] {
            let target = fresh_target(phase);
            let sidecar = default_sidecar_path(&target);
            run(&target, phase, 77);
            let active = journal(&target);
            assert!(active.join(RECORD).is_file());
            assert_eq!(target.exists(), phase == "vault");
            assert_eq!(sidecar.exists(), phase != "journal");
            let expected = [
                fs::read(active.join("new-vault")).unwrap(),
                fs::read(active.join("new-sidecar")).unwrap(),
            ];
            run(&target, "open", 0);
            assert_eq!(
                [fs::read(&target).unwrap(), fs::read(&sidecar).unwrap()],
                expected
            );
            assert!(!active.exists());
        }

        let target = fresh_target("retry");
        run(&target, "sidecar", 77);
        let expected = fs::read(journal(&target).join("new-vault")).unwrap();
        run(&target, "retry", 0);
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert!(!journal(&target).exists());

        let target = fresh_target("substituted");
        run(&target, "sidecar", 77);
        let active = journal(&target);
        let sidecar = default_sidecar_path(&target);
        let parity = fs::read(&sidecar).unwrap();
        let mut wrong = fs::read(active.join("new-vault")).unwrap();
        wrong[0] ^= 1;
        fs::write(active.join("new-vault"), &wrong).unwrap();
        run(&target, "conflict", 0);
        assert!(!target.exists());
        assert_eq!(fs::read(&sidecar).unwrap(), parity);
        assert!(active.join(RECORD).exists());

        let target = fresh_target("unrelated-vault");
        run(&target, "sidecar", 77);
        let sidecar = default_sidecar_path(&target);
        let parity = fs::read(&sidecar).unwrap();
        fs::write(&target, b"unrelated generation").unwrap();
        run(&target, "conflict", 0);
        assert_eq!(fs::read(&target).unwrap(), b"unrelated generation");
        assert_eq!(fs::read(&sidecar).unwrap(), parity);
        assert!(journal(&target).exists());

        let target = fresh_target("relocated-parent");
        run(&target, "sidecar", 77);
        let parent = target.parent().unwrap();
        let moved = fixture.path().join("parent-moved");
        fs::rename(parent, &moved).unwrap();
        let sidecar = default_sidecar_path(&moved.join(target.file_name().unwrap()));
        let original = fs::read(&sidecar).unwrap();
        fs::create_dir(parent).unwrap();
        run(&target, "conflict", 0);
        assert!(!target.exists() && !default_sidecar_path(&target).exists());
        assert_eq!(fs::read(&sidecar).unwrap(), original);
        assert!(journal(&target).exists());

        let target = fresh_target("absent-state");
        run(&target, "absent-state", 0);
        assert!(target
            .parent()
            .unwrap()
            .read_dir()
            .unwrap()
            .next()
            .is_none());

        if unsafe { libc::geteuid() } != 0 {
            let readonly = fixture
                .path()
                .join("readonly-state-home/aerovault/journals");
            fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&readonly)
                .unwrap();
            fs::set_permissions(&readonly, fs::Permissions::from_mode(0o500)).unwrap();
            let target = fresh_target("readonly-state");
            run(&target, "readonly-state", 0);
            assert!(target
                .parent()
                .unwrap()
                .read_dir()
                .unwrap()
                .next()
                .is_none());
            fs::set_permissions(&readonly, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let target = fresh_target("occupied");
        fs::write(&target, b"keep these bytes").unwrap();
        run(&target, "occupied", 0);
        assert_eq!(fs::read(&target).unwrap(), b"keep these bytes");
        assert_eq!(target.parent().unwrap().read_dir().unwrap().count(), 1);
    }
}
