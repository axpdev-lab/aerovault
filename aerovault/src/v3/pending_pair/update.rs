// SPDX-License-Identifier: MPL-2.0
//! Linux replacements of an existing vault and detached sidecar.
//!
//! A private journal binds both images and a pinned directory of exchange
//! slots. Each rename preserves its displaced inode. A portable envelope
//! blocks readers between the first and last vault exchanges.

use super::fresh::{checked_fd, publish_index, write_input, Destination};
use super::state;
use crate::lock::WriteLock;
use crate::v3::ec::default_sidecar_path;
use crate::v3::strip_transaction::{
    generation, hash_generation, private_dir, sync_dir, Generation, PrivateDir, TrustedJournal,
};
use crate::v3::unix_security::{capture_fd, copy_extraction_acl};
use crate::v3::vault::output_parent_dir;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{self, File, Permissions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

pub(super) const RECORD: &str = "update.json";
const VERSION: u8 = 1;
const LIMIT: u64 = 4096;
const SLOTS: [&CStr; 3] = [c"marker", c"sidecar", c"vault"];
const CLEANUP: [(&str, usize); 2] = [("cleanup-original", 0), ("cleanup-replacement", 3)];
const PREPARED_FILES: [&str; 4] = ["old-vault", "old-sidecar", "new-vault", "new-sidecar"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    bytes: Generation,
    security: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    source_key: [u8; 32],
    transaction: [u8; 16],
    parent: (u64, u64),
    stage: (u64, u64),
    old_vault: Snapshot,
    old_sidecar: Snapshot,
    pending: Snapshot,
    new_vault: Snapshot,
    new_sidecar: Snapshot,
}

impl Record {
    // Columns are the visible vault and sidecar, then the three exchange
    // slots. Displaced files are part of the evidence, even after a crash.
    fn phases(&self) -> [[Snapshot; 5]; 4] {
        let Self {
            old_vault,
            old_sidecar,
            pending,
            new_vault,
            new_sidecar,
            ..
        } = *self;
        [
            [old_vault, old_sidecar, pending, new_sidecar, new_vault],
            [pending, old_sidecar, old_vault, new_sidecar, new_vault],
            [pending, new_sidecar, old_vault, old_sidecar, new_vault],
            [new_vault, new_sidecar, old_vault, old_sidecar, pending],
        ]
    }
}

fn open_member(directory: &File, leaf: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the directory descriptor and NUL-terminated leaf are live.
    checked_fd(unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    })
}

fn security(file: &File) -> Result<[u8; 32], String> {
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() {
        return Err("Pair member is not a regular file".into());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(&meta.uid().to_le_bytes());
    hash.update(&meta.gid().to_le_bytes());
    hash.update(&(meta.mode() & 0o777).to_le_bytes());
    hash.update(&capture_fd(file)?);
    Ok(*hash.finalize().as_bytes())
}

fn inspect(file: &File, sizes: &[u64]) -> Result<Snapshot, String> {
    let len = file.metadata().map_err(|error| error.to_string())?.len();
    if !sizes.contains(&len) {
        return Err("Pair member has an unrecorded length".into());
    }
    let before = security(file)?;
    let mut input = file.try_clone().map_err(|error| error.to_string())?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let bytes = hash_generation(input, len)?;
    if security(file)? != before {
        return Err("Pair member permissions changed during verification".into());
    }
    Ok(Snapshot {
        bytes,
        security: before,
    })
}

fn read_snapshot(dir: &File, leaf: &CStr, sizes: &[u64]) -> Result<Snapshot, String> {
    let file = open_member(dir, leaf, libc::O_RDONLY)
        .map_err(|error| format!("Open pair member {}: {error}", leaf.to_string_lossy()))?;
    inspect(&file, sizes)
}

fn apply_security(source: &File, target: &File) -> Result<(), String> {
    let old = source.metadata().map_err(|error| error.to_string())?;
    let staged = target.metadata().map_err(|error| error.to_string())?;
    if (old.uid(), old.gid()) != (staged.uid(), staged.gid()) {
        // SAFETY: target is an open stage that we created.
        if unsafe { libc::fchown(target.as_raw_fd(), old.uid(), old.gid()) } != 0 {
            return Err(format!(
                "Preserve pair ownership: {}",
                io::Error::last_os_error()
            ));
        }
    }
    copy_extraction_acl(source, target).map_err(|error| error.to_string())?;
    target
        .set_permissions(Permissions::from_mode(old.mode() & 0o777))
        .map_err(|error| error.to_string())?;
    if security(source)? != security(target)? {
        return Err("Cannot preserve pair member permissions".into());
    }
    Ok(())
}

struct Stage {
    directory: File,
    name: CString,
    identity: (u64, u64),
}

impl Stage {
    fn name(transaction: &[u8; 16]) -> CString {
        CString::new(format!(".aerostrip-prepare-{}", hex::encode(transaction)))
            .expect("hex transaction name cannot contain a NUL")
    }

    fn create(parent: &Destination, transaction: &[u8; 16]) -> Result<Self, String> {
        parent.recheck()?;
        let name = Self::name(transaction);
        // SAFETY: name and parent fd are live and the mode is a Linux mode_t.
        if unsafe { libc::mkdirat(parent.directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(format!(
                "Create protected pair stage: {}",
                io::Error::last_os_error()
            ));
        }
        Self::open(parent, transaction)
    }

    fn open(parent: &Destination, transaction: &[u8; 16]) -> Result<Self, String> {
        Self::find(parent, transaction)?.ok_or("Protected pair stage is missing".into())
    }

    fn find(parent: &Destination, transaction: &[u8; 16]) -> Result<Option<Self>, String> {
        let name = Self::name(transaction);
        let directory =
            match open_member(&parent.directory, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(directory) => directory,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("Open protected pair stage: {error}")),
            };
        let meta = directory.metadata().map_err(|error| error.to_string())?;
        if !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.dev() != parent.device
        {
            return Err("Pair stage does not have trusted ownership and private access".into());
        }
        Ok(Some(Self {
            directory,
            name,
            identity: (meta.dev(), meta.ino()),
        }))
    }

    fn recheck(&self, parent: &Destination, transaction: &[u8; 16]) -> Result<(), String> {
        parent.recheck()?;
        if Self::open(parent, transaction)?.identity != self.identity {
            return Err("Protected pair stage directory changed".into());
        }
        Ok(())
    }

    fn sync(&self, parent: &Destination) -> Result<(), String> {
        self.directory
            .sync_all()
            .and_then(|()| parent.directory.sync_all())
            .map_err(|error| format!("Sync pair publication: {error}"))
    }

    fn write_slot(
        &self,
        index: usize,
        mut input: File,
        expected: Generation,
        envelope: Option<(&[u8], u64)>,
        permissions: Option<&File>,
        created: &mut [bool; 3],
    ) -> Result<Snapshot, String> {
        let mut target = open_member(
            &self.directory,
            SLOTS[index],
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
        )
        .map_err(|error| format!("Reserve protected pair stage file: {error}"))?;
        created[index] = true;
        let mut body_offset = 0;
        if let Some((prefix, offset)) = envelope {
            target
                .write_all(prefix)
                .map_err(|error| error.to_string())?;
            target
                .seek(SeekFrom::Start(offset))
                .map_err(|error| error.to_string())?;
            body_offset = offset;
        }
        let observed = expected
            .len
            .checked_add(body_offset)
            .ok_or("Pending pair image is too large")?;
        let copied = io::copy(
            &mut Read::by_ref(&mut input).take(expected.len),
            &mut target,
        )
        .map_err(|error| format!("Copy protected pair input: {error}"))?;
        if copied != expected.len || input.read(&mut [0]).map_err(|error| error.to_string())? != 0 {
            return Err("Protected pair input changed length".into());
        }
        // The pending image carries an intact prior vault. Verify its payload
        // separately because the portable header is also part of the image.
        if envelope.is_some() {
            target
                .seek(SeekFrom::Start(body_offset))
                .map_err(|e| e.to_string())?;
            let mut payload_hash = blake3::Hasher::new();
            let size = io::copy(
                &mut Read::by_ref(&mut target).take(expected.len),
                &mut payload_hash,
            )
            .map_err(|error| error.to_string())?;
            if size != expected.len || payload_hash.finalize().as_bytes() != &expected.hash {
                return Err("Pending image payload does not match the prepared vault".into());
            }
        }
        if let Some(source) = permissions {
            apply_security(source, &target)?;
        }
        target
            .sync_all()
            .map_err(|error| format!("Sync pair stage file: {error}"))?;
        let staged = inspect(&target, &[observed])?;
        if envelope.is_none() && staged.bytes != expected {
            return Err("Pair publication input changed content".into());
        }
        Ok(staged)
    }

    fn remove(
        &self,
        parent: &Destination,
        transaction: &[u8; 16],
        created: [bool; 3],
    ) -> Result<(), String> {
        self.recheck(parent, transaction)?;
        for (leaf, created) in SLOTS.into_iter().zip(created) {
            if created {
                // SAFETY: unlink only the fixed slot inside the verified fd.
                if unsafe { libc::unlinkat(self.directory.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
                    return Err(format!(
                        "Retire pair stage file: {}",
                        io::Error::last_os_error()
                    ));
                }
                #[cfg(test)]
                stop_after(5);
            }
        }
        // SAFETY: only remove an empty directory at the known name.
        if unsafe {
            libc::unlinkat(
                parent.directory.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(format!(
                "Retire pair stage directory: {}",
                io::Error::last_os_error()
            ));
        }
        parent
            .directory
            .sync_all()
            .map_err(|error| error.to_string())
    }
}

fn portable_header(
    prepared: &Path,
    transaction: [u8; 16],
    original: Generation,
) -> Result<(state::Header, [u8; crate::v3::constants::HEADER_SIZE]), String> {
    use crate::v3::constants::HEADER_SIZE;

    let mut envelope = state::Header {
        transaction,
        payload_len: original.len,
        payload_offset: HEADER_SIZE as u64,
        payload_hash: original.hash,
    };
    let mut bytes = envelope.encode();
    let bounds = |header: &[u8]| -> Result<[u64; 2], String> {
        let extent = |vault: &str, parity: &str| {
            crate::v3::ec::legacy_extension_bound(
                &prepared.join(vault),
                &prepared.join(parity),
                header,
            )
        };
        Ok([
            extent("old-vault", "old-sidecar")?,
            extent("new-vault", "new-sidecar")?,
        ])
    };
    let mut extents = bounds(&bytes)?;
    extents.sort_unstable();
    for end in extents {
        let encoded_len = envelope
            .payload_offset
            .checked_add(original.len)
            .ok_or("Pending pair image is too large")?;
        if end > envelope.payload_offset && end <= encoded_len {
            envelope.payload_offset = end;
        }
    }
    // Keep the same opaque prefix when changing its one location field.
    bytes[72..80].copy_from_slice(&envelope.payload_offset.to_le_bytes());
    let encoded_len = envelope
        .payload_offset
        .checked_add(original.len)
        .ok_or("Pending pair image is too large")?;
    // A legacy reader may reconstruct the entire header from parity. It
    // still reads the extension directory from the actual image before
    // manifest recovery. Its first byte must be in the zero-filled gap or
    // outside the file.
    if bounds(&bytes)?
        .into_iter()
        .any(|end| end > envelope.payload_offset && end <= encoded_len)
    {
        return Err(
            "Cannot place the recoverable legacy directory outside the pending payload".into(),
        );
    }
    Ok((envelope, bytes))
}

pub(in crate::v3) fn prepare(source: &Path, prefix: &str) -> Result<PrivateDir, String> {
    Destination::open(output_parent_dir(source))?;
    let root = state::select_root()?;
    private_dir(&root, prefix).map_err(|error| format!("Prepare private pair journal: {error}"))
}

pub(in crate::v3) fn publish(
    source: &Path,
    prepared: PrivateDir,
    lock: &WriteLock,
    sidecar_lock: &WriteLock,
) -> Result<(), String> {
    let destination = Destination::open(output_parent_dir(source))?;
    let sidecar = default_sidecar_path(source);
    let vault_leaf = destination.leaf(source)?;
    let sidecar_leaf = destination.leaf(&sidecar)?;
    check_locks(source, &sidecar, lock, sidecar_lock)?;
    let root = output_parent_dir(prepared.path());
    TrustedJournal::open(root)?;
    let input = TrustedJournal::open(prepared.path())?;
    let key = state::source_key(source);
    let active = root.join(key.to_hex().as_str());

    let original_vault = generation(&prepared.path().join("old-vault"))?;
    let original_sidecar = generation(&prepared.path().join("old-sidecar"))?;
    let sealed_vault = generation(&prepared.path().join("new-vault"))?;
    let sealed_sidecar = generation(&prepared.path().join("new-sidecar"))?;
    let vault = open_member(&destination.directory, &vault_leaf, libc::O_RDONLY)
        .map_err(|e| format!("Open original vault: {e}"))?;
    let parity = open_member(&destination.directory, &sidecar_leaf, libc::O_RDONLY)
        .map_err(|e| format!("Open original sidecar: {e}"))?;
    let old_vault = inspect(&vault, &[original_vault.len])?;
    let old_sidecar = inspect(&parity, &[original_sidecar.len])?;
    if old_vault.bytes != original_vault || old_sidecar.bytes != original_sidecar {
        return Err(
            "Vault or sidecar changed while preparing their private recovery copies".into(),
        );
    }

    let mut transaction = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut transaction);
    let (envelope, pending_header) = portable_header(prepared.path(), transaction, original_vault)?;
    let stage = Stage::create(&destination, &transaction)?;
    let mut created = [false; 3];
    let ready = (|| {
        let pending = stage.write_slot(
            0,
            input.open_input("old-vault")?,
            original_vault,
            Some((&pending_header, envelope.payload_offset)),
            None,
            &mut created,
        )?;
        let new_sidecar = stage.write_slot(
            1,
            input.open_input("new-sidecar")?,
            sealed_sidecar,
            None,
            Some(&parity),
            &mut created,
        )?;
        let new_vault = stage.write_slot(
            2,
            input.open_input("new-vault")?,
            sealed_vault,
            None,
            Some(&vault),
            &mut created,
        )?;
        if new_vault.security != old_vault.security || new_sidecar.security != old_sidecar.security
        {
            return Err("Pair permissions changed while preparing protected replacements".into());
        }
        let record = Record {
            version: VERSION,
            source_key: *key.as_bytes(),
            transaction,
            parent: (destination.device, destination.inode),
            stage: stage.identity,
            old_vault,
            old_sidecar,
            pending,
            new_vault,
            new_sidecar,
        };
        let portable = state::Record {
            version: state::VERSION,
            source_key: *key.as_bytes(),
            envelope,
            old_sidecar: Some(old_sidecar.bytes),
            new_sidecar: new_sidecar.bytes,
        };
        write_input(
            prepared.path(),
            "pair.json",
            &serde_json::to_vec(&portable).map_err(|e| e.to_string())?,
        )?;
        write_input(
            prepared.path(),
            RECORD,
            &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
        )?;
        stage.sync(&destination)?;
        sync_dir(prepared.path())?;
        publish_index(prepared.path(), &active)
    })();
    if let Err(error) = ready {
        return match stage.remove(&destination, &transaction, created) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!(
                "{error}; protected pair staging retained ({cleanup})"
            )),
        };
    }
    sync_dir(root)?;
    #[cfg(test)]
    stop_after(0);
    finish(source, &destination, &active, lock, sidecar_lock, true).map_err(|error| {
        format!(
            "Private pair recovery pending at {}: {error}",
            active.display()
        )
    })
}

pub(in crate::v3) fn recover(lock: &WriteLock, active: &Path) -> Result<(), String> {
    match fs::symlink_metadata(active.join(RECORD)) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("Inspect private pair journal: {error}")),
    }
    let source = lock.source_path();
    let sidecar = default_sidecar_path(source);
    let sidecar_lock =
        crate::lock::acquire_without_recovery(&sidecar).map_err(|e| e.to_string())?;
    let destination = Destination::open(output_parent_dir(source))?;
    finish(source, &destination, active, lock, &sidecar_lock, false).map_err(|error| {
        format!(
            "Private pair conflict; preserve the vault and recovery state at {}: {error}",
            active.display()
        )
    })
}

fn check_locks(
    source: &Path,
    sidecar: &Path,
    lock: &WriteLock,
    sidecar_lock: &WriteLock,
) -> Result<(), String> {
    if !lock.covers_namespace(source) || !sidecar_lock.covers_namespace(sidecar) {
        return Err("Pair lock namespace changed".into());
    }
    Ok(())
}

fn load(journal: &TrustedJournal<'_>) -> Result<Record, String> {
    let mut metadata = Vec::new();
    let n = journal
        .open_input(RECORD)?
        .take(LIMIT + 1)
        .read_to_end(&mut metadata)
        .map_err(|error| error.to_string())?;
    if n as u64 > LIMIT {
        return Err("Private pair record exceeds its size limit".into());
    }
    serde_json::from_slice(&metadata).map_err(|e| format!("Decode private pair record: {e}"))
}

fn phase(
    destination: &Destination,
    stage: &Stage,
    vault: &CStr,
    sidecar: &CStr,
    phases: &[[Snapshot; 5]; 4],
) -> Result<usize, String> {
    let leaves = [vault, sidecar, SLOTS[0], SLOTS[1], SLOTS[2]];
    let mut candidates = [true; 4];
    for (index, leaf) in leaves.into_iter().enumerate() {
        let sizes = phases.map(|phase| phase[index].bytes.len);
        let dir = if index < 2 {
            &destination.directory
        } else {
            &stage.directory
        };
        let observed = read_snapshot(dir, leaf, &sizes)?;
        for (candidate, expected) in candidates.iter_mut().zip(phases) {
            *candidate &= observed == expected[index];
        }
        if !candidates.iter().any(|&value| value) {
            return Err(
                "Visible or staged pair member has unexpected bytes or access permissions".into(),
            );
        }
    }
    candidates
        .iter()
        .position(|&value| value)
        .ok_or("Private pair phase is unrecognized".into())
}

fn exchange(
    destination: &Destination,
    stage: &Stage,
    target: &CStr,
    slot: usize,
    prior: [Snapshot; 2],
) -> Result<(), String> {
    if read_snapshot(&destination.directory, target, &[prior[0].bytes.len])? != prior[0]
        || read_snapshot(&stage.directory, SLOTS[slot], &[prior[1].bytes.len])? != prior[1]
    {
        return Err("Pair generation changed before atomic exchange".into());
    }
    #[cfg(test)]
    if let Some(hook) = BEFORE_EXCHANGE.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
    // SAFETY: both operands are bounded leaf names under live directory fds.
    // RENAME_EXCHANGE retains the actual displaced inode, even when another
    // writer changed the destination after the generation check.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            stage.directory.as_raw_fd(),
            SLOTS[slot].as_ptr(),
            destination.directory.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } != 0
    {
        return Err(format!(
            "Atomically exchange pair member: {}",
            io::Error::last_os_error()
        ));
    }
    stage.sync(destination)?;
    let retained_conflict = |detail: &str| {
        format!("Pair changed during atomic exchange; displaced contents retained: {detail}")
    };
    let displaced = read_snapshot(&stage.directory, SLOTS[slot], &[prior[0].bytes.len])
        .map_err(|error| retained_conflict(&error))?;
    let published = read_snapshot(&destination.directory, target, &[prior[1].bytes.len])
        .map_err(|error| retained_conflict(&error))?;
    if displaced != prior[0] || published != prior[1] {
        return Err(retained_conflict("unrecorded generation"));
    }
    Ok(())
}

fn cleanup_phase(active: &Path) -> Result<Option<usize>, String> {
    let mut outcome = None;
    for (name, phase) in CLEANUP {
        let path = active.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Inspect pair cleanup outcome: {error}")),
            Ok(_) => {
                TrustedJournal::open(&path)?;
                if outcome.replace(phase).is_some() {
                    return Err("Private pair has conflicting cleanup outcomes".into());
                }
            }
        }
    }
    Ok(outcome)
}

fn cleanup_pair(
    destination: &Destination,
    active: &Path,
    journal: TrustedJournal<'_>,
    record: &Record,
    phase: &[Snapshot; 5],
    leaves: [&CStr; 2],
) -> Result<(), String> {
    destination.recheck()?;
    for (leaf, expected) in leaves.into_iter().zip(phase[..2].iter()) {
        if read_snapshot(&destination.directory, leaf, &[expected.bytes.len])? != *expected {
            return Err("Visible pair changed before cleanup".into());
        }
    }
    if let Some(stage) = Stage::find(destination, &record.transaction)? {
        if stage.identity != record.stage {
            return Err("Private cleanup does not match the protected pair stage".into());
        }
        let mut present = [false; 3];
        for ((leaf, expected), present) in SLOTS.into_iter().zip(&phase[2..]).zip(&mut present) {
            let file = match open_member(&stage.directory, leaf, libc::O_RDONLY) {
                Ok(file) => file,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Open pair cleanup slot: {error}")),
            };
            if inspect(&file, &[expected.bytes.len])? != *expected {
                return Err("Protected pair cleanup slot has changed".into());
            }
            *present = true;
        }
        stage.remove(destination, &record.transaction, present)?;
    } else {
        // Retry a failed parent fsync if an earlier process removed the stage.
        destination
            .directory
            .sync_all()
            .map_err(|error| error.to_string())?;
    }
    #[cfg(test)]
    stop_after(6);
    // Once the rollback decision is durable, these copies are no longer
    // recovery inputs. Remove them before retiring the discoverable journal.
    for leaf in PREPARED_FILES {
        match fs::remove_file(active.join(leaf)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Remove private pair copy: {error}")),
        }
    }
    sync_dir(active)?;
    journal.retire()
}

fn finish(
    source: &Path,
    destination: &Destination,
    active: &Path,
    lock: &WriteLock,
    sidecar_lock: &WriteLock,
    publish: bool,
) -> Result<(), String> {
    TrustedJournal::open(output_parent_dir(active))?;
    let journal = TrustedJournal::open(active)?;
    let record = load(&journal)?;
    if record.version != VERSION
        || record.source_key != *state::source_key(source).as_bytes()
        || record.parent != (destination.device, destination.inode)
    {
        return Err("Private record does not match the pinned vault destination".into());
    }
    let sidecar = default_sidecar_path(source);
    let vault_leaf = destination.leaf(source)?;
    let sidecar_leaf = destination.leaf(&sidecar)?;
    let leaves = [vault_leaf.as_c_str(), sidecar_leaf.as_c_str()];
    check_locks(source, &sidecar, lock, sidecar_lock)?;
    // Recovery might be retrying a failed directory fsync after registration.
    sync_dir(output_parent_dir(active))?;
    let phases = record.phases();
    if let Some(outcome) = cleanup_phase(active)? {
        sync_dir(active)?;
        return cleanup_pair(
            destination,
            active,
            journal,
            &record,
            &phases[outcome],
            leaves,
        );
    }
    let stage = Stage::open(destination, &record.transaction)?;
    if stage.identity != record.stage {
        return Err("Private record does not match the protected pair stage".into());
    }
    let check = || {
        check_locks(source, &sidecar, lock, sidecar_lock)?;
        stage.recheck(destination, &record.transaction)
    };
    check()?;
    let current = phase(destination, &stage, &vault_leaf, &sidecar_leaf, &phases)?;
    let step = |slot: usize, phase: usize| {
        check()?;
        let (target, target_index) = if slot == 1 {
            (sidecar_leaf.as_c_str(), 1)
        } else {
            let sidecar = phases[phase][1];
            if read_snapshot(&destination.directory, &sidecar_leaf, &[sidecar.bytes.len])?
                != sidecar
            {
                return Err("Sidecar changed before vault exchange".into());
            }
            (vault_leaf.as_c_str(), 0)
        };
        exchange(
            destination,
            &stage,
            target,
            slot,
            [phases[phase][target_index], phases[phase][slot + 2]],
        )
    };

    let expected = if publish {
        if current != 0 {
            return Err("Private pair changed before publication started".into());
        }
        for slot in 0..3 {
            step(slot, slot)?;
            #[cfg(test)]
            stop_after(slot + 1);
        }
        3
    } else if current == 3 {
        3
    } else {
        // A partial publication always has a pending vault. Undo the sidecar
        // before restoring the ordinary vault, so readers outside this state
        // never see a coherent-looking but mixed pair during rollback.
        for slot in (0..current).rev() {
            step(slot, slot + 1)?;
        }
        0
    };
    check()?;
    if phase(destination, &stage, &vault_leaf, &sidecar_leaf, &phases)? != expected {
        return Err("Private pair changed before journal retirement".into());
    }
    stage.sync(destination)?;
    let name = if expected == 0 {
        CLEANUP[0].0
    } else {
        CLEANUP[1].0
    };
    // The empty marker is created atomically. No private copy is removed
    // before the cleanup outcome is committed in the user's state directory.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(active.join(name))
        .map_err(|error| format!("Record verified pair cleanup outcome: {error}"))?;
    sync_dir(active)?;
    #[cfg(test)]
    {
        stop_after(4);
        if FAIL_CLEANUP.with(|fail| fail.replace(false)) {
            return Err("Injected private pair cleanup error".into());
        }
    }
    cleanup_pair(
        destination,
        active,
        journal,
        &record,
        &phases[expected],
        leaves,
    )
}

#[cfg(test)]
fn stop_after(boundary: usize) {
    STOP_AFTER.with(|stop| {
        if stop.get() == Some(boundary) {
            std::process::exit(77);
        }
    });
}

#[cfg(test)]
thread_local! {
    static BEFORE_EXCHANGE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
    static STOP_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_CLEANUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{CreateOptionsV3, RecoveryPlacement, VaultV3};
    use std::path::PathBuf;
    use std::process::Command;

    const ACTION: &str = "AEROVAULT_TEST_PRIVATE_UPDATE";
    const PATH: &str = "AEROVAULT_TEST_PRIVATE_UPDATE_PATH";
    const TEST: &str = "v3::pending_pair::update::tests::update_recovers_each_durable_boundary_and_preserves_conflicts";
    const OLD: &str = "isolated-prior-vault-password";
    const NEW: &str = "isolated-next-vault-password";

    #[test]
    fn update_recovers_each_durable_boundary_and_preserves_conflicts() {
        if let Some(path) = std::env::var_os(PATH) {
            let path = PathBuf::from(path);
            let action = std::env::var(ACTION).unwrap();
            match action.as_str() {
                "create" => {
                    VaultV3::create_with_error_correction(
                        &CreateOptionsV3::new(&path, OLD),
                        RecoveryPlacement::Both,
                        20,
                    )
                    .unwrap();
                    let mut vault = VaultV3::open(&path, OLD).unwrap();
                    let source = path.with_file_name("payload");
                    fs::write(&source, b"isolated bytes that must survive all checkpoints")
                        .unwrap();
                    VaultV3::add_files(&mut vault, &[(source, "payload".into())]).unwrap();
                    VaultV3::export_parity(&path, OLD, None).unwrap();
                    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
                    fs::set_permissions(default_sidecar_path(&path), Permissions::from_mode(0o640))
                        .unwrap();
                }
                "open-old" | "open-new" => {
                    let password = if action == "open-old" { OLD } else { NEW };
                    let vault = VaultV3::open(&path, password).unwrap();
                    let output = path.with_file_name("restored");
                    VaultV3::extract_entry(&vault, "payload", &output).unwrap();
                    assert_eq!(
                        fs::read(output).unwrap(),
                        b"isolated bytes that must survive all checkpoints"
                    );
                }
                "reject-old" => {
                    assert!(VaultV3::open(&path, OLD).is_err());
                }
                "rotate-cleanup-error" => {
                    let mut vault = VaultV3::open(&path, OLD).unwrap();
                    FAIL_CLEANUP.with(|fail| fail.set(true));
                    let error = VaultV3::change_password(&mut vault, NEW).unwrap_err();
                    assert!(error.starts_with("Password changed on disk"), "{error}");
                    VaultV3::create_directory(&mut vault, "after-cleanup-retry").unwrap();
                }
                "inaccessible-default-journal" => {
                    let export = path.with_file_name("unexpected-export.aerocorrect");
                    for error in [
                        VaultV3::open(&path, OLD).unwrap_err(),
                        VaultV3::open(&path, NEW).unwrap_err(),
                        VaultV3::export_parity(&path, OLD, Some(&export)).unwrap_err(),
                        VaultV3::strip_parity(&path, OLD, false).unwrap_err(),
                    ] {
                        assert!(error.contains("publication is pending"), "{error}");
                        assert!(
                            error.contains("originating recovery record is missing"),
                            "{error}"
                        );
                    }
                    let error = VaultV3::create(&CreateOptionsV3::new(&path, NEW)).unwrap_err();
                    assert!(error.contains("publication is pending"), "{error}");
                    assert!(!export.exists());
                }
                "wrong-xdg" => {
                    let error = VaultV3::open(&path, OLD).unwrap_err();
                    assert!(
                        error.contains("restore its previous value and reopen the vault"),
                        "{error}"
                    );
                    assert!(VaultV3::create(&CreateOptionsV3::new(&path, NEW)).is_err());
                }
                "missing" | "conflict" => {
                    let error = VaultV3::open(&path, OLD).unwrap_err();
                    let detail = if action == "missing" {
                        "originating recovery record is missing"
                    } else {
                        "Private pair conflict"
                    };
                    assert!(error.contains(detail), "{error}");
                }
                "strip-concurrent" => {
                    let destination = path.clone();
                    BEFORE_EXCHANGE.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move || {
                            let incoming = destination.with_file_name("concurrent-generation");
                            fs::write(&incoming, b"independent replacement").unwrap();
                            fs::rename(incoming, destination).unwrap();
                        }));
                    });
                    let error = VaultV3::strip_parity(&path, OLD, false).unwrap_err();
                    assert!(error.contains("displaced contents retained"), "{error}");
                }
                _ => {
                    let (operation, boundary) = action.split_once('-').unwrap();
                    if let Ok(boundary) = boundary.parse::<usize>() {
                        STOP_AFTER.with(|stop| stop.set(Some(boundary)));
                    }
                    match operation {
                        "strip" => {
                            VaultV3::strip_parity(&path, OLD, false).unwrap();
                        }
                        "recover" => {
                            VaultV3::open(&path, OLD).unwrap();
                        }
                        "rotate" => {
                            let mut vault = VaultV3::open(&path, OLD).unwrap();
                            VaultV3::change_password(&mut vault, NEW).unwrap();
                        }
                        _ => unreachable!("unknown test operation"),
                    };
                    assert_eq!(boundary, "complete");
                }
            }
            return;
        }

        let fixture = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let home = fixture.path().join("home");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        let xdg = fixture.path().join("state");
        let root = xdg.join("aerovault/journals");
        let run = |target: &Path, action: &str, expected: i32| {
            let (action, state_home) = match action.strip_suffix("@new-xdg") {
                Some(action) => (action, fixture.path().join("new-state")),
                None => (action, xdg.clone()),
            };
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(PATH, target)
                .env(ACTION, action)
                .env("HOME", &home)
                .env("XDG_STATE_HOME", state_home)
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(expected),
                "{action}: {}{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
        };
        let make = |label: &str| {
            let directory = fixture.path().join(label);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, Permissions::from_mode(0o775)).unwrap();
            let target = directory.join("vault.aerovault");
            run(&target, "create", 0);
            target
        };
        let journal = |target: &Path| root.join(state::source_key(target).to_hex().as_str());
        let bytes = |target: &Path| {
            [
                fs::read(target).unwrap(),
                fs::read(default_sidecar_path(target)).unwrap(),
            ]
        };
        let no_recovery_assets = |target: &Path| {
            assert!(!journal(target).exists());
            assert!(target.parent().unwrap().read_dir().unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aerostrip-prepare-")
            }));
        };
        let cleanup = |target: &Path| {
            no_recovery_assets(target);
            for path in [target.to_owned(), default_sidecar_path(target)] {
                assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o640);
            }
        };

        let concurrent = make("concurrent");
        let original = bytes(&concurrent);
        run(&concurrent, "strip-concurrent", 0);
        let active = journal(&concurrent);
        let record = load(&TrustedJournal::open(&active).unwrap()).unwrap();
        let dest = Destination::open(concurrent.parent().unwrap()).unwrap();
        let stage = Stage::open(&dest, &record.transaction).unwrap();
        let mut displaced = Vec::new();
        open_member(&stage.directory, SLOTS[0], libc::O_RDONLY)
            .unwrap()
            .read_to_end(&mut displaced)
            .unwrap();
        assert_eq!(displaced, b"independent replacement");
        let visible = bytes(&concurrent);
        let envelope = state::Header::decode(&visible[0], visible[0].len() as u64).unwrap();
        assert_eq!(&visible[0][envelope.payload_offset as usize..], original[0]);
        assert_eq!(visible[1], original[1]);
        run(&concurrent, "conflict", 0);
        assert_eq!(bytes(&concurrent), visible);
        assert!(active.join(RECORD).exists());

        for operation in ["strip", "rotate"] {
            let complete = make(&format!("{operation}-complete"));
            run(&complete, &format!("{operation}-complete"), 0);
            run(
                &complete,
                if operation == "strip" {
                    "open-old"
                } else {
                    "open-new"
                },
                0,
            );
            cleanup(&complete);
            for boundary in 0..=6 {
                let target = make(&format!("{operation}-{boundary}"));
                let original = bytes(&target);
                run(&target, &format!("{operation}-{boundary}"), 77);
                let active = journal(&target);
                assert!(active.join(RECORD).exists());
                let final_bytes = [
                    fs::read(active.join("new-vault")).unwrap(),
                    fs::read(active.join("new-sidecar")).unwrap(),
                ];
                if boundary == 1 || boundary == 2 {
                    assert!(fs::read(&target).unwrap().starts_with(super::super::MAGIC));
                    let portable = target.with_file_name("moved.aerovault");
                    fs::copy(&target, &portable).unwrap();
                    fs::copy(
                        default_sidecar_path(&target),
                        default_sidecar_path(&portable),
                    )
                    .unwrap();
                    run(&portable, "missing", 0);
                    let portable = fs::read(&portable).unwrap();
                    let envelope = state::Header::decode(&portable, portable.len() as u64).unwrap();
                    assert_eq!(&portable[envelope.payload_offset as usize..], original[0]);
                }
                run(
                    &target,
                    if boundary >= 3 && operation == "rotate" {
                        "open-new"
                    } else {
                        "open-old"
                    },
                    0,
                );
                assert_eq!(
                    bytes(&target),
                    if boundary >= 3 { final_bytes } else { original }
                );
                if boundary >= 3 && operation == "rotate" {
                    run(&target, "reject-old", 0);
                }
                cleanup(&target);
            }
        }

        let switched = make("switched-xdg");
        let original = bytes(&switched);
        run(&switched, "rotate-2", 77);
        assert!(journal(&switched).join(RECORD).is_file());
        let pending = bytes(&switched);
        run(&switched, "wrong-xdg@new-xdg", 0);
        assert_eq!(bytes(&switched), pending);
        assert!(journal(&switched).join(RECORD).is_file());
        assert!(home.read_dir().unwrap().next().is_none());
        run(&switched, "open-old", 0);
        assert_eq!(bytes(&switched), original);
        cleanup(&switched);

        let rotated = make("rotate-cleanup-error");
        run(&rotated, "rotate-cleanup-error", 0);
        run(&rotated, "reject-old", 0);
        run(&rotated, "open-new", 0);
        no_recovery_assets(&rotated);

        for boundary in 4..=6 {
            let target = make(&format!("rollback-cleanup-{boundary}"));
            let original = bytes(&target);
            run(&target, "strip-2", 77);
            run(&target, &format!("recover-{boundary}"), 77);
            assert_eq!(bytes(&target), original);
            run(&target, "open-old", 0);
            assert_eq!(bytes(&target), original);
            cleanup(&target);
        }

        let narrowed = make("narrowed-permissions");
        run(&narrowed, "rotate-2", 77);
        let narrowed_sidecar = default_sidecar_path(&narrowed);
        fs::set_permissions(&narrowed_sidecar, Permissions::from_mode(0o600)).unwrap();
        let contents = bytes(&narrowed);
        run(&narrowed, "conflict", 0);
        assert_eq!(bytes(&narrowed), contents);
        assert_eq!(narrowed_sidecar.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(journal(&narrowed).join(RECORD).is_file());

        let target = make("unexpected");
        run(&target, "strip-2", 77);
        let active = journal(&target);
        let stored = TrustedJournal::open(&active).unwrap();
        let record = load(&stored).unwrap();
        let candidate = target
            .parent()
            .unwrap()
            .join(Stage::name(&record.transaction).to_str().unwrap())
            .join("vault");
        let mut foreign = fs::read(&candidate).unwrap();
        foreign[0] ^= 1;
        fs::write(&candidate, &foreign).unwrap();
        let visible = bytes(&target);
        run(&target, "conflict", 0);
        assert_eq!(bytes(&target), visible);
        assert_eq!(fs::read(&candidate).unwrap(), foreign);
        assert!(active.join(RECORD).is_file());
    }

    #[test]
    fn inaccessible_default_journal_preserves_pending_updates_under_new_xdg() {
        // Linux root can traverse a directory even when its mode is 000.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let fixture = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let home = fixture.path().join("home");
        let alternate_xdg = fixture.path().join("xdg");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&alternate_xdg).unwrap();
        fs::set_permissions(&alternate_xdg, Permissions::from_mode(0o700)).unwrap();
        let hidden_ancestor = home.join(".local");
        let journals = hidden_ancestor.join("state/aerovault/journals");

        for boundary in 1..=3 {
            let directory = fixture.path().join(boundary.to_string());
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, Permissions::from_mode(0o775)).unwrap();
            let target = directory.join("fixture.aerovault");
            let sidecar = default_sidecar_path(&target);
            let snapshot = || [fs::read(&target).unwrap(), fs::read(&sidecar).unwrap()];
            let run = |action: &str, changed_xdg: bool, expected: i32| {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", TEST, "--nocapture"])
                    .env(PATH, &target)
                    .env(ACTION, action)
                    .env("HOME", &home)
                    .env_remove("XDG_STATE_HOME");
                if changed_xdg {
                    command.env("XDG_STATE_HOME", &alternate_xdg);
                }
                let child = command.output().unwrap();
                assert_eq!(
                    child.status.code(),
                    Some(expected),
                    "{boundary}/{action}: {}{}",
                    String::from_utf8_lossy(&child.stdout),
                    String::from_utf8_lossy(&child.stderr)
                );
            };
            run("create", false, 0);
            let original = snapshot();
            run(&format!("rotate-{boundary}"), false, 77);
            let active = journals.join(state::source_key(&target).to_hex().as_str());
            assert!(active.join(RECORD).is_file());
            let interrupted = snapshot();
            assert_eq!(
                interrupted[0].starts_with(super::super::MAGIC),
                boundary < 3
            );

            let mode = hidden_ancestor.metadata().unwrap().permissions();
            fs::set_permissions(&hidden_ancestor, Permissions::from_mode(0o000)).unwrap();
            let inaccessible = std::panic::catch_unwind(|| {
                assert_eq!(
                    fs::symlink_metadata(active.join(RECORD))
                        .unwrap_err()
                        .kind(),
                    ErrorKind::PermissionDenied
                );
                if boundary < 3 {
                    run("inaccessible-default-journal", true, 0);
                } else {
                    // The final exchange has already published a coherent pair.
                    run("open-new", true, 0);
                    run("reject-old", true, 0);
                }
                assert_eq!(snapshot(), interrupted);
            });
            fs::set_permissions(&hidden_ancestor, mode).unwrap();
            if let Err(error) = inaccessible {
                std::panic::resume_unwind(error);
            }
            assert!(active.join(RECORD).is_file());

            if boundary < 3 {
                run("open-old", false, 0);
                assert_eq!(snapshot(), original);
            } else {
                run("open-new", false, 0);
                assert_eq!(snapshot(), interrupted);
                run("reject-old", false, 0);
            }
            assert!(!active.exists());
        }
    }
}
