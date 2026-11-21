// SPDX-License-Identifier: MPL-2.0
//! Portable read barrier for interrupted vault/sidecar publication.
//!
//! A pending file is deliberately outside the normal AEROVAULT3 layout. Its
//! prefix is only a reason to stop. It cannot authorize a repair, supply an
//! output path, or substitute for a trusted transaction record.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

pub(super) const MAGIC: &[u8; 15] = b"AVPAIR-PENDING\0";

const PENDING: &str =
    "AeroVault vault/sidecar publication is pending; preserve the vault and sidecar and recover the pair before opening or replacing it";

#[cfg(target_os = "linux")]
pub(super) mod fresh;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) mod state;
#[cfg(target_os = "linux")]
pub(super) mod update;

pub(super) fn require_ordinary(bytes: &[u8]) -> Result<(), String> {
    if bytes.starts_with(MAGIC) {
        return Err(PENDING.into());
    }
    Ok(())
}

/// A moved marker still stops the reader if its originating state is absent.
pub(super) fn require_ordinary_at_open(
    path: &Path,
    file: &mut File,
    bytes: &[u8],
    file_len: u64,
) -> Result<(), String> {
    if !bytes.starts_with(MAGIC) {
        return Ok(());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(header) = state::Header::decode(bytes, file_len) {
        return Err(match state::find_record(path, &header) {
            Ok(true) => match header.verify_payload(file) {
                Ok(()) => PENDING.into(),
                Err(error) => format!("{PENDING}; {error}"),
            },
            #[cfg(target_os = "linux")]
            Ok(false) => format!("{PENDING}; the originating recovery record is missing from the known state directories. If the interrupted operation used a different XDG_STATE_HOME, restore its previous value and reopen the vault"),
            #[cfg(target_os = "macos")]
            Ok(false) => format!("{PENDING}; the originating recovery record is missing at this location"),
            Err(error) => format!("{PENDING}; cannot validate local recovery state: {error}"),
        });
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (path, file, file_len);
    Err(PENDING.into())
}

/// Creation also supports replacing a regular file. Check its prefix under
/// the writer guard so that path cannot discard a pending vault image.
pub(super) fn require_replaceable(path: &Path) -> Result<(), String> {
    let mut file = match crate::source::open_regular_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("Check existing vault before creation: {error}")),
    };
    let mut prefix = [0; MAGIC.len()];
    match file.read_exact(&mut prefix) {
        Ok(()) => require_ordinary(&prefix),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(()),
        Err(error) => Err(format!(
            "Read existing vault prefix before creation: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn recover_private(lock: &crate::lock::WriteLock, active: &Path) -> Result<(), String> {
    use super::strip_transaction::TrustedJournal;
    state::validate_active_root(super::vault::output_parent_dir(active))?;
    TrustedJournal::open(active)?;
    let exists = |name: &str| match std::fs::symlink_metadata(active.join(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "Inspect private journal {} ({error})",
            active.display()
        )),
    };
    match (
        exists(fresh::RECORD)?,
        exists(update::RECORD)? || exists(update::PREPARATION)?,
    ) {
        (true, false) => fresh::recover(lock, active),
        (false, true) => update::recover(lock, active),
        _ => Err(format!(
            "Private pair journal at {} has missing or conflicting records",
            active.display()
        )),
    }
}
