// SPDX-License-Identifier: MPL-2.0
//! Read-side discovery of owner-private state for a portable pending vault.

use super::super::constants::HEADER_SIZE;
use super::super::ec::default_sidecar_path;
use super::super::strip_transaction::{recorded_generation, Generation, TrustedJournal};
use super::MAGIC;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

const VERSION: u8 = 1;
const MAX_RECORD_SIZE: u64 = 4096;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    transaction: [u8; 16],
    payload_len: u64,
    payload_hash: [u8; 32],
}

impl Header {
    pub(super) fn decode(bytes: &[u8], file_len: u64) -> Option<Self> {
        if !bytes.starts_with(MAGIC) || bytes.get(MAGIC.len()) != Some(&VERSION) {
            return None;
        }
        let transaction = bytes.get(16..32)?.try_into().ok()?;
        let payload_len = u64::from_le_bytes(bytes.get(32..40)?.try_into().ok()?);
        let payload_hash = bytes.get(40..72)?.try_into().ok()?;
        if payload_len < HEADER_SIZE as u64
            || (HEADER_SIZE as u64).checked_add(payload_len) != Some(file_len)
        {
            return None;
        }
        Some(Self {
            transaction,
            payload_len,
            payload_hash,
        })
    }

    /// Verify from the same open handle that provided the marker, without
    /// reserving memory proportional to the payload.
    pub(super) fn verify_payload(&self, file: &mut (impl Read + Seek)) -> Result<(), String> {
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))
            .map_err(|error| format!("Seek pending payload: {error}"))?;
        let mut hash = blake3::Hasher::new();
        let read = io::copy(&mut file.by_ref().take(self.payload_len), &mut hash)
            .map_err(|error| format!("Read pending payload: {error}"))?;
        if read != self.payload_len
            || hash.finalize().as_bytes() != &self.payload_hash
            || file.read(&mut [0]).map_err(|error| error.to_string())? != 0
        {
            return Err("pending payload does not match its private recovery record".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    source_key: [u8; 32],
    envelope: Header,
    old_sidecar: Option<Generation>,
    new_sidecar: Generation,
}

fn absolute_directory(value: &OsStr) -> Option<&Path> {
    let value = Path::new(value);
    (value.is_absolute() && !value.components().any(|part| part == Component::ParentDir))
        .then_some(value)
}

fn state_root(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    let base = if let Some(xdg) = xdg.filter(|path| !path.is_empty()) {
        absolute_directory(xdg)
            .ok_or("XDG_STATE_HOME must name an absolute directory")?
            .to_path_buf()
    } else {
        home.and_then(absolute_directory)
            .ok_or("No absolute HOME or XDG_STATE_HOME for AeroVault recovery")?
            .join(".local/state")
    };
    #[cfg(target_os = "macos")]
    let base = {
        let _ = xdg;
        home.and_then(absolute_directory)
            .ok_or("No absolute HOME for AeroVault recovery")?
            .join("Library/Application Support")
    };
    Ok(base.join("aerovault/journals"))
}

pub(super) fn configured_root() -> Result<PathBuf, String> {
    let xdg = std::env::var_os("XDG_STATE_HOME");
    let home = std::env::var_os("HOME");
    state_root(xdg.as_deref(), home.as_deref())
}

pub(super) fn source_key(source: &Path) -> blake3::Hash {
    blake3::hash(source.as_os_str().as_encoded_bytes())
}

pub(super) fn find_record(source: &Path, header: &Header) -> Result<bool, String> {
    find_at(&configured_root()?, source, header)
}

fn find_at(root: &Path, source: &Path, header: &Header) -> Result<bool, String> {
    let source = std::fs::canonicalize(source)
        .map_err(|error| format!("Resolve vault identity: {error}"))?;
    let key = source_key(&source);
    let path = root.join(key.to_hex().as_str());
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Inspect private transaction record: {error}")),
    }
    // The owner-only state directory is part of the trust boundary. Validate
    // it independently of the vault's destination and recheck when opening an
    // input from the transaction directory.
    TrustedJournal::open(root)?;
    let journal = TrustedJournal::open(&path)?;
    let mut data = Vec::new();
    let n = journal
        .open_input("pair.json")?
        .take(MAX_RECORD_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("Read private transaction record: {error}"))?;
    if n as u64 > MAX_RECORD_SIZE {
        return Err("Private transaction record exceeds its size limit".into());
    }
    let record: Record = serde_json::from_slice(&data)
        .map_err(|error| format!("Decode private transaction record: {error}"))?;
    if record.version != VERSION
        || record.source_key != *key.as_bytes()
        || record.envelope != *header
    {
        return Err(
            "Private transaction record does not match this vault and pending image".into(),
        );
    }
    let known = [record.old_sidecar, Some(record.new_sidecar)];
    let sidecar = default_sidecar_path(&source);
    let current = recorded_generation(&sidecar, &known)
        .map_err(|error| format!("Cannot verify the pending sidecar: {error}"))?;
    if !known.contains(&current) {
        return Err("Pending sidecar generation does not match the private recovery record".into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, Permissions};
    use std::io::{Cursor, Write};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    fn record_at(root: &Path, source: &Path, header: Header) -> PathBuf {
        let source = source.canonicalize().unwrap();
        let source_key = *blake3::hash(source.as_os_str().as_encoded_bytes()).as_bytes();
        let folder = root.join(hex::encode(source_key));
        fs::DirBuilder::new().mode(0o700).create(&folder).unwrap();
        let staged = folder.join("new-sidecar");
        fs::write(&staged, b"new parity").unwrap();
        let record = serde_json::to_vec(&Record {
            version: VERSION,
            source_key,
            envelope: header,
            old_sidecar: None,
            new_sidecar: super::super::super::strip_transaction::generation(&staged).unwrap(),
        })
        .unwrap();
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(folder.join("pair.json"))
            .unwrap()
            .write_all(&record)
            .unwrap();
        folder
    }

    #[test]
    fn envelope_header_validates_length_and_version() {
        let mut bytes = [0; HEADER_SIZE];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        bytes[MAGIC.len()] = VERSION;
        bytes[16..32].copy_from_slice(&[2; 16]);
        bytes[32..40].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
        bytes[40..72].copy_from_slice(&[3; 32]);
        assert_eq!(
            Header::decode(&bytes, (2 * HEADER_SIZE) as u64),
            Some(Header {
                transaction: [2; 16],
                payload_len: HEADER_SIZE as u64,
                payload_hash: [3; 32]
            }),
        );
        assert!(Header::decode(&bytes, HEADER_SIZE as u64).is_none());
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Header::decode(&bytes, u64::MAX).is_none());
        bytes[MAGIC.len()] += 1;
        assert!(Header::decode(&bytes, (2 * HEADER_SIZE) as u64).is_none());
    }

    #[test]
    fn private_record_requires_a_matching_location_and_trusted_ownership() {
        let dir = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let state = dir.path().join("state");
        let destination = dir.path().join("destination");
        fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        fs::DirBuilder::new()
            .mode(0o775)
            .create(&destination)
            .unwrap();
        let file = destination.join("vault.aerovault");
        let moved = destination.join("moved.aerovault");
        fs::write(&file, b"isolated identity").unwrap();
        fs::copy(&file, &moved).unwrap();
        let envelope = || Header {
            transaction: [1; 16],
            payload_len: HEADER_SIZE as u64,
            payload_hash: [2; 32],
        };
        assert!(!find_at(&state, &file, &envelope()).unwrap());
        let journal_dir = record_at(&state, &file, envelope());
        assert!(find_at(&state, &file, &envelope()).unwrap());
        assert!(!find_at(&state, &moved, &envelope()).unwrap());
        let sidecar = default_sidecar_path(&file);
        fs::write(&sidecar, b"new parity").unwrap();
        assert!(find_at(&state, &file, &envelope()).unwrap());
        fs::write(&sidecar, b"bad parity").unwrap();
        assert!(find_at(&state, &file, &envelope())
            .unwrap_err()
            .contains("sidecar generation"));
        assert_eq!(fs::read(&sidecar).unwrap(), b"bad parity");
        fs::remove_file(sidecar).unwrap();
        let other = Header {
            transaction: [3; 16],
            ..envelope()
        };
        assert!(find_at(&state, &file, &other)
            .unwrap_err()
            .contains("does not match"));

        // The destination can be group-writable. The private record and its
        // parent state directory cannot.
        fs::set_permissions(&state, Permissions::from_mode(0o775)).unwrap();
        assert!(find_at(&state, &file, &envelope())
            .unwrap_err()
            .contains("private access"));
        fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(journal_dir.join("pair.json"), Permissions::from_mode(0o660)).unwrap();
        assert!(find_at(&state, &file, &envelope())
            .unwrap_err()
            .contains("trusted ownership"));
    }

    #[test]
    fn pending_payload_is_checked_byte_for_byte() {
        let payload = [0x4a; HEADER_SIZE];
        let expected = Header {
            transaction: [1; 16],
            payload_len: payload.len() as u64,
            payload_hash: *blake3::hash(&payload).as_bytes(),
        };
        let mut envelope = vec![0u8; HEADER_SIZE];
        envelope.extend_from_slice(&payload);
        assert!(expected.verify_payload(&mut Cursor::new(&envelope)).is_ok());
        envelope[HEADER_SIZE] ^= 1;
        assert!(expected
            .verify_payload(&mut Cursor::new(&envelope))
            .is_err());
        envelope[HEADER_SIZE] ^= 1;
        envelope.push(0);
        assert!(expected
            .verify_payload(&mut Cursor::new(&envelope))
            .is_err());
        envelope.truncate(2 * HEADER_SIZE - 1);
        assert!(expected
            .verify_payload(&mut Cursor::new(&envelope))
            .is_err());
    }

    #[test]
    fn normal_open_never_treats_a_moved_or_conflicting_pending_pair_as_damage() {
        const CHILD: &str = "AEROVAULT_TEST_PENDING_OPEN_PATH";
        const EXPECT: &str = "AEROVAULT_TEST_PENDING_OPEN_REASON";
        if let Some(path) = std::env::var_os(CHILD) {
            crate::lock::take_trace();
            let error = super::super::super::vault::VaultV3::open(
                PathBuf::from(path),
                "unused-test-password",
            )
            .unwrap_err();
            assert!(error.contains("publication is pending"), "{error}");
            assert!(error.contains(&std::env::var(EXPECT).unwrap()), "{error}");
            assert!(!crate::lock::take_trace().contains(&"lock"));
            return;
        }

        let dir = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let xdg = dir.path().join("xdg");
        let root = state_root(Some(xdg.as_os_str()), Some(home.as_os_str())).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&root)
            .unwrap();

        let target = dir.path().join("original.aerovault");
        let moved = dir.path().join("moved.aerovault");
        let body = [0x3b; HEADER_SIZE];
        let header = Header {
            transaction: [9; 16],
            payload_len: body.len() as u64,
            payload_hash: *blake3::hash(&body).as_bytes(),
        };
        let mut bytes = vec![0; HEADER_SIZE];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        bytes[MAGIC.len()] = VERSION;
        bytes[16..32].copy_from_slice(&header.transaction);
        bytes[32..40].copy_from_slice(&header.payload_len.to_le_bytes());
        bytes[40..72].copy_from_slice(&header.payload_hash);
        bytes.extend_from_slice(&body);
        fs::write(&target, &bytes).unwrap();
        fs::copy(&target, &moved).unwrap();
        record_at(&root, &target, header);

        let open = |path: &Path, reason: &str| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "v3::pending_pair::state::tests::normal_open_never_treats_a_moved_or_conflicting_pending_pair_as_damage"])
                .env(CHILD, path)
                .env(EXPECT, reason)
                .env("HOME", &home)
                .env("XDG_STATE_HOME", &xdg)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        open(&target, "recover the pair before opening or replacing it");
        open(&moved, "originating recovery record is missing");
        fs::write(default_sidecar_path(&target), b"bad parity").unwrap();
        open(&target, "Pending sidecar generation does not match");
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(
            fs::read(default_sidecar_path(&target)).unwrap(),
            b"bad parity"
        );
    }

    #[test]
    fn missing_or_relative_home_is_not_a_recovery_location() {
        assert!(state_root(None, None).is_err());
        assert!(state_root(None, Some(OsStr::new("relative/home"))).is_err());
        assert!(state_root(None, Some(OsStr::new("/root/../alternative"))).is_err());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                state_root(Some(OsStr::new("/var/state")), None).unwrap(),
                Path::new("/var/state/aerovault/journals")
            );
            assert!(state_root(Some(OsStr::new("relative")), None).is_err());
        }
    }
}
