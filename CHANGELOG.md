# Changelog

All notable changes to the `aerovault` crate are documented here.

## [0.7.0] - Unreleased

### Fixed

- Restored open, extraction and writes for large v3 vaults and plaintext archives created by 0.6.8. Version 0.6.9 imposed a default 1 GiB data-section ceiling and a separate 4 GiB generation ceiling. Normal v3 operations now stream the generation hash over the actual file extent and retain the locked generation check before publication. Opening checks the file generation before loading vault data into memory. On filesystems that report sparse extents, generation checks cover allocated ranges and their positions without reading the holes. Plaintext archives validate and load the stored frames in order, leaving unclaimed gaps and trailing padding out of memory. The on-disk format is unchanged.

- When the destination ancestry cannot support a recoverable vault and detached parity pair, creation reports the refusal before acquiring either persistent lock. On Unix, creation that writes a detached sidecar makes missing destination directories private.

- On Linux, new vaults with detached parity can be created in group-writable directories when both destination names are free and the filesystem supports unnamed temporary files. A journal in the user's private state allows a restarted process to finish an interrupted creation. Existing files are preserved if either name is already occupied.

- On Linux, stripping embedded recovery or changing the password with a detached sidecar can also use private recovery state in group-writable directories. On supported filesystems, atomic exchanges retain the displaced files while the vault and sidecar are published. An interrupted update temporarily blocks normal reads until recovery can verify both generations. Existing adjacent recovery journals remain supported.

- On Linux, recovery cleans up interrupted pair preparation before a retry. If a different XDG state directory was used before a later save, AeroVault can continue to normal vault authentication once the earlier journal proves its exchange or rollback finished. In that case it retains the earlier journal and recovery copies in private state, with one retained slot per vault and state directory.

- Plaintext archives can repair damaged frames without loading intervening gaps. Scrub reports the on-disk offsets and repairs keep existing frames at those offsets.

- If a stale detached sidecar leaves damaged blocks unrepaired, `vault repair` now exits with an explicit error. Version 0.6.8 could exit successfully with the damaged blocks still present.

- On Linux, paired publication can use `~/.aerovault-state/journals` when a writable ancestor rules out the normal XDG state directory. AeroVault creates `~/.aerovault-state` with mode 0700 only when that fallback is needed. Opening checks the current XDG directory, the default state directory, and the fallback. If an interrupted update used a different custom XDG directory, restore the prior `XDG_STATE_HOME` before reopening. Recovery reports a conflict when more than one journal is found for the same vault.

### Added

- Embedders can set a stored-data budget with `VaultV3Limits` and the `*_with_limits` APIs. An open handle keeps its budget for later writes. The existing opt-in `AEROVAULT_V3_DATA_BUDGET_BYTES` setting still applies to callers that use the original entry points.

## [0.6.9] - 2026-11-19

### Security

- **A password unlock no longer opens a plaintext container.** `VaultV3::open(path, password)` accepted a plaintext-lane (`.aerozip`) container whatever the password, because that lane has no password and its header MAC key is public. Anyone able to replace a vault file (shared or synced folder, removable media) could swap in a plaintext container built with this crate: the unlock succeeded and files added afterward were stored unencrypted. The original vault's data was not exposed. `open` now returns the stable error `unencrypted .aerozip archive (plaintext lane), not an encrypted vault: open it with open_plaintext`, decided from the header alone without reading its payload. A pending strip transaction is recovered first and may restore the vault/sidecar or retire its journal before this rejection; otherwise rejection leaves the files untouched; `open_plaintext` is the explicit plaintext-unlock entrypoint. Function signatures are unchanged. A caller that opened a plaintext container through `open(path, "")` must switch to `open_plaintext`. The CLI encrypted unlock/extraction paths inherit the check; parity export and parity stripping also accept plaintext archives and do not authenticate an encrypted unlock. To extract an unencrypted archive explicitly, use `aerovault vault extract archive.aerozip --plaintext -o ./out`; this route reads no password and never acts as an automatic fallback.

- **Changing the password publishes the vault and default recovery as a recoverable pair.** A sidecar exported before rotation could reconstruct the old header and keep the old password working. When the default sidecar exists, rotation now stages the new vault and new-header recovery together, retains private rollback copies and publishes the bounded pair journal before either replacement. Reopening after an interruption restores the old pair or recognizes a completed new pair before trying a password. A completed rotation rejects the old password, including through header recovery. A failed preparation leaves the originals intact; an error after publication reports the on-disk state and retains recovery material when needed. Detached or embedded parity still requires intact blocks before rotation. With no default sidecar, rotation retains its atomic single-file save. Custom-path or externally copied backups must still be re-exported or retired explicitly. The default sidecar guard is held throughout; symbolic or unrecognized automatic destinations are refused.
- **A vault whose header was recovered from the sidecar can be saved and exported.** The check that the vault has not changed since it was opened compared the recovered header's MAC with the damaged header still on disk, so damage to the MAC made `repair` and `export-parity` report a change by another writer. The check now compares the file as read at open (its length and BLAKE3 hash) with the file on disk, so a header recovered in memory is not taken for a change.
- **Concurrent writers no longer lose updates.** Before, the check that the vault had not changed since it was opened compared only the file length and header, and nothing stopped two writers from passing it at once: both could report success while one change was overwritten (a rename to a name of the same length did not even change the header), and an export could publish a sidecar of an older header, which header recovery could later restore, together with the old password. Now every write takes an exclusive OS lock (`flock`, `LockFileEx` on Windows) on a separate `<vault>.aerolock` file: v3 saves, `export-parity`, `strip-parity`, a password change with its sidecar refresh, vault creation, every legacy v2 write, and the writes of `correct gen` / `correct repair` (and of the public `verify_repair_sync_file*` and `verify_repair_standalone_file_streamed*` functions). Under the lock, a v3 write checks that the vault file is byte for byte the one its handle read (length and BLAKE3 hash) before replacing it; a legacy write reads the file under the lock. `correct gen` and `correct repair` read the file without the lock; before their write they take the lock of the file they read, vault or not (`correct gen` too, wherever its sidecar goes), and write only if the file still holds the bytes they read (SHA-256): a vault created or saved at that path meanwhile is kept, and the tool fails with `changed while it was being read; retry`. A `<file>.aerolock` therefore appears next to a file once one of them reaches its write, also when that write is then refused; a verify that finds the file intact takes no lock. Sync tools that call these functions inside a synced folder should not upload that `<file>.aerolock`. A write that would replace a path that is a symbolic link is refused (vault writes and `correct repair`): the link and its target would lock two different files, and the rename replaced the link with a regular file, leaving the file behind it unchanged; use the target path. `correct gen` through a link still works: it writes `<link>.aerocorrect` as before and takes the lock of the file the link names. Healthy reading through a link remains supported; automatic encrypted-header recovery uses the physical container namespace refreshed by password rotation. Alias-local parity can still recover an authenticated manifest. A writer that finds the vault locked waits up to 30 seconds, then fails with `vault is locked by another writer`; a failure to create or take the lock reports its cause instead. The lock file is opened without following a symbolic link, a lock path that is not a regular file is refused, and a lock file this user may not write (created by another user) is locked through a read-only handle. Where the source lock file does not exist and cannot be created (read-only folder or media), `export-parity` and header/manifest recovery may continue reading without that source guard; every replacing write requires a real lock and fails before writing when it cannot take one. An unlocked export can be overtaken after its generation check. Lock files end in `.aerolock`, a name no write of this crate replaces: a vault write, an `export-parity --out` or `correct gen --out` target, or a `correct repair` of a file whose name ends in `.aerolock` is refused, and an extracted entry with such a name is written only where no file exists (an empty entry over an empty file, as when a folder of vaults is extracted again, keeps the file), so the lock file of a vault cannot be replaced while a writer holds it. Every sidecar destination, including the default `<file>.aerocorrect` and the sidecar seeded at creation, is also written under the lock of that path, so it cannot replace a vault that another writer is saving there (an empty `<output>.aerolock` then appears next to it); an output that is the file being read (or the input link itself) is refused, and an eligible explicitly selected output path that is a symbolic link is replaced while its destination namespace remains locked (the rename replaces the link, not the file it names). The name is compared as case-insensitive file systems see it (any case, the Kelvin sign for `k`, trailing dots and spaces, the characters HFS+ ignores), and extraction refuses to create a folder with such a name taken from the vault, which would block that vault's writes (folders in paths the caller passes are the caller's choice). On Windows the lock file is opened without delete sharing, so while a writer holds or waits for it no other program can replace or delete it; a writer that finds it held open with delete access by another program waits as for a held lock. An existing vault takes its lock file name from its real name, so a short (8.3) name or a trailing dot or space reaches the same lock file; where the file system does not report the real name (some network and RAM-disk drivers), trailing dots and spaces are dropped from the given name. Opening a v3 vault hashes the file after checking its header and before decoding the rest, and refuses a file whose start or length changed in between, so a writer that does not take the lock and rewrites the file in place during the open leaves a baseline the next save refuses. Healthy readers normally take no lock; header or manifest recovery reopens under source coordination, and a pending pair transaction requires the locks needed to recover it. The OS releases it when the holder exits or crashes, and the empty `<vault>.aerolock` file is left in place on purpose. `tests/concurrent_writers.rs` runs two writers adding files to one vault at once and checks that every add reported as done is in the vault.
- **`export-parity` checks the vault before publishing.** Right before it publishes the sidecar, the export checks that the vault was not saved since it was read, and fails instead of publishing a stale sidecar. While the export holds a real source lock, writers that take it cannot save between the check and publication. An export that cannot create the source lock on read-only media can be overtaken in that window; for a writer that does not take it (an older version, a manual copy) the check catches a save made before it, not one made between the check and the publication.
- **`correct gen` distinguishes automatic sidecars from explicit output.** Without `--out`, a symbolic link at `<file>.aerocorrect` is preserved and generation fails. Explicit output selection permits replacing the link under its destination namespace lock, without following its target, using a temp file and rename. The new sidecar is created private (0600 on Unix), since its parity can rebuild small files.
- **Repair bounds chunk records.** `repair` refuses chunk records above the 64 MiB block limit, or larger in total than the data section, before sizing its buffers. On the plaintext lane those lengths come from an unauthenticated manifest.

### Fixed

- **Detached creation stages both files before publication.** Replacing creation retains the old vault and sidecar, including an absent original sidecar, in the recoverable pair journal. A failure before the second publication restores the original state.
- **Password rotation recovers as a pair.** When the default sidecar exists, the new vault and its new-header parity are staged together behind the restart journal, so an interruption cannot expose an unjournaled new-vault/old-header pair. Rotation without a default sidecar remains a single-file save.
- **Windows paired publication preserves file security.** Private staging restricts access to the owner and SYSTEM. Publication and rollback restore the original owner and DACL or refuse if they cannot do so.
- **Reconstruction bounds its working set.** AVEC shard geometry must match the generator rule for its protected stream and data-shard count before zero-padding or shard allocation; serialized recovery byte caps are retained.
- **Automatic recovery destinations preserve unrecognized files.** Vault exports, creation, rotation and standalone generation accept only bounded recognizable sidecar framing before refreshing an existing automatic destination. Explicit output selection retains replacement semantics.
- **Directory spellings never shorten a write target.** Trailing separators and terminal dot components are refused before basename selection.

- Password-based `VaultV3::open` and CLI unlock/extraction enforce encrypted-only opening. The read-only `export-parity` and explicit `strip-parity` operations also support plaintext archives; they do not provide password-authenticated unlocking and must not be used to classify a container as encrypted.

- **Detached recovery is checked under both locks.** Ordinary mutations hold the vault and default-sidecar locks before checking pre-mutation damage and through commit. A recovery file published before those locks are acquired cannot be invalidated by a damaged-data write; an empty creation seed still permits salvage.
- **Recovered manifests keep their usable parity.** Export refuses a manifest recovered on open until `repair` persists it. It cannot replace the only usable manifest parity with parity over damaged on-disk bytes. Repair rejects mismatched chunk map keys and record identities before saving, so it cannot report failure after writing a zero-count repair.
- **Legacy password rotation streams the unchanged body.** It validates the bounded manifest through the opened regular-file handle, copies the remaining body into an atomic replacement, and preserves the original container version. Large vaults no longer require a growing whole-file allocation for this operation.
- **Locks stay with their acquired namespace.** Ignored filename characters are removed before trailing dots/spaces are trimmed. Parent paths are anchored before lock/output selection, and reusing a source guard requires the actual held lock identity. Destination validity is decided by the destination filesystem rather than a universal UTF-8 byte limit.
- **Vault sidecar parsing is bounded before allocation.** Expected segment and file-size limits apply before legacy locator allocation or checksum scanning. Recovery reads only the selected bounded parity region, while valid legacy v1 sidecars remain readable.
- **Writer tests cover stale handles and exact refusals.** A directed two-handle case complements the concurrent stress test; unrelated errors containing `blocked` or `changed` are rejected. Truncation coverage includes both legacy versions and both encryption modes. CI additionally exercises macOS and HFS+ filenames.

- **A rotted plaintext-flag bit no longer blocks header recovery.** With a password, the plaintext branch is taken only when the header also verifies under the public key, so a flipped flag bit on an encrypted vault goes through the encrypted path and its sidecar header recovery.
- **Oversized blocks are refused at write time.** Custom CDC bounds can produce a block above the 64 MiB limit that readers refuse. Such a write now fails and leaves the vault unchanged, instead of sealing content that cannot be extracted.
- **A failed write no longer leaves the open vault half-changed.** When an add, delete, move, rename, copy, directory creation or repair fails, or its save does, the open handle is restored (manifest and data section, including the data a delete had compacted), so a later write or repair on it cannot persist a change the caller was told had failed, such as the removal of a file that was being replaced.
- **Writes preserve usable parity while data is damaged.** On a vault with embedded Error Correction or a default detached recovery payload, ordinary writes are refused with "run repair" while a block is damaged, before it changes the open handle: a save would recompute embedded parity or invalidate the detached block stream. An empty parsed detached creation seed does not block salvage by deleting damaged files. Password changes with an existing sidecar or embedded parity, and explicit `export-parity`, also refuse damaged blocks before replacing recovery data. A password change refused this way, or failing to save for any other reason, leaves the open handle on the old password.
- **An empty seeded sidecar no longer hides embedded parity.** With `Both` placement, the sidecar written at creation has no data parity until `export-parity` fills it; repair now falls back to the embedded parity instead of resolving to it. Unless forced, `strip-parity` verifies detached data parity against the current intact blocks before removing embedded recovery, including current detached header/manifest parity and container binding. It refuses a symlink sidecar, bounds parity reads by the expected geometry, and refreshes detached recovery for the newly sealed header and manifest. The stripped vault and refreshed sidecar are prepared before publication. Synced on-disk rollback copies and a bounded `.aerostrip` journal survive process interruption: the next open or write under this protocol restores the original pair after a partial publication, or cleans up a completed pair. Recovery refuses unknown/newer generations and retains the rollback copies with an explicit error. Preparation, binding hashes and rollback stream through fixed-size buffers; the first open handle is dropped before building the new sidecar.
- **Repair reports damage it cannot fix.** When damaged blocks are found and none can be repaired (no parity, damage beyond the parity budget, or a stale sidecar), `repair` returns an error instead of `Ok` with a zero count. The CLI no longer prints "No repair needed" in that case.
- **Legacy vault writes on Windows no longer delete the vault before replacing it.** `std::fs::rename` already replaces an existing file; removing the vault first meant that a failed rename lost both the vault and its replacement (the temp file is deleted on drop since 0.6.8). A new test forces the commit rename to fail and checks that the original vault is unchanged and still opens; the new CI job runs the suite on `windows-latest` too.
- **Rejected writes wipe buffered plaintext.** A chunk or small-file pack refused by the content pipeline is zeroized before the error is returned; small-file packs, streaming lookahead, compression scratch, and legacy plaintext chunks also wipe on early read, encryption or output errors.
- **A save on Windows no longer fails while another process has the vault open.** The vault, its sidecar and a file repaired by `correct repair` were replaced with `MoveFileExW` alone, which fails with "Access is denied" while the destination is open, for example by a reader (readers take no lock). They are now replaced with `std::fs::rename`, which then retries with a POSIX-semantics rename. A test keeps the vault open during a save; the `windows-latest` CI job runs it.
- **`correct repair` flushes the repaired file to disk before it replaces the original**, as vault writes already did, so a crash right after the repair cannot leave an incomplete file in its place.
- **A save records the generation it wrote.** The baseline that later saves compare against is taken from the sealed file before it replaces the vault, not by re-reading the path afterwards, which could already show another writer's change.
- **A legacy password change no longer breaks a vault replaced after the handle opened it.** `Vault::change_password` wraps the handle's keys in a new header over the content on disk; when `Vault::create` had replaced the vault since the handle was opened, the result could be opened with neither password. It now checks, under the lock, that the manifest on disk decrypts under the handle's key, and otherwise fails (`… is not the vault this handle opened … or its manifest is damaged`) and leaves the file unchanged. The header on disk is not checked, so a damaged header of the handle's own vault is still rewritten.
- **Key buffers are wiped on every error.** Legacy vault creation zeroized its generated master and MAC keys only on success; v3 creation, opening and password changes left the derived and unwrapped keys in memory when they failed between deriving them and storing them in the handle, and the Argon2 and key-unwrap buffers were not wiped when those steps failed. These buffers are now zeroizing ones. Vault creation (legacy and v3) also takes the write lock before it derives any key, so a creation refused by the lock derives none, and legacy creation reads the mode of the vault it replaces under the lock.
- **Extract progress no longer overflows** on manifest sizes whose sum exceeds `u64`.

### Changed

- **The cross-process lock protocol is new in 0.6.9.** Published versions through 0.6.8 do not take these locks; unreleased intermediate builds of this PR are not a mixed-version coordination protocol.
- **Vault names at the filesystem basename limit remain writable.** Lock names normalize case, Unicode and ignored-name characters consistently at every length; when the normalized suffix name would exceed 255 native units, they use a bounded deterministic BLAKE3 name ending in `.aerolock`. Creating detached recovery whose default sidecar name exceeds the limit fails before replacing an existing vault.
- **File and vault reads reject non-regular sources.** Input handles open without waiting on Unix FIFOs and are checked before reading, including generation checks and sidecar reads under a writer lock, so a replaced path cannot stall other writers indefinitely. Ordinary input symlinks remain supported.

- **Minimum supported Rust version is now 1.89**, declared as `rust-version`, for the standard library file locks used by the write lock.
- **Opening a v3 vault and each v3 save read the whole file once more**, to hash it (BLAKE3) for the check that the vault has not changed since it was opened. A save hashes the bytes it writes as it writes them, so it does not read the new file back. `correct gen`, and a `correct repair` that rewrites the file, read the file once more, under its lock, to check that it is unchanged.
- **Writes through a symbolic link are refused** (see Security, concurrent writers): v3 and legacy writes, vault creation, `strip-parity`, password changes and `correct repair` (on any file) fail with `is a symbolic link` and name the fix: use the target path. In 0.6.8 they replaced the link with a regular file and left the file behind it unchanged. `correct gen` and read-only `export-parity` through a link remain supported.
- **Names ending in `.aerolock` are reserved for lock files** (see Security, concurrent writers). A vault, a sidecar or a `correct gen --out` target with such a name cannot be written, and `correct gen` and `correct repair` refuse such a file. Extracting an entry with such a name fails where a file of that name exists, unless both are empty (`extract_all` stops at that entry), and works elsewhere; extracting a folder with such a name fails. On Windows, a new vault path ending in a dot or a space is refused: Windows would create the file without them.
- **`correct gen` and `correct repair` leave `<file>.aerolock` next to the file they wrote** (any file, not only a vault), as vault writers leave `<vault>.aerolock`.

### Documentation

- The v3 spec now defines the writer lock on `<container>.aerolock` (section 12).
- The v3 spec now defines header flag `0x01` (`FLAG_PLAINTEXT_CONTENT`) and requires password readers to reject it.
- The v3 spec no longer claims a per-file `file_id` binding, AES-SIV filename encryption or a ChaCha20-Poly1305 cascade for AEROVAULT3; those belong to AEROVAULT2. It now states the actual block and manifest AAD.
- The `fast-kdf-for-tests` guard is described as what it is: it refuses the feature when debug assertions are off.

### Known limits

- **The write lock only coordinates writers that take it.** Versions before 0.6.9, and tools that write the file directly, do not; the check that the vault has not changed since it was opened still refuses most of their interleavings, but not all. On network file systems (SMB, NFS) the lock is only as reliable as the server's lock support; do not share one vault between machines for concurrent writing.
- **Extraction does not take the lock of the files it writes.** An entry extracted to a path that is a vault replaces that vault without waiting for its writers; extract into a folder that holds no vault you are writing to.
- **Each hard link of a vault is a separate vault to writers.** A write replaces only the name it used, as in 0.6.8, and the lock is per name.

No container-format, encryption-algorithm or key-derivation change.

## [0.6.8] - 2026-10-27

### Security

- **Exclusive temporary vault files.** Legacy vault creation, manifest replacement, compaction and password changes use randomly named, exclusively created files in the destination directory instead of predictable temporary paths. Writes, flush and file synchronization use the open handle before replacement.

### Fixed

- **Existing Unix vault permissions survive replacement.** Regular vault files retain their permission bits during updates, compaction and password changes, with special bits removed. New vaults remain private at0600, and symlink modes are not inherited. This does not preserve ownership, ACLs or extended attributes, and the existing Windows remove-before-rename behavior is unchanged.

No container-format, encryption-algorithm or key-derivation change.

## [0.6.7] - 2026-10-26

### Security

- Require zstd 0.14.3, resolving the old zstd 0.13 / zstd-safe 7 dependency path and its RustSec stream-context, decompression and memory-safety advisories. The container formats and public API are unchanged.

## [0.6.6] - 2026-09-20

No on-disk format change: the cross-impl goldens still pin byte-for-byte, and a container written by an earlier version opens unchanged.

### Changed

- **`chacha20poly1305` 0.10 to 0.11.** The outer layer of the cascade moves to the current RustCrypto AEAD generation. ChaCha20-Poly1305 is RFC 8439 and the crate version does not change it, so the ciphertext a given key, nonce and associated data produce is the same: `crate_opens_and_extracts_golden` reads the fixture written months ago and `golden_is_byte_reproducible` reproduces its bytes exactly. The change is confined to how the API is called: the two AEADs in the cascade now come from different generations of the stack, whose `Aead` and `KeyInit` traits share their names, so ChaCha's are imported under their own names instead of shadowing AES-GCM-SIV's, and the nonce is built as an array rather than through the removed `from_slice`. The benefit is for the consumer: an application that also uses `chacha20poly1305` directly no longer has to hold 0.10 back for this crate, and carries one copy of the dependency instead of two.

## [0.6.5] - 2026-09-09

### Added

- **`fast-kdf-for-tests` feature: derive with the cheapest Argon2id profile (8 MiB, t=1) instead of the audited 128 MiB / t=4, for a consumer's test suite only.** AeroFTP's tests create and open thousands of vaults per run and spent 1722 s in the KDF alone. The profile is a format constant, not a header field, so a vault written under the feature cannot be opened by a production build: the feature is refused at compile time in any non-debug build (`compile_error!`), and the audited numbers stay reachable by name (`AUDITED_ARGON2_M_COST`, `AUDITED_ARGON2_T_COST`, re-exported at the crate root). No change to any derivation without the feature; a test pins the audited profile in both feature states.

## [0.6.4] - 2026-08-31

No code change: this release exists to change the licence.

### Changed

- **Licence: GPL-3.0-only to MPL-2.0.** A GPL-3.0-only crate is effectively unusable as a general purpose Rust library: any distributed work built on it has to be distributed under GPL-compatible terms, which in an ecosystem that runs on MIT and Apache-2.0 means almost nobody can take it. The previous terms protected nothing in practice and only made the crate impossible to depend on. MPL-2.0 is file-level copyleft: `aerovault` can be used inside proprietary software without the licence reaching up into the consuming code, and modifications to `aerovault`'s own files must be made available under the MPL when they are distributed. Private, undistributed changes carry no such obligation. Every source file carries the MPL Exhibit A notice. The Exhibit B notice ("Incompatible With Secondary Licenses") is deliberately **not** applied anywhere: MPL 2.0 section 3.3 is what permits a larger work combining MPL files with GPL code, and that permission is lost if Exhibit B is used, so its absence is what keeps this crate combinable with the GPL-3.0-or-later AeroFTP application that consumes it. Versions up to and including 0.6.3 remain available under GPL-3.0-only and are unaffected.

## [0.6.3] - 2026-06-21

No on-disk format change for encrypted `.aerovault` containers or `.aerocorrect` sidecars: existing containers round-trip identically and the cross-impl goldens still pin byte-for-byte.

### Added

- **Streaming vault I/O (`#4`).** True streaming seal and extract: content is chunked, compressed, error-corrected, and written without materializing the whole payload in memory, so large vaults are bounded by chunk size rather than file size.
- **Plaintext lane (`#7`), unencrypted.** A compressed + error-corrected container with no encryption and no password (header HMAC keyed by a fixed public integrity key): integrity and recovery, not confidentiality. The public format name is **`.aerozip`** (see discussion #7); internally the lane carries a neutral codename. Library-only in this release (surfaced to users in a later release).
- **Progress callbacks (`#5`).** Optional progress reporting for `extract` and for error-correction `generate`/`verify`/`repair`.
- **Per-shard health readout (`#9`).** Standalone error-correction `verify` reports per-shard health, not just a single pass/fail.

### Changed

- **Incompressible chunks are stored raw (`#10-B`).** A chunk that does not benefit from zstd is stored uncompressed, skipping a wasted compression pass on already-compressed data.
- **CDC bounds decoupled from the zstd level.** Content-defined chunking bounds no longer scale with the compression level, so the chunk layout is stable across profiles.
- **Plaintext lane uses a neutral internal codename.** The public format name is `.aerozip` (discussion #7); the in-format HKDF domain-separation strings (`AEROVZ_MAC_IKM`, `HKDF_AEROVZ_MAC`, `aerovz_mac_key`) deliberately use a neutral codename (`aerovz`, for AeroVault-Z) so the wire format never carries a public name that might later change. The lane shipped in no prior release, so this is invisible to any existing container.

### Fixed

- **Incompressibility probe now samples across the chunk.** The probe decided compressibility from a single window, so a chunk that was incompressible only in places (e.g. a 16 MiB chunk over mixed data) could waste several MB by storing a partially-compressible payload as raw. The probe now samples head/mid/tail before deciding, recovering the lost ratio. Encode-side only; decode is unchanged.

## [0.6.2] - 2026-06-18

### Security (audit 2026-06-18 remediation)

Hardening from an independent dual blind audit (Claude Opus 4.8 + Codex GPT-5) followed by a two-round adversarial controaudit. No on-disk format change; existing `.aerovault` containers and `.aerocorrect` sidecars round-trip identically.

- **M1 (High):** standalone `.aerocorrect` repair on Windows held the target read handle across the atomic `persist`, failing the rename with `ERROR_ACCESS_DENIED` (the original stayed corrupt) and could leave a decrypted-plaintext temp beside the target on the error branch. The read handle is now dropped before `persist`, and the temp is scrubbed on the persist-error branch.
- **M2 (Medium):** v3 extract could follow a pre-planted intermediate reparse point (a Windows directory junction, no admin needed) out of the destination root. Each path component is now created refusing to follow a pre-existing reparse point, with the canonical parent asserted to stay within the canonical root, on `extract_all`, `extract_entry`, and `extract_file_entry`.
- **M3 (Low):** added an out-of-band `--expect-sha256` authenticity anchor to standalone repair (`correct_repair_anchored`): a sidecar declaring a different content hash is refused before any write. Bare `correct repair` stays an integrity tool; the anchor adds authenticity.
- **M4 (Low):** forged, critical, duplicate, or out-of-range v3 extension-directory entries are now rejected at open, hoisted above the manifest-recovery consumption, so a forged directory fails closed before any use. Full byte authentication of the directory is tracked for a future v2 header.
- **M6 (Info):** documented that `save_open_vault` is generation-check-only (the embedder owns the cross-process lock).
- **M8 (Info):** documented the `cargo-audit` ignore for RUSTSEC-2024-0384 (`instant` unmaintained), with corrected attribution (transitive via `reed-solomon-erasure 6.0.0` -> `parking_lot 0.11`, not the CLI progress stack; not locally fixable while the RS crate pins parking_lot 0.11).

### Error-correction convergence (M7) + AeroSync sidecar API

- **One implementation of the `.aerocorrect` engine.** The AeroFTP application's forked standalone error correction (the `correct` command and the `aeroftp_correct_*` MCP tools) and its AeroSync download error correction now route into this crate instead of an app-local copy, so the format has a single audited implementation. Standalone repair and AeroSync verify/repair share one persist path (one handle-drop site, one M3 anchor). The cross-impl golden (`tests/aerocorrect_cross_impl.rs`) still pins crate-generated sidecars byte-for-byte to the application's output.
- **New public `error_correction::sync` module** (re-exported at the crate root) for windowed-sidecar use cases: windowed `.aerocorrect` generation from a path or from bytes with a per-file size cap and an opt-in minimum-benefit gate (`generate_sync_sidecar_for_file_capped`, `generate_sync_sidecar_for_bytes`, `generate_sync_sidecar_for_bytes_capped`); verify/repair against an out-of-band expected SHA-256 from an on-disk sidecar, an in-memory sidecar, or in-memory bytes (`verify_repair_sync_file_streamed`, `verify_repair_sync_file`, `verify_repair_sync_bytes`); plus `estimate_aerorec_sidecar_len`, `sync_error_correction_sidecar_path`, and `parse_sha256_hex`. The overhead-level constants `ERROR_CORRECTION_DEFAULT_PCT`, `ERROR_CORRECTION_MIN_PCT`, and `ERROR_CORRECTION_MAX_PCT` are now public.

### Notes

- The AeroFTP application pins this release to consume the converged error-correction engine.
- Credit to **Ehud Kirsh** (@EhudKirsh) for the abort-cleanup report that M1 helps close.

## [0.6.1] - 2026-06-17

### Docs

- Switch the README logo, diagrams and document links from repository-relative paths to absolute GitHub URLs so they render on the crates.io page (relative paths only resolve on GitHub). No code change; identical to 0.6.0.

## [0.6.0] - 2026-06-17

### Real AEROVAULT3 container (revision 4)

- Implement the real **AEROVAULT3 container** in the crate (`aerovault::v3`): 1024-byte header, gear content-defined chunking (256 KiB / 1 MiB / 4 MiB), per-chunk zstd, keyed-BLAKE3 128-bit chunk ids with deduplication, small-file packing, an authenticated JSON manifest, and a forward-compatible extension directory. Until now the crate shipped only the legacy AEROVAULT2 lineage (512-byte header, fixed 64 KiB chunks) while its docs described AEROVAULT3, so the published format did not match the published spec. It does now.
- Port is **byte-for-byte** with the AeroFTP application: a deterministic cross-implementation fixture (`tests/aerovault3_cross_impl_v3.rs`) pins the crate's container bytes to a golden produced by the app, so a vault created by either side opens and extracts in the other.
- **Revision 4 = AEROVAULT3 + Error Correction.** Wire the `.aerocorrect` Reed-Solomon codec into the container: embedded (non-critical in-container extension), detached (sibling `.aerocorrect` sidecar, container stays byte-identical to a plain vault), or both. A plain rev. 3 reader still opens a rev. 4 file and skips the non-critical extension; the on-disk major stays 3. Header and manifest parity let a vault with a damaged header or manifest region rebuild from the sidecar on open. Repair is all-or-nothing: every reconstructed block is re-verified against the manifest before the original is replaced.
- Add the AEROVAULT3 surface to `aerovault-cli` under a new `vault` command group (`create`, `add`, `add-dir`, `list`/`ls`, `extract`, `mkdir`, `rm`, `rename`, `move`/`mv`, `copy`/`cp`, `info`, `change-password`, `check`) plus the rev. 4 recovery subset (`scrub`, `repair`, `export-parity`, `strip-parity`). Every command supports `--json`. The top-level commands stay the legacy AEROVAULT2 surface.
- Add the embedder API the AeroFTP application uses to consume the crate without manifest access: `VaultV3::summary` (`VaultSummaryV3`), `EntryInfo::chunk_count`, `VaultV3::resolve_parity_source` parity-source preflight, an optional `VaultTelemetrySink` content-pipeline seam (no-op by default, byte-neutral), and `VaultV3::create_directory` now returning whether the leaf was newly created.
- The shared `aerocrypt` crypto core (Argon2id + AES-256-KW + AES-256-GCM-SIV + AES-256-SIV + HKDF-SHA256 + HMAC-SHA512) is exported as `aerovault::aerocrypt` for reuse, byte-identical to the app's primitives.
- Credit to **Ehud Kirsh** (@EhudKirsh) for driving the AEROVAULT3 wrapper-stack design and the unified `.aerocorrect` direction in AeroFTP issue #162 and discussion #276.

## [0.5.0] - 2026-06-12

### Error Correction (`.aerocorrect`)

- Add the unified detached `.aerocorrect` Reed-Solomon sidecar format (v2) for
  any file, including `.aerovault` containers and arbitrary standalone payloads.
- Self-healing sidecar: the critical locator metadata is stored in a
  triplicated, per-copy-checksummed directory, so a lightly corrupted
  `.aerocorrect` still recovers its file; the bulk parity carries no wholesale
  checksum and rotted shards are routed around by per-shard erasure. Damage past
  the self-heal budget fails closed. Legacy v1 sidecars are still read.
- Add the public `correct_generate`, `correct_verify`, and `correct_repair` API,
  plus `AeroCorrectSidecar` parse / serialize helpers.
- Add `aerovault correct {gen,verify,repair}` to generate, verify, and repair
  standalone files with atomic all-or-nothing replacement on repair.
- Stream generation, verify, and repair in 64 MiB windows; repair reads sidecar
  parity on demand instead of loading the whole sidecar into memory.
- Pin `reed-solomon-erasure` to `=6.0.0` to keep the wire format and codec
  behavior aligned with AeroFTP v4.
- Credit to **Ehud Kirsh** for driving the one-sidecar `.aerocorrect` format
  direction in AeroFTP discussion #276.

## [0.4.2] - 2026-06-03

### Documentation / metadata only (no code or format change)

- Refresh the package description (drop the em-dash, note the CLI).
- README: replace the stale "chunk index AAD" security note with the current
  file-id-bound chunk AAD plus the new extract hardening, and add an
  Acknowledgements section crediting **Ehud Kirsh (E. Kirsh)** for the
  wrapper-stack pipeline model design contribution (AeroFTP issue #162).
- `aerovault-cli` republished at the same version to keep the two crates aligned.

## [0.4.1] - 2026-06-03

### Security (dual-independent audit remediation)

Hardens the v2/v3 extract and atomic-write paths. No format change; all 0.4.0
containers remain readable and byte-identical on re-create.

#### Fixed
- **Symlink write-through on extract (High, AV-001 / CODEX-AV-001).** Extraction
  now opens the output with `O_NOFOLLOW` + `create_new`, verifies the opened
  fd's device/inode against the path, and re-checks canonical containment, so a
  pre-planted destination symlink can no longer redirect decrypted plaintext
  outside the extraction root.
- **Unauthenticated `chunk_len` pre-read allocation (Medium, AV-006 /
  CODEX-AV-002).** Each per-chunk length is validated against the header
  `chunk_size` + AEAD overhead and the bytes remaining in the file before
  allocating, rejecting an over-declared length instead of attempting a giant
  allocation.
- **Relative-path atomic write (AV-011).** `fsync_parent_dir` treats an empty
  parent as `"."`, so creating/compacting/changing the password of a vault given
  a bare relative filename no longer reports failure on success.
- **Reserved header region now authenticated (AV-012).** The 320-byte reserved
  region is carried through the header struct so the HMAC-SHA512 covers the full
  512-byte header, and non-zero reserved bytes are rejected on read.

## [0.4.0] - 2026-06-03

### Container format v3 (file-id-bound chunk AAD)

Closes the deep-audit finding CRYPTO-01 (chunk splicing). The v2 per-chunk AAD
bound only the 4-byte chunk index, reset per file under one master key, so an
attacker who could edit a vault was able to splice file A's chunk N over file
B's and extraction returned wrong-but-authentic bytes.

#### Added
- **v3 chunk AAD** binds a per-file random 16-byte `file_id`, the chunk count,
  and the chunk index, on both the inner AEAD and the ChaCha20-Poly1305 cascade
  outer layer. `file_id` is stored in the AES-SIV-encrypted (authenticated)
  manifest and the header version is covered by the HMAC-SHA512 header MAC, so
  neither can be stripped to force the legacy path.
- **`CreateOptions::with_version`** selects the on-disk version to write
  (default v3, `LEGACY_VERSION` for v2) for migration tooling and backward-compat
  tests. Unsupported versions are rejected at create time.

#### Changed
- Container version bumped 2 to 3 (magic `AEROVAULT2` unchanged). New vaults are
  written as v3.

#### Fixed
- `add_files` now fails closed if the source changes size mid-stream, instead of
  writing a chunk-count mismatch that would make the entry unrecoverable on
  extract.

#### Compatibility
- **v2 containers remain fully readable.** Decryption is manifest-driven (no
  `file_id` means the legacy index-only AAD), and version dispatch accepts both
  2 and 3. There is no in-place v2 to v3 upgrade: existing vaults stay v2 until
  re-created.

#### Acknowledgements
- Thanks to **@EhudKirsh** for sustained community testing of AeroVault across
  releases. Audit remediation and verification by the AeroFTP team.
</content>
