# Changelog

All notable changes to the `aerovault` crate are documented here.

## [0.6.9] - 2026-11-16

### Security

- **A password unlock no longer opens a plaintext container.** `VaultV3::open(path, password)` accepted a plaintext-lane (`.aerozip`) container whatever the password, because that lane has no password and its header MAC key is public. Anyone able to replace a vault file (shared or synced folder, removable media) could swap in a plaintext container built with this crate: the unlock succeeded and files added afterwards were stored unencrypted. The original vault's data was not exposed. `open` now returns the stable error `unencrypted .aerozip archive (plaintext lane), not an encrypted vault: open it with open_plaintext`, decided from the header alone, without reading the payload or touching the file; `open_plaintext` is the only way to open the plaintext lane. Function signatures are unchanged. A caller that opened a plaintext container through `open(path, "")` must switch to `open_plaintext`. The CLI `vault` commands inherit the check.

- **Changing the password refreshes the `.aerocorrect` sidecar.** A sidecar exported before the change kept parity of the old header; header recovery rebuilt that header, so the old password still opened the vault. `VaultV3::change_password` now re-exports `<vault>.aerocorrect` when it exists, and first refuses the change if any block is damaged, so the parity that can still repair it is not replaced (run `repair` first). If the refresh itself fails, the old sidecar is removed, unless another handle has changed the vault in the meantime, and the error says to run `export-parity`; if the old sidecar cannot be removed either, the error says so, since it still accepts the old password. A sidecar kept at a custom path must be re-exported by hand.
- **A vault whose header was recovered from the sidecar can be saved and exported.** The check that the vault has not changed since it was opened compared the recovered header's MAC with the damaged header still on disk, so damage to the MAC made `repair` and `export-parity` report a change by another writer. The check now compares the file as read at open (its length and BLAKE3 hash) with the file on disk, so a header recovered in memory is not taken for a change.
- **Concurrent writers no longer lose updates.** Before, the check that the vault had not changed since it was opened compared only the file length and header, and nothing stopped two writers from passing it at once: both could report success while one change was overwritten (a rename to a name of the same length did not even change the header), and an export could publish a sidecar of an older header, which header recovery could later restore, together with the old password. Now every write takes an exclusive OS lock (`flock`, `LockFileEx` on Windows) on a separate `<vault>.lock` file: v3 saves, `export-parity`, `strip-parity`, a password change with its sidecar refresh, vault creation, every legacy v2 write, and the writes of `correct gen` / `correct repair` (and of the public `verify_repair_sync_file*` and `verify_repair_standalone_file_streamed*` functions). Under the lock, a v3 write checks that the vault file is byte for byte the one its handle read (length and BLAKE3 hash) before replacing it; a legacy write reads the file under the lock. `correct gen` and `correct repair` read the file without the lock; before their write they take the lock of the file they read, vault or not (`correct gen` too, wherever its sidecar goes), and write only if the file still holds the bytes they read (SHA-256): a vault created or saved at that path meanwhile is kept, and the tool fails with `changed while it was being read; retry`. A `<file>.lock` therefore appears next to a file once one of them reaches its write, also when that write is then refused; a verify that finds the file intact takes no lock. Sync tools that call these functions inside a synced folder should not upload that `<file>.lock`. A write that would replace a path that is a symbolic link is refused (vault writes and `correct repair`): the link and its target would lock two different files, and the rename replaced the link with a regular file, leaving the file behind it unchanged; use the target path. `correct gen` through a link still works: it writes `<link>.aerocorrect` as before and takes the lock of the file the link names. Reading through a link is unchanged. A writer that finds the vault locked waits up to 30 seconds, then fails with `vault is locked by another writer`; a failure to create or take the lock reports its cause instead. The lock file is opened without following a symbolic link, a lock path that is not a regular file is refused, and a lock file this user may not write (created by another user) is locked through a read-only handle. Where `<vault>.lock` does not exist and cannot be created (read-only folder or media), nothing is locked: such a process cannot replace the vault there, so an export to another folder still works and a write fails with its own cause. Readers never take the lock. The OS releases it when the holder exits or crashes, and the empty `<vault>.lock` file is left in place on purpose. `tests/concurrent_writers.rs` runs two writers adding files to one vault at once and checks that every add reported as done is in the vault.
- **`export-parity` checks the vault before publishing.** Even without the lock (a writer that does not take it, such as an older version), the export now checks that the vault was not saved since it was read and fails instead of publishing a stale sidecar.
- **`correct gen` no longer writes through a symlink.** The sidecar is written with a temp file and rename, like every vault write, so a symlink planted at the sidecar path is replaced instead of followed. The new sidecar is created private (0600 on Unix) instead of with the default umask, since its parity can rebuild small files.
- **Repair bounds chunk records.** `repair` refuses chunk records above the 64 MiB block limit, or larger in total than the data section, before sizing its buffers. On the plaintext lane those lengths come from an unauthenticated manifest.

### Fixed

- **A rotted plaintext-flag bit no longer blocks header recovery.** With a password, the plaintext branch is taken only when the header also verifies under the public key, so a flipped flag bit on an encrypted vault goes through the encrypted path and its sidecar header recovery.
- **Oversized blocks are refused at write time.** Custom CDC bounds can produce a block above the 64 MiB limit that readers refuse. Such a write now fails and leaves the vault unchanged, instead of sealing content that cannot be extracted.
- **A failed write no longer leaves the open vault half-changed.** When an add, delete, move, rename, copy or directory creation fails, or its save does, the open handle is restored (manifest and data section, including the data a delete had compacted), so a later write or repair on it cannot persist a change the caller was told had failed, such as the removal of a file that was being replaced.
- **Writes no longer overwrite embedded parity with parity of damaged blocks.** On a vault with embedded Error Correction, every save recomputes the parity from the current blocks. Every write and password change is now refused with "run repair" while a block is damaged, before it changes the open handle, instead of replacing the parity that can still repair it. A password change refused this way, or failing to save for any other reason, leaves the open handle on the old password.
- **An empty seeded sidecar no longer hides embedded parity.** With `Both` placement, the sidecar written at creation has no data parity until `export-parity` fills it; repair now falls back to the embedded parity instead of resolving to it.
- **Repair reports damage it cannot fix.** When damaged blocks are found and none can be repaired (no parity, damage beyond the parity budget, or a stale sidecar), `repair` returns an error instead of `Ok` with a zero count. The CLI no longer prints "No repair needed" in that case.
- **Legacy vault writes on Windows no longer delete the vault before replacing it.** `std::fs::rename` already replaces an existing file; removing the vault first meant that a failed rename lost both the vault and its replacement (the temp file is deleted on drop since 0.6.8). A new test forces the commit rename to fail and checks that the original vault is unchanged and still opens; the new CI job runs the suite on `windows-latest` too.
- **Rejected writes wipe the plaintext chunk.** A chunk or small-file pack refused by the content pipeline is zeroized before the error is returned.
- **A save on Windows no longer fails while another process has the vault open.** The vault, its sidecar and a file repaired by `correct repair` were replaced with `MoveFileExW` alone, which fails with "Access is denied" while the destination is open, for example by a reader (readers take no lock). They are now replaced with `std::fs::rename`, which then retries with a POSIX-semantics rename. A test keeps the vault open during a save; the `windows-latest` CI job runs it.
- **`correct repair` flushes the repaired file to disk before it replaces the original**, as vault writes already did, so a crash right after the repair cannot leave an incomplete file in its place.
- **A save records the generation it wrote.** The baseline that later saves compare against is taken from the sealed file before it replaces the vault, not by re-reading the path afterwards, which could already show another writer's change.
- **Extract progress no longer overflows** on manifest sizes whose sum exceeds `u64`.

### Changed

- **Minimum supported Rust version is now 1.89**, declared as `rust-version`, for the standard library file locks used by the write lock.
- **Opening a v3 vault and each v3 save read the whole file once more**, to hash it (BLAKE3) for the check that the vault has not changed since it was opened. A save hashes the bytes it writes as it writes them, so it does not read the new file back. `correct gen`, and a `correct repair` that rewrites the file, read the file once more, under its lock, to check that it is unchanged.
- **Writes through a symbolic link are refused** (see Security, concurrent writers): v3 and legacy writes, vault creation, `export-parity`, `strip-parity`, password changes and `correct repair` (on any file) fail with `is a symbolic link` and name the fix: use the target path. In 0.6.8 they replaced the link with a regular file and left the file behind it unchanged. `correct gen` through a link is unaffected.
- **`correct gen` and `correct repair` leave `<file>.lock` next to the file they wrote** (any file, not only a vault), as vault writers leave `<vault>.lock`.

### Documentation

- The v3 spec now defines the writer lock on `<container>.lock` (section 12).
- The v3 spec now defines header flag `0x01` (`FLAG_PLAINTEXT_CONTENT`) and requires password readers to reject it.
- The v3 spec no longer claims a per-file `file_id` binding, AES-SIV filename encryption or a ChaCha20-Poly1305 cascade for AEROVAULT3; those belong to AEROVAULT2. It now states the actual block and manifest AAD.
- The `fast-kdf-for-tests` guard is described as what it is: it refuses the feature when debug assertions are off.

### Known limits

- **The write lock only coordinates writers that take it.** Versions before 0.6.9, and tools that write the file directly, do not; the check that the vault has not changed since it was opened still refuses most of their interleavings, but not all. On network file systems (SMB, NFS) the lock is only as reliable as the server's lock support; do not share one vault between machines for concurrent writing.

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
