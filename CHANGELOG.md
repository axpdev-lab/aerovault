# Changelog

All notable changes to the `aerovault` crate are documented here.

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
