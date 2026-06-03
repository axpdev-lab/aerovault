# Changelog

All notable changes to the `aerovault` crate are documented here.

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
