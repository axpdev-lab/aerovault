# Changelog

All notable changes to the `aerovault` crate are documented here.

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
