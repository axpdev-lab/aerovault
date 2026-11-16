# AeroVault security model

Threat model for this repository: who can attack it, what they are after, the controls in place, and what is accepted risk. Security scans and reviews start from it; update it when the format, the attack surface or a scope decision changes.

Scope: `axpdev-lab/aerovault` (Rust workspace, v0.6.8): the `aerovault` library crate and the `aerovault-cli` binary. No network service and no infrastructure: it is a library/CLI that reads and writes local files. The AeroFTP app embeds the crate but is out of this document's scope. No infrastructure applies.

Sources: code, `README.md` (Security model section), `docs/*-SPEC.md`, and the three published audit rounds in `audit/` (2026-05-30, 2026-06-03, 2026-06-18).

## Components

| Component | Code | Notes |
|---|---|---|
| **Crypto core** | `aerovault/src/crypto.rs`, `aerovault/src/aerocrypt.rs`, `aerovault/src/constants.rs`, `aerovault/src/v3/constants.rs` | Argon2id (128 MiB/t=4/p=4), AES-256-KW, AES-256-GCM-SIV, ChaCha20-Poly1305 cascade, AES-SIV filenames, HMAC-SHA512 header MAC, HKDF-SHA256, OsRng |
| **V2 container** | `aerovault/src/vault.rs`, `aerovault/src/format.rs` | Legacy `AEROVAULT2` lineage: header/manifest parsing, add/extract/move/copy/compact, change_password, atomic temp+rename writes |
| **V3 container** | `aerovault/src/v3/*` (`vault.rs`, `format.rs`, `manifest.rs`, `block.rs`, `chunking.rs`, `packing.rs`, `ec.rs`, `telemetry.rs`) | `AEROVAULT3` (rev. 3/4): CDC chunking, zstd, keyed-BLAKE3 dedup, packing, extension directory, embedded RS error correction; byte-compatible with AeroFTP |
| **AeroCorrect** | `aerovault/src/error_correction/*` (`mod.rs`, `sidecar.rs`, `sync.rs`) | Detached `.aerocorrect` Reed-Solomon sidecars for any file; generate/verify/repair, anchored repair (`--expect-sha256`), AeroSync windowed API |
| **CLI** | `aerovault-cli/src/main.rs`, `aerovault-cli/src/v3cmd.rs` | Password prompts via `rpassword`, all user-facing commands |
| **Build & release** | `Cargo.toml`, `.cargo/`, `.github/workflows/release.yml`, cargo features `test-vectors`, `fast-kdf-for-tests` | Release binaries for Linux/Windows; dependency pinning (`reed-solomon-erasure = 6.0.0`) |

## Trust boundaries and entry points

1. **Vault / sidecar file bytes -> parser.** Any `.aerovault` (v2 or v3) or `.aerocorrect` file may be attacker-crafted (downloaded, shared, synced from cloud, tampered at rest). Reached by `Vault::open/peek/is_vault`, `VaultV3::open/peek/scrub/repair/recovery_status`, `correct_verify/correct_repair*`, `verify_repair_sync_*`, and the matching CLI commands. Header, manifest JSON, extension directory, chunk lengths, RS grid metadata and segment directories are all attacker-controlled before authentication.
2. **Vault contents -> local filesystem.** Extraction (`extract`, `extract_all`, v3 `extract_entry/extract_all`) writes paths taken from the (authenticated, but possibly attacker-authored) manifest into a user-chosen directory. A vault created by someone else with a known password is a legitimate attacker input.
3. **Local filesystem -> library writes.** Temp files, atomic rename/persist, repair-in-place, change_password, compact: another local user may pre-plant symlinks, junctions/reparse points, or race on shared directories; file permissions of outputs matter.
4. **Password -> KDF.** Password from CLI prompt or embedding app; must not leak (logs, errors, telemetry, temp files, un-zeroized memory).
5. **Library API -> embedder.** Embedders (AeroFTP) pass names/paths; the crate's validation (`validate_entry_name`, `..` checks) is the line of defence.

## Assets

- **Vault plaintext and filenames** (confidentiality) — highest value.
- **Password and derived keys** (master key, KEKs, subkeys).
- **Integrity/authenticity of vault contents** — tampering must be detected (header MAC, AEAD, `cipher_hash`).
- **User files outside the vault** — extraction/repair must never write outside the target or overwrite unrelated files.
- **Recoverability** — repair is fail-closed and all-or-nothing; a corrupt/foreign sidecar must only make repair fail, never destroy good data.
- **Cross-implementation format compatibility** with AeroFTP (pinned fixtures in `aerovault/tests/fixtures`).

## Attackers (all in scope)

- **A1 Offline file holder:** has the vault file (stolen disk, cloud copy) but not the password; goals: recover plaintext/filenames/metadata, brute-force the password, tamper undetected.
- **A2 Crafted-file author:** supplies a malicious `.aerovault` or `.aerocorrect` that the victim opens, verifies, extracts or repairs; goals: path traversal / arbitrary write, memory exhaustion or crash, overwrite of good data, misleading repair.
- **A3 Local unprivileged user** on the same machine: symlink/junction planting, temp-file races, reading world-readable outputs or plaintext temp files.

## Existing controls (from code, README and audits)

- Nonce-misuse-resistant AEAD; per-file `file_id` bound into chunk AAD (anti-splicing/reordering); HMAC-SHA512 header MAC; AES-SIV filenames.
- Entry-name validation (`..` rejected), canonical-path containment checks, `O_NOFOLLOW` + create-new on extraction outputs; reparse-point refusal per path component in v3 extract (audit R3 M2).
- Per-chunk length bounds checks before allocation; EC file cap 1 GiB; 64 MiB windowed EC.
- Atomic temp+rename/persist writes; temp scrub on persist failure (R3 M1); existing vault mode copied without special bits; legacy temp symlinks not followed.
- Repair re-verifies content SHA-256 (and header MAC / manifest `cipher_hash`) before replacing; anchored repair `--expect-sha256` (R3 M3).
- Extension directory: critical/duplicate/out-of-range entries rejected at open (R3 M4); JSON bytes not fully MAC'd (tracked residual, needs a v2 header).
- `save_open_vault` has no cross-process lock: documented that the embedder owns cross-process safety (R3 M6).
- `fast-kdf-for-tests` refused by `compile_error!` in non-debug builds; `test-vectors` replaces the CSPRNG (test-only).
- Passwords zeroized in the CLI after use.

## Out of scope / accepted risk

**Nothing is out of scope**: report everything, including denial of service from crafted files, test-only features, memory/side-channel issues and the AeroCrypt codec. No finding is lowered for being out of scope.

Known, documented design decisions (from the audits): M4 extension-directory residual and M6 no cross-process lock.

## Finding triage

- All three attacker types are in scope and nothing is excluded, so findings keep the severity their exploitability and impact give them.
- Tags per finding: `Component` (table above), `CWE`, `Format` (AEROVAULT2 / AEROVAULT3 / .aerocorrect / n/a), `AuditRegression` (the earlier audit finding ID it re-opens, e.g. `R3-M2`, if any).

## Open questions

- Is AeroFTP's use of the crate (e.g. remote-vault flow, MCP entry points) worth a separate scan of `axpdev-lab/aeroftp`?
- Which asset ranks highest if trade-offs are needed: plaintext confidentiality, integrity, or recoverability? (Assumed for now: confidentiality > integrity > recoverability.)
