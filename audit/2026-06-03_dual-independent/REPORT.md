# Round 2: AeroVault Dual-Independent Cross-Audit

**Date:** 2026-06-03. **Type:** two fully independent reviewers auditing the
identical commits, with separate proof-of-concept work. **Initial verdict:**
unanimous NO-GO. **Post-remediation:** all findings fixed; v4 development cleared
to start.

## Method

Two reviewers audited the same crate and application commits independently
(`aerovault 0.4.0` resolved in both). Because the inputs were identical, an
agreement between them is a cross-validated signal rather than a single opinion.
Each read the code from primary sources and built / ran / exercised it, including
adversarial harnesses and measured allocations. Both reached NO-GO independently,
so the verdict did not depend on any single contested finding.

The cryptographic core was confirmed sound by both reviewers (the v3 file-id-bound
chunk AAD from round 1 verified). The blockers were in the integration layer and
in two crate paths.

## Findings

Confirmed: **3 high, ~10 medium, plus low/info.** Layer tags: **[crate]** issues
live in this repository; **[app]** issues live in the
[AeroFTP](https://github.com/axpdev-lab/aeroftp) application.

### High

| ID | Layer | Title | Mechanism | Fix | Status |
|----|-------|-------|-----------|-----|--------|
| AV-001 | [crate] | Symlink write-through on extract | Extraction opened the output path without refusing a symlink, so a pre-planted destination symlink redirected decrypted plaintext to a file outside the extraction root, overwriting it. Found by both reviewers with independent proof-of-concept. The application's own v3 path was confirmed safe (it replaces via rename). | Open the output with `O_NOFOLLOW` plus `create_new`, verify the opened descriptor's device / inode against the path, and re-check canonical containment at use time. | **Fixed in 0.4.1.** |
| AV-002 | [app] | Reserved-key disclosure / 2FA disable | The credential store enforced its reserved-key filter only on `store()`, not on `get()` / `delete()`, so the public credential API could read the `totp_secret` (clone the second factor), delete it (disable 2FA), or read the master password hash (offline crack). | Apply the reserved-key guard to `get` / `get_secret` / `delete`, with an internal split for legitimate system reads. | **Fixed** (app). |
| AV-003 | [app] | "Standard" level KDF / cipher misrepresentation | The GUI "Standard" level advertised AES-256-GCM with Argon2id but created a legacy v1 WinZip AE-2 container (PBKDF2-HMAC-SHA1 at 1000 iterations plus AES-256-CTR). | Route "Standard" to the v2 stack (Argon2id plus AES-256-GCM-SIV) so the container matches what the UI claims. | **Fixed** (app). |

### Medium

| ID | Layer | Mechanism | Fix | Status |
|----|-------|-----------|-----|--------|
| AV-006 | [crate] | An unauthenticated per-chunk length prefix was read into an allocation before validation, enabling a denial-of-service (process abort under constrained address space; RSS amplification bounded by delivered file size otherwise). Confirmed by both reviewers. | Validate each per-chunk length against the header chunk size plus AEAD overhead and the bytes remaining in the file before allocating. | **Fixed in 0.4.1.** |
| AV-CONCURRENCY | [app] | A concurrent add to a v3 vault could silently lose an update (no writer lock around open / mutate / save). Reproduced by one reviewer on the application v3 path. | Cross-process write lock plus an open-time generation / MAC check on every mutating operation. | **Fixed** (app). |
| AV-TOTP-HEADLESS | [app] | The headless (CLI / MCP) TOTP path accepted a same-window replay, and the persisted lockout from round 1 was dead code on the live unlock path (a regression caught here). | Persist the replay / rate-limit state off the derived vault key and restore it on both the live and headless paths. | **Fixed** (app). |
| AV-008 | [app] | An AutoKeyring vault with 2FA could not be unlocked headlessly at all (a usability brick that pushed users away from the second factor). | Add a `2FA_REQUIRED` unlock arm to the CLI and MCP (code from an environment variable or a TTY prompt). | **Fixed** (app). |
| AV-009 | [app] | Keystore import peak memory was an unbounded multiple of the size cap. | Early buffer drop plus a decompression cap. | **Fixed** (app). |
| AV-010 | [app] | The WinSCP / FileZilla bridge export wrote credential config world-readable. | Write via an atomic 0o600 helper. | **Fixed** (app). |
| AV-005 | [app] | The v3 extract path was open to a zstd decompression bomb and a duplicate-chunk amplification. | Per-block plaintext cap from the vault's own recorded chunking maximum (clamped to the format ceiling), a bounded decoder, and an anti-amplification early break. | **Fixed** (app). |
| AV-NAMING | [crate/app] | The application's `AEROVAULT3` wrapper-stack format and the crate's `AEROVAULT2` version-3 container both carried a "v3" label, which is a real source of confusion even though each tool round-trips its own format and there is no crypto break. | Publish an explicit format / naming contract documenting the distinct magics and the intentional non-interop. | **Fixed.** Format contract published (app docs). |
| AV-004 | [app] | A temp-cleanup path could zero-fill an arbitrary file via a TOCTOU / missing `O_NOFOLLOW`. | `O_NOFOLLOW` open plus device / inode identity before and after the zero-fill. | **Fixed** (app). |

### Low / Info (summary)

All fixed across the crate 0.4.1 release and the application tranches:

- **[crate] AV-011:** atomic write reported failure-on-success for a vault given a
  bare relative path (empty parent passed to the parent-dir fsync). Fixed in 0.4.1.
- **[crate] AV-012:** the reserved header region was not actually covered by the
  header MAC (a tampered reserved byte went undetected). The region is now carried
  through the header struct so the HMAC-SHA512 covers the full 512-byte header, and
  non-zero reserved bytes are rejected. Fixed in 0.4.1.
- **[app]** v1 ZIP reads bounded per entry and cumulatively; Cryptomator
  `vault.cryptomator` HS256 signature now verified; scrypt log2(N) capped at 20;
  keystore import and v3 extract zeroize the real decrypted material; the legacy
  64 MiB KDF fallback now warns; remote upload confined to the managed temp dir;
  the local "Save" clears the live password and errors are path-redacted;
  vault-history skips ephemeral remote temp paths and tightens its database
  permissions.
- **[app] AV-024:** on open, the wrapper header version and every manifest wrapper
  algorithm id / version are validated and unknown wrappers are rejected (a
  version-confusion guard that also hardens the future v4 format evolution), and
  the data-section read is capped at the file length.
- **[crate] supply chain:** the yanked `aes 0.9.0` reachable through the ZIP / SSH
  dependency stack was bumped to 0.9.1, clearing the audit denial. The AeroVault
  crypto path itself is release-candidate-free.

## Test evidence (current, post-fix)

Run 2026-06-03 on Ubuntu 24.04.4 x86_64, rustc / cargo 1.95.0.

| Gate | Result |
|------|--------|
| crate test suite | 31 passed / 0 failed (plus 1 doctest) |
| crate clippy (all targets) | clean |
| application library test suite | 2074 passed / 0 failed / 8 ignored |
| application vault subset (vs published 0.4.1) | 10 passed / 0 failed |
| application clippy | clean |
| frontend typecheck | clean |
| application `cargo audit` | clean (the yanked `aes` denial cleared by 0.9.1) |

### Reproducible verification (published CLI)

The current secure behavior reproduces with the published crate CLI:
`cargo install aerovault-cli` installs the `aerovault` binary. Captured 2026-06-03
against 0.4.2 (`aerovault --version` reports `aerovault 0.4.2`). The password prompt
is hidden; a 1 MiB random file is the payload.

Create a v3 vault, add a file, confirm the format:

```
$ aerovault create vault.aerovault
Password:
Confirm password:
  Vault created
  Path: vault.aerovault
  Mode: AES-256-GCM-SIV
  Chunk: 64 KiB

$ aerovault add vault.aerovault secret.bin
Password:
  1 file(s) added

$ aerovault info vault.aerovault
Password:
Version: 3
Encryption: AES-256-GCM-SIV
Chunk size: 65536 bytes
KDF: Argon2id (128 MiB, t=4, p=4)
Key wrapping: AES-256-KW (RFC 3394)
Filename encryption: AES-256-SIV
Header integrity: HMAC-SHA512
Files: 1
Directories: 0
Total original size: 1.0 MiB
```

Round-trip is byte-identical:

```
$ aerovault extract vault.aerovault -o out/
Password:
  1 entries extracted to out/

$ sha256sum secret.bin out/secret.bin
f2944773e59726c8c2b01cf36f75e72608ae7679b6f7d724178bbbcdcc93353b  secret.bin
f2944773e59726c8c2b01cf36f75e72608ae7679b6f7d724178bbbcdcc93353b  out/secret.bin
```

A wrong password fails closed:

```
$ aerovault list vault.aerovault
Password:
error: crypto error: key unwrap failed (wrong password?)
```

AV-001 (symlink write-through) now refuses. Pre-plant a symlink where the extract
output would land, then extract: it fails closed and the external target is
untouched, where 0.4.0 would have followed the symlink and overwritten it:

```
$ ln -s VICTIM.txt out/secret.bin
$ aerovault extract vault.aerovault -o out/ -e secret.bin
Password:
error: I/O error: File exists (os error 17)

$ cat VICTIM.txt
ORIGINAL VICTIM CONTENT
```

The two crate hardenings that are not single CLI commands are covered by the test
suite and an adversarial harness: an over-declared per-chunk length (AV-006) is
rejected before any allocation, and a tampered reserved-header byte (AV-012) is now
detected so the open is rejected.

## v4 readiness verdict

**Start the v4 Wrapper-Stack (ECC) development line now: GO.** The security NO-GO is
lifted, the crypto / format core is sound, and the exact v3 surfaces the v4 ECC
track plugs into are present, hardened, and green under test:

| v4 dependency | v3 hook | Test evidence |
|---------------|---------|---------------|
| Scrub identifies damage before decrypt (the core v4 idea) | `cipher_hash` (BLAKE3-256 over ciphertext) separate from the chunk id | a tampered cipher block is detected pre-decrypt: PASS |
| ECC must survive truncation / corruption cleanly | bounds plus range validation plus clean errors | a truncated vault is rejected cleanly, no panic: PASS |
| ECC plugs into the extension directory | extension-directory read plus unknown-critical reject | unknown wrappers are rejected on open |
| Packing underpins compression efficiency | real batching plus pack-offset slicing | pack / dedup / multi-chunk straddle / shared-pack delete: PASS |
| Profile chunking bounds | per-profile bounds | custom and archive bounds round-trip: PASS |
| Dedup correctness | keyed-BLAKE3 chunk id | round-trip and dedup: PASS |

The remediation also made the v4 foundation better, not just safe: the new dispatch
validation (AV-024) rejects any unknown wrapper version or algorithm id on open, so
v3 now fail-closes on a future or unknown wrapper instead of decoding it with the
hardcoded stack. The v4 work extends the allow-list deliberately rather than
inheriting a silent-accept hole. The extract path the v4 scrub loop will exercise
was hardened against a decompression bomb (AV-005), so it starts from a memory-safe
baseline.

### The honest reservation

A full "GA, stable without reservations" claim is **not** yet supported, and the
reason is a validation gap, not a known defect: a live matrix (real GUI render
paths, a real 2FA unlock under the OS keyring, multi-GiB round-trips, crash /
power injection around rename and fsync, hostile bridge fuzzing) was not executed
by either reviewer. That matrix is the gate for AeroVault leaving Beta. It does
**not** block starting the v4 line.

Two other open items, by design rather than defect: the scrub of a damaged header /
manifest block is an open v4 design decision (fixed-rate parity over the header and
manifest, versus a minimal unencrypted block locator), to be settled as the first
v4 step; and the general 7z / tar / rar archive-browser extract paths
(stream-to-disk, low severity) were left unbounded since they are not part of the
AeroVault container surface.

## Versions and sequencing

| Component | Was | Now |
|-----------|-----|-----|
| `aerovault` (library) | 0.4.0 | 0.4.2 published (0.4.1 = audit fixes, 0.4.2 = metadata) |
| `aerovault-cli` | 0.3.5 | 0.4.2 published (realigned) |
| AeroFTP application dependency | 0.4.0 | 0.4.2, integrated; ships end to end in the next AeroFTP release |
