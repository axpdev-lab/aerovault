# Round 1: AeroVault Deep Security Audit

**Date:** 2026-05-30. **Type:** deep single-perspective audit, multi-dimension
review with skeptic verification of every raised finding. **Outcome:** remediated.

## Verdict

AeroVault's cryptographic core is sound. The v2 container uses well-chosen,
correctly composed primitives: AES-256-GCM-SIV content encryption with CSPRNG
nonces, AES-SIV deterministic filename encryption (the zero nonce is correct for
SIV), a ChaCha20-Poly1305 cascade with independent nonces and HKDF
domain-separated keys, Argon2id at 128 MiB / t=4 / p=4 (exceeds OWASP), AES-256-KW
key wrapping, and an HMAC-SHA512 header MAC verified before any header field is
trusted. There were no critical findings and no key-disclosure or
remote-code-execution defects in the crypto itself.

The audit confirmed one high and eight medium issues, all with concrete fixes and
none requiring a change to the on-disk byte format. The single most important one
is an authentication gap, not a crypto flaw.

This round was audit-only; the fixes were landed and verified afterward (see
Remediation).

## Tally

47 findings raised, 45 confirmed against the code, 2 refuted. Confirmed severity:
**0 critical, 1 high, 8 medium, 24 low, 12 info.**

## The 1 high

| ID | Layer | Title | Mechanism | Fix | Status |
|----|-------|-------|-----------|-----|--------|
| TOTP-01 | [app] | TOTP second factor not enforced in the default AutoKeyring vault mode | A user who enabled vault 2FA on a default install got a stored `totp_secret` that was never checked: `init()` loaded the passphrase from the OS keyring, derived the key, and cached it with no TOTP challenge. Enforcement lived only on the master-password path. | Route all unlocks through one gate: `init()` returns `2FA_REQUIRED` for an AutoKeyring vault that has a `totp_secret`, and the key is cached only after a verified code. Byte-format safe. | **Fixed.** App: `init()` returns `2FA_REQUIRED`; headless (CLI/MCP) gate completed and fail-closed. |

## The 8 medium

| ID | Layer | Category | Mechanism | Fix | Status |
|----|-------|----------|-----------|-----|--------|
| CRYPTO-01 | [crate] | integrity bypass | The v2 per-chunk AAD bound only the 4-byte chunk index, reset per file under one master key, so chunks were not bound to their file: an attacker editing a vault could splice file A's chunk N over file B's chunk N and extraction returned wrong-but-authentic bytes. | Bind a per-file id plus chunk count into the AAD (version bump to v3). | **Fixed.** Crate format **v3** (0.4.0): file-id-bound chunk AAD on both AEAD layers. |
| KMH-01 | [app] | memory disclosure | Keystore export/import held the entire decrypted credential set (server passwords, OAuth tokens, API keys) in a non-zeroized map plus JSON buffer. | `Zeroizing` / `ZeroizeOnDrop` on the buffers. | **Fixed.** Sensitive buffers zeroized. |
| KMH-03 | [app] | memory disclosure | `CredentialStore::get` returned every secret (including the TOTP seed on each unlock) as a plain non-zeroized string. | Return zeroizing / secret-wrapped values. | **Fixed.** Key material wrapped / zeroized where it counts. |
| PATH-V3-01 | [app] | path traversal | The draft v3 directory extractor joined unvalidated descendant manifest paths into the output root, so a crafted (authenticated) vault could write outside the chosen folder. | Validate each relative path and assert canonical containment before write. | **Fixed.** v3 extractor validates manifest / extract paths against traversal. |
| CRYPTO-02 | [app] | crypto flaw | scrypt N / r were read from the unauthenticated Cryptomator masterkey file with no bounds: a tampered file could downgrade the work factor toward zero or request a multi-GiB allocation (pre-auth OOM). | Enforce hard min / max on N and require r == 8 before calling scrypt. | **Fixed.** scrypt parameters hard-bounds-validated before the KDF. |
| KEYSTORE-01 | [app] | integrity bypass | Importing an authenticated keystore restored plugin scripts and marked them executable, planting enabled, auto-discovered plugins the user never installed (a defense-in-depth / backup-to-RCE-class gap; actual execution still needed a separate approval). | Never set the exec bit on import; require explicit plugin-install consent. | **Fixed.** Keystore import never sets the executable bit on plugin scripts. |
| ATOM-01 | [crate/app] | durability | The rename-final-to-bak / rename-tmp-to-final / remove-bak sequence left a crash window where the only copy sat at an undiscovered `.bak` with no auto-recovery. | Single-rename pattern (fsync tmp + parent dir, one atomic rename) plus open-time recovery. | **Fixed.** Vault rename / write are fsync-hardened. |
| ATOM-03 | [app] | durability | The legacy v1 ZIP rebuild wrote the whole container and renamed with no fsync: a power loss could replace a full vault with a truncated or empty file. | `sync_all()` the temp file before rename plus parent-dir fsync. | **Fixed.** fsync added on the v1 rebuild path. |

## Verified solid (recorded so it is not re-litigated)

- AES-SIV filename encryption: deterministic zero nonce and SIV key derivation are
  correct.
- The v2 cascade layers the two AEADs correctly with independent nonces and keys.
- v3 binds the block index plus a keyed-BLAKE3 chunk id into the AAD.
- HKDF domain separation, full-entropy per-vault salt, and verify-then-use header
  MAC are correct. The v2 header MAC covers all 512 bytes (only an in-code
  doc-comment understated it).
- v1 / v2 extraction and internal entry-name validation are sound; remote vault
  download / upload / cleanup is hardened.
- Cryptomator content-chunk AAD correctly binds chunk index plus header nonce.
- change_password and compact are crypto-consistent (MAC key preserved, only the
  KEK re-derived).

## Refuted (2)

- A claimed TOTP failed-attempt counter fail-open: the counter behavior was
  acceptable.
- A claimed Cryptomator dir_id path traversal: the derivation cannot escape the
  `d/` root.

## Remediation

Landed in the AeroFTP application (commit `72c59e5b`, "land AeroVault deep-audit
remediation; aerovault 0.4.0 (v3)"), wiring the audited crate `v3` (0.4.0) and the
app-side fixes above, plus a follow-up that persisted the TOTP throttle, added a
replay guard, and capped vault reads. Verified at the time with the TOTP, keystore,
and aerovault library test suites, a clean clippy, and real v2 / v3 byte-identical
round-trips with tamper rejection.

**Note carried into round 2:** the round 1 TOTP throttle / lockout persistence was
later found by the round 2 dual audit to be dead code on the live unlock path (a
regression of the claimed-shipped fix). It was re-implemented correctly in the
round 2 remediation. The TOTP *enforcement* gate from this round (init returns
`2FA_REQUIRED`) was solid; the *throttle persistence* sub-fix was not, and is now
fixed. See [round 2](../2026-06-03_dual-independent/REPORT.md).
