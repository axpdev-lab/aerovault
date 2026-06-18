# AeroVault Audit 2026-06-18 — Dual Blind Audit + Remediation + Controaudit (Grade A)

Round 3 of the AeroVault audit programme. An independent **dual blind** security audit of the
`aerovault` crate and its AeroFTP `aerovault_v3` embedder, followed by full remediation and a
**three-pass adversarial controaudit**. The cryptographic core and the v3 vault-container recovery
path were sound and byte-for-byte aligned crate/app from the start. Findings: **1 High, 1 Medium,
3 Low, 4 Info, 0 Critical** — all fixed and verified on both the crate and the app. **Final grade:
A — 0 open findings.**

Every finding is tagged **[crate]** or **[app]**. Crate fixes ship on
[crates.io](https://crates.io/crates/aerovault) (this round: `aerovault 0.6.2`); app fixes ship in
the corresponding AeroFTP release.

## Method

| | Engine A | Engine B | Merge / Phase 2 |
|---|---|---|---|
| Model | Claude Opus 4.8 (1M ctx) | Codex (GPT-5) | Claude (reconcile) + Claude Opus 4.8 controaudit |
| Topology | 1 primary + 2 read-only research sub-agents | 1 agent | three adversarial workflows (7 + 4 + 4 Opus reviewers) |
| Scope | own folder only | own folder only | both, re-verified vs source |

- **Blind and parallel:** two auditors ran the identical brief at the same time, each writing only to
  its own folder, never reading the other. Reaching the same boundary independently is what makes the
  verdict robust.
- **Provenance pinned:** the audited source equals the published crates.io `aerovault 0.6.1`
  (git `4c50fde`) equals the artifact the app compiled; app HEAD `268dfc05`, installed app `4.0.6`.
  No version skew.
- **Library-harness driving** (the CLI is rpassword/TTY-only) plus a live container + standalone
  matrix run on both targets and diffed: round-trip + byte-identity, scrub, repair (embedded and
  detached), header/manifest parity recovery, beyond-budget and foreign-sidecar fail-closed, cross-open
  T5 both directions, standalone `.aerocorrect` gen/verify/repair, kill-mid-seal, stale-lock, and the
  M1/M2 PoCs.
- **Controaudit (Phase 2):** every fix re-verified by independent adversarial Opus reviewers
  instructed to *refute* it, plus completeness critics hunting for new findings — iterated
  fix -> test -> re-verify to 0 open findings. Static gates (`cargo test`, `cargo clippy -D warnings`,
  `cargo audit`) green; a regression test was added per finding.

## Findings and remediation

| ID | Sev | Layer | Finding | Fix | Verification |
|----|-----|-------|---------|-----|--------------|
| M1 | High | crate + app | Standalone `.aerocorrect` repair broken on Windows (target read handle held across `persist` -> `ERROR_ACCESS_DENIED`); the app path also left a decrypted-plaintext temp on the error branch | Drop the read handle before `persist`; scrub the temp on the persist-error branch | 2 previously-red crate tests now green; `repair_restores_and_leaves_no_temp_artifact` asserts byte-restore and no temp artifact; adversarial pass confirmed all persist sites |
| M2 | Medium | crate | v3 extract followed a pre-planted intermediate reparse point (Windows directory junction, no admin) out of the destination root | Create each path component refusing a pre-existing reparse point, then assert the canonical parent stays within the canonical root; on `extract_all`, `extract_entry`, `extract_file_entry` | Junction PoC contained; 2 regression tests incl. the `extract_entry` subtree found by the controaudit |
| M3 | Low | crate + app | Bare `correct repair` reconstructs toward whatever the sidecar declares (integrity, not authenticity) | Out-of-band `--expect-sha256` anchor: a sidecar declaring a different hash is refused before any write; wired through crate lib + CLI and app lib + CLI + MCP | Anchor refuses a mismatched sidecar on every shipped surface; crate + app tests; round-2 re-verify CLOSED |
| M4 | Low | crate | Header MAC authenticates the extension-directory offset/len but not its JSON bytes | Reject critical/duplicate/out-of-range extensions at open, hoisted above the manifest-recovery consumption | `validate_extension_dir_rejects_forged_entries`; full byte-MAC tracked for a v2 header |
| M5 | Low | app | App reported EC as "stub (Phase 1)" while shipping live Reed-Solomon EC | Live RS-EC capability string | grep: 0 stub strings |
| M6 | Info | crate | `save_open_vault` is generation-check-only (no cross-process lock) | Documented the concurrency contract (the embedder owns cross-process safety) | doc verified vs the app O_EXCL lock |
| M8 | Info | crate | `cargo audit`: `instant 0.1.13` unmaintained (RUSTSEC-2024-0384) | Documented ignore with corrected attribution (transitive via `reed-solomon-erasure 6.0.0 -> parking_lot 0.11`; not locally fixable) | `cargo audit` clean |
| M9 | Info | app | A hard crash mid-seal leaves a stale `.{name}.lock` that blocks the next writer | Reclaim a lock whose recorded owner PID is provably dead; reclaim made atomic (rename-aside) | dead-pid reclaimed, live-owner never stolen |
| doc | Low/Info | both | Narrative pipeline order written `compression -> chunking` (reversed vs code/spec) | Corrected to `chunking -> compression` repo-wide (CHANGELOG, RS evaluation, telemetry, architecture primer, AppStream metainfo) | grep over both repos: 0 remaining |

## Round 3 (2026-06-18) — M7 convergence: the standalone EC fork is gone

The standing architectural follow-up from rounds 1-2 was that the app kept a **forked** copy of the
`.aerocorrect` / AVEC / Reed-Solomon engine, so M1 had to be fixed twice and only golden tests bound
the two copies. That fork is now **converged onto this crate** and removed.

- **Crate:** the new `error_correction::sync` module is the single windowed-sidecar implementation
  (generate from a path or bytes with a size cap + an opt-in minimum-benefit gate; verify/repair
  against an out-of-band expected SHA-256 from an on-disk sidecar, an in-memory sidecar, or in-memory
  bytes), re-exported at the crate root. Standalone `correct_generate/verify/repair_anchored` route
  through it; the duplicated `standalone.rs` is removed (one persist-handle site, one M3 anchor).
- **App:** its `error_correction/` is now a logic-free re-export of this crate; the ~3.5k-line fork
  (`sidecar.rs` + `aerosync.rs`) is deleted. The app consumes the crate for both its container path
  (v3, since the v4.0.6 T7 convergence) and now its standalone / AeroSync error correction.
- **Out of scope, untouched:** AeroCrypt (the separate transparent-overlay codec) is a different
  product and was not modified.
- **Adversarial round-3 controaudit (4 Opus reviewers, refute-first):** could not refute the
  convergence. Function bodies are byte-for-byte identical (app fork -> crate `sync.rs`, differing only
  by visibility / cfg / doc / formatting); the cross-impl golden (`tests/aerocorrect_cross_impl.rs`)
  stays byte-identical to the app's pre-convergence sidecar fixture; the M1 handle-drop + temp-scrub is
  intact in both repair paths; no forked EC remains in the app; `parse_sha256_hex` accept/reject is
  unchanged (only an error-message string differs). The in-memory from-bytes API and
  `verify_repair_sync_bytes` are a **deliberate** new public crate surface (documented in the 0.6.2
  CHANGELOG), not an accidental exposure.

## Gates (Windows 11)

- **Crate:** `cargo test --workspace` 116 lib + 3 integration green (both cross-impl goldens);
  `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo audit` exit 0.
- **App:** full lib suite 2185 passed / 0 failed; lib `clippy -D warnings` clean; the default-feature
  lib and the `aeroftp-cli` bin both build against the converged crate.

## Honest residuals (tracked, not blocking)

- **M4:** full byte-authentication of the v3 extension directory needs a version-2 header (would break
  v1 cross-compat); the open-time fail-closed gate bounds it to a clean refusal today.

## Acknowledgement

[Ehud Kirsh (@EhudKirsh)](https://github.com/EhudKirsh) drove the unified `.aerocorrect` direction
(AeroFTP discussion #276) and reported the abort-cleanup gap that M1 + the app's M9 close. The crypto
core (Argon2id / AES-256-GCM-SIV / AES-KW / HKDF / HMAC-SHA512) was found sound and was not modified.
