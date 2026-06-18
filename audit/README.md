# AeroVault Security Audits

AeroVault is the encrypted-container engine (the `.aerovault` format) behind
[AeroFTP](https://github.com/axpdev-lab/aeroftp). Its security is reviewed in
periodic adversarial audit rounds. Each round's report is published here **after**
the findings are remediated and the fixes are released.

## Scope

The audits cover two layers:

- **Crate (`aerovault`, this repository):** the container format (v2 / v3), the
  cryptographic core, and the extract / atomic-write paths.
- **Application (AeroFTP):** the integration layer that drives the crate, namely
  the credential store, the TOTP second factor, the CLI / MCP entry points, the
  remote-vault flow, keystore export/import, and Cryptomator interop.

Every finding below is tagged **[crate]** or **[app]**. App fixes ship in the
corresponding AeroFTP release; crate fixes ship on
[crates.io](https://crates.io/crates/aerovault).

## Rounds

| Round | Date | Method | Findings (confirmed) | Outcome |
|-------|------|--------|----------------------|---------|
| [1](2026-05-30_deep-audit/REPORT.md) | 2026-05-30 | Deep single-perspective audit (multi-dimension swarm with skeptic verification) | 0 critical, 1 high, 8 medium, plus low/info | Remediated. Crate `v3` (0.4.0), app fixes landed. |
| [2](2026-06-03_dual-independent/REPORT.md) | 2026-06-03 | Dual independent cross-audit (two separate reviewers, identical commits) | 3 high, ~10 medium, plus low/info | Remediated. Crate 0.4.1 / 0.4.2, app fixes landed. v4 development cleared to start. |
| [3](2026-06-18_phase2-controaudit/REPORT.md) | 2026-06-18 | Dual blind audit + remediation + 3-pass adversarial controaudit | 1 high, 1 medium, 3 low, 4 info, 0 critical | Remediated. Crate 0.6.2 (M1-M8 + the M7 standalone-EC convergence); app fixes landed. Grade A. |

## Current status

- **All findings from both rounds are remediated.** The cryptographic core was
  found sound in both rounds; the issues were in the integration layer and in two
  extract / atomic-write paths.
- The crate fixes are published: `aerovault 0.4.1` (security) and `0.4.2`
  (metadata), with `aerovault-cli` realigned to 0.4.2.
- `aerovault 0.5.0` adds the `.aerocorrect` detached Error Correction sidecar.
  The sidecar format is shared with AeroFTP v4, binds by content SHA-256, and
  repairs only through temp-file replacement after final SHA-256 verification.
  It is additive and does not change the `.aerovault` container layout.
- The v4 Wrapper-Stack (ECC) development line is cleared to start. A full "GA,
  stable without reservations" claim remains conditional on a live validation
  matrix (real GUI, real 2FA unlock, multi-GiB round-trips, crash injection),
  which is a validation gap, not a known defect. See round 2 for the verdict.
- **Round 3 (2026-06-18):** dual blind audit + 3-pass controaudit, grade A,
  0 open findings. `aerovault 0.6.2` ships the M1 (standalone repair) and
  M2/M4/M6 (container) fixes and converges the app's forked standalone
  `.aerocorrect` engine onto the crate (M7) — one audited implementation,
  byte-identical sidecars, verified by an adversarial round-3 pass. AeroCrypt
  (the separate transparent-overlay codec) was out of scope.

## Disclosure policy

Reports are published post-remediation. Findings, severities, code locations, and
fix descriptions are included. For issues that remain reachable on installations
that have not yet updated, the mechanism is described in prose and copy-paste
reproduction recipes are intentionally omitted.

## Method

Reviewers read the code from primary sources and build / run / exercise it
directly (functional round-trips, adversarial proof-of-concept harnesses, real
allocations measured). Round 2 ran two fully independent reviewers against the
identical commits, so an agreement between them is a cross-validated signal rather
than a single opinion.

## Acknowledgement

[Ehud Kirsh (E. Kirsh)](https://github.com/EhudKirsh) is a project contributor:
he designed the AeroVault wrapper-stack pipeline model (AeroFTP issue
[#162](https://github.com/axpdev-lab/aeroftp/issues/162)), co-authored the round 1
remediation, and has provided sustained community testing across releases.
