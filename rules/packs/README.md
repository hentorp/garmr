<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: AGPL-3.0-only
-->

# Day-one detection packs

Three packs, loaded automatically at `serve` start (rule loading is recursive):

| Pack | Source family | What it covers |
|---|---|---|
| `linux-auth` | journald (sshd, sudo, su, PAM, user mgmt) | brute force, privilege escalation, account persistence, lockouts |
| `linux-endpoint` | kunai process telemetry | droppers, reverse shells, temp-path execution, tamper, staging |
| `postgres-dba` | pgaudit via `garmr pgaudit ship` | SQL-to-RCE, privilege grants, credential-table reads, destructive DDL, audit tampering |

Every rule keys on garmr's own event projection (`field_class()` vocabulary),
carries an ATT&CK technique tag, and is exercised by the replay suite in
`crates/garmr-detect/tests/packs.rs`: fixtures are real log shapes — not the
rule's own needle pasted back — and a benign corpus must fire nothing.

## Licensing

Every rule in these packs is **original, garmr-authored work** under the
repository's AGPL-3.0-only license. Nothing here is copied or derived from
SigmaHQ or any other rule corpus — deliberately, so the packs carry no
third-party license obligations.

When you import community rules with `garmr rules import`, you take on the
source corpus's license yourself (SigmaHQ rules are under the Detection Rule
License; the import preserves rule text verbatim with a provenance header, so
attribution survives). A future vendored community pack would ship
`LICENSES/LicenseRef-DRL-1.1.txt` and per-file attribution; these packs need
neither.

## Tuning

Each rule lists its expected false-positive sources. The intended workflow is
garmr's silence machinery (human-approved, audited) for the specific noisy
pairs on your estate — not editing the pack. Rules you disagree with can be
deleted; they return on upgrade only if you re-copy the pack.
