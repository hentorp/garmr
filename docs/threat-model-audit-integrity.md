# Threat model — audit integrity

Scope: the tamper-evident audit ledger (`garmr-audit`, Phase 1) and the guarantee
that "what garmr saw and did" can be verified offline, after the fact, by a party
who does not trust the running process, the operator, or the disk.

Companion: [threat-model-learning-and-poisoning](threat-model-learning-and-poisoning.md).
Design context: [architecture/adaptive-audit-soc.md](architecture/adaptive-audit-soc.md) §2.

## Assets

- **The audit record of security-relevant actions** — auth (incl. failures),
  queries/searches for sensitive entities, exports, every proposal and decision
  (rule/threshold/prompt/model/baseline), silences, response actions, bundle
  imports, backup/restore, HA promotion, MCP registration/calls, egress-policy
  decisions, and audit-verification failures themselves.
- **The ordering and completeness** of that record (not just individual entries).
- **The signing keys** and the trust root used to verify segments offline.

## Trust boundaries and actors

| Actor | Trust | Can it be adversarial? |
|-------|-------|------------------------|
| Analyst (Analyst role) | semi-trusted | yes — insider, or compromised session |
| Operator/Admin (Admin role) | privileged | yes — the audit must constrain *even the admin* |
| The garmr process | trusted while correct | yes — post-compromise, RCE via injection |
| Disk / filesystem / backup medium | untrusted | yes — offline tampering, bit-rot |
| Log aggregator downstream (journald) | untrusted for integrity | yes |
| Offline verifier (auditor) | the relying party | no (it is who we protect) |

Key stance: the ledger must remain **verifiable by someone who trusts none of the
above except the offline verifier and the public half of the signing key**.

## Adversary goals → defenses

The mandatory tests (brief §TESTING 1–6) map one-to-one to these:

1. **Silently alter a record** (change a disposition, a principal, a timestamp).
   - Defense: each record carries `record_hash = BLAKE3(canonical(envelope) ‖
     previous_hash)`. Altering any field changes `record_hash`; verification
     recomputes and compares. *Test: mutating one record breaks verification.*
2. **Delete a record** (erase evidence of an action).
   - Defense: hash chaining + monotonic `global_sequence`. A missing record
     breaks the `previous_hash` linkage and leaves a sequence gap. *Test:
     deleting a record breaks verification.*
3. **Reorder records** (hide causality).
   - Defense: `previous_hash` fixes a total order; `global_sequence` is strictly
     monotonic. *Test: reordering breaks verification.*
4. **Insert a forged record** (fabricate an approval).
   - Defense: the inserted record cannot both hash-chain to its neighbors *and*
     carry a valid signature under a checkpoint. *Test: inserted records are
     detected.*
5. **Truncate a segment** (drop the most recent, incriminating tail).
   - Defense: periodic **signed checkpoints** commit `(global_sequence,
     segment_id, root_hash)`; a segment shorter than its sealed length, or a
     missing tail past the last checkpoint, is detected. *Test: truncation is
     detected.*
6. **Forge or strip signatures.**
   - Defense: ed25519 (software key) or PKCS#11/HSM signatures over checkpoints
     and sealed segments; verification fails on a bad/absent signature under the
     configured trust root. *Test: invalid signatures are detected.*
7. **Acknowledge a protected change without recording it** (act, then omit).
   - Defense: **outbox / fail-closed.** A high-risk administrative operation
     writes a durable *audit intent* before the effect is acknowledged; if the
     audit write cannot be durably persisted, the operation **fails closed**.
     *Test: protected state changes fail when required audit persistence fails.*

## Residual risks (documented, not hidden)

- **Single-writer key on the same host.** A full host compromise with the signing
  key can forge a *consistent* forward chain from the moment of compromise. It
  **cannot** rewrite already-checkpointed history exported off-box, and cannot
  hide the discontinuity if checkpoints are shipped to an append-only remote or
  a WORM/hardware sink. Mitigations: PKCS#11/HSM signing so the key never lives
  in process memory; frequent checkpoint export; optional external witness.
  This residual is called out in the ADR and the DoD "known residual risks".
- **Content confidentiality vs. integrity.** By default the ledger stores
  **digests + immutable evidence references**, not raw sensitive prompt/log
  content (content modes: `off | digest-only | redacted | encrypted | full`,
  default `digest-only`). This bounds exfiltration risk if the ledger leaks,
  while preserving integrity proofs. `full`/`encrypted` are opt-in per policy.
- **Availability under fail-closed.** Fail-closed on audit-persistence failure
  can deny a legitimate admin action if the disk is full/faulty. Accepted:
  security-relevant admin operations should not proceed unlogged. Non-admin hot
  paths (ingest, detection) do **not** take the fail-closed audit dependency —
  they keep an audit intent but never block ingest, preserving invariant #5 and
  the ≤10% ingest-path budget.
- **Clock trust.** `occurred_at` is source-supplied and may be wrong; the ledger
  additionally stamps a monotonic `recorded_at` and `global_sequence` so ordering
  never depends on wall-clock honesty.

## Canonicalization requirement

Hashing must be over a **deterministic canonical byte representation**, never over
nondeterministic JSON serialization (map ordering, float formatting, whitespace).
The ledger defines an explicit canonical encoding of the `AuditEvent` envelope;
the same bytes are used for hashing and signing, and the verifier reproduces them
independently. This is a correctness prerequisite for tests 1–6.

## Verification interface

- CLI: `garmr audit status | verify | export | checkpoint`.
- Read-only API: audit-verification status (chain intact, last checkpoint,
  segment count, signature validity) — never the raw sensitive content by default.
- Offline: `verify` runs with no daemon and no network, over exported segments +
  a trust root, and is the authoritative check.
