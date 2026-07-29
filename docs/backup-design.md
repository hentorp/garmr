# Backup, restore & HA promotion (Phase 13)

garmr is single-writer by design. This is the backup/restore/promote design for a
disconnected, air-gap-first SOC: a consistent, signed, content-addressed image of
the whole node, a fail-closed restore, and an audited follower→writer promotion —
all local-first, no mandatory network.

## What is captured

A node's durable state is three stores with **no cross-store transaction**:

- the **warehouse** (`store.warehouse_dir`) — the skade/Iceberg lakehouse:
  immutable content-addressed data files + `catalog.redb`, the mutable snapshot
  pointer;
- the **state DB** (`store.state_db`) — a redb database (cases, env facts,
  registries, budgets, ingest-sequence state, …);
- the **audit ledger** (`audit.dir`) — the append-only, ed25519+blake3 chained
  tamper-evident log.

## Consistency strategy (MLP): offline, writer-stopped

The single-writer interlock is the **redb exclusive file lock**. `garmr backup
create` acquires it over `state.redb` and the warehouse `catalog.redb` with a
NON-destructive probe (`try_acquire_exclusion` — a bare `redb::Database::open`,
never `open_writable`, which would create the Tantivy lock, commit to the state
DB, and run orphan cleanup). A live `serve` holds those locks, so create refuses
fail-closed, and the held guard blocks a writer from starting mid-copy.

**Guarantee:** a quiescent-consistent, integrity-verified image, byte-equivalent
to the on-disk state of a non-mutating node at the instant `serve` was stopped.
Because the node is quiescent, the three subsystem coordinates
(`T_state = T_warehouse = T_ledger`) are mutually consistent by construction.

Online (in-serve savepoint / CoW-snapshot) capture is a designed but **deferred**
follow-up; it must be drilled before anyone relies on it.

## The signed manifest

`backup.json` is a `SignedBackup` over a `BackupManifest`
([`garmr_core::backup`](../crates/garmr-core/src/backup.rs)) that binds ONE
recoverable point: the warehouse (`current_snapshot_id`, metadata location, and
the **absolute warehouse path**), the ledger (`head_seq` + `last_record_hash`),
the state DB (whole-file digest), and every copied file by BLAKE3 digest. The body
is hand-framed (domain-separated, fixed field order, entries sorted) and
ed25519-signed with the audit key. The embedded public key is a display copy —
**never a trust root**; verification requires an out-of-band trusted key.

## Secrets are never captured

The ledger is copied by the SAME allow-list as `garmr audit export` — `segments/`
+ `checkpoints/` + `public_key.hex`, **never `signing.key`**. A denylist
(`signing.key`, `*.key`, `*.pem`, live `garmr.toml`) runs over the whole staged
tree and **fails the build closed** if any secret path slipped in (a create-time
check, not a silent filter). The state DB's `auth` table does hold the
session-cookie MAC key — that is legitimate node state you want to restore, so the
backup captures it; **treat the artifact as confidential and keep it on trusted,
encrypted-at-rest media.**

## Restore: verify-before-apply, atomic, fail-closed

`garmr backup restore <dir> --key <hex>` writes nothing to any target until every
check passes, in order:

1. full `verify` (signature, self-digest, per-file digests + strict-extra +
   symlink/escape rejection, ledger cross-check) — a trusted key is required;
2. `degraded` / garmr-version guards (`--accept-degraded` / `--force`);
3. **path binding** — the target warehouse's canonical path must equal the
   ABSOLUTE path baked into the backup. Iceberg data locations are absolute, so
   restoring elsewhere would resolve **no data** despite matching digests; refused
   fail-closed (or `--force` with a loud warning for a truly equivalent path, e.g.
   a bind mount);
4. **never overwrite a live node** — a bare redb probe fences the target; a live
   `serve` ⇒ refuse.

Then each subsystem is staged into a same-filesystem sibling as a pristine byte
copy (no open before apply), and applied atomically: the live target is moved
aside to `*.pre-restore-<ts>` and the staging renamed into place, with full
rollback on any error. After the swap a **resolvability probe** opens the restored
node read-only and runs a bounded scan at the pinned snapshot; on failure it rolls
back and leaves the target untouched. `--dry-run` verifies + prints the plan.

A restored node is a read-only **follower**: restore writes a `state.redb.restored`
marker, and `serve` refuses to open writable while it exists. Full-text + semantic
search are derived and NOT captured — a restored node has cold search until
reindex. The prior data is preserved under `*.pre-restore-<ts>` (garmr never
hard-deletes).

## HA promotion

`garmr backup promote` turns a restored follower into a writer:

1. **fence** — a bare redb probe proving the lock is FREE on `state.redb` +
   `catalog.redb`; if held, the old writer is still up ⇒ refuse. This is the
   concrete, local, network-free anti-split-brain gate.
2. **audited transition** — a fail-closed `ha.promote` record (refused if auditing
   is disabled), so every promotion survives `garmr audit verify`.
3. clear the restored marker; `serve` then opens writable and a second writer on
   the same store hard-fails (exactly-one-writer, enforced by the OS lock).

## Runbook

```
# on the standby, after confirming the old writer is DOWN:
garmr backup restore /media/usb/garmr-backup --key <audit-pubkey-hex>
garmr backup promote --reason "failover 2026-07-25"
garmr serve
```

RPO = time since the last `create`; RTO = restore + verify + start.

## Honesty: what is NOT proven

The redb-lock fence is authoritative only on a **single host**. True multi-node
failover (separate hosts sharing an object store) still relies on the operational
runbook and stays **UNVERIFIED**, exactly as [ha-design.md](ha-design.md)
documents. The single-host promotion path is the drilled MLP; the online-capture
mode and cross-host failover are the honest deferrals.
