<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: AGPL-3.0-only
-->

# Defensible deletion of cold archives

garmr can expire aged cold archives and prove afterwards what it removed. This
page describes what that proof covers — and, just as importantly, what it does
not, because a deletion claim that a regulator can falsify is worse than no
claim at all.

## Expiring archives

```sh
# Always run the dry run first. It is the default for a reason.
garmr retention expire --older-than 400

# Then, having read the plan:
garmr retention expire --older-than 400 --apply
```

An archive expires only when its **whole window** is older than the cutoff — a
window straddling the boundary still holds retained data, so it stays.

Archives under legal hold are **always** skipped and **always** reported, before
anything else is printed. An operator running an erasure request has to be told
what was *not* deleted, or they will report a completion that did not happen.

```sh
garmr retention hold 2026-01-15            # place
garmr retention hold 2026-01-15 --clear    # release
```

## What a deletion actually removes

For each archive, in this order:

1. **An audit record, before anything is destroyed.** Fail-closed: if the
   tamper-evident record cannot be written, nothing is deleted. An unrecorded
   deletion of evidence is indistinguishable from tampering.
2. **The local file**, if one is present.
3. **The object-store copy**, when `GARMR_S3_*` is configured. This matters more
   than it looks: sealing uploads the archive and then drops the local copy to
   reclaim disk, so on an S3 deployment the bucket usually holds the *only*
   copy. If the remote delete fails, the manifest row is deliberately **kept**
   so a later run can still reach the object — dropping the row would strand the
   data with nothing pointing at it.
4. **The manifest row**, replaced in the same transaction by a deletion record.

## The deletion ledger

```sh
garmr retention deletions
```

Each record keeps the archive's id, **BLAKE3 checksum**, row count, byte size and
exact window, plus when and why it was deleted and which copies went. The
checksum is the point: the manifest row is where it lived, so deleting the row
without a tombstone would leave you able to say *that* something was deleted but
never *which bytes*.

A record whose copies did not all go is listed as `INCOMPLETE`, with a closing
summary. Do not report those as erased.

## Limits — read these before making a claim

**A restore resurrects deleted archives.** `garmr backup --include-cold` copies
the cold directory, the state dump includes the archive manifest, and a restore
puts both back. An archive deleted *after* a backup was taken will return if that
backup is restored. Deletion is therefore a statement about the live deployment,
not about your backup set. If an erasure request has to cover backups, it has to
be carried out against your backup rotation as a separate, deliberate act — and
until every backup taken before the deletion has aged out, the honest statement
is "removed from the live system, and scheduled to age out of backups by
<date>".

**Object stores keep copies you did not ask for.** Bucket versioning,
cross-region replication and provider-side soft-delete can all retain an object
after a successful `DELETE`. garmr issues the delete and records that it
succeeded; it cannot see, and does not claim, what the bucket does afterwards.
Check your bucket's versioning and lifecycle configuration before treating a
remote delete as final.

**A deletion record is not a media-sanitisation certificate.** It records what
garmr verifiably did: which object it deleted, which checksum that object had,
and when. Reclaimed redb pages, filesystem free-space and underlying storage
media are outside what any application can honestly attest to.

**Expiry changes hot-store pruning.** Compaction derives its prune ranges from
the cold manifest, so removing a manifest row means that window is no longer
considered sealed. In practice rows that old are long gone from the hot store,
but the interaction is worth knowing before enabling both on a young deployment.

## Targeted erasure

```sh
# Dry run first — always.
garmr erase --field src_ip --value 203.0.113.7 --reason "DSR-2026-041"
garmr erase --field src_ip --value 203.0.113.7 --reason "DSR-2026-041" --apply
```

Offline (`serve` stopped), selecting on a **closed set** of fields — `host`,
`src_ip`, `user` — because every field must be enforceable in the store, the
compaction hook and the search index alike. The value is exact, never a
pattern; an empty value is refused, not narrowed. An erasure whose time window
intersects a **legal hold** is refused outright — a partial erasure reported as
done is how "we erased them" becomes false.

The erasure places a **persistent tombstone** before deleting anything: every
subsequent compaction applies it again, so a late-arriving row matching the
erased subject — a retried batch, a collector that was offline, an imported
backlog — is removed at the next pass. The store *converges* to erased rather
than passing through that state once.

Full text follows: a host erasure deletes by exact label term; erasure by
`src_ip`/`user` **rebuilds the index from the already-erased store**, because
those values exist in the index only as message tokens and a token predicate
cannot be exact (a phrase over an IP degrades across tokenization into
fragment matching — measured, not feared).

Cold archives are **rewritten in place**: each overlapping archive is thawed
(fetched from the object store if the local copy was dropped at seal time),
its checksum verified *before* its contents are trusted — a rewrite of
tampered bytes would launder the tampering into a fresh, correctly-checksummed
archive — then filtered and resealed, with the manifest recording the checksum
transition. Replacement is installed before anything is destroyed, so a crash
mid-rewrite leaves either the old archive or the new one, never neither.

The command writes a **deletion certificate** (JSON): the predicate, rows
erased, remaining matches after verification, the full-text semantics used,
and every cold archive scanned with its checksum transition — zero-delta
archives included, so "we checked" is distinguishable from "we skipped". An
archive whose rewrite failed is named as **pending** and `complete` stays
`false`; the tombstone is already persistent, so a re-run retries it.

## What is not here yet

Automatic expiry on a schedule. Expiry and erasure are operator-run commands
today, deliberately: the first version of an irreversible operation should be
one a human types.
