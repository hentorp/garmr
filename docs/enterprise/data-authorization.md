<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: AGPL-3.0-only
-->

# Per-source data authorization

garmr can confine a credential to a subset of event sources. A confined
credential sees those sources and nothing else, across every read lane that
enforces the restriction — and is refused outright on the lanes that cannot.

This page is written to be checkable against the code rather than believed.
Where a guarantee has a limit, the limit is stated here rather than left for a
reader to discover.

## Configuring a scope

A machine credential carries an optional `sources` allow-list:

```sh
curl -X POST https://garmr.example/admin/credentials \
  -H "authorization: Bearer $GARMR_ADMIN_TOKEN" \
  -d '{"name":"hr-analytics","role":"analyst","scopes":["api:read"],
       "sources":["hr-app","hr-db"]}'
```

Passkey identities carry the same field on their stored credential.

Three rules govern how the field is read:

- **Absent means unrestricted.** Every credential issued before scopes existed
  keeps working exactly as it did. Introducing the feature does not narrow
  anyone's access.
- **An empty list means read nothing.** `"sources": []` is a coherent thing to
  issue while a collector is being provisioned. It is *not* read as "no
  restriction" — that reading would turn the most locked-down credential into
  the most permissive one.
- **Rotation inherits the scope.** Rotating a confined credential cannot quietly
  widen it.

For a passkey identity with more than one active credential, the scope is the
**union** of what those credentials grant, and a single unrestricted credential
makes the identity unrestricted. Disabled credentials contribute nothing, so
disabling the wide one narrows the identity on the next request.

## Where a scope is enforced

A confined credential may reach only the lanes below. Anything else is a **403**,
not a filtered answer.

<!-- ENFORCED_LANES:start -->
- `/api/query`
- `/api/query/cold`
- `/api/cold-query`
- `/api/search`
- `/api/hsearch`
- `/api/reproduce`
- `/api/semantic`
- `/api/capabilities`
- `/api/principals`
- `/health`
- `/ready`
<!-- ENFORCED_LANES:end -->

The last four carry no event rows — they report what the build can do, who can
act, and whether the process is alive — so scoping them would confine nothing
while breaking a console that cannot render without them.

This list is an **allow-list**, and a test asserts it matches the `ENFORCED_LANES`
constant in `api/auth.rs`. A deny-list would have to be extended in lockstep with
every endpoint ever added, and the failure mode of forgetting one is a silent
cross-source leak. With an allow-list, forgetting an endpoint means a confined
credential gets an unexpected 403: visible, reported, and fixed in an hour.

Lanes deliberately **not** on the list today:

| Lane | Why |
|---|---|
| `/api/tail` | Streams from the live pipeline with no source predicate. |
| `/api/entity`, `/api/graph` | Answer from the full corpus. |
| `/api/ask` | Runs the agent's own tool loop, which reads unscoped. |

## How enforcement works, lane by lane

**SQL (`/api/query`, both cold lanes).** Every reference to the events table is
rewritten into a source-constrained derived table, so the constraint travels
*with the reference*. Appending a `WHERE` to the outer query would not survive a
`UNION`, a join, or a subquery. Any base table that is not `events` and is not a
CTE defined in the same query is refused, so an evasion has to get a *new table
name* accepted rather than find a spelling of `events` the rewriter missed.

The cold lanes are rewritten **before** the archives are registered, because the
cold tier opens raw files in its own query session and never passes through the
hot-path guard.

**Full-text and hybrid.** The scope is a separate `Must` clause, never merged
into the caller's own source filter, so a request cannot widen its own reach.
This also means a caller who writes `source:other` inside the free-text query —
which the query parser accepts — gets nothing rather than another source's rows.

A source named in a hybrid `filter.source` that the credential may not read is a
403, not a quietly narrowed result: silently dropping it would let the caller
read "no hits" as evidence about a source that was never searched.

**Semantic.** Each vector record carries its origin. Filtering happens before
the per-signal budget is taken, so a confined credential still gets a full
budget of hits it may actually read. A record with no recorded origin is
readable by no confined credential.

## Limits worth knowing before you rely on this

**The `source` label is shipper-declared.** A collector asserts its own `source`
value at ingest. An authenticated collector is bound to an allow-list of the
sources it may claim, so a compromised collector can only forge sources it was
already permitted to send — but until per-collector source pinning is finished,
a source name is an assertion by the sender rather than a fact established by
garmr. Scope confinement is therefore as trustworthy as your collector
credentials. Treat it as a control between *cooperating* teams sharing one
deployment, not as a boundary against a hostile shipper.

**This is data-plane scoping, not multi-tenancy.** Cases, findings, risk scores
and the entity graph are not scoped. A confined credential cannot read those
surfaces at all (they 403), which is honest but blunt. For genuinely separate
tenants — an MSSP serving distinct customers — run **one garmr node per tenant**.
That is the configuration the single-binary design is good at, and it gives
separation at the process and filesystem level rather than at the query level.

**A scope narrows what is read, never how a query is interpreted.** In
particular, applying a scope does not change which retrieval leg acts as the
fusion gate in a hybrid query: the same query returns the same *shape* of answer,
with rows the credential may not read removed.

## Auditing

A read answered under a restriction emits its own audit record naming the
allow-list that applied, in addition to the normal read record. It is a separate
record rather than a flag, so an absent flag on an older record cannot be
misread as "this one was unrestricted" when it may simply predate the feature.
