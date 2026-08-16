# Audit coverage — action, call site, contract

Every audited action garmr's own ledger records for the access, lifecycle, and
agent surfaces, with the seam that emits it and its failure contract. Each row
is grep-verifiable: the **Emitted at** column names the file whose source
contains the constant, so
`grep -rn "action::<CONSTANT>" crates/garmr-cli/src` confirms (or refutes)
any row. Constants live in `crates/garmr-audit/src/event.rs`.

Two failure contracts, chosen per action rather than globally:

- **Fail-closed** — the action is *refused* if the ledger append fails. Used
  where an unaudited effect would be worse than no effect (state changes,
  writer transitions, destruction).
- **Best-effort** — the action proceeds and a failed append is logged. Used
  where refusing would deny an analyst a read that changes nothing, or hold a
  session open against its owner's will.

## Read surface

| Action | Emitted at | Contract |
|---|---|---|
| `data.query` | `api/query.rs` (SQL + cold lanes via `record_read`), `api/hsearch.rs`, `api/semantic.rs`, `api/llm.rs` (ask) | Best-effort, digest-only |
| `data.search_sensitive` | `api/query.rs` (the full-text `/api/search` lane) | Best-effort, digest-only |
| `data.export` | `api/query.rs` `record_export_if_bulk` (a response that fills the row cap) | Best-effort, row count in the record |

Read records carry the real principal, a BLAKE3 digest of the query (never its
text), and — when the caller sends `X-Garmr-Client` — an advisory client
marker, so MCP-proxied reads are separable from direct API use.

**Known gap, stated rather than implied:** the person/staff subject pages
(`/api/entity/person/:name`, `/api/entity/staff/:name`) emit **no** audit
record today, and `data.search_sensitive` is best-effort rather than
fail-closed. The plan for this area calls for those pages to be audited
fail-closed (refuse the page if the append fails). Until that lands, do not
read this table as covering subject-page access. A table that overstated its
own coverage would be worse than no table — that contradiction is the exact
thing the audit work exists to eliminate.

## Sessions and configuration

| Action | Emitted at | Contract |
|---|---|---|
| `auth.login` / `auth.login_failed` | `api/passkey.rs`, `api/oidc.rs` | Best-effort |
| `auth.logout` | `api/passkey.rs` (attributed before the cookie clears) | Best-effort — a broken ledger must not hold a session open |
| `config.apply` / `config.rollback` | `api/config.rs` | **Fail-closed** |
| `config.change` | `serve.rs` startup (on-disk override differs from the last audited revision — an out-of-band edit) | Best-effort, both digests in the record |
| `appaudit.config_reload` | `api/admin.rs` (rules hot-reload, audited before effect) | **Fail-closed** |
| `alert.silence` | `api/admin.rs`, `cmd/ops.rs` | **Fail-closed** |

## Lifecycle (backup / restore / HA)

| Action | Emitted at | Contract |
|---|---|---|
| `ha.backup` | `backup.rs` (offline create, after the writer-exclusion fence), `backup_loop.rs` (each scheduled capture) | **Fail-closed** — an append failure refuses the capture; auditing *disabled* is tolerated |
| `ha.restore` | `backup.rs` (into the pre-restore chain, before any mutation) | **Fail-closed** |
| `ha.promote` | `backup.rs` (backup promote), `main.rs` (ha promote) | **Fail-closed** — an unaudited writer transition is refused |

The restore/promote pair deliberately splits across chains: the pre-restore
ledger (preserved at `*.pre-restore-<ts>`) ends with the `ha.restore` record,
and the restored ledger carries the `ha.promote` that binds the same backup id
— a reviewer walks both chains and meets in the middle.

## Agent and MCP

| Action | Emitted at | Contract |
|---|---|---|
| `mcp.register` | `audit.rs` `McpLedgerAudit` (per connected external server) | Best-effort |
| `mcp.call` | `audit.rs` `McpLedgerAudit` (per external tool call, error paths included) | Best-effort |
| `response.decide` | `api/admin.rs` (human approve/deny with the named principal), `cmd/agent.rs` (local CLI decisions) | **Fail-closed** |
| `response.execute` | `audit.rs` `record_execute` | Best-effort — the side effect has already happened |

Inbound MCP reads (the `garmr-mcp` binary proxying the read API) are audited
by the read surface above; the binary stamps every request with
`X-Garmr-Client: garmr-mcp` so those records are attributable to the MCP path.

## What is deliberately not audited

- `/api/tail` — the console polls it on a seconds-scale sweep, so auditing it
  would write records at machine frequency and drown the ledger in noise. The
  surface is a bounded recent-window read (no query text, no subject), which
  is why it — alone among the read lanes — is excluded.
