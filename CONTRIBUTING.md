<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing to Garmr

Thanks for your interest in Garmr. It is an early **alpha**, so interfaces, schemas,
and internals change often and without compatibility guarantees before `1.0`.

## Before you start

- **Security issues:** do **not** open a public issue. Follow [`SECURITY.md`](SECURITY.md).
- **Contributor License Agreement:** Garmr is dual-licensed (AGPL-3.0-only +
  separate commercial terms). Contributions require agreement to the
  [`CLA`](CLA.md). You keep your copyright; the CLA grants the relicensing and
  patent rights the dual-license model needs. Add this line to your first PR:
  > I have read and agree to the Garmr CLA (CLA.md), version 1.0.
- **Code of Conduct:** participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- **License of your changes:** code is AGPL-3.0-only; original docs are CC-BY-4.0.
  Add SPDX headers to new files (see below). Do not add SPDX/AGPL headers to
  vendored, generated, or third-party files.

## Development setup

See [`docs/development/build.md`](docs/development/build.md) and
[`docs/development/testing.md`](docs/development/testing.md). In short:

```bash
# format, lint, test
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# repo gates (fast, no build needed) — the same scripts CI runs
bash scripts/check-doc-consistency.sh   # docs still match the code
bash scripts/check-actions-pinned.sh    # every external Action is SHA-pinned
```

Garmr vendors some dependencies under `vendor/` (skade, znippy, znippy-zoomies) so
the build is self-contained; the WebUI (`crates/garmr-webui`) is a separate
WASM workspace built with `trunk`.

## Making a change

1. **Open an issue first** for anything non-trivial, so we can agree on the
   approach before you invest time.
2. Branch from `main`. Keep changes focused.
3. **Tests are required** for behavior changes — especially anything touching
   ingest, auth, policy, detection, or the audit ledger. Security-relevant changes
   need tests that demonstrate the safe behavior (e.g. fail-closed, bounds enforced).
4. Update documentation when behavior changes. Docs must match runtime behavior —
   do not describe capabilities the code does not have. `scripts/check-doc-consistency.sh`
   enforces this for the load-bearing claims (bind defaults, fail-closed gates,
   ingest limit constants, feature names, version references, cross-doc links).
5. Run fmt + clippy (`-D warnings`) + the test suite and both repo gates locally.
6. Do **not** commit secrets, real hostnames/IPs, personal data, or internal
   infrastructure details. CI runs secret scanning and a "no private references"
   check.

## Pull requests

Fill out the PR template ([`.github/pull_request_template.md`](.github/pull_request_template.md)),
including **Security impact**, **Tests**, **Documentation**, **License & provenance**,
and **CLA status**. The CLA section is **not** optional: the `cla` check requires
the agreement line from [`CLA.md`](CLA.md) in your PR description, and a PR without
it will not be merged. Merges use squash; keep the PR title in
[Conventional Commits](https://www.conventionalcommits.org/) style
(e.g. `fix(ingest): …`, `feat(webui): …`, `docs: …`).

## SPDX headers

New Rust/source files:

```text
// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only
```

New original Markdown docs:

```html
<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->
```

## Provenance

If you include any code you did not write, disclose its source and license in the
PR, and confirm it is compatible with AGPL-3.0-only. Do not paste code of unknown
origin. See the [`CLA`](CLA.md) §4.
