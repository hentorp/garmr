<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Licensing

garmr uses a **dual-licensing model**. This page summarizes it for readers; the
authoritative texts are the root files it links to. Read it together with the
root [`LICENSE`](../../LICENSE), [`NOTICE`](../../NOTICE),
[`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md),
[`TRADEMARKS.md`](../../TRADEMARKS.md), and
[`COMMERCIAL-LICENSING.md`](../../COMMERCIAL-LICENSING.md).

## Source code — AGPL-3.0-only

All original garmr **source code** is licensed under the **GNU Affero General
Public License, version 3 only** (`AGPL-3.0-only`). The full text is in
[`LICENSES/AGPL-3.0-only.txt`](../../LICENSES/AGPL-3.0-only.txt).

Because garmr is offered under AGPL-3.0-**only**, the "or (at your option) any
later version" clause does not apply. The AGPL is a strong network-copyleft
license: if you run a modified garmr and let users interact with it over a
network, you must offer those users the corresponding source of your modified
version (AGPL §13).

## Original documentation — CC-BY-4.0

Original garmr **documentation** — the prose and diagrams authored by the project
(files under `docs/` and the Markdown guides, unless a file's own header says
otherwise) — is licensed under **CC-BY-4.0**
([`LICENSES/CC-BY-4.0.txt`](../../LICENSES/CC-BY-4.0.txt)). This page carries that
license in its header.

CC-BY-4.0 applies to documentation only, not to source code. Code embedded in
docs (examples, snippets) is offered under the code license (AGPL-3.0-only) so it
can be copied into programs.

## Trademarks — not licensed here

Neither the AGPL nor CC-BY grants any right in the **garmr** name, logo, or visual
identity. All such rights are reserved by Vetra Automation AB. Ordinary, truthful
references ("works with garmr", "a fork of garmr") are fine; presenting a fork as
an official release, or using the marks to imply endorsement, requires written
permission. See [`TRADEMARKS.md`](../../TRADEMARKS.md).

## Third-party components — their own licenses

garmr includes third-party components — including the crates it depends on and the
subtrees vendored under `vendor/` (skade, znippy, znippy-zoomies) — that remain
under **their own licenses and copyrights**. garmr as a combined work is
distributed under AGPL-3.0-only, but each third-party component keeps its original
license; the Vetra Automation AB copyright does not extend to third-party files.
The per-component inventory is [`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md),
and the full transitive dependency license report is generated separately by the
release process (`docs/legal/dependency-license-report.md`). Each vendored
component keeps its own `LICENSE` file in place — do not remove them.

## Commercial licensing — available separately

The AGPL's network-copyleft obligations do not suit every organization. As the
copyright holder of the original code, Vetra Automation AB can offer the **same
code under separate commercial terms** — for example, to embed or modify garmr
without the AGPL's source-availability obligations, or to obtain a warranty,
indemnity, or support the open-source license disclaims.

This is a possibility, not an automatic grant: **no commercial license exists
until Vetra Automation AB and the licensee execute a written agreement.** Until
then, your use is governed solely by AGPL-3.0-only. See
[`COMMERCIAL-LICENSING.md`](../../COMMERCIAL-LICENSING.md).

## Not legal advice

This page and the accompanying legal files are **informational and not legal
advice**. AGPL-3.0-only imposes real obligations. Organizations should obtain
their own legal review before deploying, modifying, or redistributing garmr.

---

SPDX summary: `AGPL-3.0-only` (code) · `CC-BY-4.0` (original docs). Per-file
`SPDX-License-Identifier` headers are authoritative where present.
