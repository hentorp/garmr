<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Public release process (private → public mirror)

Garmr is developed in a **private** repository and published as deliberate,
reviewed **public release snapshots** — never by pushing private history. This
document describes the repeatable process. The private repository keeps its full
history and stays private; the public repository has its own clean history.

> **Never** copy private `.git` data into the public repo. Do not `git clone
> --mirror`, `git push --mirror`, `filter-branch`, `filter-repo`-then-publish,
> `git replace`, or `git graft` the private repository into the public one.

## Tooling

- [`scripts/public-export.sh`](../../scripts/public-export.sh) — deterministic,
  fail-closed export of a sanitized tree from a private release commit.
- [`scripts/public-verify.sh`](../../scripts/public-verify.sh) — verifies a
  candidate public tree against the release invariants.
- [`public-export.allowlist`](../../public-export.allowlist) /
  [`public-export.denylist`](../../public-export.denylist) — the include/exclude
  policy (fail-closed: allow only listed top-level paths; never copy denied ones).

## Steps

1. **Start from a clean private release commit.** Ensure the private working tree
   is clean and tests/builds pass. The export refuses a dirty tree unless you pass
   `--snapshot` for an explicitly reviewed snapshot.

2. **Export only approved public paths.**
   ```bash
   # from the private repo root
   scripts/public-export.sh --out ../garmr-public --ref <release-commit> --dry-run
   ```
   The export is **tracked-files-only** (`git archive`, so no `.git`, no ignored
   build artifacts), then the denylist is applied, then the allowlist is enforced.
   It writes a file manifest and SHA-256 digests, and runs `public-verify.sh`
   before finalizing.

3. **Apply deterministic sanitization** (already encoded in the allow/deny lists
   and verify patterns): drop `.nornir`, `bench`, internal `docs/`, `vendor/facett`
   and `crates/garmr-map`; replace the workspace license with `AGPL-3.0-only`; set
   the public repository URL; keep vendored `LICENSE` files intact.

4. **Run secret scanning** on the export (`gitleaks detect` / ripgrep patterns)
   and confirm no secrets, private hostnames, or internal identifiers survive.
   `public-verify.sh` greps the `PATTERN:` denylist entries as a backstop.

5. **Run license checks.**
   ```bash
   cargo deny check
   cargo audit
   reuse lint            # REUSE.toml + per-file SPDX headers
   bash scripts/sbom.sh supply-chain/sbom.cdx.json
   ```

6. **Run build + tests** on the export:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features --locked
   # WebUI:
   (cd crates/garmr-webui && trunk build --release)
   ```

7. **Produce a public diff and require human review.** Finalize the export
   (drop `--dry-run`), then in the public repo:
   ```bash
   git -C ../garmr-public add -A
   git -C ../garmr-public diff --staged        # REVIEW every change
   ```
   Do not automate this away — a human reviews the diff before it lands.

8. **Commit into the public repository** (its own history) and **tag** the release
   there. Never import old commits from the private repo.

9. **Repeat per release.** The public repo receives reviewed snapshots and patches,
   not every private commit.

## Invariants (enforced by `public-verify.sh`)

- No `.git` in the tree; no forbidden/internal references; no absolute-path or
  private-git cargo dependencies; no unclear-license vendored deps.
- All required legal files present; workspace license is `AGPL-3.0-only`; no old
  MIT/Apache stubs; SPDX/REUSE coverage; export digests verify.
- Dependency graph resolves `--locked --all-features`.
