<!--
Thanks for contributing to garmr. Please fill in every section below.
Keep changes focused; unrelated cleanups belong in their own PR.
-->

## Description

<!-- What does this PR change, and why? Link any related issue (e.g. "Closes #123"). -->

## Security impact

<!--
Does this change touch any security-relevant surface? Consider:
ingest/auth, egress/air-gap, the audit ledger, RBAC/passkey, secret handling,
the agent tool surface, policy evaluation, or the model router.

State "None" only if you are confident there is no impact. If in doubt, describe
what you considered. Do NOT disclose an unfixed vulnerability here — follow
SECURITY.md.
-->

- [ ] This change has no security impact, **or** the impact is described above.

## Tests

<!--
How is this verified? List added/updated tests and how you ran them.
Note: heavy builds/tests can be memory-intensive; describe what you ran.
-->

- [ ] Added or updated automated tests, **or** explained why they are not applicable.

## Documentation

- [ ] Updated relevant docs under `docs/` (or N/A).
- [ ] User-facing strings, comments, and docs are in **English only**.

## License & provenance confirmation

- [ ] My contribution is my own original work (or I have the right to submit it).
- [ ] I license my contribution under the project's terms: **AGPL-3.0-only** for
      code and **CC-BY-4.0** for original documentation.
- [ ] I did **not** copy code/text from a source with an incompatible license, and
      any third-party material is attributed and license-compatible.
- [ ] I added no new external dependency source (only crates.io) and did not
      introduce a disallowed license (`cargo deny check` still passes).

## CLA status

Garmr is dual-licensed (AGPL-3.0-only + commercial), so **every** contribution
requires agreement to the [Contributor License Agreement](../CLA.md). There is no
exemption. You keep your copyright; the CLA grants the relicensing and patent
rights the dual-license model needs.

**Paste this line, exactly, into the PR description** (the `cla` check looks for
it and will fail without it):

> I have read and agree to the Garmr CLA (CLA.md), version 1.0.

- [ ] I have included the CLA agreement line above in this PR's description.
