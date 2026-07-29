# garmr WebUI — microcopy standards

Plain language, specific verbs, honest states. Every user-facing string should let a user who did
not build garmr know what will happen and whether it is safe. These rules are enforced by the
terminology glossary (`terminology.md`) and applied incrementally across the console.

## Buttons name their consequence

A button label is a verb + its object, not a bare verb. The user should not have to read the
surrounding context to know what a click does.

| Avoid | Prefer | Why |
|---|---|---|
| Test | Test model connection | says what is tested |
| Issue | Issue credential | says what is created |
| Clear | Clear token | says what is cleared |
| Done | Hide token | says what happens |
| Set | Save secret | says what is saved |
| Apply | Apply configuration / Apply time range | which thing is applied |
| Run | Run audit verification / Run hunt | which operation |

Destructive verbs stay precise (Revoke credential, Delete policy) and carry a confirmation that
states the impact and whether it can be undone. Do not demand a typed phrase unless the action is
genuinely high-impact.

## No hidden failure, no fake success

A control must never look like it succeeded when it did not. Success and failure messages both
carry information:

- **Success** names *what changed* and links the audit reference where one exists.
  - Good: `Monitoring started for anna@example.internal until 14 Aug 2026. Audit: 8f4…`
  - Bad: `Success.`
- **Failure** says what failed, why (when known), and **whether anything changed**.
  - Good: `Couldn't apply the configuration — validation failed on 2 fields. Nothing was saved.`
  - Bad: `Operation failed.` / `Something went wrong.` / `Invalid input.`

A restart-pending change is not "done": say `Saved. Takes effect after garmr restarts.`
An env-overridden field is not active: say `Set in the UI but overridden by an environment variable.`

## Explain disabled and empty states by cause

Never a blank panel or a dead control. Distinguish the reason and give the next step
(`ui::disabled_panel`, `ui::empty`):

- No data yet: `No audit events have arrived for this application. Check its collector and source mapping.`
- No match: `No users match the selected filters. Clear filters.`
- Feature off: `Application audit is turned off. Turn it on in System → Configuration → Detection.`
- Blocked by air-gap: `External model testing is blocked because garmr is running in air-gap mode.`
- Still learning: `The baseline is still learning; behavioral comparison needs more activity first.`

## Speak the product's words, not the build's

Internal names never appear as the primary label (see `terminology.md`). Replace:

- storage/plane internals — "Application-audit plane" → "Application audit";
- env vars — a `GARMR_ADMIN_TOKEN` placeholder → "Paste the admin token";
- config keys / CLI verbs as instructions — lead with plain language, show the exact command only
  as a copyable snippet in an offline-operation panel;
- codenames — "CodeVault 3D entity topology" → "3D topology"; "sealed store" → "encrypted store";
- raw enum values — map through friendly labels (`needs_human` → "Needs human review",
  `detector_config` → "detector configuration").

## Tone

Calm, direct, and never blaming the user. Prefer "Couldn't reach the model" over "You entered an
invalid endpoint." Keep tooltips to one or two sentences; put anything longer in an `InfoPopover`.
