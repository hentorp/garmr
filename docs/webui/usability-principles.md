# garmr WebUI — usability principles

The console must be understandable to someone who did not build garmr. A user should never need to
know Rust crate names, storage planes, registry internals, backend phases, environment-variable
names, internal detector jargon, or whether a feature was originally a CLI/TOML/API/WebUI thing.

These are the non-negotiable principles the cleanup enforces. They are the "why" behind
`terminology.md`, `microcopy.md`, `help-system.md`, `forms.md`, and `status-model.md`.

## 1. One concept, one name
Every concept has a single user-facing name across nav, titles, buttons, forms, empty states,
errors, and notifications. Internal names never surface as the primary label. Source of truth:
`docs/webui/terminology.md`.

## 2. One task, one canonical workflow
A task may be reachable from several places, but it has exactly one implementation — no two
slightly-different forms for "configure a model provider" or "start monitoring a user".

## 3. Every control explains its consequence
Buttons name a verb + object ("Test model connection", "Issue credential", "Restart garmr"), not a
bare "Run/Apply/Set". The user should know what a click does without reading the surrounding prose.

## 4. No hidden failure, no fake success
A control never looks like it succeeded when the endpoint failed, a restart is still required, a value
is overridden by the environment, the user lacks permission, or the operation only partly completed.
Success names what changed (+ audit reference); failure says what failed and whether anything changed.

## 5. Essential information is never tooltip-only
Tooltips and popovers are supplementary. Anything the user must have to act stays visible.

## 6. Hover is never the only interaction
Every tooltip/popover also works with keyboard focus, touch/click, and screen readers
(`ui::help_tip` / `ui::InfoPopover` satisfy this).

## 7. Progressive disclosure, not hiding
Show the common action first; put advanced options behind a clearly labelled expandable area;
preserve full power for experts. Simplifying never means deleting capability.

## 8. Calm, evidence-driven, trustworthy
Reserved status colours always paired with text (WCAG 1.4.1); one consistent status vocabulary;
protected actions carry an audit reference; the propose → approve → act separation is never bypassed
by a UI shortcut.

## Feel
Clear, calm, modern, consistent, powerful, trustworthy — usable for long analyst sessions, a new
administrator, and an experienced security analyst alike.
