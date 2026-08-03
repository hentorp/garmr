# garmr

A one-person agentic SOC in Rust.

## Language: English only

This is a public repository. **Everything must be written in English** — no Swedish
(or any other non-English) anywhere in the codebase. This applies to:

- source code: identifiers, comments, and doc comments;
- all human-readable strings: log/tracing messages, error messages, UI labels and
  copy, and agent/LLM prompts;
- test assertions on message substrings (translate the message and its assertion
  together so tests keep matching);
- config and rule files: comments, and rule titles/descriptions
  (`correlations/*.toml`, `hunts/*.toml`, `garmr.example.toml`);
- commit messages and documentation (`docs/`, `README.md`).

When adding or editing anything user-facing or human-readable, write it in English.

## Commits

Author commits under the **human contributor only** — Henrik, or whichever named
contributor is doing the work. Do **not** add a `Co-Authored-By: Claude …` trailer,
a "Generated with Claude" line, or any other attribution to Claude / the assistant
in commit messages or PR descriptions.
