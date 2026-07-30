<!--
SPDX-FileCopyrightText: 2026 Vetra Automation AB
SPDX-License-Identifier: CC-BY-4.0
-->

# Running the agent on a local LLM

garmr's agent talks to **one** LLM provider trait over two backends: the Anthropic
Messages API, and any **OpenAI-compatible** chat-completions endpoint — which is
what Ollama, llama.cpp's server, vLLM, and LM Studio all expose. Running triage
against a local model keeps every prompt and every piece of evidence on your own
hardware, and is the only supported agent mode under the [air-gap
profile](airgap.md).

## Configure the backend

In `garmr.toml`:

```toml
[agent]
backend = "open_ai_compat"                 # the default is "anthropic"
model   = "qwen2.5:14b-instruct"           # whatever tag your server serves
# The cheaper pre-filter ("is this case worth a full triage?") can be a smaller tag:
prefilter_model = "qwen2.5:3b-instruct"
openai_base_url = "http://127.0.0.1:11434/v1"   # Ollama default; llama.cpp: http://127.0.0.1:8080/v1
max_tokens = 1024
daily_budget_usd = 0.0                      # local inference is free; the budget gate is a no-op
allow_online_lookups = false                # keep enrichment offline too
```

- The backend enum value is exactly **`open_ai_compat`** (snake_case). `backend =
  "anthropic"` is the default.
- `openai_base_url` is the **root** of the API (`.../v1`); garmr posts to
  `<base_url>/chat/completions`.
- A hosted OpenAI-compatible endpoint that needs a key reads it from the
  environment. **Ollama and a local llama.cpp server need none** — leave it unset.

That is the whole switch. The agent loop, tools, budgets, and case flow are
backend-agnostic.

## Locality is enforced, not assumed

The egress chokepoint classifies a loopback / private-range `openai_base_url` as
**local** and a public one as **external**. Under `GARMR_AIRGAP=1`, external LLM
egress is denied outright and **cannot** be re-enabled by any other config — so an
air-gapped garmr can only ever reach a local model, and never silently falls back to
a hosted one. Keep the endpoint on `127.0.0.1` (or a private address on a trusted
segment) so it resolves as local. See [../architecture/model-routing.md](../architecture/model-routing.md).

## Serving the model on a GPU

garmr does **not** manage the model process — run it as a separate service (the
model is an external process, never in-process). Any OpenAI-compatible server works:

- **Ollama** is the simplest: install it, `ollama pull <tag>`, and it serves on
  `:11434`, using the GPU automatically when one is visible. Point `openai_base_url`
  at `http://<host>:11434/v1`.
- **llama.cpp server** (`llama-server -m model.gguf --host 0.0.0.0 --port 8080 -ngl
  999`) gives finer control; `-ngl` offloads layers to the GPU.
- **vLLM** exposes an OpenAI-compatible server as well.

Size VRAM to the model + context; a 14B Q4 model wants roughly 10–12 GB. Without a
GPU the same servers run on CPU — slower, but fine for the low case-rate of a
one-person SOC. Keep the model host separate from the live SOC box so inference load
never competes with ingest/detection.

## Verifying

Point garmr at the endpoint and self-test the agent loop against the local model,
entirely offline:

```sh
garmr selftest
```

It exercises the whole tool-calling loop against the configured backend without
touching a live warehouse.
