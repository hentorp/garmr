# Running garmr with a local LLM (and on a GPU)

garmr's agent talks to **one** [`LlmProvider`] trait over two backends: the
Anthropic Messages API, and any **OpenAI-compatible** chat-completions endpoint —
which is what Ollama, llama.cpp's server, vLLM, and LM Studio all expose. Running
the triage agent against a local model keeps every prompt and every piece of
evidence on your own hardware, and is the only supported mode under the airgap
profile (see [airgap](airgap.md)).

## Configure the backend

In `garmr.toml`:

```toml
[agent]
backend = "openai_compat"
model   = "qwen2.5:14b-instruct"          # whatever tag your server serves
# The cheaper pre-filter ("is this case worth a full triage?") can be a smaller tag:
prefilter_model = "qwen2.5:3b-instruct"
openai_base_url = "http://127.0.0.1:11434/v1"   # Ollama's default; llama.cpp: http://127.0.0.1:8080/v1
max_tokens = 1024
daily_budget_usd = 0.0                     # local inference is free; the budget gate is a no-op
allow_online_lookups = false               # keep enrichment offline too
```

- `backend = "openai_compat"` selects the OpenAI-compatible provider; the default
  is `anthropic`.
- `openai_base_url` is the **root** of the API (`.../v1`); garmr posts to
  `<base_url>/chat/completions`.
- A hosted OpenAI-compatible endpoint that needs a key reads it from
  `GARMR_OPENAI_API_KEY`. **Ollama and a local llama.cpp server need none** — leave
  it unset.

That's the whole switch. The agent loop, tools, budgets, and case flow are
backend-agnostic.

## Locality is enforced, not assumed

The egress chokepoint (see [model-routing](architecture/model-routing.md))
classifies a loopback / private-range `openai_base_url` as `llm_local` and a public
one as `llm_external`. Under `GARMR_AIRGAP=1`, external LLM egress is denied
outright and **cannot** be re-enabled by any other config — so an airgapped garmr
can only ever reach a local model, and never silently falls back to a hosted one.
Keep the endpoint on `127.0.0.1` (or a private address on a trusted segment) so it
resolves as local.

## Serving the model on a GPU

garmr does not manage the model process — run it as a separate service (invariant
#6: the model is an external process, never in-process). Any OpenAI-compatible
server works; a few notes for the Proxmox lab (see
[lab/pve-topology](lab/pve-topology.md)):

- **Ollama** is the simplest: install it, `ollama pull <tag>`, and it serves on
  `:11434` using the GPU automatically when one is visible. Point
  `openai_base_url` at `http://<host>:11434/v1`.
- **llama.cpp server** (`llama-server -m model.gguf --host 0.0.0.0 --port 8080
  -ngl 999`) gives finer control; `-ngl` offloads layers to the GPU.
- **GPU passthrough on Proxmox**: give the model VM the GPU via VFIO passthrough
  (bind the card to `vfio-pci` on the host, add it as a PCI device to the guest).
  Size VRAM to the model + context; a 14B Q4 model wants ~10–12 GB. Without a GPU,
  the same servers run on CPU — slower, but fine for the low case-rate of a
  one-person SOC.

Keep the model host on the isolated estate, not the live SOC box, so inference load
never competes with ingest/detection.

## Verifying

Point garmr at the endpoint and run a self-test of the agent loop against the local
model, entirely offline:

```
garmr selftest
```

It exercises the whole tool-calling loop against the configured backend without
touching a live warehouse.

[`LlmProvider`]: https://github.com/hentorp/garmr
