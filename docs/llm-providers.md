# LLM Providers

AgentStream's advanced AI features call an LLM:

- **Session enrichment** — chapter segmentation, titles, session classification
- **Insights pipeline** — per-session extraction (Stage 1) and cluster matching (Stage 2)
- **PR walkthroughs** — diff chunking and review sequencing
- **Personas** — `talk-to-<name>` skill generation
- **Fork context** — long-session compaction
- **Weekly summary** — activity clustering

Plus **embeddings** for insight clustering and semantic search.

By default these use Anthropic (chat) and OpenAI (embeddings). Self-hosters can
point them at any **OpenAI-compatible endpoint** (Ollama, vLLM, the W&B /
CoreWeave inference service, LocalAI, …), at **Anthropic**, or at **Amazon
Bedrock** — configured entirely through environment variables. There is no
LiteLLM or other router in the path: the backend wraps the OpenAI and Anthropic
SDKs (both already dependencies) behind one small interface
(`agentstream_api.llm`).

Everything degrades gracefully: if no provider is configured, the AI features
quietly no-op and the rest of the product works normally.

---

## Quick reference

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | auto | `anthropic`, `openai`, or `bedrock`. Auto-detected when unset (see below) |
| `LLM_API_KEY` | — | API key for the chat provider. Falls back to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` |
| `LLM_BASE_URL` | provider default | Custom endpoint base URL (must include the API version path, e.g. `/v1`) |
| `LLM_MODEL` | per-feature Claude id | Default chat model for **all** features |
| `LLM_EXTRA_HEADERS` | — | Extra request headers as a JSON object (e.g. the W&B `OpenAI-Project` header) |
| `LLM_BEDROCK_REGION` | `AWS_REGION` | Region for the Bedrock client |
| `EMBEDDINGS_API_KEY` | `OPENAI_API_KEY` | Key for the embeddings endpoint |
| `EMBEDDINGS_BASE_URL` | OpenAI | Custom embeddings endpoint |
| `EMBEDDINGS_MODEL` | `text-embedding-3-small` | Embedding model (**must output 1536-dim vectors**) |
| `EMBEDDINGS_PROVIDER` | `openai` | Set to `none` to disable embeddings entirely |

Per-feature model overrides (each falls back to `LLM_MODEL`, then to its Claude
default): `ENRICHMENT_MODEL`, `TITLE_EXTRACTION_MODEL`, `WEEKLY_SUMMARY_MODEL`,
`PERSONA_MODEL`, `FORK_CONTEXT_MODEL`, `INSIGHTS_MATCHER_MODEL`,
`ANTHROPIC_MODEL` (insights extraction + PR walkthroughs).

### How the provider is chosen

1. If `LLM_PROVIDER` is set, it wins (`anthropic` | `openai` | `bedrock`;
   aliases `claude`, `ollama`, `coreweave`, `wandb`, `vllm`, `aws` are accepted).
2. Otherwise, if `ANTHROPIC_API_KEY` is set → **anthropic**. An Anthropic key
   keeps the legacy path even when `OPENAI_API_KEY` is also set for embeddings.
3. Otherwise, if `LLM_API_KEY` or `LLM_BASE_URL` is set → **openai**.
4. Otherwise the features are disabled.

This means existing deployments that only set `ANTHROPIC_API_KEY` (and
`OPENAI_API_KEY` for embeddings) keep working unchanged — the new variables are
purely additive.

---

## Anthropic (default)

```bash
ANTHROPIC_API_KEY=sk-ant-...
# Optional: override the default model (per-feature defaults still apply)
# LLM_MODEL=claude-sonnet-4-6
```

You can also point the Anthropic SDK at an Anthropic-compatible proxy with
`LLM_BASE_URL`.

---

## OpenAI-compatible endpoints

Set a base URL (and key, if the endpoint needs one) and a model. `LLM_PROVIDER`
auto-resolves to `openai`. The backend translates each feature's Anthropic-style
request (system prompt, tool/structured output, token usage) to the OpenAI
chat-completions API, so **structured-output features require a model that
supports function/tool calling.**

> Reasoning models (OpenAI's o-series, gpt-5, …) reject the `max_tokens`
> parameter and require `max_completion_tokens`. The adapter handles this
> automatically — it sends `max_tokens` first and self-heals to
> `max_completion_tokens` on the first request, so no extra configuration is
> needed.

### Ollama (local)

```bash
LLM_BASE_URL=http://host.docker.internal:11434/v1   # from inside Docker
LLM_MODEL=llama3.3
# Ollama needs no API key.
```

> Pick a tool-calling-capable model (e.g. `llama3.3`, `qwen2.5-coder`,
> `mistral-nemo`). Models without tool support will fail the insights, persona,
> weekly-summary, and PR-walkthrough features (which force a tool call) while
> plain-text features (enrichment titles, fork context) still work.

### W&B / CoreWeave inference service

The W&B inference service is OpenAI-compatible:

```bash
LLM_BASE_URL=https://api.inference.wandb.ai/v1
LLM_API_KEY=<your-wandb-api-key>
LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct
# The inference service attributes usage to a W&B project via a header:
LLM_EXTRA_HEADERS={"OpenAI-Project": "my-team/my-project"}
```

### vLLM / LocalAI / other gateways

```bash
LLM_PROVIDER=openai
LLM_BASE_URL=https://my-vllm.internal/v1
LLM_API_KEY=<token-or-"not-needed">
LLM_MODEL=<served-model-name>
# Enterprise gateways often need auth headers:
# LLM_EXTRA_HEADERS={"X-My-Gateway-Token": "..."}
```

---

## Amazon Bedrock

Runs Anthropic models through Bedrock using the standard AWS credential chain
(env vars, shared config, or an instance/role profile):

```bash
LLM_PROVIDER=bedrock
LLM_BEDROCK_REGION=us-east-1
LLM_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
# AWS_SESSION_TOKEN=...    # if using temporary credentials
```

Because every feature's default model is a public Claude id (e.g.
`claude-sonnet-4-6`) that Bedrock doesn't recognize, **set `LLM_MODEL` to a
Bedrock model id**. To keep the cost-saving Haiku split for titles/weekly
summaries, also set `TITLE_EXTRACTION_MODEL` and `WEEKLY_SUMMARY_MODEL` to the
corresponding Bedrock Haiku id; otherwise they fall back to `LLM_MODEL`.

---

## Embeddings

Embeddings power insight clustering and semantic session search. They use an
OpenAI-compatible endpoint, independent of the chat provider:

```bash
# Defaults to OpenAI with OPENAI_API_KEY.
EMBEDDINGS_API_KEY=<key>
EMBEDDINGS_BASE_URL=https://my-endpoint/v1
EMBEDDINGS_MODEL=text-embedding-3-small
```

> **Dimension constraint.** The ClickHouse `session_embeddings` column and its
> HNSW vector index are fixed at **1536 dimensions** (migration `0004`). A
> replacement model must emit 1536-dim vectors. `text-embedding-3-small` does
> natively; `text-embedding-3-large` can if you set `EMBEDDINGS_DIMENSIONS=1536`
> (it's passed through to the API). Models with a different native size (e.g.
> `nomic-embed-text` at 768) will not insert correctly — disable embeddings with
> `EMBEDDINGS_PROVIDER=none` instead. With embeddings off, the insights matcher
> falls back to sending recent clusters straight to the judge (see
> `docs/design-insights-pipeline.md`).

---

## Verifying the configuration

On first use the API logs the resolved provider once:

```
LLM chat provider: openai (base_url=http://host.docker.internal:11434/v1, default_model=llama3.3)
```

Then exercise a feature — e.g. open a session and trigger enrichment, or request
a PR walkthrough — and watch the `app` / `worker` logs. A misconfigured endpoint
surfaces as a connection or auth error there; the feature degrades to its
fallback (e.g. a single untitled chapter) rather than failing the request.

## Weave tracing

When `WANDB_API_KEY` is set, all LLM calls are traced in Weave regardless of
provider — both the Anthropic and OpenAI SDK clients are auto-instrumented, and
the Bedrock path is the Anthropic SDK. The `weave-cost-analysis` tooling
therefore continues to attribute spend per feature on any provider.
