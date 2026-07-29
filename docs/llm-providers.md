# LLM Providers

HiveMind's advanced AI features call an LLM:

- **Session enrichment** — chapter segmentation, titles, session classification
- **Insights pipeline** — per-session extraction (Stage 1) and cluster matching (Stage 2)
- **PR walkthroughs** — diff chunking and review sequencing
- **Personas** — `talk-to-<name>` skill generation
- **Fork context** — long-session compaction
- **Weekly summary** — activity clustering

Plus **embeddings** for insight clustering and semantic search.

By default these use Anthropic (chat) and OpenAI (embeddings). Self-hosters can
point them at any **OpenAI-compatible endpoint** (Ollama, vLLM, the W&B /
CoreWeave inference service, LocalAI, …), at **Anthropic**, at **Amazon
Bedrock**, or at **Google Vertex AI** — configured entirely through environment
variables. There is no LiteLLM or other router in the path: the backend wraps
the OpenAI and Anthropic SDKs (both already dependencies) behind one small
interface (`agentstream_api.llm`).

Everything degrades gracefully: if no provider is configured, the AI features
quietly no-op and the rest of the product works normally.

---

## Quick reference

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | auto | `anthropic`, `openai`, `bedrock`, or `vertex`. Auto-detected when unset (see below) |
| `LLM_API_KEY` | — | API key for the chat provider. Falls back to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` |
| `LLM_BASE_URL` | provider default | Custom endpoint base URL (must include the API version path, e.g. `/v1`) |
| `LLM_MODEL` | per-feature Claude id | Default chat model for **all** features |
| `LLM_EXTRA_HEADERS` | — | Extra request headers as a JSON object (e.g. the W&B `OpenAI-Project` header) |
| `LLM_BEDROCK_REGION` | `AWS_REGION` | Region for the Bedrock client |
| `LLM_VERTEX_PROJECT` | `GOOGLE_CLOUD_PROJECT` | GCP project for Vertex |
| `LLM_VERTEX_LOCATION` | `global` | Vertex location (`global`, `us-east5`, `europe-west1`, …) |
| `LLM_VERTEX_CREDENTIALS` | ADC | Service-account key for Vertex: a file path or the JSON itself |
| `EMBEDDINGS_API_KEY` | `OPENAI_API_KEY` | Key for the embeddings endpoint |
| `EMBEDDINGS_BASE_URL` | OpenAI | Custom embeddings endpoint |
| `EMBEDDINGS_MODEL` | `text-embedding-3-small` | Embedding model (**must output 1536-dim vectors**) |
| `EMBEDDINGS_PROVIDER` | `openai` | `vertex`, or `none` to disable embeddings entirely |

Per-feature model overrides (each falls back to `LLM_MODEL`, then to its Claude
default): `ENRICHMENT_MODEL`, `TITLE_EXTRACTION_MODEL`, `WEEKLY_SUMMARY_MODEL`,
`PERSONA_MODEL`, `FORK_CONTEXT_MODEL`, `SKILL_EXTRACTION_MODEL`,
`INSIGHTS_MATCHER_MODEL`, `ANTHROPIC_MODEL` (insights extraction + PR
walkthroughs).

### How the provider is chosen

1. If `LLM_PROVIDER` is set, it wins (`anthropic` | `openai` | `bedrock` |
   `vertex`; aliases `claude`, `ollama`, `coreweave`, `wandb`, `vllm`, `aws`,
   `vertex-ai`, `gcp` are accepted).
2. Otherwise, if `ANTHROPIC_API_KEY` is set → **anthropic**. An Anthropic key
   keeps the legacy path even when `OPENAI_API_KEY` is also set for embeddings.
3. Otherwise, if `LLM_VERTEX_PROJECT` is set → **vertex**. Only this dedicated
   variable opts in: `GOOGLE_CLOUD_PROJECT` is set ambiently on anything running
   in GCP and must not silently reroute an existing deployment.
4. Otherwise, if `LLM_API_KEY` or `LLM_BASE_URL` is set → **openai**.
5. Otherwise the features are disabled.

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

## Google Vertex AI

```bash
LLM_PROVIDER=vertex
LLM_VERTEX_PROJECT=my-gcp-project
LLM_VERTEX_LOCATION=global          # optional; `global` is the default
LLM_MODEL=google/gemini-3.6-flash
LLM_SMALL_MODEL=google/gemini-3.5-flash-lite
```

Gemini ids carry a minor version (`3.6`, `3.5`, `3.1`) and there is no floating
`gemini-3-pro` / `gemini-3-flash` alias — check what your project actually has
before pinning one. As of July 2026 the pro tier is preview-only
(`google/gemini-3.1-pro-preview`) and it reasons before answering: the same
session enrichment took **515s on `gemini-3.1-pro-preview` vs 17s on
`gemini-3.6-flash`**, for the same extracted topics. Flash is the right default
for the per-session features; save pro for something that needs the reasoning.

> **Prefer Gemini 3.5 or newer.** Only the 3.5+ Flash models honor the request
> to stop thinking, which is what keeps HiveMind's short-prompt features fast
> and their `max_tokens` budgets meaningful — see
> [Thinking budget](#thinking-budget). Older models (3.1, the 2.5 family) still
> work: they just spend hundreds of reasoning tokens per call, so they're slower
> and cost more for the same answer. Anything below 2.5 is untested here.

### Which Vertex API a model uses

Vertex serves its models through **two different APIs**, and which one applies
is a property of the *model*, not of the deployment:

| Model | API | Model id |
|---|---|---|
| Gemini | OpenAI-compatible `chat/completions` | `google/gemini-3.6-flash` |
| Partner / MaaS (Llama, Grok, …) | OpenAI-compatible `chat/completions` | `meta/llama-…`, `grok-…` |
| Anthropic Claude | native Messages API (`:rawPredict`) | `claude-sonnet-4-5@20250929` |

The backend routes **per request** on the model id — anything containing
`claude` goes to Vertex's Anthropic endpoint, everything else to its
OpenAI-compatible one. So a single deployment can mix them, e.g. Gemini for the
short-prompt features and Claude for insights:

```bash
LLM_MODEL=claude-sonnet-4-5@20250929
LLM_SMALL_MODEL=google/gemini-3.5-flash-lite
```

Two model-id gotchas, both of which produce an opaque 404 when missed:

- Vertex addresses models as `<publisher>/<model>`. A bare `gemini-…` id is
  auto-prefixed with `google/`; anything else you must qualify yourself.
- Claude ids on Vertex are pinned to a release date
  (`claude-sonnet-4-5@20250929`), unlike the floating aliases the Anthropic API
  accepts. **Set `LLM_MODEL`** — the per-feature Claude defaults baked into the
  backend are public Anthropic ids that Vertex rejects.

### Thinking budget

Gemini thinks before it answers, and **those tokens come out of `max_tokens`** —
unlike Anthropic, where `max_tokens` bounds only the visible answer. Every
feature in this codebase picked its `max_tokens` under the Anthropic meaning, so
left alone a short-prompt feature gets nothing back: at `max_tokens=64`,
`gemini-3.6-flash` spent 59 tokens thinking and returned a 1-token answer with
`finish_reason=length` — which `skill_extraction` and `weekly_summary` read as a
truncated response. Two settings restore the Anthropic meaning, and the defaults
need no attention:

| Var | Default | Effect |
|---|---|---|
| `LLM_VERTEX_REASONING_EFFORT` | `minimal` | Thinking level: `minimal`, `low`, `medium`, `high`. Anything else (including `none`) is not sent, leaving the model's own default. |
| `LLM_VERTEX_THINKING_RESERVE` | `2048` | Tokens added to each request's `max_tokens` to pay for thinking. `0` disables the reservation. |

Whether `minimal` is *honored* is the reason to prefer 3.5+. Reasoning tokens
spent on a one-word question at `reasoning_effort=minimal`, measured on Vertex:

| Model | Reasoning tokens at `minimal` | |
|---|---|---|
| `google/gemini-3.6-flash` | **0** | recommended |
| `google/gemini-3.5-flash` | **0** | recommended |
| `google/gemini-3.5-flash-lite` | **0** | recommended (good `LLM_SMALL_MODEL`) |
| `google/gemini-3.1-flash-lite` | 61 | ignores `minimal` |
| `google/gemini-3.1-pro-preview` | 57 | can't disable thinking |
| `google/gemini-2.5-flash` / `2.5-pro` | 57 / 60 | pre-`thinking_level` generation |

The models in the bottom half still work — the reserve is what keeps them from
returning an empty message — but they pay a few hundred reasoning tokens on
every call, including one-line title extractions. Unused reserve costs nothing,
since `max_tokens` is a ceiling rather than a target.

Both apply only to Gemini ids. Claude-on-Vertex goes to the Anthropic API where
`max_tokens` already means what the callers expect, and the partner/MaaS models
reject an unexpected `reasoning_effort`.

### Location

`global` (the default) is a multi-region endpoint that serves Gemini as well as
every Claude-on-Vertex model, which makes it the setting least likely to hit a
"model not available in this region" error. Pin a region
(`us-east5`, `europe-west1`, …) if a data-residency policy requires it;
`us` and `eu` select Google's data-residency endpoints.

### Credentials

Vertex has no long-lived API key. Authentication is Google **Application
Default Credentials**, which mint an OAuth token that expires hourly — the
backend refreshes it per request, so a long-running instance doesn't go stale.

- **On GCP (GKE, GCE, Cloud Run)** — attach a service account with the
  **Vertex AI User** (`roles/aiplatform.user`) role to the workload. Nothing
  else to configure; Workload Identity is the recommended setup on GKE. On a VM
  the containers reach the instance metadata server directly, so no credential
  is written anywhere — `hivemind serve setup` detects this, fills in the
  project from metadata, and skips the credential question entirely. (It also
  warns if the VM's service account lacks the `cloud-platform` scope, which
  would make every Vertex call fail at runtime.)
- **Anywhere else** — point `LLM_VERTEX_CREDENTIALS` at a credential, either as
  a path or as the JSON itself. A service-account key with the Vertex AI User
  role, or the `authorized_user` credential that
  `gcloud auth application-default login` writes, both work:

  ```bash
  LLM_VERTEX_CREDENTIALS=/etc/hivemind/vertex-sa.json
  # or inline, on one line:
  LLM_VERTEX_CREDENTIALS={"type":"service_account","project_id":"…"}
  ```

  `hivemind serve setup` reads the file you point it at and writes the inline
  form into `.env` (mode 0600), so the Docker containers get it without an extra
  bind mount; off GCP it offers your existing gcloud login as the first option.
  Note that a user credential carries everything *you* can do, not just Vertex —
  fine for an evaluation, a service account is the right call for a real
  deployment. For **workload-identity federation**, mount the config yourself
  and set the standard `GOOGLE_APPLICATION_CREDENTIALS`; `LLM_VERTEX_CREDENTIALS`
  deliberately doesn't accept `external_account` configs, since those can name
  an executable to source the token from.

If your project is enrolled in Vertex **express mode**, set `LLM_API_KEY` to the
express API key instead; it is sent as the bearer token and ADC is skipped.

#### Testing Vertex against the dev stack

The dev containers deliberately can't see your gcloud login. Layer the override
that mounts it when you're working on this provider:

```bash
gcloud auth application-default login
# backend/.env: LLM_PROVIDER=vertex, LLM_VERTEX_PROJECT=…, LLM_MODEL=…
cd backend
docker compose -f docker-compose.dev.yaml -f docker-compose.vertex.yaml up
```

The GCP project needs `aiplatform.googleapis.com` enabled
(`gcloud services enable aiplatform.googleapis.com --project <id>`) — without
it every call fails with a `SERVICE_DISABLED` 403.

### Vertex embeddings

Optional — embeddings are configured separately and can stay on OpenAI. To keep
everything in GCP:

```bash
EMBEDDINGS_PROVIDER=vertex
# project / location / credentials are reused from the LLM_VERTEX_* settings.
```

This defaults to `gemini-embedding-001` and **pins the output to 1536
dimensions** (the model's native size is 3072, which the ClickHouse column can't
hold). Its input limit is 2048 tokens rather than OpenAI's 8192, so embedding
text is truncated to 2000 tokens on this path.

Unlike the chat models, embeddings go to Vertex's **native `:predict`
endpoint**. Its OpenAI-compatible `/embeddings` route only serves MaaS partner
models — a Google embedding model there fails with
`OpenMaaS model 'google/gemini-embedding-001' not supported` (or a bare 500 on
the `global` host). Setting `EMBEDDINGS_BASE_URL` still overrides this, for an
OpenAI-compatible gateway in front of Vertex.

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
