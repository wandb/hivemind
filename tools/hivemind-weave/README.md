# HiveMind → Weave Agents importer

> **Security status:** this is a review prototype. The attempted 45-day live
> backfill is incomplete, and live recovery is paused. Large turns now fail
> before `weave.log_turn`; the prototype does not encode content to bypass normal
> Weave inspection and does not include a manual partial-trace repair tool.

`hivemind-weave` maps recent HiveMind coding-agent sessions into Weave Agents.
It reads only through the installed, authenticated HiveMind CLI and keeps a local
SQLite journal for idempotency and crash reconciliation.

## Read this before a live import

A live import creates another copy of conversation data outside HiveMind. That
copy can include prompts, reasoning, source code, filenames, tool arguments and
results, and third-party data. Credential-pattern scrubbing and Presidio are
defense in depth, not a proof that every confidential value has been removed.

Before uploading anything:

1. confirm that you are authorized to copy every selected session;
2. review the destination project's members, visibility, retention, and data
   governance settings;
3. run `--dry-run` first, while remembering that it validates mapping,
   redaction, and size limits but cannot prove that every sensitive value was
   detected; and
4. use a new private project for evaluation, not a broadly shared default.

The CLI therefore requires an explicit `--project`. A live run also requires
`--confirm-project` with the exact same value. There is no default destination.

## Security boundaries

- HiveMind authentication stays inside `hivemind login`. The importer neither
  reads credential files nor accepts `HIVEMIND_TOKEN`.
- The HiveMind child process receives a small environment allowlist instead of
  ambient API keys, tokens, loader settings, or unrelated application secrets.
- Mapping keys and values are scrubbed before upload. Session IDs and destination
  slugs must use bounded ASCII grammars so they cannot inject terminal controls.
- Live imports currently support only the hosted W&B API and Weave trace
  endpoints. Both are resolved, validated, pinned during SDK initialization,
  and recorded in the run manifest. Redirects are refused.
- Ambient OpenTelemetry providers, endpoints, headers, samplers, resource
  attributes, TLS overrides, proxies, and SDK debug logging are rejected. The
  created exporter must retain the exact HTTPS endpoint and system certificate
  verification before any turn can be logged.
- Weave error telemetry and its third-party package-version request are
  disabled. Local response caching, dropped-item files, WAL persistence,
  code/system capture, unsafe object decoding, and implicit integration
  patching are also disabled and checked after initialization.
- The exporter batch ceiling is four spans. A larger ambient override is fatal.
- Content-bearing fields, root attributes, aggregate turn bytes, and span counts
  have conservative preflight limits. Oversized turns fail before the SDK call;
  content is never silently truncated or moved into opaque base64 fragments.
- The state directory and files must already have private ownership and modes.
  Existing paths are validated and never chmodded by the importer.

The journal intentionally contains no transcript bodies or API keys, but it does
contain sensitive session IDs, source timestamps, hashes, trace IDs, project
names, and statuses. Protect and retain it: deleting or changing the state path
after an interrupted run can remove evidence needed to avoid duplicates.

## Requirements

- Python 3.11 or 3.12.
- `uv` and the locked dependencies in this directory.
- HiveMind installed and authenticated with session-read access.
- `WANDB_API_KEY` injected into the live command's environment by a trusted
  secret manager, CI secret store, or equivalent mechanism.

Do not put the key inline in shell history, and do not `source` an arbitrary
`.env`: sourcing executes shell code and can export unrelated secrets. The
importer never opens or sources `.env` files.

```bash
hivemind login
hivemind whoami
uv sync --python 3.12 --offline --locked
```

## Usage

Start with a non-uploading mapping/redaction pass. Dry-run reads HiveMind but
performs no Weave or SQLite writes and does not print transcript content.

```bash
uv run --offline --locked hivemind-weave import \
  --days 7 \
  --project your-entity/private-hivemind-review \
  --dry-run
```

After separately injecting `WANDB_API_KEY` and reviewing the project access:

```bash
uv run --offline --locked hivemind-weave import \
  --days 7 \
  --project your-entity/private-hivemind-review \
  --confirm-project your-entity/private-hivemind-review
```

Full interface:

```text
hivemind-weave import --days N --project ENTITY/PROJECT
    [--confirm-project ENTITY/PROJECT]
    [--idle-minutes 10]
    [--state-path ~/.hivemind/weave-importer/state.sqlite3]
    [--dry-run]
```

`N` must be `1..365`. Sessions are selected when `last_activity_at` falls inside
the fixed UTC window. Sessions active within the idle grace period, or without a
reliable activity timestamp, are deferred. The CLI prints the exact destination
before discovery so a running import is easy to identify.

## Mapping

- One HiveMind session becomes `hivemind:<session-id>` in Weave.
- The HiveMind title becomes the conversation name and source agent type becomes
  the Weave agent name.
- User steps start turns. Leading system steps become system instructions;
  following agent/tool/observation steps remain with that user turn.
- Each agent step becomes an inferred LLM span. Tool calls and observations are
  correlated by call ID; unmatched data is retained with a warning.
- Child sessions remain separate conversations with a searchable parent ID.
- ATIF 1.x is parsed tolerantly; unknown major versions and inconsistent wrapper
  metadata fail closed.

The mapped root attributes include source session/repository/branch/parent data,
turn identity and hashes, ATIF/importer versions, activity time, and timestamp
inference. These ordinary inspected attributes must fit the conservative inline
budget or the turn is rejected.

## Repeatability and recovery

The default state path is `~/.hivemind/weave-importer/state.sqlite3`. State is
keyed by destination, source session, and deterministic turn key.

- Same key and source hash: skip.
- New appended turn: import once.
- Changed historical turn: conflict; do not duplicate.
- Interrupted pending turn: reconcile by turn key, hashes, timestamps/messages,
  returned IDs, and exact span count before considering a retry.
- Partial or ambiguous remote evidence: conflict; never blindly retry.

For each nonempty live run, the importer freezes the cutoff, session worklist,
activity timestamps, and ordered turn hashes before upload. Source drift during
certification or upload is a conflict. Sessions are processed one at a time, and
Weave conversation/chat APIs must show the expected traces before local commit.

## Current limitation and maintainer questions

The live experiment established that large non-atomic OTLP delivery can leave a
partial remote trace when a later request is rejected. The earlier fragment-based
workaround and one-off recovery harness have been removed. Existing recovery
evidence remains read-only; no further mutation of those partial traces is
planned without a supported atomic/idempotent API.

Self-managed W&B/Weave endpoints are intentionally unsupported in this review
prototype; adding them requires a separate, explicit trust and TLS design.

Maintainer guidance is requested on:

- a stable ATIF transcript export contract;
- cursor or snapshot-based session pagination;
- an atomic historical Agent-turn ingestion API with caller idempotency keys;
- supported compressed and uncompressed request-size limits and byte-aware SDK
  batching; and
- standard searchable source-session, parent, repository, branch, timestamp,
  hash, and importer-version attributes.

## Development

```bash
uv run --offline --locked pytest
uv run --offline --locked ruff check src tests
uv build --offline
```

The default pytest configuration excludes live tests. The opt-in smoke test must
be selected with `-m live` and requires all of:

- `HIVEMIND_WEAVE_LIVE=1`
- `HIVEMIND_WEAVE_LIVE_SESSION_ID`
- `HIVEMIND_WEAVE_LIVE_PROJECT`
- `HIVEMIND_WEAVE_LIVE_CONFIRM_PROJECT` exactly equal to that project
- authenticated HiveMind CLI and `WANDB_API_KEY`

Use a disposable private project and a fresh state path.
