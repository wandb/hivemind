# HiveMind → Weave Agents sync

`hivemind-weave` is a review implementation of a lossless, incremental importer
for the authenticated user's HiveMind chats. It discovers through the installed
HiveMind CLI, maps ATIF 1.x transcripts, redacts before serialization, seals
small immutable plans in private SQLite state, and submits one atomic historical
turn at a time.

> **Rollout status:** live backfill is intentionally blocked. The companion
> Weave change proves the SDK shape, validation, recovery, and a local SQLite
> compare-and-set, but the hosted service does not yet provide the required
> protobuf/gzip transport, immutable text references, authenticated route,
> strongly consistent commit store, or Agents-query integration. The importer
> rejects the prototype capability values, so it cannot silently fall back to
> `weave.log_turn` or OTLP.

No command in this version opens, sources, copies, or prints a `.env` file. The
abandoned 45-day upload remains paused, and this implementation does not repair
or mutate its old partial traces.

## Destinations

The rollout uses separate private projects:

- `wandb/hivemind-chats-canary` — disposable synthetic and one-session checks;
- `wandb/hivemind-chats-v2` — final backfill and incremental sync, only after
  the atomic service is deployed; and
- `wandb/hivemind-chats` — the old experiment and journal, retained read-only.

Every preview and apply requires an explicit project. Every apply additionally
requires `--confirm-project`, and the CLI prints that destination before work
starts. Verify project membership, visibility, retention, region, integrations,
and deletion policy before copying any real conversation.

## Requirements

- Python 3.11 or 3.12;
- the locked dependencies in this directory;
- an installed HiveMind CLI authenticated with `hivemind login`; and
- for an eventual manual apply, `WANDB_API_KEY` supplied by the process
  environment or a trusted secret manager.

HiveMind credentials remain inside the HiveMind CLI. Scheduled W&B credentials
are entered through a hidden macOS Keychain prompt. Secrets do not belong in
shell arguments, config files, plists, reports, or SQLite.

```bash
hivemind login
hivemind whoami
# First bootstrap requires package-index access for the locked runtime and
# Hatchling/editables build requirements. Later runs can be fully offline.
uv sync --python 3.12 --locked
uv run --offline --locked hivemind-weave --version
```

## Test one session first

An exact session filter is the most understandable first test. Preview performs
discovery, transcript mapping, redaction, reference planning, and exact wire
preparation, but does not upload content. It stores only content-free
certificates and prints aliases, counts, and size distributions.

```bash
uv run --offline --locked hivemind-weave backfill \
  --preview \
  --since 2026-06-21 \
  --until 2026-08-05T12:00:00-04:00 \
  --session-id SESSION_ID \
  --project wandb/hivemind-chats-canary
```

Alternatively, `--canary` chooses the first stable whole session in
`(last_activity_at, session_id)` order that is at least 24 hours inactive, is
not a child session, has no mapping/tool-correlation warnings, has at most three
turns and four physical spans per turn, and fits all advertised wire/reference
budgets. Limits are never loosened to manufacture a candidate.

```bash
uv run --offline --locked hivemind-weave backfill \
  --preview \
  --since 2026-06-21 \
  --canary \
  --project wandb/hivemind-chats-canary
```

After the upstream capability is deployed and the private canary project has
been reviewed, apply the printed plan alias with a one-session execution budget:

```bash
uv run --offline --locked hivemind-weave backfill \
  --plan PLAN_ALIAS \
  --max-sessions 1 \
  --confirm-project wandb/hivemind-chats-canary
```

`--max-sessions` never changes plan membership. Remaining whole sessions stay
queued. Repeating an identical apply emits zero duplicate turns.

## Date-based backfill

```text
hivemind-weave backfill --preview
    --since DATE|RFC3339
    [--until DATE|RFC3339]
    --project ENTITY/PROJECT
    [--agent NAME ...]
    [--repo OWNER/REPO ...]
    [--session-id ID ...]
    [--exclude-subagents]
    [--canary]
    [--state-path PATH]

hivemind-weave backfill
    --plan PLAN_ALIAS
    --max-sessions N
    --confirm-project ENTITY/PROJECT
    [--state-path PATH]
```

Date-only bounds mean midnight in the recorded local IANA timezone. The lower
bound is inclusive and the upper bound is exclusive. Repeated filters are exact
matches and subagents are included by default. `--days 1..365` remains a
deprecated preview alias and cannot be combined with `--since`.

The planned final rollout is:

1. one synthetic canary;
2. one real `--canary` session and a zero-emission rerun;
3. final-project cohorts of 1, then 5, then 20 sessions; and
4. only then the remaining plan and scheduled sync.

For the requested backfill, the final window begins `2026-06-21` and the final
project is `wandb/hivemind-chats-v2`. Do not run that apply while this README's
rollout status remains blocked.

## Atomic turn contract

The importer requires these Weave SDK operations:

```python
prepared = weave.prepare_turn(..., turn_key=...)
result = weave.upsert_turn(prepared)
status = weave.get_turn_status(prepared.logical_key)
```

It also requires capabilities that explicitly promise atomic turn commit,
durable idempotency, exact status lookup, gzipped protobuf transport, and
immutable authenticated content references. There is no legacy fallback.

For each session the importer:

1. brackets the transcript with direct session-summary reads;
2. prepares every turn before the first write;
3. compares source, wire, logical-key, size, reference, span, schema, and
   capability certificates with the sealed preview;
4. submits one root plus all child spans as one server transaction;
5. resolves transport ambiguity with exact `GET` status evidence; and
6. records local commit only after the Agents conversation and span views agree.

The logical key excludes content. An identical request replays the same commit;
changed historical content under the same conversation/turn key conflicts.
Nothing is truncated, split into opaque fragments, or manually repaired.

Large redacted text is expected to be externalized deterministically by the
future SDK into immutable, content-addressed references before the exact
protobuf envelope is certified. The current prototype advertises references as
unsupported, which is why planning fails closed rather than uploading a smaller
or lossy substitute.

## Incremental sync on macOS

Do not install the scheduler before the manual canary and final-project
backfill pass. Configuration, Keychain enrollment, and installation are
deliberately separate actions:

```bash
hivemind-weave sync configure \
  --since 2026-06-21 \
  --project wandb/hivemind-chats-v2 \
  --settle-minutes 60

hivemind-weave auth keychain set \
  --project wandb/hivemind-chats-v2

hivemind-weave sync once
hivemind-weave sync install --every-minutes 15
hivemind-weave sync status
hivemind-weave reconcile
```

The Keychain command uses `/usr/bin/security` with a value-less final `-w`, so
the key is entered through a hidden prompt and never placed in argv. The config
and LaunchAgent contain no credential. The LaunchAgent is not run at load,
invokes an absolute validated Python executable, inherits no ambient secrets,
and sends output to `/dev/null`; content-free status is written privately.

Each invocation takes one filesystem/SQLite writer lock, performs stable
discovery with a 24-hour overlap, explicitly tracks deferred chats, and imports
at most one settled whole session. Source activity advancement requeues the
session: identical turns skip, appended turns import, and changed history
conflicts. A processing, uncertain, blocked, or conflicting attempt pauses all
later writes while discovery and backlog accounting continue. `reconcile`
cannot blindly acknowledge a failure; it clears attention only from exact
atomic commit evidence.

Scheduler-owned files are private:

```text
~/Library/Application Support/hivemind-weave/       0700
  sync.json                                          0600
  status.json                                        0600
  sync.lock                                          0600
~/Library/LaunchAgents/
  com.wandb.hivemind-weave.sync.plist                0600
```

## Mapping and privacy

- One HiveMind session maps to `hivemind:<internal-session-id>`.
- The HiveMind title becomes the conversation name; the source agent type is
  the Weave agent name.
- User steps start turns. Leading system steps become system instructions.
- Agent steps become LLM spans; tool calls and observations correlate by call
  ID. Unmatched data remains visible with a mapping warning.
- Child sessions are separate conversations with parent/subagent attributes.
- ATIF 1.x variants are parsed tolerantly; unknown majors fail at that session.

Credential-bearing keys, bearer/API tokens, private-key blocks, and configured
PII are removed before hashing, staging, or serialization. Non-technical ATIF
step IDs use stable transcript positions rather than raw or hashed values, so
they cannot become a guessing oracle. Ordinary remaining
prompts, reasoning, code, file content, tool arguments/results, model/usage
metadata, and historical timestamps are preserved. Redaction is defense in
depth, not proof that every confidential value was detected; authorization and
destination governance still matter.

Reports never print titles, repositories, raw session IDs, prompts, tools,
hashes, trace IDs, or service error bodies. SQLite contains no transcript or API
key, but it does contain sensitive IDs, timestamps, hashes, commit evidence,
project names, and statuses. Keep its path private and do not delete it while a
destination project exists.

## State and recovery

The default database is `~/.hivemind/weave-importer/state.sqlite3`. It records
immutable plan membership, cohorts, scan watermarks, source/wire certificates,
logical keys, capability versions, reference counts, and the atomic lifecycle:

```text
planned → prepared → submitting → acknowledged → committed
                                ↘ uncertain / rejected / conflict
```

An interrupted `submitting` turn is never followed by a later turn. Exact
status lookup must prove absence before replay or prove the matching immutable
commit before local completion. Multiple or mismatched evidence is a conflict.

The legacy `hivemind-weave import --days ...` interface is retained only for
compatibility and diagnostics; use sealed date-based plans for any future live
work. It does not bypass the atomic capability gate.

## What the upstream Weave PR still needs

The companion Weave prototype intentionally fails closed in hosted adapters.
Before enabling real data it still needs:

- an authenticated hosted route deriving trusted user/project identity;
- a linearizable hosted commit ledger and immutable historical-turn writer;
- protobuf/gzip transport with compressed and decompressed boundary checks;
- staged immutable text references, authorization, TTL cleanup, and UI expand;
- unioned Agent cards, conversation, span, and message-search queries;
- response/status-code semantics, scanner policy/version evidence, retention,
  deletion tombstones, generated clients, and failure-injection coverage.

ClickHouse query-before-insert, `ReplacingMergeTree`, an in-memory lock, and
ordinary OTLP ingestion are not acceptable idempotency substitutes.

## Development

```bash
uv run --offline --locked pytest
uv run --offline --locked ruff check src tests
# The first build needs the Hatchling backend; use --offline after it is cached.
uv build
```

Tests cover date/timezone parsing, exact filters, stable pagination, canary
selection, byte-identical preview/apply certificates, redaction, ATIF mapping,
tool correlation, state migrations, cohort budgets, append/conflict behavior,
atomic recovery, locks, Keychain access, LaunchAgent content, overlap scans, and
the scheduler circuit breaker. Live tests remain opt-in and must use a fresh
private canary project and state path.
