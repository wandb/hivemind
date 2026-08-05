# HiveMind → Weave Agents importer

> **Draft status:** the offline implementation and recovery behavior are heavily
> tested, but the first 45-day live backfill is not complete. The large-history
> failures and remaining work are documented in
> [LIVE_BACKFILL_NOTES.md](LIVE_BACKFILL_NOTES.md).

`hivemind-weave` copies your recent W&B HiveMind coding-agent conversations into
the Weave Agents view. It reads HiveMind through the installed authenticated CLI,
maps ATIF trajectories to Weave conversations and turns, and keeps a local SQLite
journal so the command can be run repeatedly.

Session discovery is always scoped to the exact `user_id` returned by the
authenticated HiveMind `/auth/me` call; organization-wide sessions are never
requested.

Discovery first reads 100-row pages in `started_at ASC` order and deduplicates by
session ID. A sweep is accepted immediately only when its internally constant
`total_count` equals the number of unique IDs returned. If that primary sweep is
short because unstable equal-timestamp page boundaries repeat an ID, discovery
tries a bounded set of shifted boundaries: 100 rows descending, then 97 and 89
rows in both directions. IDs are merged only while `total_count` is identical; a
count change or same-count membership overflow resets that recovery epoch. A
complete result assembled from multiple deficient sweeps receives a final exact
sweep with the same total and identical ID set before it is accepted. Duplicate-only
nonempty pages still advance, while every echoed page, size, and sort field must exactly match the
request. The importer starts from the primary ordering at most five times, waiting
two seconds between attempts, and fails rather than importing a short result.
Authentication, response-schema, and sort-order failures are not retried.

The default destination is `wandb/hivemind-chats`.

## Privacy and behavior

This importer intentionally sends the full redacted trajectory: user and assistant
messages, system instructions, reasoning, tool arguments/results, and file-related
content. Before upload it:

1. relies on HiveMind's source-side secret redaction,
2. recursively scrubs credential-bearing fields and common token/PII patterns, and
3. enables Weave's Presidio PII recognizers using a locked, locally installed
   English NER model and bundled public-suffix snapshot (no runtime download).

It never reads HiveMind credential files directly, automatically sources an `.env`,
or prints transcript content. It fails closed if `WEAVE_REDACT_PII` disables the
destination redaction layer. Review a dry run before the first live import.

## Requirements

- Python 3.11 or 3.12. Weave's current Presidio extra does not support Python 3.13.
- HiveMind installed and authenticated with session read access.
- `WANDB_API_KEY` exported in the command's environment for a live import.

```bash
hivemind login
hivemind whoami
```

## Install and run

From this directory:

```bash
uv sync --python 3.12 --locked
uv run --offline --locked hivemind-weave import --days 7 --dry-run
```

For the live import, expose the W&B variables without echoing them. If they already
live in a trusted env file, source it in the shell before running the command:

```bash
set -a
source /path/to/your/.env
set +a
uv run --offline --locked hivemind-weave import --days 7
```

Full interface:

```text
hivemind-weave import --days N
    [--project wandb/hivemind-chats]
    [--idle-minutes 10]
    [--state-path ~/.hivemind/weave-importer/state.sqlite3]
    [--dry-run]
```

`N` must be between 1 and 365. A session is selected when its
`last_activity_at` is inside the requested UTC window. Sessions active within the
idle grace period, or lacking a reliable activity timestamp, are deferred until a
later run. The CLI prints `Weave destination (live import): <entity/project>` and
flushes that line before discovery so the destination is visible while a large
backfill is still running.

## Mapping

- One HiveMind session becomes one Weave conversation with the stable ID
  `hivemind:<session-id>`.
- The source agent type (`codex`, `cursor`, `claude`, and so on) becomes the Weave
  agent name.
- Each non-copied user step starts a turn. Leading system steps become system
  instructions; copied context remains LLM input without creating duplicate turns.
  An incomplete system/copy-only prefix waits for a later source step instead of
  creating a temporary synthetic turn that would become stale after an append.
- Every ATIF agent step becomes one inferred LLM span. Tool calls and observations
  become correlated sibling tool spans, including explicit unmatched-call warnings.
- HiveMind child sessions remain separate conversations and carry
  `hivemind.parent_session_id` for filtering and linking.

ATIF 1.x is parsed tolerantly (the fixtures cover v1.0 through v1.7); unknown major
versions and wrapper/trajectory step-count mismatches fail closed. Each exact,
redacted source step is retained in reconstructable canonical turn attributes
alongside the typed Weave fields, so multimodal metadata, copied context, terminal
file/system events, and vendor extensions are not silently discarded. Aggregate
archival attributes and any values needed to keep the repeated root payload small
are moved into dedicated `hivemind_transport_fragment` Tool spans. The root keeps
the searchable HiveMind session/turn, repository/branch, parent, schema/version,
timestamp, and payload-hash fields plus a compact archive manifest. It does not
repeat multi-megabyte archive values onto every child span.

Each archive manifest records its logical encoding, sentinel-prefixed `base64-utf8`
transport encoding, decoded byte count, fragment count, stable archive ID, and
SHA-256. Every physical chunk begins with a non-base64 transport sentinel; this
prevents Weave's hosted inline-media detector from replacing an encoded archive
chunk with a Content reference. Fragment Tool results are bounded by JSON-escaped
byte size and can have their sentinels removed, be joined, base64-decoded,
hash-checked, and parsed to recover the exact post-redaction value. Legacy bare-
base64 manifests remain readable.
Oversized typed Tool arguments/results use the same transport: the complete SDK-
serialized field receives the configured destination PII pass before it is split,
so entities cannot straddle a fragment boundary. The encoded fragment Tool subtype
then emits that already-safe payload without running the entity detector again.
Together with the per-chunk sentinel, this prevents client-side PII and server-
side media detection from changing content or invalidating its hash. The logical
Tool span remains in place with a small field manifest that
correlates it to its fragments. No content is truncated.

Turn identity is computed from the complete credential-scrubbed mapped source
before Presidio. Presidio still redacts every uploaded field, but statistical ML
redaction choices cannot change idempotency hashes between processes.

## Repeatability and recovery

The default journal is `~/.hivemind/weave-importer/state.sqlite3`. Its primary key
is destination project + HiveMind session + deterministic turn key.

For every nonempty live discovery, the importer transactionally saves an immutable
run manifest before fetching the first ATIF transcript. The summary manifest
contains the original UTC cutoff, selection/configuration versions, and the
ordered eligible session IDs with their discovery-time activity timestamps. A
certification pass then brackets every ATIF fetch with two direct session-summary
reads. The activity timestamp must remain equal to the discovery value. The
importer maps and redacts the transcript, saves each session's exact ordered
`(turn key, stable source hash)` set in an immutable run-turn table, and seals one
aggregate certificate. No Weave upload starts until every session is certified.

The upload pass fetches each session again, using the same activity brackets, and
requires its activity and complete ordered turn set to match the sealed
certificate. An append, deletion, reorder, or historical edit during either pass
is a conflict; it is never accepted into an already-started run. Appended turns
are still imported normally by a fresh run after the earlier run has completed.

If the process stops, the next invocation using the same state database, project,
`--days`, and `--idle-minutes` automatically resumes the unique unfinished
manifest. It fetches the pinned session IDs directly rather than rebuilding the
worklist from a newer moving time window, so an unprocessed session cannot age out
at the lower boundary. Resume also rechecks the saved activity and ordered turn
certificate; it does not silently absorb source drift. Each session records a
durable uncertified, certified, empty, imported, skipped, failed, or conflict
outcome. A run is completed only after every manifest entry succeeds and every
exact certified turn has a matching committed journal row. Missing, orphaned, or
hash-mismatched rows cannot satisfy completion. Multiple unfinished runs,
manifest tampering, package/schema drift, or changed selection options fail
closed. After a run completes, an immediate identical command creates a fresh
discovery manifest; the turn journal makes that rerun emit zero duplicate turns.

- An identical committed turn is skipped.
- A newly appended turn is imported.
- A changed historical turn is marked as a conflict and is not duplicated.
- A pending turn is reconciled through Weave using its stable turn key, payload
  hash, returned trace IDs, canonical timestamp/message signature, and exact total
  physical span count—including archive and Tool-field fragments—before any retry.
  A partial or ambiguous remote trace becomes a conflict instead of being
  duplicated. Once an emission count is journaled, that historical count remains
  authoritative even if a later importer changes transport thresholds.
- If a never-emitted pending payload changes after a local pre-upload failure, its
  journal hash is replaced only when no trace/root IDs or spans were recorded and
  bounded reconciliation proves that neither the old nor new hash exists remotely.

Journals created before stable source hashing are upgraded without inventing
source proof. A legacy row whose stable source identity is absent is marked as an
unprovable conflict when encountered; the importer never binds it to whatever
content happens to be returned later. Its original correlation hash and remote IDs
are retained for investigation, and no duplicate is uploaded.

Only one importer process can use a journal at a time. The state directory is
opened component-by-component without following symlinks, restricted to mode
`0700`, and required to be owned by the current user. The database, process lock,
and SQLite WAL/SHM/journal sidecars must be current-user regular files with one
hard link and mode `0600`; unsafe owners, symlinks, hard links, file types, inode
swaps, or permission failures are fatal. SQLite records an application ID and
transactional schema version, validates the exact table/index/trigger contract on
every open, and uses revision compare-and-swap guards for mutable state. The
journal contains IDs, hashes, timestamps, and status—not transcript bodies or
credentials. To start an intentionally separate history, use a different
destination project and state path; do not delete a journal merely to bypass a
conflict. Keep using the exact same state path after an interruption; changing it
also changes the recovery history.

After each session's upload, the importer flushes Weave and verifies every new
trace through both the conversation-chat and conversation-spans APIs before
committing that session and fetching the next one.
An identical committed rerun is resolved entirely from SQLite and succeeds without
initializing Weave (or requiring `WANDB_API_KEY`).
Eligible sessions are fetched, mapped, and redacted one at a time. Only compact
turn certificates are retained across sessions; emitted objects and returned IDs
are released after per-session verification, so memory use is bounded by the
largest individual session rather than the whole backfill window. Aggregate turn
certificate hashing is streamed from SQLite rather than loading all turn rows.
It also forces bounded intermediate flushes to keep large backfills below the
OpenTelemetry batch queue. Before `weave.init`, the importer temporarily supplies
`OTEL_BSP_MAX_EXPORT_BATCH_SIZE=4` when no nonblank operator value exists. The
stock OpenTelemetry processor otherwise exports as many as 512 spans in one HTTP
request, and the Weave SDK does not override that default. A four-span batch keeps
transcript-heavy OTLP requests bounded while retaining every span. An explicit
operator setting always wins; if only a positive `OTEL_BSP_MAX_QUEUE_SIZE` below
four is set, the automatic batch size is clamped to that queue size. The importer
restores the environment immediately after initialization. Its separate
intermediate-flush boundary remains 512 queued spans, and an exceptionally large
single turn (over 1,024 spans) fails explicitly instead of risking silent span
loss. Archive and oversized Tool-field fragments are byte-bounded, but turn-level
messages/system instructions and individual LLM fields remain ordinary single
spans. A pathological value in one of those remaining fields can still exceed a
server byte limit because exporter batching is count-based.
The command exits nonzero for mapping, authentication, conflict, upload, or
verification failures.

## Development

```bash
uv run --offline --locked pytest
uv run --offline --locked ruff check src tests
uv build --offline
```

The default test suite is offline and uses fake HiveMind/Weave boundaries. The
opt-in live smoke test requires `HIVEMIND_WEAVE_LIVE=1`,
`HIVEMIND_WEAVE_LIVE_SESSION_ID`, `HIVEMIND_WEAVE_LIVE_PROJECT`, an authenticated
HiveMind CLI, and `WANDB_API_KEY`; use a disposable W&B project and state path.
The smoke test checks chronological chat content, reasoning/tools, source-agent
grouping, exact trace span counts, exact canonical source attributes (including
the compact archive manifest), and zero-turn idempotency on the second run. To
also require child-session discovery via `hivemind.parent_session_id`, select a
child session and set `HIVEMIND_WEAVE_LIVE_REQUIRE_PARENT=1`.
