# HiveMind → Weave review mirror

`hivemind-weave` prepares a redacted, lossless review copy of the authenticated
user's HiveMind chats for maintainers to inspect in Weave. This path is
deliberately **noncanonical**: it writes only to the fixed private project
`wandb/hivemind-chats-review`, uses a simplified root-plus-manifest layout, and
does not replace the atomic historical-turn contract required for the eventual
canonical v2 import.

> **Rollout status:** live rollout is intentionally incremental. Synthetic
> large-turn validation and the first bounded real-session cohorts have passed;
> the remaining 21-day backlog is not claimed complete. The abandoned partial
> experiment in `wandb/hivemind-chats` remains read-only and is not repaired or
> reused.

> **State reset required:** experimental SQLite state created by any unreleased
> pre-0.4 build must be discarded according to the machine's secure local-data
> policy. It may contain a durable hash derived from a HiveMind account label and
> is neither migrated nor trusted by this workflow. Start 0.4 with a fresh state
> path. The canonical `backfill --preview` and `backfill --plan` CLI paths are
> disabled before HiveMind access or SQLite mutation; only the explicitly
> noncanonical `review` workflow is available for this prototype.

## Fixed destination and trust boundary

Every review operation is bound to:

```text
wandb/hivemind-chats-review
```

The project must already exist, be private, and be writable by the authenticated
principal. The importer checks those properties without creating a project,
changing its visibility, or writing a probe object. `review preview` requires
the explicit project spelling, `review apply` requires the same spelling through
`--confirm-project`, and any other value is rejected. Explicit preflight
recovery requires the same confirmation. `review status` and `review
reconcile` derive the destination from the sealed review state and do not
accept a project override.

The review mirror is not a staging alias for either
`wandb/hivemind-chats-v2` or `wandb/hivemind-chats`. Nothing automatically
promotes, copies, or replays review data into another project.

Only the hosted W&B control plane and hosted Weave trace service are supported.
Custom base URLs, trace endpoints, OpenTelemetry exporters, insecure TLS
settings, and diagnostic transport overrides fail before credentials or content
are used.

## Requirements

- Python 3.11 or 3.12;
- the exact lock in this directory;
- an installed HiveMind CLI authenticated with `hivemind login`; and
- `WANDB_API_KEY` already present in the process environment for apply,
  reconcile, or preflight recovery.

HiveMind credentials remain inside the HiveMind CLI. The importer does not open,
source, parse, copy, or print any `.env` file. Supply `WANDB_API_KEY` through the
calling process or a trusted secret manager; do not pass it as a command-line
argument or persist it in SQLite.

This review path is manual. It does not install or use cron, LaunchAgents,
Keychain jobs, background sync, or any other scheduler.

All canonical scheduler surfaces (`auth keychain set`, `sync configure`, `sync
once`, `sync install`, `sync status`, and top-level `reconcile`) fail closed
before config, status, SQLite, Keychain, HiveMind, plist, or `launchctl` access.
The former status path is disabled too because opening old SQLite state could
perform a schema migration, so it was not safely read-only.

If an earlier experimental build already installed the LaunchAgent, stop the
fixed service without reading a config file or touching Keychain credentials:

```text
/usr/bin/id -u
/bin/launchctl bootout gui/<UID>/com.wandb.hivemind-weave.sync
```

Replace `<UID>` with the numeric output from the first command. A “service not
found” result means it is not loaded. This only unloads the process; it neither
reads nor deletes the plist, SQLite state, config, status, or Keychain item.
Keep those artifacts untouched until they can be discarded under the machine's
approved secure local-data policy.

The Weave dependency is a PEP 508 Git reference pinned to the exact companion
prototype commit:

```text
0b58f67e1539bfaa2c705e35bed2d9896a319c6a
```

The full commit, not a moving branch or tag, must appear in both
`pyproject.toml` and the resolved `uv.lock`. That commit reports Weave version
`0.53.5.dev0`; capability checks, rather than the version string alone, decide
whether canonical v2 operations are safe.

Before importing any Weave module, review commands require exactly one installed
Weave distribution, verify its exact PEP 610 Git URL/revision, hash and size
check every installed `weave/*` file against its wheel `RECORD`, and require
Python's resolved package origin to be that verified distribution. The imported
package and conversation module are bound to the same files again afterward.
This prevents a shadow package from executing before rejection and detects
post-install file changes. It does not prove that an installed wheel was
reproducibly built from the Git source: the build process itself creates
`RECORD`.

```bash
hivemind login
hivemind whoami
uv sync --python 3.12 --locked
uv run --offline --locked hivemind-weave --version
```

`uv.lock` pins the application/runtime graph. A first trusted online bootstrap
is required unless the Git source and isolated build requirements are already
cached; `--offline` is a post-bootstrap no-fetch mode, not a fresh-machine or
build-provenance guarantee. Stronger provenance would require a reviewed,
vendored and hashed Weave wheel plus hashed build constraints.

## Review interfaces

### Preview

Preview discovers a stable source window, fetches and maps ATIF 1.x
transcripts, performs the final redaction pass, constructs and self-verifies
complete review manifests, and seals content-free plan certificates in private
SQLite state. Before discovery, it verifies the installed Weave distribution's
PEP 610 provenance and exact pinned client interface. For every turn it also
constructs the pinned SDK's real `Message`, `UriPart`, and zero-child `Turn`
models and exercises Weave's own root-attribute encoder and deterministic local
serialization. An SDK/schema mismatch therefore fails before source discovery,
plan mutation, or object publication. Preview does not upload manifests,
objects, roots, or other content.

Because HiveMind exposes neither a transcript snapshot cursor nor a completion
event, every selected transcript is exported, redacted, serialized, and
certified twice. The first mapped transcript is released before the second is
loaded, so this stability check does not double peak transcript memory. A
summary-stable but export-unstable session is rejected before a plan is sealed
and can be retried in a later one-session microplan.

```text
hivemind-weave review preview
    --since RFC3339
    [--until RFC3339]
    --project wandb/hivemind-chats-review
    [--agent NAME ...]
    [--repo OWNER/REPO ...]
    [--session-id ID ...]
    [--exclude-subagents]
    [--canary]
    [--next-sessions N]
    [--session-timeout-minutes MINUTES]
    [--state-path PATH]
```

For example:

```bash
uv run --offline --locked hivemind-weave review preview \
  --since 2026-07-16T00:00:00-04:00 \
  --until 2026-08-06T00:00:00-04:00 \
  --project wandb/hivemind-chats-review \
  --canary
```

Bounds must be RFC3339 instants with explicit offsets. They are normalized to
UTC in the sealed plan; the lower bound is inclusive and the upper bound is
exclusive. Omitting `--until` captures the current UTC instant once. For a real
rollout, record that cutoff and calculate the trailing 21-day lower bound from
it rather than relying on a moving `--days` value. Repeated filters are exact
matches; child sessions are included unless `--exclude-subagents` is present.

`--canary` examines stable `(last_activity_at, session_id)` order and seals the
first whole real session that is at least 24 hours inactive, is not a child,
has no mapping/tool-correlation warnings, has at most three turns and four
source spans per turn, and needs exactly one content chunk plus its index for
each turn. When the source summary supplies `turn_count`, known values above
three are rejected before transcript download and redaction. Summaries that
prove more than six tool calls or more than 100,000 aggregate source tokens are
also skipped. Missing or unfamiliar counts fall back to the complete check.
At most 25 plausible transcripts are examined in one canary invocation; a miss
fails with the explicit-session suggestion instead of turning a one-chat test
into an unbounded source scan. It does not loosen limits to manufacture a
candidate.

`--next-sessions N` is the resumable backlog path. It seals only the next
1–100 whole session revisions in a deterministic least-known-work order using
content-free summary counts, with `(last_activity_at, session_id)` as the stable
tie-breaker, after excluding exact revisions already completed in the
destination project. This lets early rollout cohorts exercise ordinary chats
before the largest transcripts without omitting those larger revisions from
the backlog.
The report always prints the remaining unplanned backlog count. It cannot be
combined with `--canary` or `--session-id`, and it refuses to create a later
microplan while an earlier plan for the same window is unfinished. If a
previously completed session's activity timestamp advances, that new revision
re-enters planning so appended turns can be imported and changed historical
turns can conflict normally.

The live rollout uses `--next-sessions 1`. Larger microplans remain useful for
offline planning and future cohorts, but explicit zero-write recovery is
deliberately limited to an isolated one-session plan. This keeps a drifting
HiveMind export from stranding or obscuring work that already completed in the
same plan.

Every real CLI review preview mode runs each session in a fresh read-only
worker with a hard wall-clock deadline. The default is 15 minutes and
`--session-timeout-minutes` accepts 1–60 for backlog, canary, and exact-session
previews. Only source coordinates, immutable digests, timestamps, size counts,
an authoritative subagent boolean, and content-free per-turn canary counts
return through a bounded private pipe—never transcript content. Worker-only
canary facts are excluded from the plan hash and SQLite.
The worker receives no W&B/model credential, SQLite path, or upload interface.
If it times out, the complete worker process group (including an active
HiveMind CLI child) is terminated and reaped before the parent records the
content-free `preparation_timeout` retry state in `--next-sessions` mode. A
timeout always stops the invocation without sealing a plan; it never advances
to a later chat. Canary and exact-session timeouts do not create retry rows.
Only a parent-side source-metadata request that contains invalid Unicode or
exceeds the 2 MiB private request bound is classified as
`source_serialization`: backlog mode records that content-free code and
continues fairly, canary mode may examine the next candidate within its fixed
budget, and an exact/all-session preview aborts. Worker spawn failures,
malformed or oversized responses, orphaned descendants, and unknown failures
remain unrecorded run-level errors.

An exact session revision that already ended in a terminal zero-write
retirement or revalidation sorts behind every untouched revision. It is not
filtered out and remains in the reported backlog; after fresh work is drained,
it is retried deterministically. A later activity timestamp is a new revision
and enters the fresh tier immediately. Explicit `--session-id` selection is
unchanged by this fairness rule.

### Apply

Apply accepts only a sealed preview plan. It re-fetches the selected whole
sessions, repeats mapping and redaction, reconstructs every manifest, and
requires the source, manifest, index, preview, ordering, and project
certificates to match before the first write.

```text
hivemind-weave review apply
    --plan PLAN_ID
    --max-sessions N
    --confirm-project wandb/hivemind-chats-review
    [--state-path PATH]
```

```bash
uv run --offline --locked hivemind-weave review apply \
  --plan PLAN_ID \
  --max-sessions 1 \
  --confirm-project wandb/hivemind-chats-review
```

`--max-sessions` exposes the next stable whole-session cohort without changing
the sealed plan's membership. An identical completed apply skips the same
turns. Newly appended turns require a new preview; changed historical content
under the same session/turn key is a conflict and is never duplicated.

### Status

Status reads only local content-free evidence. It reports plan/session progress,
the number of exact session revisions currently eligible for a fair pre-seal
retry, and counts for planned, object-publishing, object-verified, root-submitting,
visible, uncertain, and conflicting turns. It never fetches transcripts or
prints titles, prompts, object contents, credentials, hashes, trace IDs, or raw
session IDs. Immutable rejection evidence remains in the journal, but the retry
count excludes a revision once a live or completed plan owns it; retired and
revalidated terminal attempts remain eligible until a successor plan is sealed.

```text
hivemind-weave review status
    [--state-path PATH]
```

### Reconcile

Reconcile is for an apply whose root result became ambiguous after submission.
It queries exact remote evidence for the sealed plan and changes local state
only when the matching root identity and manifest references are unambiguous.

```text
hivemind-weave review reconcile
    --plan PLAN_ID
    [--state-path PATH]
```

Reconcile never resubmits an uncertain root, treats absence as success, chooses
between multiple matches, or overwrites mismatched evidence. One exact match
becomes `visible`; no authoritative match remains `uncertain`; multiple or
mismatched evidence becomes `conflict`. An unresolved uncertainty or conflict
keeps the cohort and all later writes blocked.

### Recover a zero-write preflight conflict

This command is only for a sealed plan that detected changed HiveMind source
during apply **before** any object or root attempt. It is not ordinary root
reconciliation and cannot clear publication-stage, uncertain, visible, or
empty-transcript conflicts.

```text
hivemind-weave review recover-preflight
    --plan PLAN_ID
    --confirm-project wandb/hivemind-chats-review
    [--state-path PATH]
```

Recovery performs no upload and accepts only a one-session plan. It requires
revision-one zero-write ledger evidence, two complete read-only hosted queries
showing no root at every old logical key, and two matching current HiveMind
export certificates. The old attempt is terminal either way: a source that
again equals the seal is recorded as revalidated, while different stable
content is recorded as retired. The next preview derives a fresh deterministic
successor attempt from the immutable resolution proof. This also handles a
source that oscillates between two stable exports without reopening or erasing
an earlier attempt. Successor apply repeats the broad hosted-absence query
immediately before its first object publication. A positive, malformed, or
unavailable query leaves work blocked; no root is retried or inferred away.

## Full manifests and root-only previews

After final redaction, every mapped turn becomes canonical UTF-8 JSON containing
the complete remaining messages, system instructions, reasoning, tool
arguments/results, per-step usage, timestamps, mapping warnings, immutable
source metadata, and child-session links. The mutable trajectory-wide
`final_metrics` aggregate is deliberately excluded from per-turn identity so a
normal append cannot rewrite an already visible turn; the per-step usage records
remain complete. The full turn manifest is never silently truncated.

Each manifest is split only at UTF-8 boundaries into at most 64 independently
hashed chunks of at most 8 MiB each. The sealed planning index records the
ordered chunk names, SHA-256 values, byte counts, manifest hash, source payload
hash, and preview signature. After chunk publication, a separate hosted index
records the ordered immutable `weave://` refs and their read-back digests. A turn
requiring more than 64 chunks fails before upload. Publishing uses deterministic
content-addressed names and verifies every byte before the root is attempted.

The Agents-visible review trace is intentionally root-only. Its visible message
content consists of clearly marked previews of the first user message and final
assistant response, each bounded to 4,096 characters. The root also carries the
verified index/manifest references and bounded review metadata. Those previews
are navigation aids, explicitly declare when they are truncated, and are never
presented as the complete transcript. The full redacted turn remains in the
verified manifest chunks.

This flattened review representation is useful for inspection but is not the
canonical conversation topology: it does not claim to recreate historical LLM,
tool, or subagent spans.

## Manual 21-day rollout

The rollout is intentionally sequential:

1. apply one generated synthetic fixture and inspect project privacy, object
   references, root previews, and reconstruction;
2. preview and apply one real `--canary` session, inspect it manually, then
   confirm an identical rerun emits nothing;
3. using the same explicit trailing-21-day bounds, seal a
   `--next-sessions 1` microplan and apply it completely;
4. after status and UI inspection, keep repeating one-session preview/apply
   transactions; and
5. stop on any unresolved attempt before selecting another session. Never
   preflight or upload the entire backlog as one failure domain.

Each microplan still performs complete mapping, redaction, exact wire
serialization, and source-revision certification before its first upload. The
full eligible-universe digest is sealed into every microplan, while only the
bounded whole sessions and their turn certificates are retained as membership.
Recognized candidate-local preparation failures do not consume the requested
success budget, but each preview examines at most `N + 8` transcripts (and no
more than 108). Failed exact revisions remain in the backlog. Untouched
revisions run first; retries rotate by bounded attempt count and oldest attempt
time instead of letting one malformed chat monopolize `--next-sessions 1`.

Stop at the first uncertain response, conflict, privacy/permission failure,
reference mismatch, manifest reconstruction error, count mismatch, or other
verification failure. Do not skip the blocked item or continue with later
sessions. `review status` and evidence-only `review reconcile` are the only
normal next actions after an ambiguous root.

No scheduler is added after this rollout. A future incremental sync needs a
separate security and operations review.

## State and uncertainty

The default state database is
`~/.hivemind/weave-importer/state.sqlite3`. It stores content-free plan
membership, source and manifest certificates, object references, counts,
bounded error codes, and remote root identity. It contains no transcript or API
key, but its IDs, timestamps, hashes, project name, and statuses are still
sensitive; keep its directory private and retain it while the review project
exists.

Pre-seal retry evidence is one bounded row per exact session revision. It keeps
only the UUID/timestamps, immutable first and latest allowlisted error codes,
first/latest local attempt times, and a saturating attempt count. It never keeps
exception text or transcript-derived hashes. These rows are intentionally
non-deletable within the journal, so failed-only UUID coordinates persist for
the journal's lifetime; treat UUIDv5 values as sensitive metadata, not as
anonymous identifiers.

One turn follows this order:

```text
planned → objects_publishing → objects_verified → root_submitting → visible
                                                              ↘ uncertain
                  any immutable mismatch or duplicate evidence → conflict
```

Objects are written and verified before the single root. Object publication is
content-addressed and repeatable, but root submission is treated conservatively:
once its response is ambiguous, automatic replay is forbidden because the
remote write may have succeeded. Local `visible` means exact remote evidence
was observed, not merely that a request returned successfully. `uncertain`
means the outcome is not knowable from current evidence; it is not failure,
absence, or permission to retry. `conflict` means immutable evidence disagrees
and requires investigation outside the automated path.

The ledger's immutable historical identity is the redacted per-turn source
hash, not mutable session-wide presentation metadata. A previously visible turn
with the same source hash is kept as the original immutable archive snapshot
even if a later preview has a different title, branch, or other non-source
manifest metadata; the appended turn receives the current metadata. The same
manifest difference before visibility is a conflict because object publication
may already have started. Any changed source hash under an existing
session/turn key is always a changed-history conflict.

## Mapping and privacy

- One HiveMind session maps to `hivemind:<internal-session-id>`.
- The HiveMind title becomes the conversation name; source agent type becomes
  the agent name.
- User steps start turns. Leading system steps become system instructions.
- Agent steps, tool calls, observations, reasoning, usage, and historical
  timestamps remain in the complete manifest. Unmatched tool data remains
  visible with a mapping warning.
- Child sessions are separate conversations with parent/subagent attributes.
- Known ATIF 1.x variants are parsed tolerantly; unknown major versions fail at
  that session.

Credential-bearing keys, bearer/API tokens, private-key blocks, and configured
PII are removed before hashing, planning, serialization, or publication.
Nontechnical ATIF step IDs use stable transcript positions instead of raw or
hashed values, so they cannot become a guessing oracle. Redaction is defense in
depth, not proof that every confidential value was detected; the private fixed
destination and manual cohort review remain required.

SQLite retains HiveMind's internal session ID because it is the source
coordinate required for incremental conflict detection and transcript
re-fetching. Review v1 accepts session and nonempty parent coordinates only as
canonical lowercase RFC-variant UUIDv4, UUIDv5, or UUIDv7 text. Unsupported legacy IDs,
slugs, names, uppercase encodings, and other uncontracted formats fail before a
plan is sealed. UUIDv5 is name-derived, so its accepted syntax is not treated as
proof of opacity: it is preserved only in validated source-coordinate fields,
is scrubbed from generic chat fields, and keeps both local and remote review
state sensitive. HiveMind account labels are used only by the CLI while it
authenticates and are never copied or hashed into the plan. Before a cohort
starts, apply proves that the current login can still list every sealed session
ID with its exact start and activity timestamps. It then re-fetches and deeply
preflights every transcript, ordering, and turn certificate in the current
cohort before that cohort's first upload. A different login cannot silently
substitute another session universe.
Exact agent/repository selectors are used only in memory during preview. The
sealed plan and SQLite retain their non-sensitive kinds and counts, never the
raw selector values or deterministic value hashes; selected session membership
and turn certificates provide the durable cohort evidence.

Agent-native and subagent IDs are not used for refetching or idempotency. Only
their canonical UUIDv4/v7 values are preserved; UUIDv5 and any other value are
replaced by the constant `[REDACTED_SOURCE_COORDINATE]`, including in nested
metadata. UUIDv5 is allowed only for validated internal session and parent
coordinates. Generic chat
strings receive no broad `session-*`,
`call-*`, or model-prefix exemption: name-like content hidden inside a technical
shape is still scrubbed. Only independently validated UUID coordinates, ATIF
version syntax, and field-specific finite agent/provider/model metadata receive
protocol treatment. State remains private even though prompts and tool content
are never stored there.

## Canonical v2 remains gated

The review mirror does not weaken, bypass, or satisfy the canonical v2 gate.
Writes to `wandb/hivemind-chats-v2` remain blocked until a hosted Weave service
advertises and implements the reviewed historical-turn capabilities used by:

```python
capabilities = weave.get_turn_capabilities()
prepared = weave.prepare_turn(..., turn_key=...)
result = weave.upsert_turn(prepared)
status = weave.get_turn_status(prepared.logical_key)
```

The gate requires atomic root-plus-child commit, durable idempotency, exact
status lookup, authenticated project-derived identity, gzipped protobuf
transport with compressed and decompressed limits, immutable authenticated text
references, strong commit storage, and Agents conversation/span/search query
integration. Unknown, missing, or prototype-only capability values fail closed;
there is no fallback to `weave.log_turn`, OTLP, query-before-insert, or the
noncanonical review layout.

The pinned companion commit is useful for validating the client contract but
does not establish that the hosted service has those production guarantees.
Canonical import remains paused until the service deployment and capability
evidence are independently reviewed.

## Development

```bash
uv run --offline --locked pytest
uv run --offline --locked ruff check src tests
# The first build needs the Hatchling backend; use --offline after it is cached.
uv build
```

Tests should cover deterministic manifests and indexes, UTF-8 chunk boundaries,
the 8 MiB/64-chunk limits, root preview labels, content-free state, fixed-project
guards, project privacy/write preflight, preview/apply equality, cohort ordering,
idempotent object publication, ambiguous-root reconciliation, changed-history
conflicts, redaction, ATIF mapping, and the unchanged canonical capability gate.
Live tests remain opt-in, must use fresh private state, and must target only the
fixed review project.

The opt-in live test uses only an in-memory synthetic transcript. It requires a
globally fresh bounded run ID and a caller-created persistent directory with
mode `0700`; preserve that directory after any uncertain result. The API key
must already be present in the process environment; never source an `.env`
file. The test never reads HiveMind chats, and its payload forces multi-chunk
publication and reconstruction:

```bash
install -d -m 700 /absolute/private/path
HIVEMIND_WEAVE_LIVE=1 \
HIVEMIND_WEAVE_LIVE_CONFIRM_PROJECT=wandb/hivemind-chats-review \
HIVEMIND_WEAVE_LIVE_RUN_ID=synthetic-YYYYMMDD-N \
HIVEMIND_WEAVE_LIVE_STATE_PATH=/absolute/private/path/state.sqlite3 \
uv run --offline --locked pytest -q -o addopts= -m live tests/test_live.py
```
