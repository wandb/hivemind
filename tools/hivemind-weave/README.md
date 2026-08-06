# HiveMind → Weave review mirror

`hivemind-weave` prepares a redacted, lossless review copy of the authenticated
user's HiveMind chats for maintainers to inspect in Weave. This path is
deliberately **noncanonical**: it writes only to the fixed private project
`wandb/hivemind-chats-review`, uses a simplified root-plus-manifest layout, and
does not replace the atomic historical-turn contract required for the eventual
canonical v2 import.

> **Rollout status:** no live review upload or real-chat backfill is claimed by
> this branch. Preview, state, manifest, and transport behavior must pass review
> before the first synthetic apply. The abandoned partial experiment in
> `wandb/hivemind-chats` remains read-only and is not repaired or reused.

## Fixed destination and trust boundary

Every review operation is bound to:

```text
wandb/hivemind-chats-review
```

The project must already exist, be private, and be writable by the authenticated
principal. The importer checks those properties without creating a project,
changing its visibility, or writing a probe object. `review preview` requires
the explicit project spelling, `review apply` requires the same spelling through
`--confirm-project`, and any other value is rejected. `review status` and
`review reconcile` derive the destination from the sealed review state and do
not accept a project override.

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
- `WANDB_API_KEY` already present in the process environment for apply or
  reconcile.

HiveMind credentials remain inside the HiveMind CLI. The importer does not open,
source, parse, copy, or print any `.env` file. Supply `WANDB_API_KEY` through the
calling process or a trusted secret manager; do not pass it as a command-line
argument or persist it in SQLite.

This review path is manual. It does not install or use cron, LaunchAgents,
Keychain jobs, background sync, or any other scheduler.

The Weave dependency is a PEP 508 Git reference pinned to the exact companion
prototype commit:

```text
eaf0a27beffd13f90d4ec64547c53a37df4bdb94
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
each turn. It does not loosen limits to manufacture a candidate.

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

Status reads only local content-free evidence. It reports plan/session progress
and counts for planned, object-publishing, object-verified, root-submitting,
visible, uncertain, and conflicting turns. It never fetches transcripts or
prints titles, prompts, object contents, credentials, hashes, trace IDs, or raw
session IDs.

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
3. seal one immutable plan for the trailing 21-day window using an explicit
   captured cutoff;
4. apply the plan in whole-session cohorts of 1, then 5, then 20; and
5. only after each cohort is fully visible and reviewed, apply the remainder in
   another explicitly bounded cohort.

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
canonical lowercase RFC-variant UUIDv4 or UUIDv7 text. Unsupported legacy IDs,
slugs, names, uppercase encodings, and other uncontracted formats fail before a
plan is sealed. The authenticated HiveMind principal must satisfy the same
opaque-ID contract before its one-way plan-binding digest is calculated, so a
username or email address cannot become a durable offline-guessable fingerprint.
Exact agent/repository selectors are used only in memory during preview. The
sealed plan and SQLite retain their non-sensitive kinds and counts, never the
raw selector values or deterministic value hashes; selected session membership
and turn certificates provide the durable cohort evidence.

Agent-native and subagent IDs are not used for refetching or idempotency. A
canonical UUIDv4/v7 is preserved; any other value is replaced by the constant
`[REDACTED_SOURCE_COORDINATE]`, including in nested metadata. Generic chat
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
new bounded run ID and a caller-created persistent directory with mode `0700`;
it never reads HiveMind chats:

```bash
HIVEMIND_WEAVE_LIVE=1 \
HIVEMIND_WEAVE_LIVE_CONFIRM_PROJECT=wandb/hivemind-chats-review \
HIVEMIND_WEAVE_LIVE_RUN_ID=synthetic-YYYYMMDD-N \
HIVEMIND_WEAVE_LIVE_STATE_PATH=/absolute/private/path/state.sqlite3 \
uv run --offline --locked pytest -q tests/test_live.py
```
