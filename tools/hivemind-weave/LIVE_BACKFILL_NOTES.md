# Live backfill notes: what I tried, what failed, and what I still need

I want a supported way to take my recent HiveMind coding-agent sessions and review
them as conversations in Weave Agents. I built this prototype to test the full
path with real, unusually large sessions instead of proving only a small demo.

This is a draft because the mapping and local safety work are in place, but my
first 45-day live backfill has not completed. I am opening the work now so the
maintainers can validate the direction and help identify which parts should be
official product behavior instead of importer-owned recovery logic.

## What I built

The importer:

- discovers only the authenticated user's HiveMind sessions active in a fixed
  recent window;
- fetches ATIF 1.x transcripts through the authenticated HiveMind CLI;
- maps one HiveMind session to one Weave conversation and splits turns at user
  steps;
- preserves redacted system prompts, reasoning, messages, tool calls/results,
  timestamps, usage, model metadata, child-session links, and source attributes;
- logs turns independently with stable conversation and turn identities;
- keeps a secure SQLite journal so identical reruns skip, appends import once,
  historical edits conflict, and interrupted uploads are reconciled before retry;
- freezes a run's cutoff, eligible session list, activity timestamps, and exact
  turn hashes before the first upload so a long import cannot silently change
  underneath itself;
- verifies emitted turns through the Weave conversation APIs before committing
  local state; and
- bounds memory to the largest session and fragments archival fields instead of
  silently truncating them.

The offline suite covers pagination, ATIF variants, mapping, PII and credential
redaction, large-field transport, state security, crash recovery, conflicts,
remote verification, and idempotent reruns. The current suite passes 300 tests
with one opt-in live test skipped, and Ruff is clean.

## What happened in the live 45-day run

### 1. Large turns exceeded the hosted request limit

My first live attempt used a one-off four-worker backfill runner to reduce the
wall-clock time. The sessions were much larger than ordinary chat examples. The
OpenTelemetry batch processor grouped too many large spans into one request and
Weave returned HTTP 413.

That failure was not atomic. Some roots and children were already visible remotely
when a later request failed. At the point I stopped, 71 turns were committed in
the local worker journals and 7 remained pending. Three pending turns had partial
remote roots, with 210 expected child spans still absent. I did not mark those
turns committed and did not blindly retry them, because either choice could hide
missing content or create duplicate conversations.

The package now defaults the exporter to four spans per batch when the operator
has not supplied a value, flushes and verifies one session at a time, and transports
large archival and tool fields in bounded fragments. It also rejects a single
pathological turn above an explicit span ceiling. One remaining limitation is that
an individual ordinary message or LLM field can still exceed a server byte limit;
span-count batching alone cannot solve that case.

### 2. Recovery needed exact remote evidence, not “try again”

Once partial traces existed, normal idempotency was no longer enough. I built a
read-only recovery auditor that reconstructs each expected turn, proves the remote
root, inventories its children, and identifies only the missing spans. It is
deliberately fail-closed: multiple possible roots, unexpected children, changed
source content, or an uncertain match stops recovery.

This is where the work became much harder than the basic importer. There is no
single supported operation that says “append exactly these missing children to
this historical turn if this idempotency key and payload hash still match.” The
prototype therefore has to combine trace IDs, canonical message content,
timestamps, hashes, and exact child counts across several APIs.

### 3. PII model labels varied across fresh processes

The same already-redacted logical payload was classified with a different typed
PII label in one fresh process. One audit therefore saw a reviewed one-leaf
typed-to-typed substitution, while a later process could see an exact match. The
text was not exposed, but a recovery policy that required exactly one particular
typed substitution rejected the stronger all-exact result.

The normal importer now computes turn identity from the complete
credential-scrubbed source before Presidio, so a statistical label choice cannot
change idempotency on future runs. Historical partial traces still require a
small, explicit compatibility policy that accepts either an all-exact graph or
the one reviewed typed-to-typed edge and binds the observed branch into its proof.

### 4. My recovery sandbox treated harmless CLI cache activity as mutation

I ran the recovery audit in a deny-default macOS sandbox and used a private HOME so
the audit could not modify the real HiveMind login state. HiveMind 1.0.6 creates a
versioned cache directory under HOME. My first manifest included parent directory
metadata, so that expected cache creation looked like protected-state drift.

I replaced that with a cache-aware scratch wrapper that pre-creates, attests,
accounts for, and removes only the expected cache subtree. The wrapper holds file
descriptors to the real auth files, checks their metadata before and after, never
reads their contents, and keeps direct and data-volume aliases write-denied.

### 5. The recovery sandbox omitted HiveMind's macOS Keychain helper

After fixing the cache false positive, the sealed audit still failed during the
HiveMind authentication stage. A paired fixed-stage diagnostic reproduced
`cli_auth / audit_failure` in two isolated workers.

Static inspection showed why: HiveMind 1.0.6 retrieves its macOS Keychain secret
by spawning `/usr/bin/security`, but my deny-default sandbox allowed only the
Python and HiveMind executables. A direct output-suppressed auth probe outside that
custom sandbox succeeds; the conservative recovery harness was blocking the
credential helper it depended on.

The narrow next step is to pin the Apple-owned helper binary by hash and metadata,
allow only that literal executable for process execution and executable mapping,
retain every existing auth-file write denial, and rerun the read-only audit. This
is a problem in my one-off recovery sandbox, not evidence that the normal importer
cannot use an authenticated HiveMind CLI.

## Why there were so many diagnostics

Every diagnostic after the 413 was read-only and used fixed-enum output. I kept the
existing workflow lock, suppressed child stdout/stderr, pinned the exact scripts
and runtime closure, checked the worker databases and recovery journal after each
attempt, and refused to let a diagnostic authorize an upload. The state stayed at
71 committed, 7 pending, and zero recovery-journal commits.

That caution made the investigation slow, but it avoided turning a recoverable
partial import into silent data loss or duplicates. It also exposed a useful
product boundary: importing is straightforward when every turn succeeds, while
recovering a partially accepted distributed trace needs stronger server-side
idempotency and append semantics than a client can safely infer.

## What still needs to happen before this is ready

1. Finish the narrowly pinned Keychain-helper policy and rerun the read-only
   partial-trace audit.
2. Accept either the all-exact graph or the single reviewed typed-to-typed
   compatibility edge, with the actual graph bound into a new recovery proof.
3. Append only the 210 proven-missing children, verify the three partial roots,
   and commit those pending turns.
4. Consolidate the old experimental worker journals into one canonical journal
   without losing pending evidence.
5. Run the hardened single-process CLI for the fixed 45-day window.
6. Verify the Weave Agents UI grouping, full redacted content, historical order,
   tools/reasoning, and child-session links.
7. Run the identical command again and require zero emitted turns.
8. Exercise the opt-in live smoke test in a disposable project.

## What I would like maintainer guidance on

I would like to converge this prototype on supported contracts instead of keeping
all of the complexity in a sidecar tool. In particular:

- Is ATIF the intended long-term transcript export contract, including copied
  context, tool observations, child sessions, and historical timestamps?
- Can session pagination expose a stable cursor or snapshot token so a large
  account does not need repeated offset sweeps around equal timestamps?
- Is there a supported Weave ingestion path for historical Agent conversations
  with a caller-provided idempotency key and an atomic turn boundary?
- Can a client query a turn by that key and ask which expected spans are missing,
  or conditionally append children to an existing root?
- What are the supported compressed and uncompressed request limits for
  `log_turn` and OTLP export, and should the SDK provide byte-aware batching?
- Can HiveMind expose a documented non-interactive auth mode for headless import
  jobs, or at least document the macOS Keychain helper dependency?
- Which searchable attributes should be standardized for source session, parent
  session, repository, branch, source activity time, payload hash, and importer
  version?

I am not asking to merge this as production-ready yet. I am asking whether this is
the right product direction and which pieces should move into HiveMind, Weave, or
their supported SDKs before I finish the live backfill.
