"""Secure, durable SQLite state for fixed-worklist imports and turn recovery."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from . import __version__
from .errors import StateConflictError, StateStoreError
from .utils import canonical_json, isoformat_z, parse_datetime, sha256_json

try:
    import fcntl
except ImportError:  # pragma: no cover - the importer targets macOS/Linux.
    fcntl = None  # type: ignore[assignment]


DB_APPLICATION_ID = 0x484D5756
DB_SCHEMA_VERSION = 13
RUN_SCHEMA_VERSION = "2"
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ATOMIC_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RUN_SUCCESS_STATUSES = frozenset({"empty", "imported", "skipped"})
_SESSION_PROCESSABLE_STATUSES = frozenset({"certified", "failed", "conflict"})


@dataclass(frozen=True)
class StateRow:
    project: str
    session_id: str
    turn_key: str
    payload_sha256: str
    source_payload_sha256: str
    verification_signature: str
    status: str
    source_last_activity_at: str
    atif_schema_version: str
    trace_ids: list[str]
    root_span_ids: list[str]
    span_count: int
    last_error: str
    revision: int


@dataclass(frozen=True)
class ImportRun:
    run_id: str
    project: str
    cutoff: datetime
    days: int
    idle_minutes: int
    config: dict[str, Any]
    config_sha256: str
    importer_version: str
    schema_version: str
    status: str
    phase: str
    session_count: int
    discovered_count: int
    deferred_count: int
    total_turn_count: int
    turn_manifest_sha256: str
    revision: int


@dataclass(frozen=True)
class ImportRunSession:
    run_id: str
    ordinal: int
    session_id: str
    summary_last_activity_at: datetime
    status: str
    turn_count: int
    turn_set_sha256: str
    last_error: str
    revision: int


@dataclass(frozen=True)
class ImportRunTurn:
    run_id: str
    session_id: str
    ordinal: int
    turn_key: str
    source_payload_sha256: str


@dataclass(frozen=True)
class BackfillPlan:
    plan_id: str
    project: str
    source_principal_sha256: str
    since_utc: datetime
    until_utc: datetime
    timezone_name: str
    selector: str
    universe_sha256: str
    status: str
    discovered_count: int
    eligible_count: int
    deferred_count: int
    invalid_count: int
    selected_count: int
    attempts: int
    last_error_code: str


@dataclass(frozen=True)
class BackfillPlanSession:
    plan_id: str
    ordinal: int
    session_id: str
    started_at: datetime
    last_activity_at: datetime
    status: str


@dataclass(frozen=True)
class BackfillPlanTurn:
    plan_id: str
    session_id: str
    ordinal: int
    turn_key: str
    source_payload_sha256: str
    wire_sha256: str
    logical_key: str
    span_count: int
    compressed_bytes: int
    uncompressed_bytes: int
    reference_count: int
    capability_version: str
    atif_schema_version: str


@dataclass(frozen=True)
class BackfillPlanStats:
    plan_id: str
    turn_count: int
    total_compressed_bytes: int
    max_compressed_bytes: int
    total_uncompressed_bytes: int
    max_uncompressed_bytes: int
    total_reference_count: int
    max_reference_count: int
    max_span_count: int
    compressed_le_64k: int
    compressed_le_256k: int
    compressed_le_1m: int
    compressed_gt_1m: int
    uncompressed_le_256k: int
    uncompressed_le_1m: int
    uncompressed_le_5m: int
    uncompressed_gt_5m: int


@dataclass(frozen=True)
class BackfillCohort:
    cohort_id: str
    plan_id: str
    ordinal: int
    status: str
    session_count: int
    attempts: int
    imported_turns: int
    skipped_turns: int
    conflicted_turns: int
    failed_items: int
    emitted_spans: int
    last_error_code: str


@dataclass(frozen=True)
class SyncFeed:
    project: str
    config_sha256: str
    since_utc: datetime
    successful_scan_watermark: datetime | None
    last_scan_started_at: datetime | None
    last_scan_succeeded_at: datetime | None
    candidate_universe_sha256: str


@dataclass(frozen=True)
class SyncDiscoveryRecord:
    session_id: str
    started_at: datetime
    last_activity_at: datetime
    activity_known: bool
    eligible_after: datetime
    status: str


@dataclass(frozen=True)
class SyncLedgerSession:
    project: str
    session_id: str
    started_at: datetime
    last_activity_at: datetime
    activity_known: bool
    eligible_after: datetime
    status: str
    plan_id: str
    completed_activity_at: datetime | None
    attempts: int


@dataclass(frozen=True)
class SyncReconcileResult:
    resolved_attempts: int
    unresolved_attempts: int
    evidence_available: bool


@dataclass(frozen=True)
class AtomicTurnAttempt:
    project: str
    session_id: str
    turn_key: str
    source_payload_sha256: str
    status: str
    wire_sha256: str
    logical_key: str
    capability_version: str
    reference_count: int
    span_count: int
    commit_id: str
    trace_ids: tuple[str, ...]
    root_span_ids: tuple[str, ...]
    error_code: str
    revision: int


def _certified_backfill_stats(
    plan_id: str,
    turns: list[BackfillPlanTurn],
) -> BackfillPlanStats:
    compressed = [turn.compressed_bytes for turn in turns]
    uncompressed = [turn.uncompressed_bytes for turn in turns]
    references = [turn.reference_count for turn in turns]
    spans = [turn.span_count for turn in turns]
    return BackfillPlanStats(
        plan_id=plan_id,
        turn_count=len(turns),
        total_compressed_bytes=sum(compressed),
        max_compressed_bytes=max(compressed, default=0),
        total_uncompressed_bytes=sum(uncompressed),
        max_uncompressed_bytes=max(uncompressed, default=0),
        total_reference_count=sum(references),
        max_reference_count=max(references, default=0),
        max_span_count=max(spans, default=0),
        compressed_le_64k=sum(value <= 64 * 1024 for value in compressed),
        compressed_le_256k=sum(64 * 1024 < value <= 256 * 1024 for value in compressed),
        compressed_le_1m=sum(256 * 1024 < value <= 1024 * 1024 for value in compressed),
        compressed_gt_1m=sum(value > 1024 * 1024 for value in compressed),
        uncompressed_le_256k=sum(value <= 256 * 1024 for value in uncompressed),
        uncompressed_le_1m=sum(256 * 1024 < value <= 1024 * 1024 for value in uncompressed),
        uncompressed_le_5m=sum(1024 * 1024 < value <= 5 * 1024 * 1024 for value in uncompressed),
        uncompressed_gt_5m=sum(value > 5 * 1024 * 1024 for value in uncompressed),
    )


_IMPORTED_TURNS_SQL = """
CREATE TABLE imported_turns (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL DEFAULT '',
    verification_signature TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'committed', 'conflict')),
    source_last_activity_at TEXT NOT NULL,
    atif_schema_version TEXT NOT NULL,
    trace_ids_json TEXT NOT NULL DEFAULT '[]',
    root_span_ids_json TEXT NOT NULL DEFAULT '[]',
    span_count INTEGER NOT NULL DEFAULT 0 CHECK(span_count >= 0),
    importer_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    imported_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (project, session_id, turn_key)
)
"""

_IMPORT_RUNS_SQL = """
CREATE TABLE import_runs (
    run_id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    cutoff TEXT NOT NULL,
    days INTEGER NOT NULL CHECK(days BETWEEN 1 AND 365),
    idle_minutes INTEGER NOT NULL CHECK(idle_minutes >= 0),
    config_json TEXT NOT NULL,
    config_sha256 TEXT NOT NULL,
    importer_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'completed')),
    phase TEXT NOT NULL CHECK(phase IN ('certifying', 'ready', 'completed')),
    session_count INTEGER NOT NULL CHECK(session_count > 0),
    discovered_count INTEGER NOT NULL CHECK(discovered_count >= session_count),
    deferred_count INTEGER NOT NULL CHECK(deferred_count >= 0),
    manifest_sha256 TEXT NOT NULL,
    total_turn_count INTEGER NOT NULL DEFAULT 0 CHECK(total_turn_count >= 0),
    turn_manifest_sha256 TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    certified_at TEXT,
    completed_at TEXT,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    CHECK(
        (status = 'active' AND phase IN ('certifying', 'ready') AND completed_at IS NULL)
        OR (status = 'completed' AND phase = 'completed' AND completed_at IS NOT NULL)
    )
)
"""

_IMPORT_RUN_SESSIONS_SQL = """
CREATE TABLE import_run_sessions (
    run_id TEXT NOT NULL REFERENCES import_runs(run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    summary_last_activity_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(
        status IN (
            'uncertified', 'certified', 'empty', 'imported', 'skipped', 'failed', 'conflict'
        )
    ),
    turn_count INTEGER NOT NULL DEFAULT -1 CHECK(turn_count >= -1),
    turn_set_sha256 TEXT NOT NULL DEFAULT '',
    certified_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (run_id, session_id),
    UNIQUE (run_id, ordinal),
    CHECK(
        (turn_count = -1 AND turn_set_sha256 = '' AND certified_at IS NULL)
        OR (turn_count >= 0 AND length(turn_set_sha256) = 64 AND certified_at IS NOT NULL)
    )
)
"""

_IMPORT_RUN_TURNS_SQL = """
CREATE TABLE import_run_turns (
    run_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    PRIMARY KEY (run_id, session_id, turn_key),
    UNIQUE (run_id, session_id, ordinal),
    FOREIGN KEY (run_id, session_id)
        REFERENCES import_run_sessions(run_id, session_id)
)
"""

_BACKFILL_PLANS_SQL = """
CREATE TABLE backfill_plans (
    plan_id TEXT PRIMARY KEY CHECK(length(plan_id) = 64),
    project TEXT NOT NULL,
    source_principal_sha256 TEXT NOT NULL CHECK(length(source_principal_sha256) = 64),
    since_utc TEXT NOT NULL,
    until_utc TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    selector TEXT NOT NULL CHECK(selector IN ('backlog', 'canary')),
    universe_sha256 TEXT NOT NULL CHECK(length(universe_sha256) = 64),
    status TEXT NOT NULL CHECK(status IN ('planned', 'applying', 'completed', 'blocked')),
    discovered_count INTEGER NOT NULL CHECK(discovered_count >= 0),
    eligible_count INTEGER NOT NULL CHECK(eligible_count >= 0),
    deferred_count INTEGER NOT NULL CHECK(deferred_count >= 0),
    invalid_count INTEGER NOT NULL CHECK(invalid_count >= 0),
    selected_count INTEGER NOT NULL CHECK(selected_count >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK(
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status != 'completed' AND completed_at IS NULL)
    )
)
"""

_BACKFILL_PLAN_SESSIONS_SQL = """
CREATE TABLE backfill_plan_sessions (
    plan_id TEXT NOT NULL REFERENCES backfill_plans(plan_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'completed')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plan_id, session_id),
    UNIQUE (plan_id, ordinal)
)
"""

_BACKFILL_PLAN_FILTERS_SQL = """
CREATE TABLE backfill_plan_filters (
    plan_id TEXT NOT NULL REFERENCES backfill_plans(plan_id),
    filter_kind TEXT NOT NULL CHECK(
        filter_kind IN ('agent', 'repository', 'session', 'exclude_subagents')
    ),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    filter_value TEXT NOT NULL,
    PRIMARY KEY (plan_id, filter_kind, ordinal),
    UNIQUE (plan_id, filter_kind, filter_value)
)
"""

_BACKFILL_PLAN_TURNS_SQL = """
CREATE TABLE backfill_plan_turns (
    plan_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    wire_sha256 TEXT NOT NULL CHECK(length(wire_sha256) = 64),
    logical_key TEXT NOT NULL CHECK(length(logical_key) = 64),
    span_count INTEGER NOT NULL CHECK(span_count > 0),
    compressed_bytes INTEGER NOT NULL CHECK(compressed_bytes > 0),
    uncompressed_bytes INTEGER NOT NULL CHECK(uncompressed_bytes > 0),
    reference_count INTEGER NOT NULL CHECK(reference_count >= 0),
    capability_version TEXT NOT NULL,
    atif_schema_version TEXT NOT NULL,
    PRIMARY KEY (plan_id, session_id, turn_key),
    UNIQUE (plan_id, session_id, ordinal),
    FOREIGN KEY (plan_id, session_id)
        REFERENCES backfill_plan_sessions(plan_id, session_id)
)
"""

_BACKFILL_PLAN_STATS_SQL = """
CREATE TABLE backfill_plan_stats (
    plan_id TEXT PRIMARY KEY REFERENCES backfill_plans(plan_id),
    turn_count INTEGER NOT NULL CHECK(turn_count >= 0),
    total_compressed_bytes INTEGER NOT NULL CHECK(total_compressed_bytes >= 0),
    max_compressed_bytes INTEGER NOT NULL CHECK(max_compressed_bytes >= 0),
    total_uncompressed_bytes INTEGER NOT NULL CHECK(total_uncompressed_bytes >= 0),
    max_uncompressed_bytes INTEGER NOT NULL CHECK(max_uncompressed_bytes >= 0),
    total_reference_count INTEGER NOT NULL CHECK(total_reference_count >= 0),
    max_reference_count INTEGER NOT NULL CHECK(max_reference_count >= 0),
    max_span_count INTEGER NOT NULL CHECK(max_span_count >= 0),
    compressed_le_64k INTEGER NOT NULL CHECK(compressed_le_64k >= 0),
    compressed_le_256k INTEGER NOT NULL CHECK(compressed_le_256k >= 0),
    compressed_le_1m INTEGER NOT NULL CHECK(compressed_le_1m >= 0),
    compressed_gt_1m INTEGER NOT NULL CHECK(compressed_gt_1m >= 0),
    uncompressed_le_256k INTEGER NOT NULL CHECK(uncompressed_le_256k >= 0),
    uncompressed_le_1m INTEGER NOT NULL CHECK(uncompressed_le_1m >= 0),
    uncompressed_le_5m INTEGER NOT NULL CHECK(uncompressed_le_5m >= 0),
    uncompressed_gt_5m INTEGER NOT NULL CHECK(uncompressed_gt_5m >= 0),
    CHECK(
        compressed_le_64k + compressed_le_256k + compressed_le_1m + compressed_gt_1m
        = turn_count
    ),
    CHECK(
        uncompressed_le_256k + uncompressed_le_1m
        + uncompressed_le_5m + uncompressed_gt_5m = turn_count
    )
)
"""

_SYNC_FEEDS_SQL = """
CREATE TABLE sync_feeds (
    project TEXT PRIMARY KEY,
    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
    since_utc TEXT NOT NULL,
    successful_scan_watermark TEXT NOT NULL DEFAULT '',
    last_scan_started_at TEXT NOT NULL DEFAULT '',
    last_scan_succeeded_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
, candidate_universe_sha256 TEXT NOT NULL DEFAULT ''
    CHECK(length(candidate_universe_sha256) IN (0, 64)))
"""

_SYNC_SESSIONS_SQL = """
CREATE TABLE sync_sessions (
    project TEXT NOT NULL REFERENCES sync_feeds(project),
    session_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    activity_known INTEGER NOT NULL CHECK(activity_known IN (0, 1)),
    eligible_after TEXT NOT NULL,
    status TEXT NOT NULL CHECK(
        status IN ('deferred', 'queued', 'processing', 'completed', 'blocked')
    ),
    plan_id TEXT NOT NULL DEFAULT '' CHECK(length(plan_id) IN (0, 64)),
    completed_activity_at TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    observed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (project, session_id)
)
"""

_SYNC_ATTEMPTS_SQL = """
CREATE TABLE sync_attempts (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    plan_id TEXT NOT NULL REFERENCES backfill_plans(plan_id) CHECK(length(plan_id) = 64),
    source_last_activity_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('processing', 'blocked', 'completed')),
    error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (project, session_id, plan_id),
    FOREIGN KEY (project, session_id) REFERENCES sync_sessions(project, session_id),
    CHECK(
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status != 'completed' AND completed_at IS NULL)
    )
)
"""

_SYNC_SESSION_QUEUE_INDEX_SQL = """
CREATE INDEX sync_sessions_queue
ON sync_sessions(project, status, last_activity_at, session_id)
"""

_SYNC_ATTEMPT_STATUS_INDEX_SQL = """
CREATE INDEX sync_attempts_status
ON sync_attempts(project, status)
"""

_SYNC_FEED_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER sync_feeds_immutable
BEFORE UPDATE OF project, config_sha256, since_utc ON sync_feeds
BEGIN
    SELECT RAISE(ABORT, 'sync feed identity is immutable');
END
"""

_SYNC_FEED_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER sync_feeds_no_delete
BEFORE DELETE ON sync_feeds
BEGIN
    SELECT RAISE(ABORT, 'sync feeds cannot be deleted');
END
"""

_SYNC_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER sync_sessions_immutable
BEFORE UPDATE OF project, session_id, started_at ON sync_sessions
BEGIN
    SELECT RAISE(ABORT, 'sync session identity is immutable');
END
"""

_SYNC_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER sync_sessions_no_delete
BEFORE DELETE ON sync_sessions
BEGIN
    SELECT RAISE(ABORT, 'sync sessions cannot be deleted');
END
"""

_SYNC_ATTEMPT_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER sync_attempts_immutable
BEFORE UPDATE OF project, session_id, plan_id, source_last_activity_at ON sync_attempts
BEGIN
    SELECT RAISE(ABORT, 'sync attempt identity is immutable');
END
"""

_SYNC_ATTEMPT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER sync_attempts_no_delete
BEFORE DELETE ON sync_attempts
BEGIN
    SELECT RAISE(ABORT, 'sync attempts cannot be deleted');
END
"""

_SYNC_SCHEMA_SQL = (
    _SYNC_FEEDS_SQL,
    _SYNC_SESSIONS_SQL,
    _SYNC_ATTEMPTS_SQL,
    _SYNC_SESSION_QUEUE_INDEX_SQL,
    _SYNC_ATTEMPT_STATUS_INDEX_SQL,
    _SYNC_FEED_IMMUTABLE_TRIGGER_SQL,
    _SYNC_FEED_NO_DELETE_TRIGGER_SQL,
    _SYNC_SESSION_IMMUTABLE_TRIGGER_SQL,
    _SYNC_SESSION_NO_DELETE_TRIGGER_SQL,
    _SYNC_ATTEMPT_IMMUTABLE_TRIGGER_SQL,
    _SYNC_ATTEMPT_NO_DELETE_TRIGGER_SQL,
)

_ATOMIC_TURN_ATTEMPTS_SQL = """
CREATE TABLE atomic_turn_attempts (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    status TEXT NOT NULL CHECK(
        status IN (
            'planned', 'prepared', 'submitting', 'acknowledged', 'committed',
            'rejected', 'uncertain', 'conflict'
        )
    ),
    error_code TEXT NOT NULL DEFAULT '' CHECK(length(error_code) <= 64),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (project, session_id, turn_key)
)
"""

_ATOMIC_TURN_CERTIFICATES_SQL = """
CREATE TABLE atomic_turn_certificates (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    wire_sha256 TEXT NOT NULL CHECK(length(wire_sha256) = 64),
    logical_key TEXT NOT NULL CHECK(length(logical_key) = 64),
    capability_version TEXT NOT NULL CHECK(length(capability_version) BETWEEN 1 AND 128),
    reference_count INTEGER NOT NULL CHECK(reference_count >= 0),
    span_count INTEGER NOT NULL CHECK(span_count > 0),
    prepared_at TEXT NOT NULL,
    PRIMARY KEY (project, session_id, turn_key),
    FOREIGN KEY (project, session_id, turn_key)
        REFERENCES atomic_turn_attempts(project, session_id, turn_key)
)
"""

_ATOMIC_TURN_RECEIPTS_SQL = """
CREATE TABLE atomic_turn_receipts (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    commit_id TEXT NOT NULL CHECK(length(commit_id) BETWEEN 1 AND 256),
    trace_ids_json TEXT NOT NULL,
    root_span_ids_json TEXT NOT NULL,
    acknowledged_at TEXT NOT NULL,
    PRIMARY KEY (project, session_id, turn_key),
    FOREIGN KEY (project, session_id, turn_key)
        REFERENCES atomic_turn_attempts(project, session_id, turn_key)
)
"""

_ATOMIC_TURN_STATUS_INDEX_SQL = """
CREATE INDEX atomic_turn_attempts_status
ON atomic_turn_attempts(project, status)
"""

_ATOMIC_TURN_IDENTITY_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_attempts_identity_immutable
BEFORE UPDATE OF project, session_id, turn_key, source_payload_sha256
ON atomic_turn_attempts
BEGIN
    SELECT RAISE(ABORT, 'atomic turn identity is immutable');
END
"""

_ATOMIC_TURN_REVISION_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_attempts_revision_guard
BEFORE UPDATE ON atomic_turn_attempts
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'atomic turn revision was not advanced');
END
"""

_ATOMIC_TURN_TRANSITION_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_attempts_transition_guard
BEFORE UPDATE OF status ON atomic_turn_attempts
WHEN NOT (
    (OLD.status = 'planned' AND NEW.status IN ('prepared', 'conflict'))
    OR (OLD.status = 'prepared' AND NEW.status IN ('submitting', 'rejected', 'conflict'))
    OR (
        OLD.status = 'submitting'
        AND NEW.status IN ('acknowledged', 'rejected', 'uncertain', 'conflict')
    )
    OR (
        OLD.status = 'uncertain'
        AND NEW.status IN ('submitting', 'acknowledged', 'rejected', 'conflict')
    )
    OR (OLD.status = 'acknowledged' AND NEW.status IN ('committed', 'conflict'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid atomic turn lifecycle transition');
END
"""

_ATOMIC_TURN_PREPARED_GUARD_SQL = """
CREATE TRIGGER atomic_turn_attempts_prepared_guard
BEFORE UPDATE OF status ON atomic_turn_attempts
WHEN NEW.status = 'prepared' AND NOT EXISTS (
    SELECT 1 FROM atomic_turn_certificates AS certificate
    WHERE certificate.project = NEW.project
      AND certificate.session_id = NEW.session_id
      AND certificate.turn_key = NEW.turn_key
)
BEGIN
    SELECT RAISE(ABORT, 'prepared atomic turn lacks an immutable certificate');
END
"""

_ATOMIC_TURN_ACKNOWLEDGED_GUARD_SQL = """
CREATE TRIGGER atomic_turn_attempts_acknowledged_guard
BEFORE UPDATE OF status ON atomic_turn_attempts
WHEN NEW.status = 'acknowledged' AND NOT EXISTS (
    SELECT 1 FROM atomic_turn_receipts AS receipt
    WHERE receipt.project = NEW.project
      AND receipt.session_id = NEW.session_id
      AND receipt.turn_key = NEW.turn_key
)
BEGIN
    SELECT RAISE(ABORT, 'acknowledged atomic turn lacks immutable returned evidence');
END
"""

_ATOMIC_TURN_COMMITTED_GUARD_SQL = """
CREATE TRIGGER atomic_turn_attempts_committed_guard
BEFORE UPDATE OF status ON atomic_turn_attempts
WHEN NEW.status = 'committed' AND (
    NOT EXISTS (
        SELECT 1 FROM atomic_turn_certificates AS certificate
        WHERE certificate.project = NEW.project
          AND certificate.session_id = NEW.session_id
          AND certificate.turn_key = NEW.turn_key
    )
    OR NOT EXISTS (
        SELECT 1 FROM atomic_turn_receipts AS receipt
        WHERE receipt.project = NEW.project
          AND receipt.session_id = NEW.session_id
          AND receipt.turn_key = NEW.turn_key
          AND json_array_length(receipt.trace_ids_json) > 0
          AND json_array_length(receipt.root_span_ids_json) > 0
    )
)
BEGIN
    SELECT RAISE(ABORT, 'committed atomic turn lacks complete private evidence');
END
"""

_ATOMIC_TURN_CERTIFICATE_INSERT_GUARD_SQL = """
CREATE TRIGGER atomic_turn_certificates_insert_guard
BEFORE INSERT ON atomic_turn_certificates
WHEN NOT EXISTS (
    SELECT 1 FROM atomic_turn_attempts AS attempt
    WHERE attempt.project = NEW.project
      AND attempt.session_id = NEW.session_id
      AND attempt.turn_key = NEW.turn_key
      AND attempt.status = 'planned'
)
BEGIN
    SELECT RAISE(ABORT, 'atomic turn certificate can only be inserted while planned');
END
"""

_ATOMIC_TURN_RECEIPT_INSERT_GUARD_SQL = """
CREATE TRIGGER atomic_turn_receipts_insert_guard
BEFORE INSERT ON atomic_turn_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM atomic_turn_attempts AS attempt
    WHERE attempt.project = NEW.project
      AND attempt.session_id = NEW.session_id
      AND attempt.turn_key = NEW.turn_key
      AND attempt.status IN ('submitting', 'uncertain')
)
BEGIN
    SELECT RAISE(ABORT, 'atomic returned evidence has no active submission');
END
"""

_ATOMIC_TURN_CERTIFICATE_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_certificates_immutable
BEFORE UPDATE ON atomic_turn_certificates
BEGIN
    SELECT RAISE(ABORT, 'atomic turn certificates are immutable');
END
"""

_ATOMIC_TURN_CERTIFICATE_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_certificates_no_delete
BEFORE DELETE ON atomic_turn_certificates
BEGIN
    SELECT RAISE(ABORT, 'atomic turn certificates cannot be deleted');
END
"""

_ATOMIC_TURN_RECEIPT_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_receipts_immutable
BEFORE UPDATE ON atomic_turn_receipts
BEGIN
    SELECT RAISE(ABORT, 'atomic returned evidence is immutable');
END
"""

_ATOMIC_TURN_RECEIPT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_receipts_no_delete
BEFORE DELETE ON atomic_turn_receipts
BEGIN
    SELECT RAISE(ABORT, 'atomic returned evidence cannot be deleted');
END
"""

_ATOMIC_TURN_ATTEMPT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER atomic_turn_attempts_no_delete
BEFORE DELETE ON atomic_turn_attempts
BEGIN
    SELECT RAISE(ABORT, 'atomic turn attempts cannot be deleted');
END
"""

_ATOMIC_TURN_SCHEMA_SQL = (
    _ATOMIC_TURN_ATTEMPTS_SQL,
    _ATOMIC_TURN_CERTIFICATES_SQL,
    _ATOMIC_TURN_RECEIPTS_SQL,
    _ATOMIC_TURN_STATUS_INDEX_SQL,
    _ATOMIC_TURN_IDENTITY_TRIGGER_SQL,
    _ATOMIC_TURN_REVISION_TRIGGER_SQL,
    _ATOMIC_TURN_TRANSITION_TRIGGER_SQL,
    _ATOMIC_TURN_PREPARED_GUARD_SQL,
    _ATOMIC_TURN_ACKNOWLEDGED_GUARD_SQL,
    _ATOMIC_TURN_COMMITTED_GUARD_SQL,
    _ATOMIC_TURN_CERTIFICATE_INSERT_GUARD_SQL,
    _ATOMIC_TURN_RECEIPT_INSERT_GUARD_SQL,
    _ATOMIC_TURN_CERTIFICATE_IMMUTABLE_TRIGGER_SQL,
    _ATOMIC_TURN_CERTIFICATE_NO_DELETE_TRIGGER_SQL,
    _ATOMIC_TURN_RECEIPT_IMMUTABLE_TRIGGER_SQL,
    _ATOMIC_TURN_RECEIPT_NO_DELETE_TRIGGER_SQL,
    _ATOMIC_TURN_ATTEMPT_NO_DELETE_TRIGGER_SQL,
)

_REVIEW_PLANS_SQL = """
CREATE TABLE review_plans (
    plan_id TEXT PRIMARY KEY CHECK(length(plan_id) = 64),
    project TEXT NOT NULL,
    -- Legacy column name: this stores a public source-scope certificate,
    -- never a username-, email-, or principal-derived digest.
    source_principal_sha256 TEXT NOT NULL CHECK(length(source_principal_sha256) = 64),
    since_utc TEXT NOT NULL,
    until_utc TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    selector TEXT NOT NULL CHECK(selector IN ('backlog', 'canary')),
    universe_sha256 TEXT NOT NULL CHECK(length(universe_sha256) = 64),
    status TEXT NOT NULL CHECK(status IN ('planned', 'applying', 'completed', 'blocked')),
    discovered_count INTEGER NOT NULL CHECK(discovered_count >= 0),
    eligible_count INTEGER NOT NULL CHECK(eligible_count >= 0),
    deferred_count INTEGER NOT NULL CHECK(deferred_count >= 0),
    invalid_count INTEGER NOT NULL CHECK(invalid_count >= 0),
    selected_count INTEGER NOT NULL CHECK(selected_count >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    last_error_code TEXT NOT NULL DEFAULT '' CHECK(length(last_error_code) <= 64),
    CHECK(
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status != 'completed' AND completed_at IS NULL)
    )
)
"""

_REVIEW_PLAN_SESSIONS_SQL = """
CREATE TABLE review_plan_sessions (
    plan_id TEXT NOT NULL REFERENCES review_plans(plan_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'blocked')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plan_id, session_id),
    UNIQUE (plan_id, ordinal)
)
"""

_REVIEW_PLAN_FILTERS_SQL = """
CREATE TABLE review_plan_filters (
    plan_id TEXT NOT NULL REFERENCES review_plans(plan_id),
    filter_kind TEXT NOT NULL CHECK(
        filter_kind IN ('agent', 'repository', 'session', 'exclude_subagents')
    ),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    filter_value TEXT NOT NULL,
    PRIMARY KEY (plan_id, filter_kind, ordinal),
    UNIQUE (plan_id, filter_kind, filter_value)
)
"""

_REVIEW_PLAN_TURNS_SQL = """
CREATE TABLE review_plan_turns (
    plan_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
    index_sha256 TEXT NOT NULL CHECK(length(index_sha256) = 64),
    logical_key TEXT NOT NULL CHECK(length(logical_key) = 64),
    preview_signature TEXT NOT NULL CHECK(length(preview_signature) = 64),
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    manifest_bytes INTEGER NOT NULL CHECK(manifest_bytes > 0),
    chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 64),
    max_chunk_bytes INTEGER NOT NULL CHECK(max_chunk_bytes BETWEEN 1 AND 8388608),
    index_bytes INTEGER NOT NULL CHECK(index_bytes > 0),
    atif_schema_version TEXT NOT NULL,
    PRIMARY KEY (plan_id, session_id, turn_key),
    UNIQUE (plan_id, session_id, ordinal),
    FOREIGN KEY (plan_id, session_id)
        REFERENCES review_plan_sessions(plan_id, session_id)
)
"""

_REVIEW_COHORTS_SQL = """
CREATE TABLE review_cohorts (
    cohort_id TEXT PRIMARY KEY CHECK(length(cohort_id) = 64),
    plan_id TEXT NOT NULL REFERENCES review_plans(plan_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    status TEXT NOT NULL CHECK(status IN ('planned', 'applying', 'completed', 'blocked')),
    session_count INTEGER NOT NULL CHECK(session_count > 0),
    visible_turns INTEGER NOT NULL DEFAULT 0 CHECK(visible_turns >= 0),
    skipped_turns INTEGER NOT NULL DEFAULT 0 CHECK(skipped_turns >= 0),
    conflicted_turns INTEGER NOT NULL DEFAULT 0 CHECK(conflicted_turns >= 0),
    failed_items INTEGER NOT NULL DEFAULT 0 CHECK(failed_items >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    last_error_code TEXT NOT NULL DEFAULT '' CHECK(length(last_error_code) <= 64),
    UNIQUE (plan_id, ordinal),
    CHECK(
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status != 'completed' AND completed_at IS NULL)
    )
)
"""

_REVIEW_COHORT_SESSIONS_SQL = """
CREATE TABLE review_cohort_sessions (
    cohort_id TEXT NOT NULL REFERENCES review_cohorts(cohort_id),
    plan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    PRIMARY KEY (cohort_id, session_id),
    UNIQUE (cohort_id, ordinal),
    FOREIGN KEY (plan_id, session_id)
        REFERENCES review_plan_sessions(plan_id, session_id)
)
"""

_REVIEW_TURN_LEDGER_SQL = """
CREATE TABLE review_turn_ledger (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
    logical_key TEXT NOT NULL CHECK(length(logical_key) = 64),
    preview_signature TEXT NOT NULL CHECK(length(preview_signature) = 64),
    manifest_bytes INTEGER NOT NULL CHECK(manifest_bytes > 0),
    chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 64),
    status TEXT NOT NULL CHECK(status IN (
        'planned', 'objects_publishing', 'objects_verified', 'root_submitting',
        'visible', 'uncertain', 'conflict'
    )),
    chunk_refs_json TEXT NOT NULL DEFAULT '[]',
    chunk_hashes_json TEXT NOT NULL DEFAULT '[]',
    chunk_sizes_json TEXT NOT NULL DEFAULT '[]',
    index_ref TEXT NOT NULL DEFAULT '',
    index_sha256 TEXT NOT NULL DEFAULT '' CHECK(length(index_sha256) IN (0, 64)),
    trace_id TEXT NOT NULL DEFAULT '',
    root_span_id TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '' CHECK(length(error_code) <= 64),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    visible_at TEXT,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    index_size INTEGER NOT NULL DEFAULT 0 CHECK(index_size >= 0),
    PRIMARY KEY (project, session_id, turn_key),
    CHECK(
        (status = 'visible' AND visible_at IS NOT NULL)
        OR (status != 'visible' AND visible_at IS NULL)
    )
)
"""

_REVIEW_PREFLIGHT_CONFLICT_ARCHIVE_SQL = """
CREATE TABLE review_preflight_conflict_archive (
    plan_id TEXT NOT NULL,
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
    logical_key TEXT NOT NULL CHECK(length(logical_key) = 64),
    preview_signature TEXT NOT NULL CHECK(length(preview_signature) = 64),
    manifest_bytes INTEGER NOT NULL CHECK(manifest_bytes > 0),
    chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 64),
    ledger_revision INTEGER NOT NULL CHECK(ledger_revision = 1),
    ledger_created_at TEXT NOT NULL,
    ledger_updated_at TEXT NOT NULL,
    ledger_error_code TEXT NOT NULL CHECK(
        ledger_error_code IN ('preflight_session_conflict', 'preflight_source_drift')
    ),
    proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256) = 64),
    archived_at TEXT NOT NULL,
    PRIMARY KEY (plan_id, session_id, turn_key),
    FOREIGN KEY (plan_id, session_id, turn_key)
        REFERENCES review_plan_turns(plan_id, session_id, turn_key)
)
"""

_REVIEW_PLAN_RETIREMENTS_SQL = """
CREATE TABLE review_plan_retirements (
    plan_id TEXT PRIMARY KEY REFERENCES review_plans(plan_id),
    project TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason = 'preflight_source_drift'),
    archived_turn_count INTEGER NOT NULL CHECK(archived_turn_count > 0),
    remote_match_count INTEGER NOT NULL CHECK(remote_match_count = 0),
    proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256) = 64),
    importer_version TEXT NOT NULL CHECK(length(importer_version) BETWEEN 1 AND 64),
    retired_at TEXT NOT NULL
)
"""

_REVIEW_PLAN_REVALIDATIONS_SQL = """
CREATE TABLE review_plan_revalidations (
    plan_id TEXT PRIMARY KEY REFERENCES review_plans(plan_id),
    project TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason = 'transient_preflight_export'),
    archived_turn_count INTEGER NOT NULL CHECK(archived_turn_count > 0),
    remote_match_count INTEGER NOT NULL CHECK(remote_match_count = 0),
    proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256) = 64),
    importer_version TEXT NOT NULL CHECK(length(importer_version) BETWEEN 1 AND 64),
    revalidated_at TEXT NOT NULL
)
"""

# RFC3339 UTC text with an optional fractional component is not lexicographically
# ordered within one second (``...00Z`` sorts after ``...00.1Z``). The facade
# parses, canonicalizes, and compares every source/attempt timestamp instead of
# encoding a misleading TEXT-order CHECK here or in the update trigger below.
_REVIEW_PRESEAL_FAILURES_SQL = """
CREATE TABLE review_preseal_failures (
    project TEXT NOT NULL CHECK(project = 'wandb/hivemind-chats-review'),
    session_id TEXT NOT NULL CHECK(length(session_id) = 36),
    started_at TEXT NOT NULL CHECK(length(started_at) BETWEEN 20 AND 40),
    last_activity_at TEXT NOT NULL CHECK(length(last_activity_at) BETWEEN 20 AND 40),
    first_error_code TEXT NOT NULL CHECK(first_error_code IN (
        'atif_schema', 'manifest_size', 'mapping_invalid', 'redaction_failed',
        'preparation_timeout', 'source_changed', 'source_serialization', 'source_unstable'
    )),
    last_error_code TEXT NOT NULL CHECK(last_error_code IN (
        'atif_schema', 'manifest_size', 'mapping_invalid', 'redaction_failed',
        'preparation_timeout', 'source_changed', 'source_serialization', 'source_unstable'
    )),
    attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 1 AND 65535),
    first_attempt_at TEXT NOT NULL CHECK(length(first_attempt_at) BETWEEN 20 AND 40),
    last_attempt_at TEXT NOT NULL CHECK(length(last_attempt_at) BETWEEN 20 AND 40),
    PRIMARY KEY (project, session_id, started_at, last_activity_at)
)
"""

_REVIEW_PLANS_INDEX_SQL = """
CREATE INDEX review_plans_project_status ON review_plans(project, status)
"""

_REVIEW_LEDGER_INDEX_SQL = """
CREATE INDEX review_turn_ledger_project_status ON review_turn_ledger(project, status)
"""

_REVIEW_PLAN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plans_immutable
BEFORE UPDATE OF
    plan_id, project, source_principal_sha256, since_utc, until_utc,
    timezone_name, selector, universe_sha256, discovered_count,
    eligible_count, deferred_count, invalid_count, selected_count, created_at
ON review_plans
BEGIN
    SELECT RAISE(ABORT, 'review plan identity is immutable');
END
"""

_REVIEW_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_sessions_immutable
BEFORE UPDATE OF plan_id, ordinal, session_id, started_at, last_activity_at
ON review_plan_sessions
BEGIN
    SELECT RAISE(ABORT, 'review plan session identity is immutable');
END
"""

_REVIEW_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_filters_immutable
BEFORE UPDATE ON review_plan_filters
BEGIN
    SELECT RAISE(ABORT, 'review plan filters are immutable');
END
"""

_REVIEW_PLAN_TURN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_turns_immutable
BEFORE UPDATE ON review_plan_turns
BEGIN
    SELECT RAISE(ABORT, 'review plan turn certificates are immutable');
END
"""

_REVIEW_COHORT_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_cohorts_immutable
BEFORE UPDATE OF cohort_id, plan_id, ordinal, session_count, created_at
ON review_cohorts
BEGIN
    SELECT RAISE(ABORT, 'review cohort identity is immutable');
END
"""

_REVIEW_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_cohort_sessions_immutable
BEFORE UPDATE ON review_cohort_sessions
BEGIN
    SELECT RAISE(ABORT, 'review cohort membership is immutable');
END
"""

_REVIEW_LEDGER_IDENTITY_TRIGGER_SQL = """
CREATE TRIGGER review_turn_ledger_identity_immutable
BEFORE UPDATE OF
    project, session_id, turn_key, source_payload_sha256, manifest_sha256,
    logical_key, preview_signature, manifest_bytes, chunk_count, created_at
ON review_turn_ledger
BEGIN
    SELECT RAISE(ABORT, 'review turn identity is immutable');
END
"""

_REVIEW_LEDGER_REVISION_TRIGGER_SQL = """
CREATE TRIGGER review_turn_ledger_revision_guard
BEFORE UPDATE ON review_turn_ledger
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'review turn revision was not advanced');
END
"""

_REVIEW_LEDGER_TRANSITION_TRIGGER_SQL = """
CREATE TRIGGER review_turn_ledger_transition_guard
BEFORE UPDATE OF status ON review_turn_ledger
WHEN NOT (
    (OLD.status = 'planned' AND NEW.status IN ('objects_publishing', 'conflict'))
    OR (OLD.status = 'objects_publishing' AND NEW.status IN (
        'objects_publishing', 'objects_verified', 'conflict'
    ))
    OR (OLD.status = 'objects_verified' AND NEW.status IN ('root_submitting', 'conflict'))
    OR (OLD.status = 'root_submitting' AND NEW.status IN ('visible', 'uncertain', 'conflict'))
    OR (OLD.status = 'uncertain' AND NEW.status IN ('uncertain', 'visible', 'conflict'))
    OR (OLD.status = 'visible' AND NEW.status IN ('visible', 'conflict'))
    OR (OLD.status = NEW.status AND OLD.status = 'conflict')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid review turn state transition');
END
"""

_REVIEW_PLAN_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plans_no_delete
BEFORE DELETE ON review_plans
BEGIN
    SELECT RAISE(ABORT, 'review plans cannot be deleted');
END
"""

_REVIEW_PLAN_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_sessions_no_delete
BEFORE DELETE ON review_plan_sessions
BEGIN
    SELECT RAISE(ABORT, 'review plan sessions cannot be deleted');
END
"""

_REVIEW_PLAN_FILTER_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_filters_no_delete
BEFORE DELETE ON review_plan_filters
BEGIN
    SELECT RAISE(ABORT, 'review plan filters cannot be deleted');
END
"""

_REVIEW_PLAN_TURN_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_turns_no_delete
BEFORE DELETE ON review_plan_turns
BEGIN
    SELECT RAISE(ABORT, 'review plan turn certificates cannot be deleted');
END
"""

_REVIEW_COHORT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_cohorts_no_delete
BEFORE DELETE ON review_cohorts
BEGIN
    SELECT RAISE(ABORT, 'review cohorts cannot be deleted');
END
"""

_REVIEW_COHORT_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_cohort_sessions_no_delete
BEFORE DELETE ON review_cohort_sessions
BEGIN
    SELECT RAISE(ABORT, 'review cohort membership cannot be deleted');
END
"""

# The review ledger predates attempt lineage and is globally keyed by source
# turn.  Until a future schema migration keys it by plan attempt, an archived
# row may authorize deletion only when no nonterminal plan owns the exact turn
# certificate.  This prevents an old archive from matching a later identical
# revision-1 conflict.
_REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_turn_ledger_no_delete
BEFORE DELETE ON review_turn_ledger
WHEN NOT EXISTS (
    SELECT 1
    FROM review_preflight_conflict_archive AS archive
    WHERE archive.project = OLD.project
      AND archive.session_id = OLD.session_id
      AND archive.turn_key = OLD.turn_key
      AND archive.source_payload_sha256 = OLD.source_payload_sha256
      AND archive.manifest_sha256 = OLD.manifest_sha256
      AND archive.logical_key = OLD.logical_key
      AND archive.preview_signature = OLD.preview_signature
      AND archive.manifest_bytes = OLD.manifest_bytes
      AND archive.chunk_count = OLD.chunk_count
      AND archive.ledger_revision = OLD.revision
      AND archive.ledger_error_code = OLD.error_code
      AND archive.ledger_created_at = OLD.created_at
      AND archive.ledger_updated_at = OLD.updated_at
      AND (
          EXISTS (
              SELECT 1 FROM review_plan_retirements AS retirement
              WHERE retirement.plan_id = archive.plan_id
                AND retirement.project = archive.project
                AND retirement.proof_sha256 = archive.proof_sha256
          )
          OR EXISTS (
              SELECT 1 FROM review_plan_revalidations AS revalidation
              WHERE revalidation.plan_id = archive.plan_id
                AND revalidation.project = archive.project
                AND revalidation.proof_sha256 = archive.proof_sha256
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM review_plan_turns AS active_turn
          JOIN review_plans AS active_plan
            ON active_plan.plan_id = active_turn.plan_id
          WHERE active_plan.project = OLD.project
            AND active_turn.session_id = OLD.session_id
            AND active_turn.turn_key = OLD.turn_key
            AND active_turn.source_payload_sha256 = OLD.source_payload_sha256
            AND active_turn.manifest_sha256 = OLD.manifest_sha256
            AND active_turn.logical_key = OLD.logical_key
            AND active_turn.preview_signature = OLD.preview_signature
            AND active_turn.manifest_bytes = OLD.manifest_bytes
            AND active_turn.chunk_count = OLD.chunk_count
            AND NOT EXISTS (
                SELECT 1 FROM review_plan_retirements AS active_retirement
                WHERE active_retirement.plan_id = active_turn.plan_id
            )
            AND NOT EXISTS (
                SELECT 1 FROM review_plan_revalidations AS active_revalidation
                WHERE active_revalidation.plan_id = active_turn.plan_id
            )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'review turn evidence cannot be deleted');
END
"""

_REVIEW_PREFLIGHT_ARCHIVE_INSERT_GUARD_SQL = """
CREATE TRIGGER review_preflight_conflict_archive_insert_guard
BEFORE INSERT ON review_preflight_conflict_archive
WHEN NOT EXISTS (
    SELECT 1
    FROM review_turn_ledger AS ledger
    JOIN review_plans AS plan ON plan.plan_id = NEW.plan_id
    JOIN review_plan_turns AS planned
      ON planned.plan_id = NEW.plan_id
     AND planned.session_id = NEW.session_id
     AND planned.turn_key = NEW.turn_key
    WHERE ledger.project = NEW.project
      AND ledger.session_id = NEW.session_id
      AND ledger.turn_key = NEW.turn_key
      AND plan.project = NEW.project
      AND plan.status = 'blocked'
      AND ledger.status = 'conflict'
      AND ledger.error_code IN ('preflight_session_conflict', 'preflight_source_drift')
      AND ledger.chunk_refs_json = '[]'
      AND ledger.chunk_hashes_json = '[]'
      AND ledger.chunk_sizes_json = '[]'
      AND ledger.index_ref = ''
      AND ledger.index_sha256 = ''
      AND ledger.index_size = 0
      AND ledger.trace_id = ''
      AND ledger.root_span_id = ''
      AND ledger.visible_at IS NULL
      AND ledger.revision = 1
      AND ledger.source_payload_sha256 = NEW.source_payload_sha256
      AND ledger.manifest_sha256 = NEW.manifest_sha256
      AND ledger.logical_key = NEW.logical_key
      AND ledger.preview_signature = NEW.preview_signature
      AND ledger.manifest_bytes = NEW.manifest_bytes
      AND ledger.chunk_count = NEW.chunk_count
      AND ledger.revision = NEW.ledger_revision
      AND ledger.created_at = NEW.ledger_created_at
      AND ledger.updated_at = NEW.ledger_updated_at
      AND ledger.error_code = NEW.ledger_error_code
)
BEGIN
    SELECT RAISE(ABORT, 'review preflight archive lacks exact zero-write evidence');
END
"""

_REVIEW_PREFLIGHT_ARCHIVE_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_preflight_conflict_archive_immutable
BEFORE UPDATE ON review_preflight_conflict_archive
BEGIN
    SELECT RAISE(ABORT, 'review preflight conflict archives are immutable');
END
"""

_REVIEW_PREFLIGHT_ARCHIVE_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_preflight_conflict_archive_no_delete
BEFORE DELETE ON review_preflight_conflict_archive
BEGIN
    SELECT RAISE(ABORT, 'review preflight conflict archives cannot be deleted');
END
"""

_REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL = """
CREATE TRIGGER review_plan_retirements_insert_guard
BEFORE INSERT ON review_plan_retirements
WHEN NOT (
    EXISTS (
        SELECT 1 FROM review_plans
        WHERE plan_id = NEW.plan_id
          AND project = NEW.project
          AND status = 'blocked'
          AND selected_count = 1
    )
    AND NEW.archived_turn_count = (
        SELECT COUNT(*) FROM review_preflight_conflict_archive
        WHERE plan_id = NEW.plan_id AND project = NEW.project
    )
    AND NOT EXISTS (
        SELECT 1 FROM review_plan_revalidations
        WHERE plan_id = NEW.plan_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM review_plan_turns AS planned
        JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
        JOIN review_turn_ledger AS ledger
          ON ledger.project = plan.project
         AND ledger.session_id = planned.session_id
         AND ledger.turn_key = planned.turn_key
        WHERE planned.plan_id = NEW.plan_id
          AND ledger.status IN (
              'objects_publishing', 'objects_verified', 'root_submitting',
              'visible', 'uncertain'
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM review_plan_turns AS planned
        JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
        JOIN review_turn_ledger AS ledger
          ON ledger.project = plan.project
         AND ledger.session_id = planned.session_id
         AND ledger.turn_key = planned.turn_key
        WHERE planned.plan_id = NEW.plan_id
          AND NOT EXISTS (
              SELECT 1
              FROM review_preflight_conflict_archive AS archive
              WHERE archive.plan_id = NEW.plan_id
                AND archive.project = NEW.project
                AND archive.session_id = ledger.session_id
                AND archive.turn_key = ledger.turn_key
                AND archive.source_payload_sha256 = ledger.source_payload_sha256
                AND archive.manifest_sha256 = ledger.manifest_sha256
                AND archive.logical_key = ledger.logical_key
                AND archive.preview_signature = ledger.preview_signature
                AND archive.ledger_revision = ledger.revision
                AND archive.ledger_error_code = ledger.error_code
          )
    )
    AND NOT EXISTS (
        SELECT 1 FROM review_cohorts
        WHERE plan_id = NEW.plan_id
          AND (
              status != 'blocked' OR session_count != 1
              OR visible_turns != 0 OR skipped_turns != 0
          )
    )
    AND 1 = (SELECT COUNT(*) FROM review_cohorts WHERE plan_id = NEW.plan_id)
)
BEGIN
    SELECT RAISE(ABORT, 'review plan retirement lacks complete preflight-only evidence');
END
"""

_REVIEW_PLAN_RETIREMENT_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_retirements_immutable
BEFORE UPDATE ON review_plan_retirements
BEGIN
    SELECT RAISE(ABORT, 'review plan retirements are immutable');
END
"""

_REVIEW_PLAN_RETIREMENT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_retirements_no_delete
BEFORE DELETE ON review_plan_retirements
BEGIN
    SELECT RAISE(ABORT, 'review plan retirements cannot be deleted');
END
"""

_REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL = """
CREATE TRIGGER review_plan_revalidations_insert_guard
BEFORE INSERT ON review_plan_revalidations
WHEN NOT (
    EXISTS (
        SELECT 1 FROM review_plans
        WHERE plan_id = NEW.plan_id
          AND project = NEW.project
          AND status = 'blocked'
          AND selected_count = 1
    )
    AND NOT EXISTS (
        SELECT 1 FROM review_plan_retirements
        WHERE plan_id = NEW.plan_id
    )
    AND EXISTS (
        SELECT 1 FROM review_preflight_conflict_archive
        WHERE plan_id = NEW.plan_id AND project = NEW.project
    )
    AND NEW.archived_turn_count = (
        SELECT COUNT(*) FROM review_preflight_conflict_archive
        WHERE plan_id = NEW.plan_id AND project = NEW.project
    )
    AND NOT EXISTS (
        SELECT 1
        FROM review_plan_turns AS planned
        JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
        JOIN review_turn_ledger AS ledger
          ON ledger.project = plan.project
         AND ledger.session_id = planned.session_id
         AND ledger.turn_key = planned.turn_key
        WHERE planned.plan_id = NEW.plan_id
          AND ledger.status IN (
              'objects_publishing', 'objects_verified', 'root_submitting',
              'visible', 'uncertain'
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM review_plan_turns AS planned
        JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
        JOIN review_turn_ledger AS ledger
          ON ledger.project = plan.project
         AND ledger.session_id = planned.session_id
         AND ledger.turn_key = planned.turn_key
        WHERE planned.plan_id = NEW.plan_id
          AND NOT EXISTS (
              SELECT 1
              FROM review_preflight_conflict_archive AS archive
              WHERE archive.plan_id = NEW.plan_id
                AND archive.project = NEW.project
                AND archive.session_id = ledger.session_id
                AND archive.turn_key = ledger.turn_key
                AND archive.source_payload_sha256 = ledger.source_payload_sha256
                AND archive.manifest_sha256 = ledger.manifest_sha256
                AND archive.logical_key = ledger.logical_key
                AND archive.preview_signature = ledger.preview_signature
                AND archive.ledger_revision = ledger.revision
                AND archive.ledger_error_code = ledger.error_code
          )
    )
    AND NOT EXISTS (
        SELECT 1 FROM review_cohorts
        WHERE plan_id = NEW.plan_id
          AND (
              status != 'blocked' OR session_count != 1
              OR visible_turns != 0 OR skipped_turns != 0
          )
    )
    AND 1 = (SELECT COUNT(*) FROM review_cohorts WHERE plan_id = NEW.plan_id)
)
BEGIN
    SELECT RAISE(ABORT, 'review plan revalidation lacks complete preflight-only evidence');
END
"""

_REVIEW_PLAN_REVALIDATION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_revalidations_immutable
BEFORE UPDATE ON review_plan_revalidations
BEGIN
    SELECT RAISE(ABORT, 'review plan revalidations are immutable');
END
"""

_REVIEW_PLAN_REVALIDATION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_plan_revalidations_no_delete
BEFORE DELETE ON review_plan_revalidations
BEGIN
    SELECT RAISE(ABORT, 'review plan revalidations cannot be deleted');
END
"""

_REVIEW_PRESEAL_FAILURE_IDENTITY_TRIGGER_SQL = """
CREATE TRIGGER review_preseal_failures_identity_immutable
BEFORE UPDATE OF
    project, session_id, started_at, last_activity_at,
    first_error_code, first_attempt_at
ON review_preseal_failures
BEGIN
    SELECT RAISE(ABORT, 'review pre-seal failure identity is immutable');
END
"""

_REVIEW_PRESEAL_FAILURE_INSERT_TRIGGER_SQL = """
CREATE TRIGGER review_preseal_failures_insert_guard
BEFORE INSERT ON review_preseal_failures
WHEN NEW.attempt_count != 1
  OR NEW.first_error_code != NEW.last_error_code
  OR NEW.first_attempt_at != NEW.last_attempt_at
BEGIN
    SELECT RAISE(ABORT, 'review pre-seal failure lacks initial attempt evidence');
END
"""

_REVIEW_PRESEAL_FAILURE_ATTEMPT_TRIGGER_SQL = """
CREATE TRIGGER review_preseal_failures_attempt_guard
BEFORE UPDATE ON review_preseal_failures
WHEN NOT (
    NEW.attempt_count = CASE
        WHEN OLD.attempt_count < 65535 THEN OLD.attempt_count + 1
        ELSE 65535
    END
    AND NEW.last_error_code IN (
        'atif_schema', 'manifest_size', 'mapping_invalid', 'redaction_failed',
        'preparation_timeout', 'source_changed', 'source_serialization', 'source_unstable'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'review pre-seal failure attempt evidence is invalid');
END
"""

_REVIEW_PRESEAL_FAILURE_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER review_preseal_failures_no_delete
BEFORE DELETE ON review_preseal_failures
BEGIN
    SELECT RAISE(ABORT, 'review pre-seal failure evidence cannot be deleted');
END
"""

_REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL = (
    _REVIEW_PRESEAL_FAILURES_SQL,
    _REVIEW_PRESEAL_FAILURE_IDENTITY_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_INSERT_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_ATTEMPT_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_NO_DELETE_TRIGGER_SQL,
)

_REVIEW_PREFLIGHT_RECOVERY_SCHEMA_SQL = (
    _REVIEW_PREFLIGHT_CONFLICT_ARCHIVE_SQL,
    _REVIEW_PLAN_RETIREMENTS_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_INSERT_GUARD_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL,
    _REVIEW_PLAN_RETIREMENT_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_RETIREMENT_NO_DELETE_TRIGGER_SQL,
)

_REVIEW_REVALIDATION_SCHEMA_SQL = (
    _REVIEW_PLAN_REVALIDATIONS_SQL,
    _REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL,
    _REVIEW_PLAN_REVALIDATION_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_REVALIDATION_NO_DELETE_TRIGGER_SQL,
)

_REVIEW_SCHEMA_SQL = (
    _REVIEW_PLANS_SQL,
    _REVIEW_PLAN_SESSIONS_SQL,
    _REVIEW_PLAN_FILTERS_SQL,
    _REVIEW_PLAN_TURNS_SQL,
    _REVIEW_COHORTS_SQL,
    _REVIEW_COHORT_SESSIONS_SQL,
    _REVIEW_TURN_LEDGER_SQL,
    _REVIEW_PREFLIGHT_CONFLICT_ARCHIVE_SQL,
    _REVIEW_PLAN_RETIREMENTS_SQL,
    _REVIEW_PLAN_REVALIDATIONS_SQL,
    _REVIEW_PRESEAL_FAILURES_SQL,
    _REVIEW_PLANS_INDEX_SQL,
    _REVIEW_LEDGER_INDEX_SQL,
    _REVIEW_PLAN_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_TURN_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_COHORT_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_INSERT_GUARD_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PREFLIGHT_ARCHIVE_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL,
    _REVIEW_PLAN_RETIREMENT_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_RETIREMENT_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL,
    _REVIEW_PLAN_REVALIDATION_IMMUTABLE_TRIGGER_SQL,
    _REVIEW_PLAN_REVALIDATION_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_IDENTITY_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_INSERT_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_ATTEMPT_TRIGGER_SQL,
    _REVIEW_PRESEAL_FAILURE_NO_DELETE_TRIGGER_SQL,
    _REVIEW_LEDGER_IDENTITY_TRIGGER_SQL,
    _REVIEW_LEDGER_REVISION_TRIGGER_SQL,
    _REVIEW_LEDGER_TRANSITION_TRIGGER_SQL,
    _REVIEW_PLAN_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_SESSION_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_FILTER_NO_DELETE_TRIGGER_SQL,
    _REVIEW_PLAN_TURN_NO_DELETE_TRIGGER_SQL,
    _REVIEW_COHORT_NO_DELETE_TRIGGER_SQL,
    _REVIEW_COHORT_SESSION_NO_DELETE_TRIGGER_SQL,
    _REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL,
)

_BACKFILL_COHORTS_SQL = """
CREATE TABLE backfill_cohorts (
    cohort_id TEXT PRIMARY KEY CHECK(length(cohort_id) = 64),
    plan_id TEXT NOT NULL REFERENCES backfill_plans(plan_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    status TEXT NOT NULL CHECK(status IN ('planned', 'applying', 'completed', 'blocked')),
    session_count INTEGER NOT NULL CHECK(session_count > 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    imported_turns INTEGER NOT NULL DEFAULT 0 CHECK(imported_turns >= 0),
    skipped_turns INTEGER NOT NULL DEFAULT 0 CHECK(skipped_turns >= 0),
    conflicted_turns INTEGER NOT NULL DEFAULT 0 CHECK(conflicted_turns >= 0),
    failed_items INTEGER NOT NULL DEFAULT 0 CHECK(failed_items >= 0),
    emitted_spans INTEGER NOT NULL DEFAULT 0 CHECK(emitted_spans >= 0),
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (plan_id, ordinal),
    CHECK(
        (status = 'completed' AND completed_at IS NOT NULL)
        OR (status != 'completed' AND completed_at IS NULL)
    )
)
"""

_BACKFILL_COHORT_SESSIONS_SQL = """
CREATE TABLE backfill_cohort_sessions (
    cohort_id TEXT NOT NULL REFERENCES backfill_cohorts(cohort_id),
    plan_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    PRIMARY KEY (cohort_id, session_id),
    UNIQUE (cohort_id, ordinal),
    FOREIGN KEY (plan_id, session_id)
        REFERENCES backfill_plan_sessions(plan_id, session_id)
)
"""

_BACKFILL_PLAN_INDEX_SQL = """
CREATE INDEX backfill_plans_project_status ON backfill_plans(project, status)
"""

_BACKFILL_PLAN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plans_immutable
BEFORE UPDATE OF
    plan_id, project, source_principal_sha256, since_utc, until_utc,
    timezone_name, selector, universe_sha256, discovered_count,
    eligible_count, deferred_count, invalid_count, selected_count, created_at
ON backfill_plans
BEGIN
    SELECT RAISE(ABORT, 'backfill plan is immutable');
END
"""

_BACKFILL_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_sessions_immutable
BEFORE UPDATE OF plan_id, ordinal, session_id, started_at, last_activity_at
ON backfill_plan_sessions
BEGIN
    SELECT RAISE(ABORT, 'backfill plan session is immutable');
END
"""

_BACKFILL_PLAN_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plans_no_delete
BEFORE DELETE ON backfill_plans
BEGIN
    SELECT RAISE(ABORT, 'backfill plan is immutable');
END
"""

_BACKFILL_PLAN_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_sessions_no_delete
BEFORE DELETE ON backfill_plan_sessions
BEGIN
    SELECT RAISE(ABORT, 'backfill plan session is immutable');
END
"""

_BACKFILL_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_filters_immutable
BEFORE UPDATE ON backfill_plan_filters
BEGIN
    SELECT RAISE(ABORT, 'backfill plan filters are immutable');
END
"""

_BACKFILL_PLAN_FILTER_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_filters_no_delete
BEFORE DELETE ON backfill_plan_filters
BEGIN
    SELECT RAISE(ABORT, 'backfill plan filters are immutable');
END
"""

_BACKFILL_PLAN_TURN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_turns_immutable
BEFORE UPDATE ON backfill_plan_turns
BEGIN
    SELECT RAISE(ABORT, 'backfill plan turn certificates are immutable');
END
"""

_BACKFILL_PLAN_TURN_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_turns_no_delete
BEFORE DELETE ON backfill_plan_turns
BEGIN
    SELECT RAISE(ABORT, 'backfill plan turn certificates are immutable');
END
"""

_BACKFILL_PLAN_STATS_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_stats_immutable
BEFORE UPDATE ON backfill_plan_stats
BEGIN
    SELECT RAISE(ABORT, 'backfill plan size statistics are immutable');
END
"""

_BACKFILL_PLAN_STATS_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_plan_stats_no_delete
BEFORE DELETE ON backfill_plan_stats
BEGIN
    SELECT RAISE(ABORT, 'backfill plan size statistics are immutable');
END
"""

_BACKFILL_COHORT_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_cohorts_immutable
BEFORE UPDATE OF cohort_id, plan_id, ordinal, session_count, created_at
ON backfill_cohorts
BEGIN
    SELECT RAISE(ABORT, 'backfill cohort is immutable');
END
"""

_BACKFILL_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER backfill_cohort_sessions_immutable
BEFORE UPDATE ON backfill_cohort_sessions
BEGIN
    SELECT RAISE(ABORT, 'backfill cohort membership is immutable');
END
"""

_BACKFILL_COHORT_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_cohorts_no_delete
BEFORE DELETE ON backfill_cohorts
BEGIN
    SELECT RAISE(ABORT, 'backfill cohort is immutable');
END
"""

_BACKFILL_COHORT_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER backfill_cohort_sessions_no_delete
BEFORE DELETE ON backfill_cohort_sessions
BEGIN
    SELECT RAISE(ABORT, 'backfill cohort membership is immutable');
END
"""

_RUN_INDEX_SQL = """
CREATE INDEX import_runs_project_status ON import_runs(project, status)
"""

_ACTIVE_RUN_INDEX_SQL = """
CREATE UNIQUE INDEX import_runs_one_active_project
ON import_runs(project) WHERE status = 'active'
"""

_RUN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_runs_immutable
BEFORE UPDATE OF
    run_id, project, cutoff, days, idle_minutes, config_json, config_sha256,
    importer_version, schema_version, session_count, discovered_count,
    deferred_count, manifest_sha256
ON import_runs
BEGIN
    SELECT RAISE(ABORT, 'import run manifest is immutable');
END
"""

_RUN_REVISION_TRIGGER_SQL = """
CREATE TRIGGER import_runs_revision_guard
BEFORE UPDATE ON import_runs
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'import run revision was not advanced');
END
"""

_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_immutable
BEFORE UPDATE OF run_id, ordinal, session_id, summary_last_activity_at
ON import_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'import run session manifest is immutable');
END
"""

_SESSION_CERTIFICATE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_certificate_immutable
BEFORE UPDATE OF turn_count, turn_set_sha256, certified_at
ON import_run_sessions
WHEN OLD.certified_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'import run session certificate is immutable');
END
"""

_SESSION_REVISION_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_revision_guard
BEFORE UPDATE ON import_run_sessions
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'import run session revision was not advanced');
END
"""

_SESSION_SUCCESS_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_success_guard
BEFORE UPDATE OF status ON import_run_sessions
WHEN NEW.status IN ('empty', 'imported', 'skipped') AND (
    NEW.certified_at IS NULL
    OR NEW.turn_count < 0
    OR (NEW.status = 'empty' AND NEW.turn_count != 0)
    OR (
        NEW.status IN ('imported', 'skipped') AND (
            NEW.turn_count = 0
            OR (
                SELECT COUNT(*)
                FROM import_run_turns AS certified_turn
                WHERE certified_turn.run_id = NEW.run_id
                  AND certified_turn.session_id = NEW.session_id
            ) != NEW.turn_count
            OR EXISTS (
                SELECT 1
                FROM import_run_turns AS run_turn
                JOIN import_runs AS run ON run.run_id = run_turn.run_id
                LEFT JOIN imported_turns AS turn
                  ON turn.project = run.project
                 AND turn.session_id = run_turn.session_id
                 AND turn.turn_key = run_turn.turn_key
                 AND turn.source_payload_sha256 = run_turn.source_payload_sha256
                 AND turn.status = 'committed'
                WHERE run_turn.run_id = NEW.run_id
                  AND run_turn.session_id = NEW.session_id
                  AND turn.turn_key IS NULL
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'successful session status lacks certified turn evidence');
END
"""

_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_no_delete
BEFORE DELETE ON import_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'import run session manifest is immutable');
END
"""

_RUN_TURNS_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_immutable
BEFORE UPDATE ON import_run_turns
BEGIN
    SELECT RAISE(ABORT, 'import run turn certificate is immutable');
END
"""

_RUN_TURNS_INSERT_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_insert_guard
BEFORE INSERT ON import_run_turns
WHEN NOT EXISTS (
    SELECT 1
    FROM import_run_sessions AS session
    JOIN import_runs AS run ON run.run_id = session.run_id
    WHERE session.run_id = NEW.run_id
      AND session.session_id = NEW.session_id
      AND session.status IN ('uncertified', 'failed')
      AND session.turn_count = -1
      AND run.status = 'active'
      AND run.phase = 'certifying'
)
BEGIN
    SELECT RAISE(ABORT, 'run turns can only be added during session certification');
END
"""

_RUN_TURNS_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_no_delete
BEFORE DELETE ON import_run_turns
BEGIN
    SELECT RAISE(ABORT, 'import run turn certificate is immutable');
END
"""

_TURN_REVISION_TRIGGER_SQL = """
CREATE TRIGGER imported_turns_revision_guard
BEFORE UPDATE ON imported_turns
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'imported turn revision was not advanced');
END
"""

_BACKFILL_SCHEMA_SQL = (
    _BACKFILL_PLANS_SQL,
    _BACKFILL_PLAN_SESSIONS_SQL,
    _BACKFILL_COHORTS_SQL,
    _BACKFILL_COHORT_SESSIONS_SQL,
    _BACKFILL_PLAN_INDEX_SQL,
    _BACKFILL_PLAN_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_PLAN_NO_DELETE_TRIGGER_SQL,
    _BACKFILL_PLAN_SESSION_NO_DELETE_TRIGGER_SQL,
    _BACKFILL_COHORT_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_COHORT_NO_DELETE_TRIGGER_SQL,
    _BACKFILL_COHORT_SESSION_NO_DELETE_TRIGGER_SQL,
)

_BACKFILL_CERTIFICATE_SCHEMA_SQL = (
    _BACKFILL_PLAN_FILTERS_SQL,
    _BACKFILL_PLAN_TURNS_SQL,
    _BACKFILL_PLAN_STATS_SQL,
    _BACKFILL_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_PLAN_FILTER_NO_DELETE_TRIGGER_SQL,
    _BACKFILL_PLAN_TURN_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_PLAN_TURN_NO_DELETE_TRIGGER_SQL,
    _BACKFILL_PLAN_STATS_IMMUTABLE_TRIGGER_SQL,
    _BACKFILL_PLAN_STATS_NO_DELETE_TRIGGER_SQL,
)

_SCHEMA_SQL = (
    _IMPORTED_TURNS_SQL,
    _IMPORT_RUNS_SQL,
    _IMPORT_RUN_SESSIONS_SQL,
    _IMPORT_RUN_TURNS_SQL,
    _RUN_INDEX_SQL,
    _ACTIVE_RUN_INDEX_SQL,
    _RUN_IMMUTABLE_TRIGGER_SQL,
    _RUN_REVISION_TRIGGER_SQL,
    _SESSION_IMMUTABLE_TRIGGER_SQL,
    _SESSION_CERTIFICATE_TRIGGER_SQL,
    _SESSION_REVISION_TRIGGER_SQL,
    _SESSION_SUCCESS_TRIGGER_SQL,
    _SESSION_NO_DELETE_TRIGGER_SQL,
    _RUN_TURNS_IMMUTABLE_TRIGGER_SQL,
    _RUN_TURNS_INSERT_TRIGGER_SQL,
    _RUN_TURNS_NO_DELETE_TRIGGER_SQL,
    _TURN_REVISION_TRIGGER_SQL,
    *_BACKFILL_SCHEMA_SQL,
    *_BACKFILL_CERTIFICATE_SCHEMA_SQL,
    *_SYNC_SCHEMA_SQL,
    *_ATOMIC_TURN_SCHEMA_SQL,
    *_REVIEW_SCHEMA_SQL,
)

_EXPECTED_SCHEMA_SQL = {
    "imported_turns": _IMPORTED_TURNS_SQL,
    "import_runs": _IMPORT_RUNS_SQL,
    "import_run_sessions": _IMPORT_RUN_SESSIONS_SQL,
    "import_run_turns": _IMPORT_RUN_TURNS_SQL,
    "import_runs_project_status": _RUN_INDEX_SQL,
    "import_runs_one_active_project": _ACTIVE_RUN_INDEX_SQL,
    "import_runs_immutable": _RUN_IMMUTABLE_TRIGGER_SQL,
    "import_runs_revision_guard": _RUN_REVISION_TRIGGER_SQL,
    "import_run_sessions_immutable": _SESSION_IMMUTABLE_TRIGGER_SQL,
    "import_run_sessions_certificate_immutable": _SESSION_CERTIFICATE_TRIGGER_SQL,
    "import_run_sessions_revision_guard": _SESSION_REVISION_TRIGGER_SQL,
    "import_run_sessions_success_guard": _SESSION_SUCCESS_TRIGGER_SQL,
    "import_run_sessions_no_delete": _SESSION_NO_DELETE_TRIGGER_SQL,
    "import_run_turns_immutable": _RUN_TURNS_IMMUTABLE_TRIGGER_SQL,
    "import_run_turns_insert_guard": _RUN_TURNS_INSERT_TRIGGER_SQL,
    "import_run_turns_no_delete": _RUN_TURNS_NO_DELETE_TRIGGER_SQL,
    "imported_turns_revision_guard": _TURN_REVISION_TRIGGER_SQL,
    "backfill_plans": _BACKFILL_PLANS_SQL,
    "backfill_plan_sessions": _BACKFILL_PLAN_SESSIONS_SQL,
    "backfill_cohorts": _BACKFILL_COHORTS_SQL,
    "backfill_cohort_sessions": _BACKFILL_COHORT_SESSIONS_SQL,
    "backfill_plans_project_status": _BACKFILL_PLAN_INDEX_SQL,
    "backfill_plans_immutable": _BACKFILL_PLAN_IMMUTABLE_TRIGGER_SQL,
    "backfill_plan_sessions_immutable": _BACKFILL_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL,
    "backfill_plans_no_delete": _BACKFILL_PLAN_NO_DELETE_TRIGGER_SQL,
    "backfill_plan_sessions_no_delete": _BACKFILL_PLAN_SESSION_NO_DELETE_TRIGGER_SQL,
    "backfill_cohorts_immutable": _BACKFILL_COHORT_IMMUTABLE_TRIGGER_SQL,
    "backfill_cohort_sessions_immutable": _BACKFILL_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL,
    "backfill_cohorts_no_delete": _BACKFILL_COHORT_NO_DELETE_TRIGGER_SQL,
    "backfill_cohort_sessions_no_delete": _BACKFILL_COHORT_SESSION_NO_DELETE_TRIGGER_SQL,
    "backfill_plan_filters": _BACKFILL_PLAN_FILTERS_SQL,
    "backfill_plan_turns": _BACKFILL_PLAN_TURNS_SQL,
    "backfill_plan_stats": _BACKFILL_PLAN_STATS_SQL,
    "backfill_plan_filters_immutable": _BACKFILL_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL,
    "backfill_plan_filters_no_delete": _BACKFILL_PLAN_FILTER_NO_DELETE_TRIGGER_SQL,
    "backfill_plan_turns_immutable": _BACKFILL_PLAN_TURN_IMMUTABLE_TRIGGER_SQL,
    "backfill_plan_turns_no_delete": _BACKFILL_PLAN_TURN_NO_DELETE_TRIGGER_SQL,
    "backfill_plan_stats_immutable": _BACKFILL_PLAN_STATS_IMMUTABLE_TRIGGER_SQL,
    "backfill_plan_stats_no_delete": _BACKFILL_PLAN_STATS_NO_DELETE_TRIGGER_SQL,
    "sync_feeds": _SYNC_FEEDS_SQL,
    "sync_sessions": _SYNC_SESSIONS_SQL,
    "sync_attempts": _SYNC_ATTEMPTS_SQL,
    "sync_sessions_queue": _SYNC_SESSION_QUEUE_INDEX_SQL,
    "sync_attempts_status": _SYNC_ATTEMPT_STATUS_INDEX_SQL,
    "sync_feeds_immutable": _SYNC_FEED_IMMUTABLE_TRIGGER_SQL,
    "sync_feeds_no_delete": _SYNC_FEED_NO_DELETE_TRIGGER_SQL,
    "sync_sessions_immutable": _SYNC_SESSION_IMMUTABLE_TRIGGER_SQL,
    "sync_sessions_no_delete": _SYNC_SESSION_NO_DELETE_TRIGGER_SQL,
    "sync_attempts_immutable": _SYNC_ATTEMPT_IMMUTABLE_TRIGGER_SQL,
    "sync_attempts_no_delete": _SYNC_ATTEMPT_NO_DELETE_TRIGGER_SQL,
    "atomic_turn_attempts": _ATOMIC_TURN_ATTEMPTS_SQL,
    "atomic_turn_certificates": _ATOMIC_TURN_CERTIFICATES_SQL,
    "atomic_turn_receipts": _ATOMIC_TURN_RECEIPTS_SQL,
    "atomic_turn_attempts_status": _ATOMIC_TURN_STATUS_INDEX_SQL,
    "atomic_turn_attempts_identity_immutable": _ATOMIC_TURN_IDENTITY_TRIGGER_SQL,
    "atomic_turn_attempts_revision_guard": _ATOMIC_TURN_REVISION_TRIGGER_SQL,
    "atomic_turn_attempts_transition_guard": _ATOMIC_TURN_TRANSITION_TRIGGER_SQL,
    "atomic_turn_attempts_prepared_guard": _ATOMIC_TURN_PREPARED_GUARD_SQL,
    "atomic_turn_attempts_acknowledged_guard": _ATOMIC_TURN_ACKNOWLEDGED_GUARD_SQL,
    "atomic_turn_attempts_committed_guard": _ATOMIC_TURN_COMMITTED_GUARD_SQL,
    "atomic_turn_certificates_insert_guard": _ATOMIC_TURN_CERTIFICATE_INSERT_GUARD_SQL,
    "atomic_turn_receipts_insert_guard": _ATOMIC_TURN_RECEIPT_INSERT_GUARD_SQL,
    "atomic_turn_certificates_immutable": _ATOMIC_TURN_CERTIFICATE_IMMUTABLE_TRIGGER_SQL,
    "atomic_turn_certificates_no_delete": _ATOMIC_TURN_CERTIFICATE_NO_DELETE_TRIGGER_SQL,
    "atomic_turn_receipts_immutable": _ATOMIC_TURN_RECEIPT_IMMUTABLE_TRIGGER_SQL,
    "atomic_turn_receipts_no_delete": _ATOMIC_TURN_RECEIPT_NO_DELETE_TRIGGER_SQL,
    "atomic_turn_attempts_no_delete": _ATOMIC_TURN_ATTEMPT_NO_DELETE_TRIGGER_SQL,
    "review_plans": _REVIEW_PLANS_SQL,
    "review_plan_sessions": _REVIEW_PLAN_SESSIONS_SQL,
    "review_plan_filters": _REVIEW_PLAN_FILTERS_SQL,
    "review_plan_turns": _REVIEW_PLAN_TURNS_SQL,
    "review_cohorts": _REVIEW_COHORTS_SQL,
    "review_cohort_sessions": _REVIEW_COHORT_SESSIONS_SQL,
    "review_turn_ledger": _REVIEW_TURN_LEDGER_SQL,
    "review_preflight_conflict_archive": _REVIEW_PREFLIGHT_CONFLICT_ARCHIVE_SQL,
    "review_plan_retirements": _REVIEW_PLAN_RETIREMENTS_SQL,
    "review_plan_revalidations": _REVIEW_PLAN_REVALIDATIONS_SQL,
    "review_preseal_failures": _REVIEW_PRESEAL_FAILURES_SQL,
    "review_plans_project_status": _REVIEW_PLANS_INDEX_SQL,
    "review_turn_ledger_project_status": _REVIEW_LEDGER_INDEX_SQL,
    "review_plans_immutable": _REVIEW_PLAN_IMMUTABLE_TRIGGER_SQL,
    "review_plan_sessions_immutable": _REVIEW_PLAN_SESSION_IMMUTABLE_TRIGGER_SQL,
    "review_plan_filters_immutable": _REVIEW_PLAN_FILTER_IMMUTABLE_TRIGGER_SQL,
    "review_plan_turns_immutable": _REVIEW_PLAN_TURN_IMMUTABLE_TRIGGER_SQL,
    "review_cohorts_immutable": _REVIEW_COHORT_IMMUTABLE_TRIGGER_SQL,
    "review_cohort_sessions_immutable": _REVIEW_COHORT_SESSION_IMMUTABLE_TRIGGER_SQL,
    "review_preflight_conflict_archive_insert_guard": (_REVIEW_PREFLIGHT_ARCHIVE_INSERT_GUARD_SQL),
    "review_preflight_conflict_archive_immutable": (
        _REVIEW_PREFLIGHT_ARCHIVE_IMMUTABLE_TRIGGER_SQL
    ),
    "review_preflight_conflict_archive_no_delete": (
        _REVIEW_PREFLIGHT_ARCHIVE_NO_DELETE_TRIGGER_SQL
    ),
    "review_plan_retirements_insert_guard": _REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL,
    "review_plan_retirements_immutable": _REVIEW_PLAN_RETIREMENT_IMMUTABLE_TRIGGER_SQL,
    "review_plan_retirements_no_delete": _REVIEW_PLAN_RETIREMENT_NO_DELETE_TRIGGER_SQL,
    "review_plan_revalidations_insert_guard": _REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL,
    "review_plan_revalidations_immutable": _REVIEW_PLAN_REVALIDATION_IMMUTABLE_TRIGGER_SQL,
    "review_plan_revalidations_no_delete": _REVIEW_PLAN_REVALIDATION_NO_DELETE_TRIGGER_SQL,
    "review_preseal_failures_identity_immutable": (_REVIEW_PRESEAL_FAILURE_IDENTITY_TRIGGER_SQL),
    "review_preseal_failures_insert_guard": _REVIEW_PRESEAL_FAILURE_INSERT_TRIGGER_SQL,
    "review_preseal_failures_attempt_guard": _REVIEW_PRESEAL_FAILURE_ATTEMPT_TRIGGER_SQL,
    "review_preseal_failures_no_delete": _REVIEW_PRESEAL_FAILURE_NO_DELETE_TRIGGER_SQL,
    "review_turn_ledger_identity_immutable": _REVIEW_LEDGER_IDENTITY_TRIGGER_SQL,
    "review_turn_ledger_revision_guard": _REVIEW_LEDGER_REVISION_TRIGGER_SQL,
    "review_turn_ledger_transition_guard": _REVIEW_LEDGER_TRANSITION_TRIGGER_SQL,
    "review_plans_no_delete": _REVIEW_PLAN_NO_DELETE_TRIGGER_SQL,
    "review_plan_sessions_no_delete": _REVIEW_PLAN_SESSION_NO_DELETE_TRIGGER_SQL,
    "review_plan_filters_no_delete": _REVIEW_PLAN_FILTER_NO_DELETE_TRIGGER_SQL,
    "review_plan_turns_no_delete": _REVIEW_PLAN_TURN_NO_DELETE_TRIGGER_SQL,
    "review_cohorts_no_delete": _REVIEW_COHORT_NO_DELETE_TRIGGER_SQL,
    "review_cohort_sessions_no_delete": _REVIEW_COHORT_SESSION_NO_DELETE_TRIGGER_SQL,
    "review_turn_ledger_no_delete": _REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL,
}


def _normalize_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split()).lower()


def _canonical_config(config: dict[str, Any]) -> tuple[str, str]:
    config_json = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return config_json, sha256_json(config)


def _session_certificate(turns: list[tuple[str, str]]) -> str:
    return sha256_json(
        [
            {"ordinal": ordinal, "turn_key": turn_key, "source_payload_sha256": source_hash}
            for ordinal, (turn_key, source_hash) in enumerate(turns)
        ]
    )


def _manifest_payload(
    *,
    run_id: str,
    project: str,
    cutoff: datetime,
    days: int,
    idle_minutes: int,
    config_sha256: str,
    importer_version: str,
    schema_version: str,
    discovered_count: int,
    deferred_count: int,
    sessions: list[tuple[str, datetime]],
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "project": project,
        "cutoff": isoformat_z(cutoff),
        "days": days,
        "idle_minutes": idle_minutes,
        "config_sha256": config_sha256,
        "importer_version": importer_version,
        "schema_version": schema_version,
        "discovered_count": discovered_count,
        "deferred_count": deferred_count,
        "sessions": [
            {
                "ordinal": ordinal,
                "session_id": session_id,
                "summary_last_activity_at": isoformat_z(activity),
            }
            for ordinal, (session_id, activity) in enumerate(sessions)
        ],
    }


class StateStore:
    """One-process state store with a private, immutable recovery manifest."""

    def __init__(self, path: Path) -> None:
        if fcntl is None:  # pragma: no cover - only unsupported platforms.
            raise StateStoreError("local state locking is unavailable on this platform")
        expanded = path.expanduser()
        if ".." in expanded.parts:
            raise StateConflictError("state path cannot contain parent-directory traversal")
        self.path = Path(os.path.abspath(expanded))
        if not self.path.name or self.path.name in {".", ".."}:
            raise StateConflictError("state path must name a database file")
        self.resource_stack = ExitStack()
        self.connection: sqlite3.Connection | None = None
        self._closed = False
        previous_umask = os.umask(0o077)
        try:
            self._open_private_parent()
            self._open_and_lock()
            self._secure_database_files(create_database=True)
            self.connection = self._connect_database()
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            journal_mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise StateStoreError("local state database did not enable WAL journaling")
            self._migrate_and_validate()
            self._secure_database_files(create_database=False)
        except Exception:
            if self.connection is not None:
                self.connection.close()
            self.resource_stack.close()
            raise
        finally:
            os.umask(previous_umask)

    @property
    def _db(self) -> sqlite3.Connection:
        if self.connection is None:
            raise StateStoreError("local state database is not open")
        return self.connection

    def _open_private_parent(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(os.path.sep, flags)
        except OSError as error:
            raise StateConflictError("state directory could not be opened safely") from error
        directory_fds = [directory_fd]
        directory_chain: list[tuple[int, str, int]] = []
        try:
            for component in self.path.parent.parts[1:]:
                while True:
                    try:
                        next_fd = os.open(component, flags, dir_fd=directory_fd)
                    except FileNotFoundError:
                        try:
                            os.mkdir(component, 0o700, dir_fd=directory_fd)
                        except FileExistsError:
                            continue
                        except OSError as error:
                            raise StateConflictError(
                                "state directory could not be created safely"
                            ) from error
                        continue
                    except OSError as error:
                        raise StateConflictError(
                            "state directory could not be opened safely"
                        ) from error
                    directory_chain.append((directory_fd, component, next_fd))
                    directory_fds.append(next_fd)
                    directory_fd = next_fd
                    break
        except Exception:
            for opened_fd in reversed(directory_fds):
                os.close(opened_fd)
            raise
        for opened_fd in directory_fds:
            self.resource_stack.callback(os.close, opened_fd)
        self._directory_chain = tuple(directory_chain)
        self.directory_fd = directory_fd
        self._secure_fd(directory_fd, directory=True, mode=0o700, label="state directory")
        self._validate_directory_chain()

    def _validate_directory_chain(self) -> None:
        """Prove the absolute state path still resolves through every pinned directory."""
        allowed_owners = {0, os.geteuid()}
        for parent_fd, component, child_fd in self._directory_chain:
            try:
                parent_details = os.fstat(parent_fd)
                child_details = os.fstat(child_fd)
                path_details = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise StateConflictError(
                    "state directory ancestry identity could not be validated"
                ) from error
            if not stat.S_ISDIR(parent_details.st_mode) or not stat.S_ISDIR(child_details.st_mode):
                raise StateConflictError("state directory ancestry has an unsafe file type")
            if (
                parent_details.st_uid not in allowed_owners
                or child_details.st_uid not in allowed_owners
            ):
                raise StateConflictError("state directory ancestry has an unsafe owner")
            parent_writable = stat.S_IMODE(parent_details.st_mode) & 0o022
            trusted_sticky_parent = parent_details.st_uid == 0 and bool(
                parent_details.st_mode & stat.S_ISVTX
            )
            if parent_writable and not trusted_sticky_parent:
                raise StateConflictError("state directory ancestry has unsafe permissions")
            if (child_details.st_dev, child_details.st_ino) != (
                path_details.st_dev,
                path_details.st_ino,
            ):
                raise StateConflictError("state directory changed while it was opened")

    def _connect_database(self) -> sqlite3.Connection:
        """Connect only while holding an identity-pinned database descriptor."""
        self._validate_directory_chain()
        database_fd = self._open_regular_at(
            self.path.name,
            create=False,
            label="state database file",
        )
        try:
            self._secure_fd(
                database_fd,
                directory=False,
                mode=0o600,
                label="state database file",
            )
            self._validate_fd_path_identity(
                database_fd,
                self.path.name,
                label="state database file",
            )
            self._validate_directory_chain()
            connection = sqlite3.connect(self.path)
            self._validate_directory_chain()
            self._validate_fd_path_identity(
                database_fd,
                self.path.name,
                label="state database file",
            )
            return connection
        except Exception:
            if "connection" in locals():
                connection.close()
            raise
        finally:
            os.close(database_fd)

    def _secure_fd(self, fd: int, *, directory: bool, mode: int, label: str) -> os.stat_result:
        try:
            details = os.fstat(fd)
            expected_type = (
                stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode)
            )
            if not expected_type or details.st_uid != os.geteuid():
                raise StateConflictError(f"{label} has an unsafe owner or file type")
            if not directory and details.st_nlink != 1:
                raise StateConflictError(f"{label} must not be hard-linked")
            secured = os.fstat(fd)
        except OSError as error:
            raise StateConflictError(f"{label} permissions could not be validated") from error
        if stat.S_IMODE(secured.st_mode) != mode:
            raise StateConflictError(
                f"{label} permissions are not private; refusing to change an existing path"
            )
        return secured

    def _open_regular_at(self, name: str, *, create: bool, label: str) -> int:
        base_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        while True:
            self._validate_directory_chain()
            try:
                fd = os.open(name, base_flags, dir_fd=self.directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    fd = os.open(
                        name,
                        base_flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=self.directory_fd,
                    )
                except FileExistsError:
                    continue
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise StateConflictError(f"{label} must not be a symlink") from error
                raise StateConflictError(f"{label} could not be opened safely") from error
            try:
                self._validate_directory_chain()
            except Exception:
                os.close(fd)
                raise
            return fd

    def _validate_fd_path_identity(self, fd: int, name: str, *, label: str) -> None:
        self._validate_directory_chain()
        try:
            fd_stat = os.fstat(fd)
            path_stat = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
        except OSError as error:
            raise StateConflictError(f"{label} identity could not be validated") from error
        if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise StateConflictError(f"{label} changed while it was opened")
        self._validate_directory_chain()

    def _open_and_lock(self) -> None:
        lock_name = f"{self.path.name}.lock"
        lock_fd = self._open_regular_at(lock_name, create=True, label="state lock file")
        try:
            self._secure_fd(lock_fd, directory=False, mode=0o600, label="state lock file")
            self._validate_fd_path_identity(lock_fd, lock_name, label="state lock file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(lock_fd)
            raise StateConflictError(
                f"another importer is using state database {self.path}"
            ) from error
        except Exception:
            os.close(lock_fd)
            raise
        self.lock_file: IO[str] = os.fdopen(lock_fd, "a+", encoding="utf-8")
        self.resource_stack.enter_context(self.lock_file)

    def _secure_database_files(self, *, create_database: bool) -> None:
        self._validate_directory_chain()
        names = [
            self.path.name,
            f"{self.path.name}-wal",
            f"{self.path.name}-shm",
            f"{self.path.name}-journal",
        ]
        for index, name in enumerate(names):
            try:
                fd = self._open_regular_at(
                    name,
                    create=create_database and index == 0,
                    label="state database file" if index == 0 else "state database sidecar",
                )
            except FileNotFoundError:
                continue
            try:
                label = "state database file" if index == 0 else "state database sidecar"
                self._secure_fd(fd, directory=False, mode=0o600, label=label)
                self._validate_fd_path_identity(fd, name, label=label)
            finally:
                os.close(fd)
        self._validate_directory_chain()

    def _schema_objects(self) -> dict[str, sqlite3.Row]:
        rows = self._db.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_autoindex_%'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        return {str(row["name"]): row for row in rows}

    def _migrate_and_validate(self) -> None:
        user_version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(self._db.execute("PRAGMA application_id").fetchone()[0])
        if user_version > DB_SCHEMA_VERSION:
            raise StateConflictError("state database schema is newer than this importer")
        if application_id not in {0, DB_APPLICATION_ID}:
            raise StateConflictError("state database belongs to a different application")
        try:
            self._db.execute("BEGIN IMMEDIATE")
            if user_version == DB_SCHEMA_VERSION:
                if application_id != DB_APPLICATION_ID:
                    raise StateConflictError("state database application identity is missing")
            elif user_version == 12 and application_id == DB_APPLICATION_ID:
                legacy_table = "review_preseal_failures_v12"
                legacy_rows = int(
                    self._db.execute("SELECT COUNT(*) FROM review_preseal_failures").fetchone()[0]
                )
                for trigger in (
                    "review_preseal_failures_identity_immutable",
                    "review_preseal_failures_insert_guard",
                    "review_preseal_failures_attempt_guard",
                    "review_preseal_failures_no_delete",
                ):
                    self._db.execute(f"DROP TRIGGER {trigger}")
                self._db.execute(f"ALTER TABLE review_preseal_failures RENAME TO {legacy_table}")
                self._db.execute(_REVIEW_PRESEAL_FAILURES_SQL)
                self._db.execute(
                    f"""
                    INSERT INTO review_preseal_failures (
                        project, session_id, started_at, last_activity_at,
                        first_error_code, last_error_code, attempt_count,
                        first_attempt_at, last_attempt_at
                    )
                    SELECT
                        project, session_id, started_at, last_activity_at,
                        first_error_code, last_error_code, attempt_count,
                        first_attempt_at, last_attempt_at
                    FROM {legacy_table}
                    """
                )
                migrated_rows = int(
                    self._db.execute("SELECT COUNT(*) FROM review_preseal_failures").fetchone()[0]
                )
                if migrated_rows != legacy_rows:
                    raise StateConflictError("review pre-seal failure migration lost rows")
                self._db.execute(f"DROP TABLE {legacy_table}")
                for statement in (
                    _REVIEW_PRESEAL_FAILURE_IDENTITY_TRIGGER_SQL,
                    _REVIEW_PRESEAL_FAILURE_INSERT_TRIGGER_SQL,
                    _REVIEW_PRESEAL_FAILURE_ATTEMPT_TRIGGER_SQL,
                    _REVIEW_PRESEAL_FAILURE_NO_DELETE_TRIGGER_SQL,
                ):
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 11 and application_id == DB_APPLICATION_ID:
                for statement in _REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 10 and application_id == DB_APPLICATION_ID:
                self._db.execute("DROP TRIGGER review_turn_ledger_no_delete")
                self._db.execute("DROP TRIGGER review_plan_retirements_insert_guard")
                self._db.execute("DROP TRIGGER review_plan_revalidations_insert_guard")
                self._db.execute(_REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL)
                self._db.execute(_REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL)
                self._db.execute(_REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL)
                for statement in _REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 9 and application_id == DB_APPLICATION_ID:
                self._db.execute("DROP TRIGGER review_turn_ledger_no_delete")
                self._db.execute("DROP TRIGGER review_plan_retirements_insert_guard")
                for statement in _REVIEW_REVALIDATION_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(_REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL)
                self._db.execute(_REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL)
                for statement in _REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 8 and application_id == DB_APPLICATION_ID:
                self._db.execute("DROP TRIGGER review_turn_ledger_no_delete")
                for statement in _REVIEW_PREFLIGHT_RECOVERY_SCHEMA_SQL:
                    self._db.execute(statement)
                for statement in _REVIEW_REVALIDATION_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(_REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL)
                for statement in _REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 7 and application_id == DB_APPLICATION_ID:
                self._db.execute(
                    """
                    ALTER TABLE review_turn_ledger
                    ADD COLUMN index_size INTEGER NOT NULL DEFAULT 0 CHECK(index_size >= 0)
                    """
                )
                self._db.execute("DROP TRIGGER review_turn_ledger_no_delete")
                for statement in _REVIEW_PREFLIGHT_RECOVERY_SCHEMA_SQL:
                    self._db.execute(statement)
                for statement in _REVIEW_REVALIDATION_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(_REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL)
                for statement in _REVIEW_PRESEAL_FAIRNESS_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 6 and application_id == DB_APPLICATION_ID:
                for statement in _REVIEW_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 2 and application_id == DB_APPLICATION_ID:
                for statement in (
                    *_BACKFILL_SCHEMA_SQL,
                    *_BACKFILL_CERTIFICATE_SCHEMA_SQL,
                    *_SYNC_SCHEMA_SQL,
                    *_ATOMIC_TURN_SCHEMA_SQL,
                    *_REVIEW_SCHEMA_SQL,
                ):
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 3 and application_id == DB_APPLICATION_ID:
                for statement in (
                    *_BACKFILL_CERTIFICATE_SCHEMA_SQL,
                    *_SYNC_SCHEMA_SQL,
                    *_ATOMIC_TURN_SCHEMA_SQL,
                    *_REVIEW_SCHEMA_SQL,
                ):
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 4 and application_id == DB_APPLICATION_ID:
                for statement in (
                    *_SYNC_SCHEMA_SQL,
                    *_ATOMIC_TURN_SCHEMA_SQL,
                    *_REVIEW_SCHEMA_SQL,
                ):
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 5 and application_id == DB_APPLICATION_ID:
                self._db.execute(
                    """
                    ALTER TABLE sync_feeds
                    ADD COLUMN candidate_universe_sha256 TEXT NOT NULL DEFAULT ''
                        CHECK(length(candidate_universe_sha256) IN (0, 64))
                    """
                )
                for statement in _ATOMIC_TURN_SCHEMA_SQL:
                    self._db.execute(statement)
                for statement in _REVIEW_SCHEMA_SQL:
                    self._db.execute(statement)
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            elif user_version == 0 and application_id == 0:
                self._migrate_unversioned()
                self._db.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            else:
                raise StateConflictError("state database schema version is incompatible")
            self._validate_schema_contract()
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _migrate_unversioned(self) -> None:
        objects = self._schema_objects()
        if not objects:
            for statement in _SCHEMA_SQL:
                self._db.execute(statement)
            return
        if "imported_turns" not in objects or objects["imported_turns"]["type"] != "table":
            raise StateConflictError("unversioned state database has an unknown schema")
        allowed_old_names = {
            "imported_turns",
            "import_runs",
            "import_run_sessions",
            "import_runs_project_status",
            "import_runs_immutable",
            "import_run_sessions_immutable",
            "import_run_sessions_no_delete",
        }
        if not set(objects).issubset(allowed_old_names):
            raise StateConflictError("unversioned state database has unexpected schema objects")
        imported_columns = [
            str(row["name"])
            for row in self._db.execute("PRAGMA table_info(imported_turns)").fetchall()
        ]
        required = [
            "project",
            "session_id",
            "turn_key",
            "payload_sha256",
            "verification_signature",
            "status",
            "source_last_activity_at",
            "atif_schema_version",
            "trace_ids_json",
            "root_span_ids_json",
            "span_count",
            "importer_version",
            "created_at",
            "updated_at",
            "imported_at",
            "last_error",
        ]
        if any(column not in imported_columns for column in required):
            raise StateConflictError("legacy imported-turn journal has an unknown schema")
        if set(objects) != {"imported_turns"}:
            if "import_runs" not in objects or "import_run_sessions" not in objects:
                raise StateConflictError("unversioned run-manifest migration was incomplete")
            active = int(
                self._db.execute(
                    "SELECT COUNT(*) FROM import_runs WHERE status = 'active'"
                ).fetchone()[0]
            )
            if active:
                raise StateConflictError(
                    "unfinished legacy run lacks certified turns and cannot be resumed safely"
                )
            for trigger in (
                "import_run_sessions_no_delete",
                "import_run_sessions_immutable",
                "import_runs_immutable",
            ):
                if trigger in objects:
                    self._db.execute(f"DROP TRIGGER {trigger}")
            if "import_runs_project_status" in objects:
                self._db.execute("DROP INDEX import_runs_project_status")
            self._db.execute("DROP TABLE import_run_sessions")
            self._db.execute("DROP TABLE import_runs")

        self._db.execute("ALTER TABLE imported_turns RENAME TO imported_turns_legacy")
        self._db.execute(_IMPORTED_TURNS_SQL)
        source_expression = (
            "source_payload_sha256" if "source_payload_sha256" in imported_columns else "''"
        )
        revision_expression = "revision" if "revision" in imported_columns else "0"
        self._db.execute(
            f"""
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at, atif_schema_version,
                trace_ids_json, root_span_ids_json, span_count, importer_version, created_at,
                updated_at, imported_at, last_error, revision
            )
            SELECT
                project, session_id, turn_key, payload_sha256, {source_expression},
                verification_signature, status, source_last_activity_at, atif_schema_version,
                trace_ids_json, root_span_ids_json, span_count, importer_version, created_at,
                updated_at, imported_at, last_error, {revision_expression}
            FROM imported_turns_legacy
            """
        )
        self._db.execute("DROP TABLE imported_turns_legacy")
        for statement in _SCHEMA_SQL[1:]:
            self._db.execute(statement)

    def _validate_schema_contract(self) -> None:
        objects = self._schema_objects()
        if set(objects) != set(_EXPECTED_SCHEMA_SQL):
            raise StateConflictError("state database schema objects do not match the importer")
        for name, expected_sql in _EXPECTED_SCHEMA_SQL.items():
            stored_sql = objects[name]["sql"]
            if not isinstance(stored_sql, str) or _normalize_sql(stored_sql) != _normalize_sql(
                expected_sql
            ):
                raise StateConflictError(f"state database object {name} has an invalid contract")
        index_columns = [
            str(row["name"])
            for row in self._db.execute("PRAGMA index_info(import_runs_project_status)").fetchall()
        ]
        if index_columns != ["project", "status"]:
            raise StateConflictError("state database run index has an invalid contract")
        foreign_keys = self._db.execute("PRAGMA foreign_key_list(import_run_turns)").fetchall()
        if len(foreign_keys) != 2 or {
            (str(row["from"]), str(row["to"])) for row in foreign_keys
        } != {("run_id", "run_id"), ("session_id", "session_id")}:
            raise StateConflictError("state database run-turn foreign key is invalid")
        quick_check = self._db.execute("PRAGMA quick_check").fetchall()
        if [str(row[0]) for row in quick_check] != ["ok"]:
            raise StateConflictError("state database integrity check failed")
        if self._db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StateConflictError("state database foreign-key check failed")

    def _after_write(self) -> None:
        self._db.commit()
        self._secure_database_files(create_database=False)

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        try:
            self._secure_database_files(create_database=False)
        except Exception as error:
            failure = error
        try:
            self._db.close()
        finally:
            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                self.resource_stack.close()
                self._closed = True
        if failure is not None:
            raise failure

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _state_row(self, row: sqlite3.Row) -> StateRow:
        try:
            trace_ids = json.loads(row["trace_ids_json"])
            root_span_ids = json.loads(row["root_span_ids_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise StateConflictError("saved turn evidence is malformed") from error
        if not isinstance(trace_ids, list) or not all(isinstance(item, str) for item in trace_ids):
            raise StateConflictError("saved turn trace IDs are malformed")
        if not isinstance(root_span_ids, list) or not all(
            isinstance(item, str) for item in root_span_ids
        ):
            raise StateConflictError("saved turn root-span IDs are malformed")
        return StateRow(
            project=str(row["project"]),
            session_id=str(row["session_id"]),
            turn_key=str(row["turn_key"]),
            payload_sha256=str(row["payload_sha256"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            verification_signature=str(row["verification_signature"]),
            status=str(row["status"]),
            source_last_activity_at=str(row["source_last_activity_at"]),
            atif_schema_version=str(row["atif_schema_version"]),
            trace_ids=trace_ids,
            root_span_ids=root_span_ids,
            span_count=int(row["span_count"]),
            last_error=str(row["last_error"]),
            revision=int(row["revision"]),
        )

    def get(self, project: str, session_id: str, turn_key: str) -> StateRow | None:
        row = self._db.execute(
            """
            SELECT * FROM imported_turns
            WHERE project = ? AND session_id = ? AND turn_key = ?
            """,
            (project, session_id, turn_key),
        ).fetchone()
        return None if row is None else self._state_row(row)

    def _validated_run(self, row: sqlite3.Row) -> ImportRun:
        try:
            parsed_config = json.loads(row["config_json"])
            cutoff = parse_datetime(row["cutoff"])
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise StateConflictError("saved import run metadata is malformed") from error
        if not isinstance(parsed_config, dict) or cutoff is None:
            raise StateConflictError("saved import run metadata is malformed")
        config_json, config_sha256 = _canonical_config(parsed_config)
        if config_json != row["config_json"] or config_sha256 != row["config_sha256"]:
            raise StateConflictError("saved import run configuration failed its integrity check")
        if row["schema_version"] != RUN_SCHEMA_VERSION:
            raise StateConflictError(
                "unfinished import run uses an incompatible state schema version"
            )
        if row["importer_version"] != __version__:
            raise StateConflictError("unfinished import run uses an incompatible importer version")
        session_rows = self._db.execute(
            """
            SELECT *
            FROM import_run_sessions WHERE run_id = ? ORDER BY ordinal ASC
            """,
            (row["run_id"],),
        ).fetchall()
        if len(session_rows) != int(row["session_count"]):
            raise StateConflictError("saved import run session manifest is incomplete")
        sessions: list[tuple[str, datetime]] = []
        for expected_ordinal, session_row in enumerate(session_rows):
            activity = parse_datetime(session_row["summary_last_activity_at"])
            if int(session_row["ordinal"]) != expected_ordinal or activity is None:
                raise StateConflictError("saved import run session manifest is malformed")
            sessions.append((str(session_row["session_id"]), activity))
        manifest = _manifest_payload(
            run_id=str(row["run_id"]),
            project=str(row["project"]),
            cutoff=cutoff,
            days=int(row["days"]),
            idle_minutes=int(row["idle_minutes"]),
            config_sha256=config_sha256,
            importer_version=str(row["importer_version"]),
            schema_version=str(row["schema_version"]),
            discovered_count=int(row["discovered_count"]),
            deferred_count=int(row["deferred_count"]),
            sessions=sessions,
        )
        if sha256_json(manifest) != row["manifest_sha256"]:
            raise StateConflictError("saved import run manifest failed its integrity check")
        phase = str(row["phase"])
        if phase == "certifying":
            if (
                int(row["total_turn_count"]) != 0
                or str(row["turn_manifest_sha256"])
                or row["certified_at"] is not None
            ):
                raise StateConflictError("unsealed import run has unexpected turn evidence")
        else:
            turn_count, turn_manifest_sha256 = self._calculate_turn_manifest(
                str(row["run_id"]),
                session_rows,
            )
            if (
                turn_count != int(row["total_turn_count"])
                or turn_manifest_sha256 != str(row["turn_manifest_sha256"])
                or row["certified_at"] is None
            ):
                raise StateConflictError(
                    "saved import run turn certificate failed its integrity check"
                )
        return ImportRun(
            run_id=str(row["run_id"]),
            project=str(row["project"]),
            cutoff=cutoff,
            days=int(row["days"]),
            idle_minutes=int(row["idle_minutes"]),
            config=parsed_config,
            config_sha256=config_sha256,
            importer_version=str(row["importer_version"]),
            schema_version=str(row["schema_version"]),
            status=str(row["status"]),
            phase=phase,
            session_count=int(row["session_count"]),
            discovered_count=int(row["discovered_count"]),
            deferred_count=int(row["deferred_count"]),
            total_turn_count=int(row["total_turn_count"]),
            turn_manifest_sha256=str(row["turn_manifest_sha256"]),
            revision=int(row["revision"]),
        )

    def find_resumable_run(self, *, project: str, config: dict[str, Any]) -> ImportRun | None:
        rows = self._db.execute(
            """
            SELECT * FROM import_runs
            WHERE project = ? AND status = 'active' ORDER BY created_at ASC
            """,
            (project,),
        ).fetchall()
        if len(rows) > 1:
            raise StateConflictError(
                "multiple unfinished import runs exist for this project in the state database"
            )
        if not rows:
            return None
        run = self._validated_run(rows[0])
        _config_json, expected_hash = _canonical_config(config)
        if run.config_sha256 != expected_hash:
            raise StateConflictError(
                "unfinished import run configuration does not match this invocation"
            )
        return run

    def create_run(
        self,
        *,
        project: str,
        cutoff: datetime,
        days: int,
        idle_minutes: int,
        config: dict[str, Any],
        sessions: list[tuple[str, datetime]],
        discovered_count: int,
        deferred_count: int,
    ) -> ImportRun:
        if not sessions or len({session_id for session_id, _ in sessions}) != len(sessions):
            raise StateConflictError("import run requires unique eligible session IDs")
        run_id = uuid.uuid4().hex
        config_json, config_sha256 = _canonical_config(config)
        manifest = _manifest_payload(
            run_id=run_id,
            project=project,
            cutoff=cutoff,
            days=days,
            idle_minutes=idle_minutes,
            config_sha256=config_sha256,
            importer_version=__version__,
            schema_version=RUN_SCHEMA_VERSION,
            discovered_count=discovered_count,
            deferred_count=deferred_count,
            sessions=sessions,
        )
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            if self._db.execute(
                "SELECT 1 FROM import_runs WHERE project = ? AND status = 'active' LIMIT 1",
                (project,),
            ).fetchone():
                raise StateConflictError("an unfinished import run appeared during discovery")
            self._db.execute(
                """
                INSERT INTO import_runs (
                    run_id, project, cutoff, days, idle_minutes, config_json, config_sha256,
                    importer_version, schema_version, status, phase, session_count,
                    discovered_count, deferred_count, manifest_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'certifying', ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    project,
                    isoformat_z(cutoff),
                    days,
                    idle_minutes,
                    config_json,
                    config_sha256,
                    __version__,
                    RUN_SCHEMA_VERSION,
                    len(sessions),
                    discovered_count,
                    deferred_count,
                    sha256_json(manifest),
                    now,
                    now,
                ),
            )
            self._db.executemany(
                """
                INSERT INTO import_run_sessions (
                    run_id, ordinal, session_id, summary_last_activity_at,
                    status, updated_at
                ) VALUES (?, ?, ?, ?, 'uncertified', ?)
                """,
                [
                    (run_id, ordinal, session_id, isoformat_z(activity), now)
                    for ordinal, (session_id, activity) in enumerate(sessions)
                ],
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute("SELECT * FROM import_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:  # pragma: no cover - guarded by committed insert.
            raise StateConflictError("created import run disappeared from local state")
        return self._validated_run(row)

    def _session_row(self, row: sqlite3.Row) -> ImportRunSession:
        activity = parse_datetime(row["summary_last_activity_at"])
        if activity is None:
            raise StateConflictError("saved import run activity timestamp is malformed")
        return ImportRunSession(
            run_id=str(row["run_id"]),
            ordinal=int(row["ordinal"]),
            session_id=str(row["session_id"]),
            summary_last_activity_at=activity,
            status=str(row["status"]),
            turn_count=int(row["turn_count"]),
            turn_set_sha256=str(row["turn_set_sha256"]),
            last_error=str(row["last_error"]),
            revision=int(row["revision"]),
        )

    def get_run_sessions(self, run_id: str) -> list[ImportRunSession]:
        run_row = self._db.execute(
            "SELECT * FROM import_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run_row is None:
            raise StateConflictError("saved import run no longer exists")
        self._validated_run(run_row)
        return [
            self._session_row(row)
            for row in self._db.execute(
                "SELECT * FROM import_run_sessions WHERE run_id = ? ORDER BY ordinal ASC",
                (run_id,),
            ).fetchall()
        ]

    def get_run_turns(self, run_id: str, session_id: str) -> list[ImportRunTurn]:
        return [
            ImportRunTurn(
                run_id=str(row["run_id"]),
                session_id=str(row["session_id"]),
                ordinal=int(row["ordinal"]),
                turn_key=str(row["turn_key"]),
                source_payload_sha256=str(row["source_payload_sha256"]),
            )
            for row in self._db.execute(
                """
                SELECT * FROM import_run_turns
                WHERE run_id = ? AND session_id = ? ORDER BY ordinal ASC
                """,
                (run_id, session_id),
            ).fetchall()
        ]

    @staticmethod
    def turn_set_certificate(turns: list[tuple[str, str]]) -> str:
        return _session_certificate(turns)

    def certify_run_session(
        self,
        *,
        run_id: str,
        session_id: str,
        expected_revision: int,
        turns: list[tuple[str, str]],
    ) -> ImportRunSession:
        if len({turn_key for turn_key, _ in turns}) != len(turns) or any(
            not turn_key or not _HEX_SHA256.fullmatch(source_hash)
            for turn_key, source_hash in turns
        ):
            raise StateConflictError("session turn certificate is malformed")
        certificate = _session_certificate(turns)
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            current = self._db.execute(
                """
                SELECT session.*
                FROM import_run_sessions AS session
                JOIN import_runs AS run ON run.run_id = session.run_id
                WHERE session.run_id = ? AND session.session_id = ?
                  AND session.revision = ?
                  AND session.status IN ('uncertified', 'failed')
                  AND session.turn_count = -1
                  AND run.status = 'active' AND run.phase = 'certifying'
                """,
                (run_id, session_id, expected_revision),
            ).fetchone()
            if current is None:
                raise StateConflictError("session certification state changed unexpectedly")
            self._db.executemany(
                """
                INSERT INTO import_run_turns (
                    run_id, session_id, ordinal, turn_key, source_payload_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (run_id, session_id, ordinal, turn_key, source_hash)
                    for ordinal, (turn_key, source_hash) in enumerate(turns)
                ],
            )
            cursor = self._db.execute(
                """
                UPDATE import_run_sessions
                SET status = 'certified', turn_count = ?, turn_set_sha256 = ?,
                    certified_at = ?, attempts = attempts + 1, last_error = '',
                    updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND session_id = ? AND revision = ?
                  AND status IN ('uncertified', 'failed') AND turn_count = -1
                """,
                (
                    len(turns),
                    certificate,
                    now,
                    now,
                    run_id,
                    session_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("session certification state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (run_id, session_id),
        ).fetchone()
        if row is None:  # pragma: no cover
            raise StateConflictError("certified session disappeared from local state")
        return self._session_row(row)

    def record_uncertified_error(
        self,
        *,
        run_id: str,
        session_id: str,
        expected_revision: int,
        error: str,
    ) -> ImportRunSession:
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = 'failed', attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ?
              AND status IN ('uncertified', 'failed') AND turn_count = -1
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active' AND phase = 'certifying'
              )
            """,
            (
                error[:500],
                isoformat_z(datetime.now(UTC)),
                run_id,
                session_id,
                expected_revision,
                run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("uncertified session state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (run_id, session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def certificate_matches(
        self,
        entry: ImportRunSession,
        turns: list[tuple[str, str]],
    ) -> bool:
        saved = self.get_run_turns(entry.run_id, entry.session_id)
        expected = [(item.turn_key, item.source_payload_sha256) for item in saved]
        return (
            entry.turn_count == len(turns)
            and entry.turn_set_sha256 == _session_certificate(turns)
            and expected == turns
        )

    def restore_certified_session(
        self,
        *,
        entry: ImportRunSession,
    ) -> ImportRunSession:
        if entry.turn_count < 0 or not entry.turn_set_sha256:
            raise StateConflictError("uncertified session cannot be restored")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = 'certified', attempts = attempts + 1, last_error = '',
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ?
              AND status IN ('failed', 'conflict')
              AND turn_set_sha256 = ? AND turn_count = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active'
              )
            """,
            (
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.turn_set_sha256,
                entry.turn_count,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session recovery state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def seal_run(self, run: ImportRun) -> ImportRun:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            sessions = self._db.execute(
                """
                SELECT * FROM import_run_sessions
                WHERE run_id = ? ORDER BY ordinal ASC
                """,
                (run.run_id,),
            ).fetchall()
            if len(sessions) != run.session_count or any(
                row["status"] != "certified" or int(row["turn_count"]) < 0 for row in sessions
            ):
                raise StateConflictError("run cannot be sealed before every session is certified")
            total, manifest_hash = self._calculate_turn_manifest(run.run_id, sessions)
            now = isoformat_z(datetime.now(UTC))
            cursor = self._db.execute(
                """
                UPDATE import_runs
                SET phase = 'ready', total_turn_count = ?, turn_manifest_sha256 = ?,
                    certified_at = ?, updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status = 'active' AND phase = 'certifying'
                  AND revision = ? AND turn_manifest_sha256 = ''
                """,
                (total, manifest_hash, now, now, run.run_id, run.revision),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("run sealing state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM import_runs WHERE run_id = ?", (run.run_id,)
        ).fetchone()
        assert row is not None
        return self._validated_run(row)

    def _calculate_turn_manifest(
        self,
        run_id: str,
        sessions: list[sqlite3.Row],
    ) -> tuple[int, str]:
        """Stream the exact certified turn manifest without retaining all turns."""
        session_contract = {
            str(row["session_id"]): (int(row["ordinal"]), int(row["turn_count"]))
            for row in sessions
        }
        expected_total = sum(turn_count for _ordinal, turn_count in session_contract.values())
        observed_counts = {session_id: 0 for session_id in session_contract}
        digest = hashlib.sha256()
        digest.update(b"[")
        observed_total = 0
        turn_rows = self._db.execute(
            """
            SELECT session.ordinal AS session_ordinal, turn.ordinal AS turn_ordinal,
                   turn.session_id, turn.turn_key, turn.source_payload_sha256
            FROM import_run_sessions AS session
            JOIN import_run_turns AS turn
              ON turn.run_id = session.run_id AND turn.session_id = session.session_id
            WHERE session.run_id = ?
            ORDER BY session.ordinal ASC, turn.ordinal ASC
            """,
            (run_id,),
        )
        for row in turn_rows:
            session_id = str(row["session_id"])
            contract = session_contract.get(session_id)
            turn_ordinal = int(row["turn_ordinal"])
            if (
                contract is None
                or int(row["session_ordinal"]) != contract[0]
                or turn_ordinal != observed_counts[session_id]
            ):
                raise StateConflictError("run turn certificate ordering is malformed")
            payload = {
                "session_ordinal": contract[0],
                "turn_ordinal": turn_ordinal,
                "session_id": session_id,
                "turn_key": str(row["turn_key"]),
                "source_payload_sha256": str(row["source_payload_sha256"]),
            }
            if observed_total:
                digest.update(b",")
            digest.update(canonical_json(payload).encode("utf-8"))
            observed_counts[session_id] += 1
            observed_total += 1
        digest.update(b"]")
        if observed_total != expected_total or any(
            observed_counts[session_id] != turn_count
            for session_id, (_ordinal, turn_count) in session_contract.items()
        ):
            raise StateConflictError("run turn certificate is incomplete")
        return observed_total, digest.hexdigest()

    def mark_run_session_terminal(
        self,
        *,
        entry: ImportRunSession,
        status: str,
        error: str = "",
    ) -> ImportRunSession:
        if status not in {"empty", "imported", "skipped"}:
            raise ValueError(f"invalid terminal session status: {status}")
        if entry.status not in _SESSION_PROCESSABLE_STATUSES:
            raise StateConflictError("session terminal transition started from an invalid status")
        if entry.turn_count < 0 or not _HEX_SHA256.fullmatch(entry.turn_set_sha256):
            raise StateConflictError("session terminal transition lacks a turn certificate")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = ?, attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ? AND status = ?
              AND turn_count = ? AND turn_set_sha256 = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active' AND phase = 'ready'
              )
            """,
            (
                status,
                error[:500],
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.status,
                entry.turn_count,
                entry.turn_set_sha256,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session terminal state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def mark_run_session_issue(
        self,
        *,
        entry: ImportRunSession,
        status: str,
        error: str,
    ) -> ImportRunSession:
        if status not in {"failed", "conflict"}:
            raise ValueError(f"invalid session issue status: {status}")
        if entry.status not in _SESSION_PROCESSABLE_STATUSES:
            raise StateConflictError("session issue transition started from an invalid status")
        if entry.turn_count < 0 or not _HEX_SHA256.fullmatch(entry.turn_set_sha256):
            raise StateConflictError("session issue transition lacks a turn certificate")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = ?, attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ? AND status = ?
              AND turn_count = ? AND turn_set_sha256 = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active'
              )
            """,
            (
                status,
                error[:500],
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.status,
                entry.turn_count,
                entry.turn_set_sha256,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session issue state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def complete_run(self, run: ImportRun) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            status_rows = self._db.execute(
                """
                SELECT status, COUNT(*) AS count FROM import_run_sessions
                WHERE run_id = ? GROUP BY status
                """,
                (run.run_id,),
            ).fetchall()
            status_counts = {str(row["status"]): int(row["count"]) for row in status_rows}
            if sum(status_counts.values()) != run.session_count or any(
                status not in _RUN_SUCCESS_STATUSES for status in status_counts
            ):
                raise StateConflictError(
                    "import run cannot complete while session work is pending or unsuccessful"
                )
            session_rows = self._db.execute(
                """
                SELECT * FROM import_run_sessions
                WHERE run_id = ? ORDER BY ordinal ASC
                """,
                (run.run_id,),
            ).fetchall()
            total_turn_count, turn_manifest_sha256 = self._calculate_turn_manifest(
                run.run_id,
                session_rows,
            )
            if (
                total_turn_count != run.total_turn_count
                or turn_manifest_sha256 != run.turn_manifest_sha256
            ):
                raise StateConflictError("certified run turn manifest changed before completion")
            unresolved = int(
                self._db.execute(
                    """
                    SELECT COUNT(*)
                    FROM import_run_turns AS run_turn
                    LEFT JOIN imported_turns AS turn
                      ON turn.project = ?
                     AND turn.session_id = run_turn.session_id
                     AND turn.turn_key = run_turn.turn_key
                     AND turn.source_payload_sha256 = run_turn.source_payload_sha256
                     AND turn.status = 'committed'
                    WHERE run_turn.run_id = ? AND turn.turn_key IS NULL
                    """,
                    (run.project, run.run_id),
                ).fetchone()[0]
            )
            if unresolved:
                raise StateConflictError(
                    "import run cannot complete while certified turns are unresolved"
                )
            now = isoformat_z(datetime.now(UTC))
            cursor = self._db.execute(
                """
                UPDATE import_runs
                SET status = 'completed', phase = 'completed', completed_at = ?,
                    updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status = 'active' AND phase = 'ready'
                  AND revision = ? AND turn_manifest_sha256 != ''
                """,
                (now, now, run.run_id, run.revision),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("saved import run completion state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise

    def begin_pending(
        self,
        *,
        run_id: str,
        project: str,
        session_id: str,
        turn_key: str,
        payload_sha256: str,
        verification_signature: str,
        source_last_activity_at: datetime,
        atif_schema_version: str,
    ) -> StateRow:
        now = isoformat_z(datetime.now(UTC))
        cursor = self._db.execute(
            """
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at,
                atif_schema_version, importer_version, created_at, updated_at
            )
            SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?
            FROM import_run_turns AS run_turn
            JOIN import_runs AS run ON run.run_id = run_turn.run_id
            JOIN import_run_sessions AS session
              ON session.run_id = run_turn.run_id AND session.session_id = run_turn.session_id
            WHERE run_turn.run_id = ? AND run_turn.session_id = ? AND run_turn.turn_key = ?
              AND run_turn.source_payload_sha256 = ?
              AND run.project = ? AND run.status = 'active' AND run.phase = 'ready'
              AND session.status IN ('certified', 'failed', 'conflict')
            """,
            (
                project,
                session_id,
                turn_key,
                payload_sha256,
                payload_sha256,
                verification_signature,
                isoformat_z(source_last_activity_at),
                atif_schema_version,
                __version__,
                now,
                now,
                run_id,
                session_id,
                turn_key,
                payload_sha256,
                project,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn was not bound to the certified run manifest")
        self._after_write()
        row = self.get(project, session_id, turn_key)
        assert row is not None
        return row

    def record_emitted(
        self,
        *,
        row: StateRow,
        trace_ids: list[str],
        root_span_ids: list[str],
        span_count: int,
    ) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET trace_ids_json = ?, root_span_ids_json = ?, span_count = ?,
                updated_at = ?, last_error = '', revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending'
              AND payload_sha256 = ? AND verification_signature = ?
            """,
            (
                json.dumps(trace_ids),
                json.dumps(root_span_ids),
                span_count,
                isoformat_z(datetime.now(UTC)),
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before emission evidence was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_committed(
        self,
        *,
        row: StateRow,
        trace_ids: list[str] | None = None,
        root_span_ids: list[str] | None = None,
        span_count: int | None = None,
    ) -> StateRow:
        now = isoformat_z(datetime.now(UTC))
        assignments = [
            "status = 'committed'",
            "updated_at = ?",
            "imported_at = ?",
            "last_error = ''",
            "revision = revision + 1",
        ]
        values: list[object] = [now, now]
        if trace_ids is not None:
            assignments.append("trace_ids_json = ?")
            values.append(json.dumps(trace_ids))
        if root_span_ids is not None:
            assignments.append("root_span_ids_json = ?")
            values.append(json.dumps(root_span_ids))
        if span_count is not None:
            assignments.append("span_count = ?")
            values.append(span_count)
        values.extend(
            [
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ]
        )
        cursor = self._db.execute(
            f"""
            UPDATE imported_turns SET {", ".join(assignments)}
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending'
              AND payload_sha256 = ? AND verification_signature = ?
            """,
            values,
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before it was committed")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_conflict(
        self,
        *,
        row: StateRow,
        new_payload_sha256: str,
        error: str | None = None,
    ) -> StateRow:
        message = error or f"source payload changed to {new_payload_sha256}"
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET status = 'conflict', updated_at = ?, last_error = ?, revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = ? AND payload_sha256 = ?
              AND source_payload_sha256 = ? AND verification_signature = ?
            """,
            (
                isoformat_z(datetime.now(UTC)),
                message[:500],
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.status,
                row.payload_sha256,
                row.source_payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("turn changed before its conflict was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def replace_unemitted_pending_payload(
        self,
        *,
        row: StateRow,
        payload_sha256: str,
        verification_signature: str,
        source_last_activity_at: datetime,
        atif_schema_version: str,
    ) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET payload_sha256 = ?, source_payload_sha256 = ?, verification_signature = ?,
                status = 'pending', source_last_activity_at = ?, atif_schema_version = ?,
                importer_version = ?, updated_at = ?, last_error = '', revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND payload_sha256 = ?
              AND status IN ('pending', 'conflict')
              AND span_count = 0 AND trace_ids_json = '[]' AND root_span_ids_json = '[]'
            """,
            (
                payload_sha256,
                payload_sha256,
                verification_signature,
                isoformat_z(source_last_activity_at),
                atif_schema_version,
                __version__,
                isoformat_z(datetime.now(UTC)),
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError(
                "could not replace pending payload because emission evidence or state changed"
            )
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def record_error(self, *, row: StateRow, error: str) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET updated_at = ?, last_error = ?, revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending' AND payload_sha256 = ?
              AND verification_signature = ?
            """,
            (
                isoformat_z(datetime.now(UTC)),
                error[:500],
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before its error was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_remote_conflict(self, *, row: StateRow, error: str) -> StateRow:
        if row.status != "pending":
            raise StateConflictError("only a pending turn can receive a remote conflict")
        return self.mark_conflict(row=row, new_payload_sha256=row.payload_sha256, error=error)

    def _backfill_plan_row(self, row: sqlite3.Row) -> BackfillPlan:
        since_utc = parse_datetime(row["since_utc"])
        until_utc = parse_datetime(row["until_utc"])
        if since_utc is None or until_utc is None or since_utc >= until_utc:
            raise StateConflictError("saved backfill plan window is malformed")
        return BackfillPlan(
            plan_id=str(row["plan_id"]),
            project=str(row["project"]),
            source_principal_sha256=str(row["source_principal_sha256"]),
            since_utc=since_utc,
            until_utc=until_utc,
            timezone_name=str(row["timezone_name"]),
            selector=str(row["selector"]),
            universe_sha256=str(row["universe_sha256"]),
            status=str(row["status"]),
            discovered_count=int(row["discovered_count"]),
            eligible_count=int(row["eligible_count"]),
            deferred_count=int(row["deferred_count"]),
            invalid_count=int(row["invalid_count"]),
            selected_count=int(row["selected_count"]),
            attempts=int(row["attempts"]),
            last_error_code=str(row["last_error_code"]),
        )

    def _backfill_plan_session_row(self, row: sqlite3.Row) -> BackfillPlanSession:
        started_at = parse_datetime(row["started_at"])
        last_activity_at = parse_datetime(row["last_activity_at"])
        if started_at is None or last_activity_at is None:
            raise StateConflictError("saved backfill plan session is malformed")
        return BackfillPlanSession(
            plan_id=str(row["plan_id"]),
            ordinal=int(row["ordinal"]),
            session_id=str(row["session_id"]),
            started_at=started_at,
            last_activity_at=last_activity_at,
            status=str(row["status"]),
        )

    def _backfill_plan_turn_row(self, row: sqlite3.Row) -> BackfillPlanTurn:
        return BackfillPlanTurn(
            plan_id=str(row["plan_id"]),
            session_id=str(row["session_id"]),
            ordinal=int(row["ordinal"]),
            turn_key=str(row["turn_key"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            wire_sha256=str(row["wire_sha256"]),
            logical_key=str(row["logical_key"]),
            span_count=int(row["span_count"]),
            compressed_bytes=int(row["compressed_bytes"]),
            uncompressed_bytes=int(row["uncompressed_bytes"]),
            reference_count=int(row["reference_count"]),
            capability_version=str(row["capability_version"]),
            atif_schema_version=str(row["atif_schema_version"]),
        )

    def _backfill_plan_stats_row(self, row: sqlite3.Row) -> BackfillPlanStats:
        return BackfillPlanStats(
            plan_id=str(row["plan_id"]),
            turn_count=int(row["turn_count"]),
            total_compressed_bytes=int(row["total_compressed_bytes"]),
            max_compressed_bytes=int(row["max_compressed_bytes"]),
            total_uncompressed_bytes=int(row["total_uncompressed_bytes"]),
            max_uncompressed_bytes=int(row["max_uncompressed_bytes"]),
            total_reference_count=int(row["total_reference_count"]),
            max_reference_count=int(row["max_reference_count"]),
            max_span_count=int(row["max_span_count"]),
            compressed_le_64k=int(row["compressed_le_64k"]),
            compressed_le_256k=int(row["compressed_le_256k"]),
            compressed_le_1m=int(row["compressed_le_1m"]),
            compressed_gt_1m=int(row["compressed_gt_1m"]),
            uncompressed_le_256k=int(row["uncompressed_le_256k"]),
            uncompressed_le_1m=int(row["uncompressed_le_1m"]),
            uncompressed_le_5m=int(row["uncompressed_le_5m"]),
            uncompressed_gt_5m=int(row["uncompressed_gt_5m"]),
        )

    def _backfill_cohort_row(self, row: sqlite3.Row) -> BackfillCohort:
        return BackfillCohort(
            cohort_id=str(row["cohort_id"]),
            plan_id=str(row["plan_id"]),
            ordinal=int(row["ordinal"]),
            status=str(row["status"]),
            session_count=int(row["session_count"]),
            attempts=int(row["attempts"]),
            imported_turns=int(row["imported_turns"]),
            skipped_turns=int(row["skipped_turns"]),
            conflicted_turns=int(row["conflicted_turns"]),
            failed_items=int(row["failed_items"]),
            emitted_spans=int(row["emitted_spans"]),
            last_error_code=str(row["last_error_code"]),
        )

    def get_backfill_plan(self, plan_id: str) -> BackfillPlan | None:
        row = self._db.execute(
            "SELECT * FROM backfill_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        return None if row is None else self._backfill_plan_row(row)

    def resolve_backfill_plan(self, reference: str) -> BackfillPlan | None:
        """Resolve a full plan hash or an unambiguous content-free 12+ hex alias."""
        if not re.fullmatch(r"[0-9a-f]{12,64}", reference):
            raise StateConflictError("backfill plan reference is malformed")
        rows = self._db.execute(
            """
            SELECT * FROM backfill_plans
            WHERE substr(plan_id, 1, length(?)) = ?
            ORDER BY plan_id ASC LIMIT 2
            """,
            (reference, reference),
        ).fetchall()
        if len(rows) > 1:
            raise StateConflictError(
                "backfill plan alias is ambiguous; use a longer alias from private state"
            )
        return None if not rows else self._backfill_plan_row(rows[0])

    def get_backfill_plan_sessions(self, plan_id: str) -> list[BackfillPlanSession]:
        rows = self._db.execute(
            """
            SELECT * FROM backfill_plan_sessions
            WHERE plan_id = ? ORDER BY ordinal ASC
            """,
            (plan_id,),
        ).fetchall()
        sessions = [self._backfill_plan_session_row(row) for row in rows]
        if any(item.ordinal != ordinal for ordinal, item in enumerate(sessions)):
            raise StateConflictError("saved backfill plan session ordering is malformed")
        return sessions

    def get_backfill_plan_filters(self, plan_id: str) -> list[tuple[str, str]]:
        rows = self._db.execute(
            """
            SELECT filter_kind, filter_value FROM backfill_plan_filters
            WHERE plan_id = ? ORDER BY filter_kind ASC, ordinal ASC
            """,
            (plan_id,),
        ).fetchall()
        return [(str(row["filter_kind"]), str(row["filter_value"])) for row in rows]

    def get_backfill_plan_turns(
        self,
        plan_id: str,
        *,
        session_ids: set[str] | None = None,
    ) -> list[BackfillPlanTurn]:
        rows = self._db.execute(
            """
            SELECT turn.*
            FROM backfill_plan_turns AS turn
            JOIN backfill_plan_sessions AS session
              ON session.plan_id = turn.plan_id AND session.session_id = turn.session_id
            WHERE turn.plan_id = ?
            ORDER BY session.ordinal ASC, turn.ordinal ASC
            """,
            (plan_id,),
        ).fetchall()
        turns = [self._backfill_plan_turn_row(row) for row in rows]
        if session_ids is not None:
            turns = [turn for turn in turns if turn.session_id in session_ids]
        return turns

    def get_backfill_plan_stats(self, plan_id: str) -> BackfillPlanStats:
        row = self._db.execute(
            "SELECT * FROM backfill_plan_stats WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise StateConflictError("backfill plan is missing its size certificate")
        return self._backfill_plan_stats_row(row)

    def create_backfill_plan(
        self,
        *,
        plan_id: str,
        project: str,
        source_principal_sha256: str,
        since_utc: datetime,
        until_utc: datetime,
        timezone_name: str,
        selector: str,
        universe_sha256: str,
        sessions: list[tuple[str, datetime, datetime]],
        filters: list[tuple[str, str]],
        turns: list[BackfillPlanTurn],
        stats: BackfillPlanStats,
        discovered_count: int,
        eligible_count: int,
        deferred_count: int,
        invalid_count: int,
    ) -> BackfillPlan:
        if not _HEX_SHA256.fullmatch(plan_id):
            raise StateConflictError("backfill plan ID is malformed")
        if not _HEX_SHA256.fullmatch(source_principal_sha256) or not _HEX_SHA256.fullmatch(
            universe_sha256
        ):
            raise StateConflictError("backfill plan identity is malformed")
        if selector not in {"backlog", "canary"}:
            raise StateConflictError("backfill plan selector is unsupported")
        if since_utc >= until_utc:
            raise StateConflictError("backfill plan window is empty")
        if len({session_id for session_id, _started, _activity in sessions}) != len(sessions):
            raise StateConflictError("backfill plan requires unique session IDs")
        allowed_filter_kinds = {"agent", "repository", "session", "exclude_subagents"}
        if any(kind not in allowed_filter_kinds or not value for kind, value in filters):
            raise StateConflictError("backfill plan contains an invalid exact filter")
        if filters != sorted(filters) or any(
            kind == "exclude_subagents" and value != "true" for kind, value in filters
        ):
            raise StateConflictError("backfill plan exact filters are not canonical")
        if len(filters) != len(set(filters)):
            raise StateConflictError("backfill plan contains duplicate exact filters")
        session_ids = {session_id for session_id, _started, _activity in sessions}
        if stats != _certified_backfill_stats(plan_id, turns):
            raise StateConflictError("backfill plan size certificate is inconsistent")
        if any(
            turn.plan_id != plan_id
            or turn.session_id not in session_ids
            or not _HEX_SHA256.fullmatch(turn.source_payload_sha256)
            or not _HEX_SHA256.fullmatch(turn.wire_sha256)
            or not _HEX_SHA256.fullmatch(turn.logical_key)
            or turn.span_count <= 0
            or turn.compressed_bytes <= 0
            or turn.uncompressed_bytes <= 0
            or turn.reference_count < 0
            or not turn.capability_version
            or not turn.atif_schema_version
            for turn in turns
        ):
            raise StateConflictError("backfill plan contains an invalid turn certificate")
        turn_identities = [(turn.session_id, turn.ordinal, turn.turn_key) for turn in turns]
        if len(turn_identities) != len(set(turn_identities)):
            raise StateConflictError("backfill plan contains duplicate turn certificates")
        expected_turn_order = [
            turn
            for session_id, _started, _activity in sessions
            for turn in sorted(
                (item for item in turns if item.session_id == session_id),
                key=lambda item: item.ordinal,
            )
        ]
        if turns != expected_turn_order or any(
            turn.ordinal != ordinal
            for session_id, _started, _activity in sessions
            for ordinal, turn in enumerate(item for item in turns if item.session_id == session_id)
        ):
            raise StateConflictError("backfill plan turn ordering is not canonical")
        existing = self.get_backfill_plan(plan_id)
        if existing is not None:
            saved = self.get_backfill_plan_sessions(plan_id)
            saved_filters = self.get_backfill_plan_filters(plan_id)
            saved_turns = self.get_backfill_plan_turns(plan_id)
            saved_stats = self.get_backfill_plan_stats(plan_id)
            expected_sessions = [
                (session_id, isoformat_z(started_at), isoformat_z(activity))
                for session_id, started_at, activity in sessions
            ]
            actual_sessions = [
                (item.session_id, isoformat_z(item.started_at), isoformat_z(item.last_activity_at))
                for item in saved
            ]
            expected_identity = (
                project,
                source_principal_sha256,
                isoformat_z(since_utc),
                isoformat_z(until_utc),
                timezone_name,
                selector,
                universe_sha256,
                discovered_count,
                eligible_count,
                deferred_count,
                invalid_count,
                len(sessions),
            )
            actual_identity = (
                existing.project,
                existing.source_principal_sha256,
                isoformat_z(existing.since_utc),
                isoformat_z(existing.until_utc),
                existing.timezone_name,
                existing.selector,
                existing.universe_sha256,
                existing.discovered_count,
                existing.eligible_count,
                existing.deferred_count,
                existing.invalid_count,
                existing.selected_count,
            )
            if (
                actual_identity != expected_identity
                or actual_sessions != expected_sessions
                or saved_filters != filters
                or saved_turns != turns
                or saved_stats != stats
            ):
                raise StateConflictError("backfill plan ID collided with different source evidence")
            return existing

        now = isoformat_z(datetime.now(UTC))
        initial_status = "completed" if not sessions else "planned"
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO backfill_plans (
                    plan_id, project, source_principal_sha256, since_utc, until_utc,
                    timezone_name, selector, universe_sha256, status,
                    discovered_count, eligible_count, deferred_count, invalid_count,
                    selected_count, created_at, updated_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    project,
                    source_principal_sha256,
                    isoformat_z(since_utc),
                    isoformat_z(until_utc),
                    timezone_name,
                    selector,
                    universe_sha256,
                    initial_status,
                    discovered_count,
                    eligible_count,
                    deferred_count,
                    invalid_count,
                    len(sessions),
                    now,
                    now,
                    now if not sessions else None,
                ),
            )
            self._db.executemany(
                """
                INSERT INTO backfill_plan_sessions (
                    plan_id, ordinal, session_id, started_at, last_activity_at,
                    status, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                [
                    (
                        plan_id,
                        ordinal,
                        session_id,
                        isoformat_z(started_at),
                        isoformat_z(activity),
                        now,
                    )
                    for ordinal, (session_id, started_at, activity) in enumerate(sessions)
                ],
            )
            filter_ordinals: dict[str, int] = {}
            filter_rows: list[tuple[str, str, int, str]] = []
            for kind, value in filters:
                ordinal = filter_ordinals.get(kind, 0)
                filter_rows.append((plan_id, kind, ordinal, value))
                filter_ordinals[kind] = ordinal + 1
            self._db.executemany(
                """
                INSERT INTO backfill_plan_filters (
                    plan_id, filter_kind, ordinal, filter_value
                ) VALUES (?, ?, ?, ?)
                """,
                filter_rows,
            )
            self._db.executemany(
                """
                INSERT INTO backfill_plan_turns (
                    plan_id, session_id, ordinal, turn_key, source_payload_sha256,
                    wire_sha256, logical_key, span_count, compressed_bytes,
                    uncompressed_bytes, reference_count, capability_version,
                    atif_schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        turn.plan_id,
                        turn.session_id,
                        turn.ordinal,
                        turn.turn_key,
                        turn.source_payload_sha256,
                        turn.wire_sha256,
                        turn.logical_key,
                        turn.span_count,
                        turn.compressed_bytes,
                        turn.uncompressed_bytes,
                        turn.reference_count,
                        turn.capability_version,
                        turn.atif_schema_version,
                    )
                    for turn in turns
                ],
            )
            self._db.execute(
                """
                INSERT INTO backfill_plan_stats (
                    plan_id, turn_count, total_compressed_bytes, max_compressed_bytes,
                    total_uncompressed_bytes, max_uncompressed_bytes,
                    total_reference_count, max_reference_count, max_span_count,
                    compressed_le_64k, compressed_le_256k, compressed_le_1m,
                    compressed_gt_1m, uncompressed_le_256k, uncompressed_le_1m,
                    uncompressed_le_5m, uncompressed_gt_5m
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stats.plan_id,
                    stats.turn_count,
                    stats.total_compressed_bytes,
                    stats.max_compressed_bytes,
                    stats.total_uncompressed_bytes,
                    stats.max_uncompressed_bytes,
                    stats.total_reference_count,
                    stats.max_reference_count,
                    stats.max_span_count,
                    stats.compressed_le_64k,
                    stats.compressed_le_256k,
                    stats.compressed_le_1m,
                    stats.compressed_gt_1m,
                    stats.uncompressed_le_256k,
                    stats.uncompressed_le_1m,
                    stats.uncompressed_le_5m,
                    stats.uncompressed_gt_5m,
                ),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        created = self.get_backfill_plan(plan_id)
        assert created is not None
        return created

    def get_or_create_backfill_cohort(
        self,
        *,
        plan_id: str,
        max_sessions: int,
    ) -> BackfillCohort | None:
        if not 1 <= max_sessions <= 10_000:
            raise ValueError("max_sessions must be between 1 and 10000")
        plan = self.get_backfill_plan(plan_id)
        if plan is None:
            raise StateConflictError("backfill plan was not found in the private state database")
        active_rows = self._db.execute(
            """
            SELECT * FROM backfill_cohorts
            WHERE plan_id = ? AND status != 'completed'
            ORDER BY ordinal ASC
            """,
            (plan_id,),
        ).fetchall()
        if len(active_rows) > 1:
            raise StateConflictError("backfill plan has multiple unfinished cohorts")
        if active_rows:
            return self._backfill_cohort_row(active_rows[0])
        pending = self._db.execute(
            """
            SELECT * FROM backfill_plan_sessions
            WHERE plan_id = ? AND status = 'pending'
            ORDER BY ordinal ASC LIMIT ?
            """,
            (plan_id, max_sessions),
        ).fetchall()
        if not pending:
            return None
        cohort_ordinal = int(
            self._db.execute(
                "SELECT COUNT(*) FROM backfill_cohorts WHERE plan_id = ?", (plan_id,)
            ).fetchone()[0]
        )
        membership = [
            {
                "ordinal": int(row["ordinal"]),
                "session_id": str(row["session_id"]),
                "last_activity_at": str(row["last_activity_at"]),
            }
            for row in pending
        ]
        cohort_id = sha256_json(
            {
                "schema": "hivemind-weave-backfill-cohort-v1",
                "plan_id": plan_id,
                "cohort_ordinal": cohort_ordinal,
                "sessions": membership,
            }
        )
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO backfill_cohorts (
                    cohort_id, plan_id, ordinal, status, session_count, created_at, updated_at
                ) VALUES (?, ?, ?, 'planned', ?, ?, ?)
                """,
                (cohort_id, plan_id, cohort_ordinal, len(pending), now, now),
            )
            self._db.executemany(
                """
                INSERT INTO backfill_cohort_sessions (
                    cohort_id, plan_id, ordinal, session_id
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (cohort_id, plan_id, ordinal, str(row["session_id"]))
                    for ordinal, row in enumerate(pending)
                ],
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM backfill_cohorts WHERE cohort_id = ?", (cohort_id,)
        ).fetchone()
        assert row is not None
        return self._backfill_cohort_row(row)

    def get_backfill_cohort_sessions(self, cohort_id: str) -> list[BackfillPlanSession]:
        rows = self._db.execute(
            """
            SELECT plan_session.*
            FROM backfill_cohort_sessions AS cohort_session
            JOIN backfill_plan_sessions AS plan_session
              ON plan_session.plan_id = cohort_session.plan_id
             AND plan_session.session_id = cohort_session.session_id
            WHERE cohort_session.cohort_id = ?
            ORDER BY cohort_session.ordinal ASC
            """,
            (cohort_id,),
        ).fetchall()
        return [self._backfill_plan_session_row(row) for row in rows]

    def begin_backfill_cohort(self, cohort: BackfillCohort) -> BackfillCohort:
        if cohort.status == "completed":
            return cohort
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            cursor = self._db.execute(
                """
                UPDATE backfill_cohorts
                SET status = 'applying', attempts = attempts + 1,
                    last_error_code = '', updated_at = ?
                WHERE cohort_id = ? AND status IN ('planned', 'applying', 'blocked')
                  AND attempts = ?
                """,
                (now, cohort.cohort_id, cohort.attempts),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("backfill cohort changed before apply")
            self._db.execute(
                """
                UPDATE backfill_plans
                SET status = 'applying', attempts = attempts + 1,
                    last_error_code = '', updated_at = ?
                WHERE plan_id = ? AND status IN ('planned', 'applying', 'blocked')
                """,
                (now, cohort.plan_id),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM backfill_cohorts WHERE cohort_id = ?", (cohort.cohort_id,)
        ).fetchone()
        assert row is not None
        return self._backfill_cohort_row(row)

    def finish_backfill_cohort(
        self,
        *,
        cohort: BackfillCohort,
        success: bool,
        imported_turns: int,
        skipped_turns: int,
        conflicted_turns: int,
        failed_items: int,
        emitted_spans: int,
        error_code: str = "",
    ) -> BackfillPlan:
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            status = "completed" if success else "blocked"
            cursor = self._db.execute(
                """
                UPDATE backfill_cohorts
                SET status = ?, imported_turns = ?, skipped_turns = ?,
                    conflicted_turns = ?, failed_items = ?, emitted_spans = ?,
                    last_error_code = ?, updated_at = ?, completed_at = ?
                WHERE cohort_id = ? AND status = 'applying' AND attempts = ?
                """,
                (
                    status,
                    imported_turns,
                    skipped_turns,
                    conflicted_turns,
                    failed_items,
                    emitted_spans,
                    "" if success else error_code[:64],
                    now,
                    now if success else None,
                    cohort.cohort_id,
                    cohort.attempts,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("backfill cohort changed before completion")
            if success:
                self._db.execute(
                    """
                    UPDATE backfill_plan_sessions
                    SET status = 'completed', updated_at = ?
                    WHERE plan_id = ? AND session_id IN (
                        SELECT session_id FROM backfill_cohort_sessions WHERE cohort_id = ?
                    )
                    """,
                    (now, cohort.plan_id, cohort.cohort_id),
                )
                remaining = int(
                    self._db.execute(
                        """
                        SELECT COUNT(*) FROM backfill_plan_sessions
                        WHERE plan_id = ? AND status = 'pending'
                        """,
                        (cohort.plan_id,),
                    ).fetchone()[0]
                )
                plan_status = "completed" if remaining == 0 else "planned"
                self._db.execute(
                    """
                    UPDATE backfill_plans
                    SET status = ?, last_error_code = '', updated_at = ?, completed_at = ?
                    WHERE plan_id = ? AND status = 'applying'
                    """,
                    (
                        plan_status,
                        now,
                        now if plan_status == "completed" else None,
                        cohort.plan_id,
                    ),
                )
            else:
                self._db.execute(
                    """
                    UPDATE backfill_plans
                    SET status = 'blocked', last_error_code = ?, updated_at = ?
                    WHERE plan_id = ? AND status = 'applying'
                    """,
                    (error_code[:64], now, cohort.plan_id),
                )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        plan = self.get_backfill_plan(cohort.plan_id)
        assert plan is not None
        return plan

    def backfill_progress(self, plan_id: str) -> tuple[int, int]:
        rows = self._db.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM backfill_plan_sessions WHERE plan_id = ? GROUP BY status
            """,
            (plan_id,),
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        return counts.get("completed", 0), counts.get("pending", 0)

    def _sync_feed_row(self, row: sqlite3.Row) -> SyncFeed:
        since = parse_datetime(row["since_utc"])
        watermark = parse_datetime(row["successful_scan_watermark"])
        scan_started = parse_datetime(row["last_scan_started_at"])
        scan_succeeded = parse_datetime(row["last_scan_succeeded_at"])
        if since is None:
            raise StateConflictError("saved sync feed has an invalid start timestamp")
        return SyncFeed(
            project=str(row["project"]),
            config_sha256=str(row["config_sha256"]),
            since_utc=since,
            successful_scan_watermark=watermark,
            last_scan_started_at=scan_started,
            last_scan_succeeded_at=scan_succeeded,
            candidate_universe_sha256=str(row["candidate_universe_sha256"]),
        )

    def _sync_session_row(self, row: sqlite3.Row) -> SyncLedgerSession:
        started = parse_datetime(row["started_at"])
        activity = parse_datetime(row["last_activity_at"])
        eligible_after = parse_datetime(row["eligible_after"])
        completed_activity = parse_datetime(row["completed_activity_at"])
        if started is None or activity is None or eligible_after is None:
            raise StateConflictError("saved sync session has invalid timestamps")
        return SyncLedgerSession(
            project=str(row["project"]),
            session_id=str(row["session_id"]),
            started_at=started,
            last_activity_at=activity,
            activity_known=bool(row["activity_known"]),
            eligible_after=eligible_after,
            status=str(row["status"]),
            plan_id=str(row["plan_id"]),
            completed_activity_at=completed_activity,
            attempts=int(row["attempts"]),
        )

    def get_sync_feed(self, project: str) -> SyncFeed | None:
        row = self._db.execute("SELECT * FROM sync_feeds WHERE project = ?", (project,)).fetchone()
        return None if row is None else self._sync_feed_row(row)

    def ensure_sync_feed(
        self,
        *,
        project: str,
        config_sha256: str,
        since_utc: datetime,
    ) -> SyncFeed:
        if not project or not _HEX_SHA256.fullmatch(config_sha256):
            raise StateConflictError("sync feed identity is malformed")
        existing = self.get_sync_feed(project)
        if existing is not None:
            if (
                existing.config_sha256 != config_sha256
                or existing.since_utc != since_utc.astimezone(UTC)
            ):
                raise StateConflictError(
                    "saved sync discovery policy differs from the configured policy"
                )
            return existing
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO sync_feeds (
                    project, config_sha256, since_utc, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (project, config_sha256, isoformat_z(since_utc), now, now),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        created = self.get_sync_feed(project)
        assert created is not None
        return created

    def record_sync_scan(
        self,
        *,
        project: str,
        config_sha256: str,
        since_utc: datetime,
        scan_started_at: datetime,
        cutoff: datetime,
        records: list[SyncDiscoveryRecord],
    ) -> SyncFeed:
        feed = self.ensure_sync_feed(
            project=project,
            config_sha256=config_sha256,
            since_utc=since_utc,
        )
        cutoff = cutoff.astimezone(UTC)
        scan_started_at = scan_started_at.astimezone(UTC)
        if feed.successful_scan_watermark is not None and cutoff < feed.successful_scan_watermark:
            raise StateConflictError("sync scan watermark cannot move backwards")
        if len({record.session_id for record in records}) != len(records):
            raise StateConflictError("sync discovery contains duplicate session IDs")
        if any(
            record.status not in {"deferred", "queued"}
            or record.started_at.tzinfo is None
            or record.last_activity_at.tzinfo is None
            or record.eligible_after.tzinfo is None
            for record in records
        ):
            raise StateConflictError("sync discovery record is malformed")

        observed_at = isoformat_z(cutoff)
        candidate_universe_sha256 = sha256_json(
            [
                {
                    "session_id": record.session_id,
                    "last_activity_at": isoformat_z(record.last_activity_at),
                }
                for record in sorted(records, key=lambda item: item.session_id)
            ]
        )
        try:
            self._db.execute("BEGIN IMMEDIATE")
            for record in records:
                row = self._db.execute(
                    "SELECT * FROM sync_sessions WHERE project = ? AND session_id = ?",
                    (project, record.session_id),
                ).fetchone()
                if row is None:
                    self._db.execute(
                        """
                        INSERT INTO sync_sessions (
                            project, session_id, started_at, last_activity_at,
                            activity_known, eligible_after, status, observed_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            project,
                            record.session_id,
                            isoformat_z(record.started_at),
                            isoformat_z(record.last_activity_at),
                            int(record.activity_known),
                            isoformat_z(record.eligible_after),
                            record.status,
                            observed_at,
                            observed_at,
                        ),
                    )
                    continue

                current = self._sync_session_row(row)
                if current.started_at != record.started_at.astimezone(UTC):
                    raise StateConflictError("a discovered sync session changed its start time")
                if (
                    current.activity_known
                    and record.activity_known
                    and record.last_activity_at.astimezone(UTC) < current.last_activity_at
                ):
                    raise StateConflictError("a discovered sync session activity regressed")
                accept_activity = record.activity_known or not current.activity_known
                new_activity = (
                    record.last_activity_at.astimezone(UTC)
                    if accept_activity
                    else current.last_activity_at
                )
                new_known = current.activity_known or record.activity_known
                advanced = record.activity_known and (
                    not current.activity_known or new_activity > current.last_activity_at
                )
                status = current.status
                plan_id = current.plan_id
                completed_activity = current.completed_activity_at
                if advanced:
                    status = record.status
                    plan_id = ""
                    completed_activity = None
                elif current.status == "deferred" and record.status == "queued":
                    status = "queued"
                self._db.execute(
                    """
                    UPDATE sync_sessions
                    SET last_activity_at = ?, activity_known = ?, eligible_after = ?,
                        status = ?, plan_id = ?, completed_activity_at = ?,
                        observed_at = ?, updated_at = ?, revision = revision + 1
                    WHERE project = ? AND session_id = ? AND revision = ?
                    """,
                    (
                        isoformat_z(new_activity),
                        int(new_known),
                        isoformat_z(record.eligible_after),
                        status,
                        plan_id,
                        "" if completed_activity is None else isoformat_z(completed_activity),
                        observed_at,
                        observed_at,
                        project,
                        record.session_id,
                        int(row["revision"]),
                    ),
                )
            self._db.execute(
                """
                UPDATE sync_feeds
                SET successful_scan_watermark = ?, last_scan_started_at = ?,
                    last_scan_succeeded_at = ?, updated_at = ?,
                    candidate_universe_sha256 = ?
                WHERE project = ? AND config_sha256 = ?
                """,
                (
                    isoformat_z(cutoff),
                    isoformat_z(scan_started_at),
                    observed_at,
                    observed_at,
                    candidate_universe_sha256,
                    project,
                    config_sha256,
                ),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        updated = self.get_sync_feed(project)
        assert updated is not None
        return updated

    def get_next_sync_session(self, project: str) -> SyncLedgerSession | None:
        row = self._db.execute(
            """
            SELECT * FROM sync_sessions
            WHERE project = ? AND status = 'queued'
            ORDER BY last_activity_at ASC, session_id ASC LIMIT 1
            """,
            (project,),
        ).fetchone()
        return None if row is None else self._sync_session_row(row)

    def get_deferred_sync_sessions(self, project: str) -> list[SyncLedgerSession]:
        """Return the durable deferred worklist in a stable content-free order."""
        rows = self._db.execute(
            """
            SELECT * FROM sync_sessions
            WHERE project = ? AND status = 'deferred'
            ORDER BY eligible_after ASC, last_activity_at ASC, session_id ASC
            """,
            (project,),
        ).fetchall()
        return [self._sync_session_row(row) for row in rows]

    def sync_backlog_counts(self, project: str) -> tuple[int, int]:
        rows = self._db.execute(
            """
            SELECT status, COUNT(*) AS count FROM sync_sessions
            WHERE project = ? GROUP BY status
            """,
            (project,),
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        queued = counts.get("queued", 0)
        deferred = counts.get("deferred", 0)
        return queued, deferred

    def begin_sync_attempt(
        self,
        *,
        session: SyncLedgerSession,
        plan_id: str,
    ) -> None:
        if not _HEX_SHA256.fullmatch(plan_id) or session.status != "queued":
            raise StateConflictError("sync attempt identity is malformed")
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO sync_attempts (
                    project, session_id, plan_id, source_last_activity_at,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'processing', ?, ?)
                """,
                (
                    session.project,
                    session.session_id,
                    plan_id,
                    isoformat_z(session.last_activity_at),
                    now,
                    now,
                ),
            )
            cursor = self._db.execute(
                """
                UPDATE sync_sessions
                SET status = 'processing', plan_id = ?, attempts = attempts + 1,
                    updated_at = ?, revision = revision + 1
                WHERE project = ? AND session_id = ? AND status = 'queued'
                  AND last_activity_at = ?
                """,
                (
                    plan_id,
                    now,
                    session.project,
                    session.session_id,
                    isoformat_z(session.last_activity_at),
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("sync session changed before its attempt began")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise

    def finish_sync_attempt(
        self,
        *,
        project: str,
        session_id: str,
        plan_id: str,
        success: bool,
        error_code: str = "",
    ) -> None:
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            cursor = self._db.execute(
                """
                UPDATE sync_attempts
                SET status = ?, error_code = ?, updated_at = ?, completed_at = ?
                WHERE project = ? AND session_id = ? AND plan_id = ?
                  AND status = 'processing'
                """,
                (
                    "completed" if success else "blocked",
                    "" if success else error_code[:64],
                    now,
                    now if success else None,
                    project,
                    session_id,
                    plan_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("sync attempt changed before completion")
            self._db.execute(
                """
                UPDATE sync_sessions
                SET status = ?, completed_activity_at = ?, updated_at = ?,
                    revision = revision + 1
                WHERE project = ? AND session_id = ? AND plan_id = ?
                """,
                (
                    "completed" if success else "blocked",
                    (
                        isoformat_z(
                            self._sync_session_row(
                                self._db.execute(
                                    """
                                    SELECT * FROM sync_sessions
                                    WHERE project = ? AND session_id = ?
                                    """,
                                    (project, session_id),
                                ).fetchone()
                            ).last_activity_at
                        )
                        if success
                        else ""
                    ),
                    now,
                    project,
                    session_id,
                    plan_id,
                ),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise

    def has_unresolved_sync_attempts(self, project: str) -> bool:
        row = self._db.execute(
            """
            SELECT 1 FROM sync_attempts
            WHERE project = ? AND status IN ('processing', 'blocked') LIMIT 1
            """,
            (project,),
        ).fetchone()
        return row is not None

    def has_completed_sync_attempt_since(
        self,
        project: str,
        started_at: datetime,
    ) -> bool:
        if started_at.tzinfo is None or started_at.utcoffset() is None:
            raise StateConflictError("sync recovery timestamp must be timezone-aware")
        row = self._db.execute(
            """
            SELECT 1 FROM sync_attempts
            WHERE project = ? AND status = 'completed'
              AND completed_at IS NOT NULL
              AND julianday(completed_at) >= julianday(?)
            LIMIT 1
            """,
            (project, isoformat_z(started_at.astimezone(UTC))),
        ).fetchone()
        return row is not None

    def get_unresolved_sync_plan_ids(self, project: str) -> list[str]:
        rows = self._db.execute(
            """
            SELECT plan_id FROM sync_attempts
            WHERE project = ? AND status IN ('processing', 'blocked')
            ORDER BY created_at ASC, session_id ASC, plan_id ASC
            """,
            (project,),
        ).fetchall()
        plan_ids = [str(row["plan_id"]) for row in rows]
        if any(not _HEX_SHA256.fullmatch(value) for value in plan_ids):
            raise StateConflictError("saved sync attempt has a malformed plan identity")
        return plan_ids

    def reconcile_sync_attempts(self, project: str) -> SyncReconcileResult:
        attempts = self._db.execute(
            """
            SELECT * FROM sync_attempts
            WHERE project = ? AND status IN ('processing', 'blocked')
            ORDER BY created_at ASC, session_id ASC
            """,
            (project,),
        ).fetchall()
        if not attempts:
            return SyncReconcileResult(0, 0, False)

        resolvable: list[sqlite3.Row] = []
        evidence_available = True
        unresolved = 0
        for attempt in attempts:
            turns = self.get_backfill_plan_turns(
                str(attempt["plan_id"]),
                session_ids={str(attempt["session_id"])},
            )
            if not turns:
                evidence_available = False
                unresolved += 1
                continue
            valid = True
            for turn in turns:
                row = self.get(project, turn.session_id, turn.turn_key)
                if row is None:
                    evidence_available = False
                    valid = False
                    break
                if (
                    row.status != "committed"
                    or row.source_payload_sha256 != turn.source_payload_sha256
                    or row.span_count != turn.span_count
                    or not row.trace_ids
                    or not row.root_span_ids
                ):
                    valid = False
                    break
            if valid:
                resolvable.append(attempt)
            else:
                unresolved += 1

        global_unresolved = self._db.execute(
            """
            SELECT 1 FROM imported_turns
            WHERE project = ? AND status != 'committed' LIMIT 1
            """,
            (project,),
        ).fetchone()
        if global_unresolved is not None:
            unresolved = max(1, unresolved)
        if unresolved:
            return SyncReconcileResult(0, unresolved, evidence_available)

        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            for attempt in resolvable:
                self._db.execute(
                    """
                    UPDATE sync_attempts
                    SET status = 'completed', error_code = '', updated_at = ?, completed_at = ?
                    WHERE project = ? AND session_id = ? AND plan_id = ?
                      AND status IN ('processing', 'blocked')
                    """,
                    (
                        now,
                        now,
                        project,
                        str(attempt["session_id"]),
                        str(attempt["plan_id"]),
                    ),
                )
                self._db.execute(
                    """
                    UPDATE sync_sessions
                    SET status = 'completed', completed_activity_at = last_activity_at,
                        updated_at = ?, revision = revision + 1
                    WHERE project = ? AND session_id = ? AND plan_id = ?
                      AND last_activity_at = ? AND status IN ('processing', 'blocked')
                    """,
                    (
                        now,
                        project,
                        str(attempt["session_id"]),
                        str(attempt["plan_id"]),
                        str(attempt["source_last_activity_at"]),
                    ),
                )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        return SyncReconcileResult(len(resolvable), 0, True)

    @staticmethod
    def _validate_atomic_coordinate(value: str, *, label: str) -> None:
        if not value or len(value) > 512 or any(ord(character) < 0x20 for character in value):
            raise StateConflictError(f"atomic turn {label} is malformed")

    @staticmethod
    def _validate_atomic_error_code(error_code: str) -> str:
        if error_code and (
            len(error_code) > 64 or _ATOMIC_EVIDENCE_ID.fullmatch(error_code) is None
        ):
            raise StateConflictError("atomic turn error code is malformed")
        return error_code

    def _atomic_turn_row(self, row: sqlite3.Row) -> AtomicTurnAttempt:
        try:
            trace_ids_raw = json.loads(str(row["trace_ids_json"] or "[]"))
            root_ids_raw = json.loads(str(row["root_span_ids_json"] or "[]"))
        except json.JSONDecodeError as error:
            raise StateConflictError("saved atomic returned evidence is malformed") from error
        if not isinstance(trace_ids_raw, list) or not isinstance(root_ids_raw, list):
            raise StateConflictError("saved atomic returned evidence is malformed")
        trace_ids = tuple(str(value) for value in trace_ids_raw)
        root_ids = tuple(str(value) for value in root_ids_raw)
        if any(_ATOMIC_EVIDENCE_ID.fullmatch(value) is None for value in (*trace_ids, *root_ids)):
            raise StateConflictError("saved atomic returned evidence has invalid identifiers")
        return AtomicTurnAttempt(
            project=str(row["project"]),
            session_id=str(row["session_id"]),
            turn_key=str(row["turn_key"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            status=str(row["status"]),
            wire_sha256=str(row["wire_sha256"] or ""),
            logical_key=str(row["logical_key"] or ""),
            capability_version=str(row["capability_version"] or ""),
            reference_count=int(row["reference_count"] or 0),
            span_count=int(row["span_count"] or 0),
            commit_id=str(row["commit_id"] or ""),
            trace_ids=trace_ids,
            root_span_ids=root_ids,
            error_code=str(row["error_code"]),
            revision=int(row["revision"]),
        )

    def get_atomic_turn(
        self,
        project: str,
        session_id: str,
        turn_key: str,
    ) -> AtomicTurnAttempt | None:
        row = self._db.execute(
            """
            SELECT attempt.*,
                   certificate.wire_sha256, certificate.logical_key,
                   certificate.capability_version, certificate.reference_count,
                   certificate.span_count,
                   receipt.commit_id, receipt.trace_ids_json, receipt.root_span_ids_json
            FROM atomic_turn_attempts AS attempt
            LEFT JOIN atomic_turn_certificates AS certificate
              ON certificate.project = attempt.project
             AND certificate.session_id = attempt.session_id
             AND certificate.turn_key = attempt.turn_key
            LEFT JOIN atomic_turn_receipts AS receipt
              ON receipt.project = attempt.project
             AND receipt.session_id = attempt.session_id
             AND receipt.turn_key = attempt.turn_key
            WHERE attempt.project = ? AND attempt.session_id = ? AND attempt.turn_key = ?
            """,
            (project, session_id, turn_key),
        ).fetchone()
        return None if row is None else self._atomic_turn_row(row)

    def get_unresolved_atomic_turns(self, project: str) -> list[AtomicTurnAttempt]:
        rows = self._db.execute(
            """
            SELECT attempt.*,
                   certificate.wire_sha256, certificate.logical_key,
                   certificate.capability_version, certificate.reference_count,
                   certificate.span_count,
                   receipt.commit_id, receipt.trace_ids_json, receipt.root_span_ids_json
            FROM atomic_turn_attempts AS attempt
            LEFT JOIN atomic_turn_certificates AS certificate
              ON certificate.project = attempt.project
             AND certificate.session_id = attempt.session_id
             AND certificate.turn_key = attempt.turn_key
            LEFT JOIN atomic_turn_receipts AS receipt
              ON receipt.project = attempt.project
             AND receipt.session_id = attempt.session_id
             AND receipt.turn_key = attempt.turn_key
            WHERE attempt.project = ? AND attempt.status != 'committed'
            ORDER BY attempt.created_at ASC, attempt.session_id ASC, attempt.turn_key ASC
            """,
            (project,),
        ).fetchall()
        return [self._atomic_turn_row(row) for row in rows]

    def sync_diagnostic_counts(self, project: str) -> dict[str, int]:
        atomic_rows = self._db.execute(
            """
            SELECT status, COUNT(*) AS count FROM atomic_turn_attempts
            WHERE project = ? GROUP BY status
            """,
            (project,),
        ).fetchall()
        atomic = {str(row["status"]): int(row["count"]) for row in atomic_rows}
        preflighted = int(
            self._db.execute(
                "SELECT COUNT(*) FROM atomic_turn_certificates WHERE project = ?",
                (project,),
            ).fetchone()[0]
        )
        blocked_attempts = int(
            self._db.execute(
                """
                SELECT COUNT(*) FROM sync_attempts
                WHERE project = ? AND status = 'blocked'
                """,
                (project,),
            ).fetchone()[0]
        )
        return {
            "preflighted": preflighted,
            "committed": atomic.get("committed", 0),
            "blocked": blocked_attempts + atomic.get("rejected", 0),
            "uncertain": (
                atomic.get("submitting", 0)
                + atomic.get("uncertain", 0)
                + atomic.get("acknowledged", 0)
            ),
            "conflicted": atomic.get("conflict", 0),
        }

    def plan_atomic_turn(
        self,
        *,
        project: str,
        session_id: str,
        turn_key: str,
        source_payload_sha256: str,
    ) -> AtomicTurnAttempt:
        self._validate_atomic_coordinate(project, label="project")
        self._validate_atomic_coordinate(session_id, label="session ID")
        self._validate_atomic_coordinate(turn_key, label="key")
        if not _HEX_SHA256.fullmatch(source_payload_sha256):
            raise StateConflictError("atomic turn source certificate is malformed")
        existing = self.get_atomic_turn(project, session_id, turn_key)
        if existing is not None:
            if existing.source_payload_sha256 != source_payload_sha256:
                if existing.status != "committed":
                    self.mark_atomic_turn_conflict(
                        existing,
                        error_code="source_certificate_changed",
                    )
                raise StateConflictError("atomic turn source certificate changed")
            return existing
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO atomic_turn_attempts (
                    project, session_id, turn_key, source_payload_sha256,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'planned', ?, ?)
                """,
                (project, session_id, turn_key, source_payload_sha256, now, now),
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        created = self.get_atomic_turn(project, session_id, turn_key)
        assert created is not None
        return created

    def record_atomic_turn_prepared(
        self,
        attempt: AtomicTurnAttempt,
        *,
        wire_sha256: str,
        logical_key: str,
        capability_version: str,
        reference_count: int,
        span_count: int,
    ) -> AtomicTurnAttempt:
        if (
            not _HEX_SHA256.fullmatch(wire_sha256)
            or not _HEX_SHA256.fullmatch(logical_key)
            or not capability_version
            or len(capability_version) > 128
            or any(ord(character) < 0x20 for character in capability_version)
            or type(reference_count) is not int
            or reference_count < 0
            or type(span_count) is not int
            or span_count <= 0
        ):
            raise StateConflictError("atomic turn prepared certificate is malformed")
        current = self.get_atomic_turn(attempt.project, attempt.session_id, attempt.turn_key)
        if current is None or current.source_payload_sha256 != attempt.source_payload_sha256:
            raise StateConflictError("atomic turn changed before preparation")
        expected = (
            wire_sha256,
            logical_key,
            capability_version,
            reference_count,
            span_count,
        )
        actual = (
            current.wire_sha256,
            current.logical_key,
            current.capability_version,
            current.reference_count,
            current.span_count,
        )
        if current.wire_sha256:
            if actual != expected:
                if current.status not in {"committed", "rejected", "conflict"}:
                    self.mark_atomic_turn_conflict(
                        current,
                        error_code="prepared_certificate_changed",
                    )
                raise StateConflictError("atomic turn prepared certificate changed")
            return current
        if current.status != "planned" or current.revision != attempt.revision:
            raise StateConflictError("atomic turn is not in its planned state")
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO atomic_turn_certificates (
                    project, session_id, turn_key, wire_sha256, logical_key,
                    capability_version, reference_count, span_count, prepared_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.project,
                    attempt.session_id,
                    attempt.turn_key,
                    wire_sha256,
                    logical_key,
                    capability_version,
                    reference_count,
                    span_count,
                    now,
                ),
            )
            cursor = self._db.execute(
                """
                UPDATE atomic_turn_attempts
                SET status = 'prepared', error_code = '', updated_at = ?,
                    revision = revision + 1
                WHERE project = ? AND session_id = ? AND turn_key = ?
                  AND status = 'planned' AND revision = ?
                """,
                (
                    now,
                    attempt.project,
                    attempt.session_id,
                    attempt.turn_key,
                    attempt.revision,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("atomic turn changed during preparation")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        prepared = self.get_atomic_turn(attempt.project, attempt.session_id, attempt.turn_key)
        assert prepared is not None
        return prepared

    def begin_atomic_turn_submit(self, attempt: AtomicTurnAttempt) -> AtomicTurnAttempt:
        if attempt.status not in {"prepared", "uncertain"}:
            raise StateConflictError(
                "atomic turn must be prepared or proven absent before submission"
            )
        return self._transition_atomic_turn(
            attempt,
            from_status=attempt.status,
            to_status="submitting",
            error_code="",
        )

    def mark_atomic_turn_uncertain(
        self,
        attempt: AtomicTurnAttempt,
        *,
        error_code: str = "transport_uncertain",
    ) -> AtomicTurnAttempt:
        return self._transition_atomic_turn(
            attempt,
            from_status="submitting",
            to_status="uncertain",
            error_code=self._validate_atomic_error_code(error_code),
        )

    def mark_atomic_turn_rejected(
        self,
        attempt: AtomicTurnAttempt,
        *,
        error_code: str = "remote_rejected",
    ) -> AtomicTurnAttempt:
        if attempt.status not in {"prepared", "submitting", "uncertain"}:
            raise StateConflictError("atomic turn cannot be rejected from its current state")
        return self._transition_atomic_turn(
            attempt,
            from_status=attempt.status,
            to_status="rejected",
            error_code=self._validate_atomic_error_code(error_code),
        )

    def mark_atomic_turn_conflict(
        self,
        attempt: AtomicTurnAttempt,
        *,
        error_code: str = "evidence_conflict",
    ) -> AtomicTurnAttempt:
        if attempt.status not in {
            "planned",
            "prepared",
            "submitting",
            "uncertain",
            "acknowledged",
        }:
            raise StateConflictError("atomic turn conflict cannot replace a terminal state")
        return self._transition_atomic_turn(
            attempt,
            from_status=attempt.status,
            to_status="conflict",
            error_code=self._validate_atomic_error_code(error_code),
        )

    def _transition_atomic_turn(
        self,
        attempt: AtomicTurnAttempt,
        *,
        from_status: str,
        to_status: str,
        error_code: str,
    ) -> AtomicTurnAttempt:
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            cursor = self._db.execute(
                """
                UPDATE atomic_turn_attempts
                SET status = ?, error_code = ?, updated_at = ?, revision = revision + 1
                WHERE project = ? AND session_id = ? AND turn_key = ?
                  AND status = ? AND revision = ? AND source_payload_sha256 = ?
                """,
                (
                    to_status,
                    error_code,
                    now,
                    attempt.project,
                    attempt.session_id,
                    attempt.turn_key,
                    from_status,
                    attempt.revision,
                    attempt.source_payload_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("atomic turn lifecycle changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        updated = self.get_atomic_turn(attempt.project, attempt.session_id, attempt.turn_key)
        assert updated is not None
        return updated

    @staticmethod
    def _validate_atomic_returned_ids(values: list[str], *, label: str) -> tuple[str, ...]:
        if (
            not values
            or len(values) > 10_000
            or len(values) != len(set(values))
            or any(_ATOMIC_EVIDENCE_ID.fullmatch(value) is None for value in values)
        ):
            raise StateConflictError(f"atomic turn {label} are malformed")
        return tuple(values)

    def record_atomic_turn_acknowledged(
        self,
        attempt: AtomicTurnAttempt,
        *,
        commit_id: str,
        trace_ids: list[str],
        root_span_ids: list[str],
    ) -> AtomicTurnAttempt:
        if _ATOMIC_EVIDENCE_ID.fullmatch(commit_id) is None:
            raise StateConflictError("atomic turn commit ID is malformed")
        traces = self._validate_atomic_returned_ids(trace_ids, label="trace IDs")
        roots = self._validate_atomic_returned_ids(root_span_ids, label="root span IDs")
        current = self.get_atomic_turn(attempt.project, attempt.session_id, attempt.turn_key)
        if current is None:
            raise StateConflictError("atomic turn disappeared before acknowledgement")
        expected = (commit_id, traces, roots)
        actual = (current.commit_id, current.trace_ids, current.root_span_ids)
        if current.commit_id:
            if actual != expected:
                if current.status == "acknowledged":
                    self.mark_atomic_turn_conflict(
                        current,
                        error_code="returned_evidence_changed",
                    )
                raise StateConflictError("atomic returned evidence changed")
            return current
        if (
            current.status not in {"submitting", "uncertain"}
            or current.revision != attempt.revision
        ):
            raise StateConflictError("atomic turn is not awaiting acknowledgement")
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO atomic_turn_receipts (
                    project, session_id, turn_key, commit_id,
                    trace_ids_json, root_span_ids_json, acknowledged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.project,
                    attempt.session_id,
                    attempt.turn_key,
                    commit_id,
                    json.dumps(traces, separators=(",", ":")),
                    json.dumps(roots, separators=(",", ":")),
                    now,
                ),
            )
            cursor = self._db.execute(
                """
                UPDATE atomic_turn_attempts
                SET status = 'acknowledged', error_code = '', updated_at = ?,
                    revision = revision + 1
                WHERE project = ? AND session_id = ? AND turn_key = ?
                  AND status = ? AND revision = ?
                """,
                (
                    now,
                    attempt.project,
                    attempt.session_id,
                    attempt.turn_key,
                    attempt.status,
                    attempt.revision,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("atomic turn changed during acknowledgement")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        acknowledged = self.get_atomic_turn(
            attempt.project,
            attempt.session_id,
            attempt.turn_key,
        )
        assert acknowledged is not None
        return acknowledged

    def commit_atomic_turn(self, attempt: AtomicTurnAttempt) -> AtomicTurnAttempt:
        if (
            attempt.status != "acknowledged"
            or not attempt.commit_id
            or not attempt.trace_ids
            or not attempt.root_span_ids
        ):
            raise StateConflictError(
                "atomic turn requires acknowledged server and UI evidence before commit"
            )
        return self._transition_atomic_turn(
            attempt,
            from_status="acknowledged",
            to_status="committed",
            error_code="",
        )
