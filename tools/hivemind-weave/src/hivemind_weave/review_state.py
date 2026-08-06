"""Content-free state for the explicitly noncanonical review mirror."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import StateConflictError
from .redaction import redact_string
from .source_identity import is_opaque_source_coordinate
from .state import StateStore
from .utils import canonical_json, isoformat_z, parse_datetime, sha256_json

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(
    r"^weave:///wandb/hivemind-chats-review/object/"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}:"
    r"(?:[A-Za-z0-9]{43}|[0-9a-f]{64})$"
)
_CERTIFIED_HASH_RUN = re.compile(r"[0-9a-f]{16,64}", re.IGNORECASE)
_ERROR_CODE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
_LEDGER_STATES = frozenset(
    {
        "planned",
        "objects_publishing",
        "objects_verified",
        "root_submitting",
        "visible",
        "uncertain",
        "conflict",
    }
)


@dataclass(frozen=True)
class ReviewPlan:
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
    last_error_code: str


@dataclass(frozen=True)
class ReviewPlanSession:
    plan_id: str
    ordinal: int
    session_id: str
    started_at: datetime
    last_activity_at: datetime
    status: str


@dataclass(frozen=True)
class ReviewTurnCertificate:
    plan_id: str
    session_id: str
    ordinal: int
    turn_key: str
    source_payload_sha256: str
    manifest_sha256: str
    index_sha256: str
    logical_key: str
    preview_signature: str
    started_at: datetime
    ended_at: datetime
    manifest_bytes: int
    chunk_count: int
    max_chunk_bytes: int
    index_bytes: int
    atif_schema_version: str


@dataclass(frozen=True)
class ReviewCohort:
    cohort_id: str
    plan_id: str
    ordinal: int
    status: str
    session_count: int
    visible_turns: int
    skipped_turns: int
    conflicted_turns: int
    failed_items: int
    last_error_code: str


@dataclass(frozen=True)
class ReviewLedgerTurn:
    project: str
    session_id: str
    turn_key: str
    source_payload_sha256: str
    manifest_sha256: str
    logical_key: str
    preview_signature: str
    manifest_bytes: int
    chunk_count: int
    status: str
    chunk_refs: tuple[str, ...]
    chunk_hashes: tuple[str, ...]
    chunk_sizes: tuple[int, ...]
    index_ref: str
    index_sha256: str
    index_size: int
    trace_id: str
    root_span_id: str
    error_code: str
    revision: int


@dataclass(frozen=True)
class ReviewStatus:
    plans: int
    queued_sessions: int
    completed_sessions: int
    planned_turns: int
    objects_publishing: int
    objects_verified: int
    root_submitting: int
    visible: int
    uncertain: int
    conflicted: int


def review_plan_id(payload: dict[str, Any]) -> str:
    """Hash a caller-supplied canonical plan certificate."""
    return sha256_json({"schema": "hivemind-review-plan-v2", **payload})


def review_logical_key(project: str, conversation_id: str, turn_key: str) -> str:
    value = f"hivemind-review-root-v1\0{project}\0{conversation_id}\0{turn_key}"
    return hashlib.sha256(value.encode()).hexdigest()


def valid_review_trace_id(value: Any) -> bool:
    """Accept only nonzero W3C trace identifiers returned by Weave."""
    return isinstance(value, str) and bool(_TRACE_ID.fullmatch(value)) and int(value, 16) != 0


def valid_review_span_id(value: Any) -> bool:
    """Accept only nonzero W3C span identifiers returned by Weave."""
    return isinstance(value, str) and bool(_SPAN_ID.fullmatch(value)) and int(value, 16) != 0


def _valid_review_reference(value: Any) -> bool:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        return False
    name = value.rsplit("/", 1)[-1].rsplit(":", 1)[0]
    redaction_probe = _CERTIFIED_HASH_RUN.sub("certifiedhash", name)
    return redact_string(redaction_probe) == redaction_probe


def review_filter_summary(filters: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return only non-sensitive selector kinds and counts for durable state.

    A plain digest of an exact repository or agent selector is still an offline
    dictionary oracle.  The selected session universe and turn certificates
    already seal plan membership, so durable filter evidence needs no value-
    derived material at all.
    """
    counts: dict[str, int] = {}
    for kind, _value in filters:
        counts[kind] = counts.get(kind, 0) + 1
    return [(kind, str(counts[kind])) for kind in sorted(counts)]


def _timestamp(value: Any, *, label: str) -> datetime:
    parsed = parse_datetime(value)
    if parsed is None:
        raise StateConflictError(f"saved review {label} is malformed")
    return parsed


def _source_id(value: Any) -> str:
    candidate = str(value)
    if not is_opaque_source_coordinate(candidate):
        raise StateConflictError("saved review session identity is unsafe")
    return candidate


def _json_tuple(value: Any, *, kind: str) -> tuple[Any, ...]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as error:
        raise StateConflictError(f"saved review {kind} evidence is malformed") from error
    if not isinstance(parsed, list):
        raise StateConflictError(f"saved review {kind} evidence is malformed")
    return tuple(parsed)


class ReviewStateStore:
    """Review-specific facade over the importer's locked private state database."""

    def __init__(self, path: Path) -> None:
        self._state = StateStore(path)

    @property
    def _db(self) -> Any:
        return self._state._db

    def _commit(self) -> None:
        self._state._after_write()

    def close(self) -> None:
        self._state.close()

    def __enter__(self) -> ReviewStateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _plan(row: Any) -> ReviewPlan:
        since = _timestamp(row["since_utc"], label="plan start")
        until = _timestamp(row["until_utc"], label="plan end")
        if since >= until:
            raise StateConflictError("saved review plan window is malformed")
        return ReviewPlan(
            plan_id=str(row["plan_id"]),
            project=str(row["project"]),
            source_principal_sha256=str(row["source_principal_sha256"]),
            since_utc=since,
            until_utc=until,
            timezone_name=str(row["timezone_name"]),
            selector=str(row["selector"]),
            universe_sha256=str(row["universe_sha256"]),
            status=str(row["status"]),
            discovered_count=int(row["discovered_count"]),
            eligible_count=int(row["eligible_count"]),
            deferred_count=int(row["deferred_count"]),
            invalid_count=int(row["invalid_count"]),
            selected_count=int(row["selected_count"]),
            last_error_code=str(row["last_error_code"]),
        )

    @staticmethod
    def _session(row: Any) -> ReviewPlanSession:
        return ReviewPlanSession(
            plan_id=str(row["plan_id"]),
            ordinal=int(row["ordinal"]),
            session_id=_source_id(row["session_id"]),
            started_at=_timestamp(row["started_at"], label="session start"),
            last_activity_at=_timestamp(row["last_activity_at"], label="session activity"),
            status=str(row["status"]),
        )

    @staticmethod
    def _certificate(row: Any) -> ReviewTurnCertificate:
        return ReviewTurnCertificate(
            plan_id=str(row["plan_id"]),
            session_id=_source_id(row["session_id"]),
            ordinal=int(row["ordinal"]),
            turn_key=str(row["turn_key"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            manifest_sha256=str(row["manifest_sha256"]),
            index_sha256=str(row["index_sha256"]),
            logical_key=str(row["logical_key"]),
            preview_signature=str(row["preview_signature"]),
            started_at=_timestamp(row["started_at"], label="turn start"),
            ended_at=_timestamp(row["ended_at"], label="turn end"),
            manifest_bytes=int(row["manifest_bytes"]),
            chunk_count=int(row["chunk_count"]),
            max_chunk_bytes=int(row["max_chunk_bytes"]),
            index_bytes=int(row["index_bytes"]),
            atif_schema_version=str(row["atif_schema_version"]),
        )

    @staticmethod
    def _cohort(row: Any) -> ReviewCohort:
        return ReviewCohort(
            cohort_id=str(row["cohort_id"]),
            plan_id=str(row["plan_id"]),
            ordinal=int(row["ordinal"]),
            status=str(row["status"]),
            session_count=int(row["session_count"]),
            visible_turns=int(row["visible_turns"]),
            skipped_turns=int(row["skipped_turns"]),
            conflicted_turns=int(row["conflicted_turns"]),
            failed_items=int(row["failed_items"]),
            last_error_code=str(row["last_error_code"]),
        )

    @staticmethod
    def _ledger(row: Any) -> ReviewLedgerTurn:
        refs = _json_tuple(row["chunk_refs_json"], kind="chunk reference")
        hashes = _json_tuple(row["chunk_hashes_json"], kind="chunk hash")
        sizes = _json_tuple(row["chunk_sizes_json"], kind="chunk size")
        if not all(isinstance(item, str) and _REFERENCE.fullmatch(item) for item in refs):
            raise StateConflictError("saved review chunk references are malformed")
        if not all(isinstance(item, str) and _SHA256.fullmatch(item) for item in hashes):
            raise StateConflictError("saved review chunk hashes are malformed")
        if not all(type(item) is int and item > 0 for item in sizes):
            raise StateConflictError("saved review chunk sizes are malformed")
        status = str(row["status"])
        chunk_count = int(row["chunk_count"])
        index_ref = str(row["index_ref"])
        index_sha256 = str(row["index_sha256"])
        index_size = int(row["index_size"])
        evidence_lengths = {len(refs), len(hashes), len(sizes)}
        if status in {"objects_verified", "root_submitting", "visible", "uncertain"}:
            if (
                evidence_lengths != {chunk_count}
                or not _REFERENCE.fullmatch(index_ref)
                or not _SHA256.fullmatch(index_sha256)
                or index_size <= 0
            ):
                raise StateConflictError("saved review object evidence is incomplete")
        elif status == "conflict":
            has_empty_index = not index_ref and not index_sha256 and index_size == 0
            has_full_index = bool(
                _REFERENCE.fullmatch(index_ref)
                and _SHA256.fullmatch(index_sha256)
                and index_size > 0
            )
            if (
                evidence_lengths not in ({0}, {chunk_count})
                or (evidence_lengths == {0} and not has_empty_index)
                or (evidence_lengths == {chunk_count} and not has_full_index)
            ):
                raise StateConflictError("saved review conflict evidence is inconsistent")
        elif evidence_lengths != {0} or index_ref or index_sha256 or index_size:
            raise StateConflictError("saved review turn has premature object evidence")
        return ReviewLedgerTurn(
            project=str(row["project"]),
            session_id=_source_id(row["session_id"]),
            turn_key=str(row["turn_key"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            manifest_sha256=str(row["manifest_sha256"]),
            logical_key=str(row["logical_key"]),
            preview_signature=str(row["preview_signature"]),
            manifest_bytes=int(row["manifest_bytes"]),
            chunk_count=chunk_count,
            status=status,
            chunk_refs=tuple(str(item) for item in refs),
            chunk_hashes=tuple(str(item) for item in hashes),
            chunk_sizes=tuple(int(item) for item in sizes),
            index_ref=index_ref,
            index_sha256=index_sha256,
            index_size=index_size,
            trace_id=str(row["trace_id"]),
            root_span_id=str(row["root_span_id"]),
            error_code=str(row["error_code"]),
            revision=int(row["revision"]),
        )

    def resolve_plan(self, reference: str) -> ReviewPlan | None:
        if not re.fullmatch(r"[0-9a-f]{12,64}", reference):
            raise StateConflictError("review plan reference is malformed")
        rows = self._db.execute(
            """
            SELECT * FROM review_plans
            WHERE substr(plan_id, 1, length(?)) = ?
            ORDER BY plan_id LIMIT 2
            """,
            (reference, reference),
        ).fetchall()
        if len(rows) > 1:
            raise StateConflictError("review plan alias is ambiguous")
        return None if not rows else self._plan(rows[0])

    def get_sessions(self, plan_id: str) -> list[ReviewPlanSession]:
        rows = self._db.execute(
            "SELECT * FROM review_plan_sessions WHERE plan_id = ? ORDER BY ordinal",
            (plan_id,),
        ).fetchall()
        result = [self._session(row) for row in rows]
        if any(item.ordinal != ordinal for ordinal, item in enumerate(result)):
            raise StateConflictError("saved review session ordering is malformed")
        return result

    def get_filters(self, plan_id: str) -> list[tuple[str, str]]:
        rows = self._db.execute(
            """
            SELECT filter_kind, filter_value FROM review_plan_filters
            WHERE plan_id = ? ORDER BY filter_kind, ordinal
            """,
            (plan_id,),
        ).fetchall()
        return [(str(row["filter_kind"]), str(row["filter_value"])) for row in rows]

    def get_turns(
        self,
        plan_id: str,
        *,
        session_ids: set[str] | None = None,
    ) -> list[ReviewTurnCertificate]:
        rows = self._db.execute(
            """
            SELECT turn.* FROM review_plan_turns AS turn
            JOIN review_plan_sessions AS session
              ON session.plan_id = turn.plan_id AND session.session_id = turn.session_id
            WHERE turn.plan_id = ?
            ORDER BY session.ordinal, turn.ordinal
            """,
            (plan_id,),
        ).fetchall()
        result = [self._certificate(row) for row in rows]
        if session_ids is not None:
            result = [item for item in result if item.session_id in session_ids]
        return result

    def create_plan(
        self,
        *,
        plan: ReviewPlan,
        sessions: list[tuple[str, datetime, datetime]],
        filters: list[tuple[str, str]],
        turns: list[ReviewTurnCertificate],
    ) -> ReviewPlan:
        if not all(
            _SHA256.fullmatch(value)
            for value in (plan.plan_id, plan.source_principal_sha256, plan.universe_sha256)
        ):
            raise StateConflictError("review plan identity is malformed")
        if plan.status not in {"planned", "completed"} or plan.selector not in {
            "backlog",
            "canary",
        }:
            raise StateConflictError("review plan state is malformed")
        if plan.since_utc >= plan.until_utc or plan.selected_count != len(sessions):
            raise StateConflictError("review plan membership is inconsistent")
        if len({item[0] for item in sessions}) != len(sessions):
            raise StateConflictError("review plan contains duplicate sessions")
        if any(not is_opaque_source_coordinate(item[0]) for item in sessions):
            raise StateConflictError("review plan contains an unsafe session identity")
        if filters != sorted(set(filters)):
            raise StateConflictError("review plan filters are not canonical")
        sealed_filters = review_filter_summary(filters)
        session_ids = {item[0] for item in sessions}
        if any(
            item.plan_id != plan.plan_id
            or item.session_id not in session_ids
            or not all(
                _SHA256.fullmatch(value)
                for value in (
                    item.source_payload_sha256,
                    item.manifest_sha256,
                    item.index_sha256,
                    item.logical_key,
                    item.preview_signature,
                )
            )
            or not 1 <= item.chunk_count <= 64
            or not 1 <= item.max_chunk_bytes <= 8 * 1024 * 1024
            or item.manifest_bytes <= 0
            or item.started_at > item.ended_at
            or item.index_bytes <= 0
            for item in turns
        ):
            raise StateConflictError("review plan contains an invalid turn certificate")
        expected_order = [
            item
            for session_id, _started, _activity in sessions
            for item in sorted(
                (candidate for candidate in turns if candidate.session_id == session_id),
                key=lambda candidate: candidate.ordinal,
            )
        ]
        if expected_order != turns or any(
            item.ordinal != ordinal
            for session_id, _started, _activity in sessions
            for ordinal, item in enumerate(
                candidate for candidate in turns if candidate.session_id == session_id
            )
        ):
            raise StateConflictError("review plan turn ordering is not canonical")

        existing = self.resolve_plan(plan.plan_id)
        if existing is not None:
            expected_plan_identity = (
                plan.plan_id,
                plan.project,
                plan.source_principal_sha256,
                plan.since_utc,
                plan.until_utc,
                plan.timezone_name,
                plan.selector,
                plan.universe_sha256,
                plan.discovered_count,
                plan.eligible_count,
                plan.deferred_count,
                plan.invalid_count,
                plan.selected_count,
            )
            saved_plan_identity = (
                existing.plan_id,
                existing.project,
                existing.source_principal_sha256,
                existing.since_utc,
                existing.until_utc,
                existing.timezone_name,
                existing.selector,
                existing.universe_sha256,
                existing.discovered_count,
                existing.eligible_count,
                existing.deferred_count,
                existing.invalid_count,
                existing.selected_count,
            )
            saved_sessions = self.get_sessions(plan.plan_id)
            expected_sessions = [
                (ordinal, session_id, started, activity)
                for ordinal, (session_id, started, activity) in enumerate(sessions)
            ]
            saved_session_identities = [
                (item.ordinal, item.session_id, item.started_at, item.last_activity_at)
                for item in saved_sessions
            ]
            if (
                saved_plan_identity != expected_plan_identity
                or saved_session_identities != expected_sessions
                or self.get_filters(plan.plan_id) != sealed_filters
                or self.get_turns(plan.plan_id) != turns
            ):
                raise StateConflictError("review plan ID collided with different evidence")
            return existing

        now = isoformat_z(datetime.now(UTC))
        initial_status = "completed" if not sessions else "planned"
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO review_plans (
                    plan_id, project, source_principal_sha256, since_utc, until_utc,
                    timezone_name, selector, universe_sha256, status, discovered_count,
                    eligible_count, deferred_count, invalid_count, selected_count,
                    created_at, updated_at, completed_at, last_error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
                """,
                (
                    plan.plan_id,
                    plan.project,
                    plan.source_principal_sha256,
                    isoformat_z(plan.since_utc),
                    isoformat_z(plan.until_utc),
                    plan.timezone_name,
                    plan.selector,
                    plan.universe_sha256,
                    initial_status,
                    plan.discovered_count,
                    plan.eligible_count,
                    plan.deferred_count,
                    plan.invalid_count,
                    plan.selected_count,
                    now,
                    now,
                    now if not sessions else None,
                ),
            )
            self._db.executemany(
                """
                INSERT INTO review_plan_sessions (
                    plan_id, ordinal, session_id, started_at, last_activity_at, status, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                [
                    (
                        plan.plan_id,
                        ordinal,
                        session_id,
                        isoformat_z(started),
                        isoformat_z(activity),
                        now,
                    )
                    for ordinal, (session_id, started, activity) in enumerate(sessions)
                ],
            )
            ordinals: dict[str, int] = {}
            filter_rows: list[tuple[str, str, int, str]] = []
            for kind, value in sealed_filters:
                ordinal = ordinals.get(kind, 0)
                filter_rows.append((plan.plan_id, kind, ordinal, value))
                ordinals[kind] = ordinal + 1
            self._db.executemany(
                """
                INSERT INTO review_plan_filters (
                    plan_id, filter_kind, ordinal, filter_value
                ) VALUES (?, ?, ?, ?)
                """,
                filter_rows,
            )
            self._db.executemany(
                """
                INSERT INTO review_plan_turns (
                    plan_id, session_id, ordinal, turn_key, source_payload_sha256,
                    manifest_sha256, index_sha256, logical_key, preview_signature,
                    started_at, ended_at, manifest_bytes, chunk_count, max_chunk_bytes, index_bytes,
                    atif_schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        item.plan_id,
                        item.session_id,
                        item.ordinal,
                        item.turn_key,
                        item.source_payload_sha256,
                        item.manifest_sha256,
                        item.index_sha256,
                        item.logical_key,
                        item.preview_signature,
                        isoformat_z(item.started_at),
                        isoformat_z(item.ended_at),
                        item.manifest_bytes,
                        item.chunk_count,
                        item.max_chunk_bytes,
                        item.index_bytes,
                        item.atif_schema_version,
                    )
                    for item in turns
                ],
            )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        created = self.resolve_plan(plan.plan_id)
        if created is None:  # pragma: no cover - guarded by the transaction.
            raise StateConflictError("review plan was not stored")
        return created

    def get_or_create_cohort(self, plan_id: str, max_sessions: int) -> ReviewCohort | None:
        if not 1 <= max_sessions <= 10_000:
            raise ValueError("--max-sessions must be between 1 and 10000")
        active = self._db.execute(
            """
            SELECT * FROM review_cohorts WHERE plan_id = ? AND status != 'completed'
            ORDER BY ordinal LIMIT 2
            """,
            (plan_id,),
        ).fetchall()
        if len(active) > 1:
            raise StateConflictError("review plan has multiple unfinished cohorts")
        if active:
            return self._cohort(active[0])
        pending = self._db.execute(
            """
            SELECT * FROM review_plan_sessions
            WHERE plan_id = ? AND status = 'pending' ORDER BY ordinal LIMIT ?
            """,
            (plan_id, max_sessions),
        ).fetchall()
        if not pending:
            return None
        cohort_ordinal = int(
            self._db.execute(
                "SELECT COUNT(*) FROM review_cohorts WHERE plan_id = ?", (plan_id,)
            ).fetchone()[0]
        )
        cohort_id = sha256_json(
            {
                "schema": "hivemind-review-cohort-v1",
                "plan_id": plan_id,
                "ordinal": cohort_ordinal,
                "sessions": [
                    {
                        "ordinal": int(row["ordinal"]),
                        "session_id": str(row["session_id"]),
                        "last_activity_at": str(row["last_activity_at"]),
                    }
                    for row in pending
                ],
            }
        )
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO review_cohorts (
                    cohort_id, plan_id, ordinal, status, session_count, created_at, updated_at
                ) VALUES (?, ?, ?, 'planned', ?, ?, ?)
                """,
                (cohort_id, plan_id, cohort_ordinal, len(pending), now, now),
            )
            self._db.executemany(
                """
                INSERT INTO review_cohort_sessions (cohort_id, plan_id, ordinal, session_id)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (cohort_id, plan_id, ordinal, str(row["session_id"]))
                    for ordinal, row in enumerate(pending)
                ],
            )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        return self.get_cohort(cohort_id)

    def get_cohort(self, cohort_id: str) -> ReviewCohort:
        row = self._db.execute(
            "SELECT * FROM review_cohorts WHERE cohort_id = ?", (cohort_id,)
        ).fetchone()
        if row is None:
            raise StateConflictError("review cohort was not found")
        return self._cohort(row)

    def get_cohort_sessions(self, cohort_id: str) -> list[ReviewPlanSession]:
        rows = self._db.execute(
            """
            SELECT session.* FROM review_cohort_sessions AS member
            JOIN review_plan_sessions AS session
              ON session.plan_id = member.plan_id AND session.session_id = member.session_id
            WHERE member.cohort_id = ? ORDER BY member.ordinal
            """,
            (cohort_id,),
        ).fetchall()
        return [self._session(row) for row in rows]

    def begin_cohort(self, cohort: ReviewCohort) -> ReviewCohort:
        if cohort.status == "blocked":
            raise StateConflictError("review cohort is blocked; reconcile it before applying")
        if cohort.status == "completed":
            return cohort
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                "UPDATE review_cohorts SET status = 'applying', updated_at = ? WHERE cohort_id = ?",
                (now, cohort.cohort_id),
            )
            self._db.execute(
                "UPDATE review_plans SET status = 'applying', updated_at = ? WHERE plan_id = ?",
                (now, cohort.plan_id),
            )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        return self.get_cohort(cohort.cohort_id)

    def finish_cohort(
        self,
        cohort: ReviewCohort,
        *,
        success: bool,
        visible_turns: int,
        skipped_turns: int,
        conflicted_turns: int,
        failed_items: int,
        error_code: str = "",
    ) -> ReviewPlan:
        self._validate_error_code(error_code)
        now = isoformat_z(datetime.now(UTC))
        status = "completed" if success else "blocked"
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                UPDATE review_cohorts
                SET status = ?, visible_turns = ?, skipped_turns = ?,
                    conflicted_turns = ?, failed_items = ?, last_error_code = ?,
                    updated_at = ?, completed_at = ?
                WHERE cohort_id = ? AND status = 'applying'
                """,
                (
                    status,
                    visible_turns,
                    skipped_turns,
                    conflicted_turns,
                    failed_items,
                    error_code,
                    now,
                    now if success else None,
                    cohort.cohort_id,
                ),
            )
            if success:
                self._db.execute(
                    """
                    UPDATE review_plan_sessions SET status = 'completed', updated_at = ?
                    WHERE plan_id = ? AND session_id IN (
                        SELECT session_id FROM review_cohort_sessions WHERE cohort_id = ?
                    )
                    """,
                    (now, cohort.plan_id, cohort.cohort_id),
                )
                remaining = int(
                    self._db.execute(
                        """
                        SELECT COUNT(*) FROM review_plan_sessions
                        WHERE plan_id = ? AND status = 'pending'
                        """,
                        (cohort.plan_id,),
                    ).fetchone()[0]
                )
                plan_status = "completed" if remaining == 0 else "planned"
                self._db.execute(
                    """
                    UPDATE review_plans SET status = ?, updated_at = ?, completed_at = ?,
                        last_error_code = '' WHERE plan_id = ?
                    """,
                    (plan_status, now, now if plan_status == "completed" else None, cohort.plan_id),
                )
            else:
                self._db.execute(
                    """
                    UPDATE review_plan_sessions SET status = 'blocked', updated_at = ?
                    WHERE plan_id = ? AND session_id IN (
                        SELECT session_id FROM review_cohort_sessions WHERE cohort_id = ?
                    )
                    """,
                    (now, cohort.plan_id, cohort.cohort_id),
                )
                self._db.execute(
                    """
                    UPDATE review_plans SET status = 'blocked', updated_at = ?,
                        last_error_code = ? WHERE plan_id = ?
                    """,
                    (now, error_code, cohort.plan_id),
                )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        plan = self.resolve_plan(cohort.plan_id)
        if plan is None:  # pragma: no cover
            raise StateConflictError("review plan disappeared")
        return plan

    def resume_after_reconcile(self, plan_id: str) -> None:
        unresolved = int(
            self._db.execute(
                """
                SELECT COUNT(*) FROM review_plan_turns AS planned
                JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
                JOIN review_turn_ledger AS ledger
                  ON ledger.project = plan.project
                 AND ledger.session_id = planned.session_id
                 AND ledger.turn_key = planned.turn_key
                WHERE planned.plan_id = ? AND ledger.status IN ('uncertain', 'conflict')
                """,
                (plan_id,),
            ).fetchone()[0]
        )
        if unresolved:
            return
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                "UPDATE review_cohorts SET status = 'planned', updated_at = ?, "
                "last_error_code = '' "
                "WHERE plan_id = ? AND status = 'blocked'",
                (now, plan_id),
            )
            self._db.execute(
                "UPDATE review_plan_sessions SET status = 'pending', updated_at = ? "
                "WHERE plan_id = ? AND status = 'blocked'",
                (now, plan_id),
            )
            self._db.execute(
                "UPDATE review_plans SET status = 'planned', updated_at = ?, last_error_code = '' "
                "WHERE plan_id = ? AND status = 'blocked'",
                (now, plan_id),
            )
            self._commit()
        except Exception:
            self._db.rollback()
            raise

    def get_ledger(self, project: str, session_id: str, turn_key: str) -> ReviewLedgerTurn | None:
        row = self._db.execute(
            """
            SELECT * FROM review_turn_ledger
            WHERE project = ? AND session_id = ? AND turn_key = ?
            """,
            (project, session_id, turn_key),
        ).fetchone()
        return None if row is None else self._ledger(row)

    def ensure_ledger(
        self,
        project: str,
        certificate: ReviewTurnCertificate,
    ) -> tuple[ReviewLedgerTurn, str]:
        if not is_opaque_source_coordinate(certificate.session_id):
            raise StateConflictError("review ledger contains an unsafe session identity")
        existing = self.get_ledger(project, certificate.session_id, certificate.turn_key)
        identity = (
            certificate.source_payload_sha256,
            certificate.manifest_sha256,
            certificate.logical_key,
            certificate.preview_signature,
            certificate.manifest_bytes,
            certificate.chunk_count,
        )
        if existing is not None:
            if existing.source_payload_sha256 != certificate.source_payload_sha256:
                if existing.status != "conflict":
                    self.mark_conflict(existing, "changed_history")
                conflicted = self.get_ledger(project, certificate.session_id, certificate.turn_key)
                assert conflicted is not None
                return conflicted, "conflict"
            saved = (
                existing.source_payload_sha256,
                existing.manifest_sha256,
                existing.logical_key,
                existing.preview_signature,
                existing.manifest_bytes,
                existing.chunk_count,
            )
            if saved != identity:
                # The already-visible object remains the immutable record when
                # only session-wide metadata changed during a normal append.
                # Before visibility, a different manifest is ambiguous because
                # immutable object publication may already have started.
                if existing.status == "visible":
                    return existing, "same_source_visible"
                if existing.status != "conflict":
                    self.mark_conflict(existing, "inflight_manifest_changed")
                conflicted = self.get_ledger(project, certificate.session_id, certificate.turn_key)
                assert conflicted is not None
                return conflicted, "conflict"
            return existing, "same"
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                """
                INSERT INTO review_turn_ledger (
                    project, session_id, turn_key, source_payload_sha256,
                    manifest_sha256, logical_key, preview_signature, manifest_bytes,
                    chunk_count, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?)
                """,
                (
                    project,
                    certificate.session_id,
                    certificate.turn_key,
                    certificate.source_payload_sha256,
                    certificate.manifest_sha256,
                    certificate.logical_key,
                    certificate.preview_signature,
                    certificate.manifest_bytes,
                    certificate.chunk_count,
                    now,
                    now,
                ),
            )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        created = self.get_ledger(project, certificate.session_id, certificate.turn_key)
        assert created is not None
        return created, "new"

    @staticmethod
    def _validate_error_code(error_code: str) -> None:
        if error_code and not _ERROR_CODE.fullmatch(error_code):
            raise ValueError("review error codes must be bounded content-free identifiers")

    def _transition(
        self,
        turn: ReviewLedgerTurn,
        status: str,
        *,
        fields: dict[str, Any] | None = None,
        error_code: str = "",
    ) -> ReviewLedgerTurn:
        if status not in _LEDGER_STATES:
            raise ValueError("unsupported review turn state")
        self._validate_error_code(error_code)
        assignments = ["status = ?", "error_code = ?", "updated_at = ?", "revision = revision + 1"]
        values: list[Any] = [status, error_code, isoformat_z(datetime.now(UTC))]
        resolved_fields = dict(fields or {})
        if status == "conflict":
            resolved_fields["visible_at"] = None
        for name, value in resolved_fields.items():
            if name not in {
                "chunk_refs_json",
                "chunk_hashes_json",
                "chunk_sizes_json",
                "index_ref",
                "index_sha256",
                "index_size",
                "trace_id",
                "root_span_id",
                "visible_at",
            }:
                raise ValueError("unsupported review evidence field")
            assignments.append(f"{name} = ?")
            values.append(value)
        values.extend([turn.project, turn.session_id, turn.turn_key, turn.revision, turn.status])
        try:
            self._db.execute("BEGIN IMMEDIATE")
            cursor = self._db.execute(
                f"""
                UPDATE review_turn_ledger SET {", ".join(assignments)}
                WHERE project = ? AND session_id = ? AND turn_key = ?
                  AND revision = ? AND status = ?
                """,
                values,
            )
            if cursor.rowcount != 1:
                raise StateConflictError("review turn changed before its state transition")
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        updated = self.get_ledger(turn.project, turn.session_id, turn.turn_key)
        assert updated is not None
        return updated

    def mark_objects_publishing(self, turn: ReviewLedgerTurn) -> ReviewLedgerTurn:
        if turn.status == "objects_publishing":
            return turn
        return self._transition(turn, "objects_publishing")

    def mark_objects_verified(
        self,
        turn: ReviewLedgerTurn,
        *,
        chunk_refs: tuple[str, ...],
        chunk_hashes: tuple[str, ...],
        chunk_sizes: tuple[int, ...],
        index_ref: str,
        index_sha256: str,
        index_size: int,
    ) -> ReviewLedgerTurn:
        if not (
            len(chunk_refs) == len(chunk_hashes) == len(chunk_sizes) == turn.chunk_count
            and all(_valid_review_reference(item) for item in chunk_refs)
            and all(_SHA256.fullmatch(item) for item in chunk_hashes)
            and all(type(item) is int and item > 0 for item in chunk_sizes)
            and all(
                digest in reference
                for reference, digest in zip(chunk_refs, chunk_hashes, strict=True)
            )
            and _valid_review_reference(index_ref)
            and _SHA256.fullmatch(index_sha256)
            and index_sha256 in index_ref
            and type(index_size) is int
            and index_size > 0
        ):
            raise StateConflictError("review object publication returned invalid evidence")
        fields = {
            "chunk_refs_json": canonical_json(list(chunk_refs)),
            "chunk_hashes_json": canonical_json(list(chunk_hashes)),
            "chunk_sizes_json": canonical_json(list(chunk_sizes)),
            "index_ref": index_ref,
            "index_sha256": index_sha256,
            "index_size": index_size,
        }
        if turn.status == "objects_verified":
            expected = (
                chunk_refs,
                chunk_hashes,
                chunk_sizes,
                index_ref,
                index_sha256,
                index_size,
            )
            actual = (
                turn.chunk_refs,
                turn.chunk_hashes,
                turn.chunk_sizes,
                turn.index_ref,
                turn.index_sha256,
                turn.index_size,
            )
            if actual != expected:
                return self.mark_conflict(turn, "object_evidence_mismatch")
            return turn
        return self._transition(turn, "objects_verified", fields=fields)

    def mark_root_submitting(self, turn: ReviewLedgerTurn) -> ReviewLedgerTurn:
        return self._transition(turn, "root_submitting")

    def mark_visible(
        self,
        turn: ReviewLedgerTurn,
        *,
        trace_id: str,
        root_span_id: str,
    ) -> ReviewLedgerTurn:
        if not valid_review_trace_id(trace_id) or not valid_review_span_id(root_span_id):
            raise StateConflictError("review root returned invalid identity evidence")
        if turn.status == "visible":
            if (turn.trace_id, turn.root_span_id) != (trace_id, root_span_id):
                return self.mark_conflict(turn, "root_identity_mismatch")
            return turn
        return self._transition(
            turn,
            "visible",
            fields={
                "trace_id": trace_id,
                "root_span_id": root_span_id,
                "visible_at": isoformat_z(datetime.now(UTC)),
            },
        )

    def mark_uncertain(self, turn: ReviewLedgerTurn, error_code: str) -> ReviewLedgerTurn:
        if turn.status == "uncertain":
            return turn
        return self._transition(turn, "uncertain", error_code=error_code)

    def mark_conflict(self, turn: ReviewLedgerTurn, error_code: str) -> ReviewLedgerTurn:
        if turn.status == "conflict":
            return turn
        return self._transition(turn, "conflict", error_code=error_code)

    def reconcilable_turns(self, plan_id: str) -> list[ReviewLedgerTurn]:
        rows = self._db.execute(
            """
            SELECT ledger.* FROM review_plan_turns AS planned
            JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
            JOIN review_turn_ledger AS ledger
              ON ledger.project = plan.project
             AND ledger.session_id = planned.session_id
             AND ledger.turn_key = planned.turn_key
            WHERE planned.plan_id = ? AND ledger.status IN ('root_submitting', 'uncertain')
            ORDER BY planned.session_id, planned.ordinal
            """,
            (plan_id,),
        ).fetchall()
        return [self._ledger(row) for row in rows]

    def progress(self, plan_id: str) -> tuple[int, int]:
        rows = self._db.execute(
            """
            SELECT status, COUNT(*) AS count FROM review_plan_sessions
            WHERE plan_id = ? GROUP BY status
            """,
            (plan_id,),
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        return counts.get("completed", 0), counts.get("pending", 0) + counts.get("blocked", 0)

    def status(self, project: str | None = None) -> ReviewStatus:
        plan_where = "" if project is None else " WHERE project = ?"
        args: tuple[Any, ...] = () if project is None else (project,)
        plans = int(
            self._db.execute(f"SELECT COUNT(*) FROM review_plans{plan_where}", args).fetchone()[0]
        )
        session_rows = self._db.execute(
            """
            SELECT session.status, COUNT(*) AS count FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            """
            + (" WHERE plan.project = ?" if project is not None else "")
            + " GROUP BY session.status",
            args,
        ).fetchall()
        sessions = {str(row["status"]): int(row["count"]) for row in session_rows}
        turn_rows = self._db.execute(
            "SELECT status, COUNT(*) AS count FROM review_turn_ledger"
            + (" WHERE project = ?" if project is not None else "")
            + " GROUP BY status",
            args,
        ).fetchall()
        turns = {str(row["status"]): int(row["count"]) for row in turn_rows}
        return ReviewStatus(
            plans=plans,
            queued_sessions=sessions.get("pending", 0) + sessions.get("blocked", 0),
            completed_sessions=sessions.get("completed", 0),
            planned_turns=turns.get("planned", 0),
            objects_publishing=turns.get("objects_publishing", 0),
            objects_verified=turns.get("objects_verified", 0),
            root_submitting=turns.get("root_submitting", 0),
            visible=turns.get("visible", 0),
            uncertain=turns.get("uncertain", 0),
            conflicted=turns.get("conflict", 0),
        )
