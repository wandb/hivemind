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
_IMPORTER_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]{1,32})?$")
_MAX_PLAN_SUCCESSOR_DEPTH = 256
_MAX_PRESEAL_ATTEMPTS = 65535
_REVIEW_PROJECT = "wandb/hivemind-chats-review"
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
REVIEW_SOURCE_SCOPE_SHA256 = hashlib.sha256(
    b"hivemind-review-authenticated-session-certificates-v1"
).hexdigest()
REVIEW_PRESEAL_FAILURE_CODES = frozenset(
    {
        "atif_schema",
        "manifest_size",
        "mapping_invalid",
        "preparation_timeout",
        "redaction_failed",
        "source_changed",
        "source_serialization",
        "source_unstable",
    }
)


@dataclass(frozen=True)
class ReviewPlan:
    plan_id: str
    project: str
    source_scope_sha256: str
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
class ReviewRetiredTurnEvidence:
    plan_id: str
    logical_key: str
    proof_sha256: str


@dataclass(frozen=True)
class ReviewPresealFailure:
    project: str
    session_id: str
    started_at: datetime
    last_activity_at: datetime
    first_error_code: str
    last_error_code: str
    attempt_count: int
    first_attempt_at: datetime
    last_attempt_at: datetime


@dataclass(frozen=True)
class ReviewRetryAttempt:
    attempt_count: int
    last_attempt_at: datetime


@dataclass(frozen=True)
class ReviewStatus:
    plans: int
    queued_sessions: int
    completed_sessions: int
    preseal_retries: int
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


def review_successor_plan_id(
    predecessor_plan_id: str,
    *,
    outcome: str,
    resolution_proof_sha256: str,
) -> str:
    """Derive the next immutable attempt from one terminal predecessor."""
    if not _SHA256.fullmatch(predecessor_plan_id) or not _SHA256.fullmatch(resolution_proof_sha256):
        raise StateConflictError("review successor evidence is malformed")
    if outcome not in {"retired", "revalidated"}:
        raise StateConflictError("review successor outcome is malformed")
    value = (
        "hivemind-review-plan-successor-v1\0"
        f"{outcome}\0{predecessor_plan_id}\0{resolution_proof_sha256}"
    )
    return hashlib.sha256(value.encode()).hexdigest()


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


def _canonical_saved_timestamp(value: Any, *, label: str) -> datetime:
    """Decode only the UTC representation emitted by this importer."""
    if not isinstance(value, str):
        raise StateConflictError(f"saved review {label} is malformed")
    parsed = _timestamp(value, label=label)
    if isoformat_z(parsed) != value:
        raise StateConflictError(f"saved review {label} is not canonical UTC")
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
        source_scope_sha256 = str(row["source_principal_sha256"])
        if source_scope_sha256 != REVIEW_SOURCE_SCOPE_SHA256:
            raise StateConflictError("saved review source scope is malformed")
        return ReviewPlan(
            plan_id=str(row["plan_id"]),
            project=str(row["project"]),
            source_scope_sha256=source_scope_sha256,
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
    def _preseal_failure(row: Any) -> ReviewPresealFailure:
        project = str(row["project"])
        if project != _REVIEW_PROJECT:
            raise StateConflictError("saved review pre-seal project is malformed")
        started_at = _canonical_saved_timestamp(row["started_at"], label="pre-seal session start")
        last_activity_at = _canonical_saved_timestamp(
            row["last_activity_at"], label="pre-seal session activity"
        )
        first_attempt_at = _canonical_saved_timestamp(
            row["first_attempt_at"], label="first pre-seal attempt time"
        )
        last_attempt_at = _canonical_saved_timestamp(
            row["last_attempt_at"], label="pre-seal attempt time"
        )
        first_error_code = str(row["first_error_code"])
        last_error_code = str(row["last_error_code"])
        attempt_count = int(row["attempt_count"])
        if (
            started_at > last_activity_at
            or first_attempt_at > last_attempt_at
            or first_error_code not in REVIEW_PRESEAL_FAILURE_CODES
            or last_error_code not in REVIEW_PRESEAL_FAILURE_CODES
            or not 1 <= attempt_count <= _MAX_PRESEAL_ATTEMPTS
        ):
            raise StateConflictError("saved review pre-seal failure is malformed")
        return ReviewPresealFailure(
            project=project,
            session_id=_source_id(row["session_id"]),
            started_at=started_at,
            last_activity_at=last_activity_at,
            first_error_code=first_error_code,
            last_error_code=last_error_code,
            attempt_count=attempt_count,
            first_attempt_at=first_attempt_at,
            last_attempt_at=last_attempt_at,
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

    def is_plan_retired(self, plan_id: str) -> bool:
        """Return whether an exact sealed plan has an immutable retirement record."""
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        return (
            self._db.execute(
                "SELECT 1 FROM review_plan_retirements WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
            is not None
        )

    def is_plan_revalidated(self, plan_id: str) -> bool:
        """Return whether a transient preflight drift was immutably revalidated."""
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        return (
            self._db.execute(
                "SELECT 1 FROM review_plan_revalidations WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
            is not None
        )

    def is_plan_terminal(self, plan_id: str) -> bool:
        """Return whether a plan attempt has either immutable resolution."""
        return self.is_plan_retired(plan_id) or self.is_plan_revalidated(plan_id)

    def _successor_plan_chain(self, base_plan_id: str) -> tuple[str, ...]:
        if not _SHA256.fullmatch(base_plan_id):
            raise StateConflictError("review plan identity is malformed")
        current = base_plan_id
        chain: list[str] = []
        seen: set[str] = set()
        for _depth in range(_MAX_PLAN_SUCCESSOR_DEPTH):
            if current in seen:
                raise StateConflictError("review successor chain contains a cycle")
            seen.add(current)
            chain.append(current)
            retired = self._db.execute(
                "SELECT * FROM review_plan_retirements WHERE plan_id = ?",
                (current,),
            ).fetchone()
            revalidated = self._db.execute(
                "SELECT * FROM review_plan_revalidations WHERE plan_id = ?",
                (current,),
            ).fetchone()
            if retired is not None and revalidated is not None:
                raise StateConflictError("review plan has contradictory resolution evidence")
            if retired is None and revalidated is None:
                return tuple(chain)
            resolution = retired if retired is not None else revalidated
            assert resolution is not None
            outcome = "retired" if retired is not None else "revalidated"
            expected_reason = (
                "preflight_source_drift" if outcome == "retired" else "transient_preflight_export"
            )
            proof_sha256 = str(resolution["proof_sha256"])
            if (
                str(resolution["reason"]) != expected_reason
                or int(resolution["remote_match_count"]) != 0
                or not _SHA256.fullmatch(proof_sha256)
                or not _IMPORTER_VERSION.fullmatch(str(resolution["importer_version"]))
            ):
                raise StateConflictError("saved review resolution evidence is malformed")
            current = review_successor_plan_id(
                current,
                outcome=outcome,
                resolution_proof_sha256=proof_sha256,
            )
        raise StateConflictError("review successor chain exceeds its safety bound")

    def successor_plan_id(self, base_plan_id: str) -> str:
        """Resolve the deterministic writable identity after terminal attempts."""
        return self._successor_plan_chain(base_plan_id)[-1]

    def plan_id_in_successor_chain(self, base_plan_id: str, plan_id: str) -> bool:
        """Validate a stored current or historical plan against its base certificate."""
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        return plan_id in self._successor_plan_chain(base_plan_id)

    def retired_preflight_evidence(
        self,
        *,
        project: str,
        session_id: str,
        turn_key: str,
    ) -> tuple[ReviewRetiredTurnEvidence, ...]:
        """Return immutable logical-key proofs overlapping a successor turn."""
        safe_session_id = _source_id(session_id)
        rows = self._db.execute(
            """
            SELECT archive.plan_id, archive.logical_key, archive.proof_sha256
            FROM review_preflight_conflict_archive AS archive
            LEFT JOIN review_plan_retirements AS retired
              ON retired.plan_id = archive.plan_id
             AND retired.project = archive.project
             AND retired.proof_sha256 = archive.proof_sha256
            LEFT JOIN review_plan_revalidations AS revalidated
              ON revalidated.plan_id = archive.plan_id
             AND revalidated.project = archive.project
             AND revalidated.proof_sha256 = archive.proof_sha256
            WHERE archive.project = ?
              AND archive.session_id = ?
              AND archive.turn_key = ?
              AND (retired.plan_id IS NOT NULL OR revalidated.plan_id IS NOT NULL)
            ORDER BY COALESCE(retired.retired_at, revalidated.revalidated_at), archive.plan_id
            """,
            (project, safe_session_id, turn_key),
        ).fetchall()
        result: list[ReviewRetiredTurnEvidence] = []
        for row in rows:
            plan_id = str(row["plan_id"])
            logical_key = str(row["logical_key"])
            proof_sha256 = str(row["proof_sha256"])
            if not all(_SHA256.fullmatch(value) for value in (plan_id, logical_key, proof_sha256)):
                raise StateConflictError("saved review retirement evidence is malformed")
            result.append(
                ReviewRetiredTurnEvidence(
                    plan_id=plan_id,
                    logical_key=logical_key,
                    proof_sha256=proof_sha256,
                )
            )
        return tuple(result)

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

    def completed_session_snapshots(
        self,
        project: str,
    ) -> set[tuple[str, datetime, datetime]]:
        """Return exact source revisions already completed in this project."""
        rows = self._db.execute(
            """
            SELECT DISTINCT session.session_id, session.started_at, session.last_activity_at
            FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            WHERE plan.project = ? AND session.status = 'completed'
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = plan.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = plan.plan_id
              )
            """,
            (project,),
        ).fetchall()
        return {
            (
                _source_id(row["session_id"]),
                _timestamp(row["started_at"], label="completed session start"),
                _timestamp(row["last_activity_at"], label="completed session activity"),
            )
            for row in rows
        }

    def terminal_session_snapshots(
        self,
        project: str,
    ) -> set[tuple[str, datetime, datetime]]:
        """Return exact source revisions that already consumed a terminal attempt."""
        rows = self._db.execute(
            """
            SELECT DISTINCT session.session_id, session.started_at, session.last_activity_at
            FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            WHERE plan.project = ?
              AND (
                  EXISTS (
                      SELECT 1 FROM review_plan_retirements AS retired
                      WHERE retired.plan_id = plan.plan_id
                  )
                  OR EXISTS (
                      SELECT 1 FROM review_plan_revalidations AS revalidated
                      WHERE revalidated.plan_id = plan.plan_id
                  )
              )
            """,
            (project,),
        ).fetchall()
        return {
            (
                _source_id(row["session_id"]),
                _timestamp(row["started_at"], label="terminal session start"),
                _timestamp(row["last_activity_at"], label="terminal session activity"),
            )
            for row in rows
        }

    def record_preseal_failure(
        self,
        *,
        project: str,
        session_id: str,
        started_at: datetime,
        last_activity_at: datetime,
        error_code: str,
    ) -> ReviewPresealFailure:
        """Record one recognized, candidate-local preparation rejection.

        The row intentionally contains no exception text, payload digest, title,
        repository, selector, or transcript-derived metadata. The exact source
        revision remains pending; this evidence is used only to schedule fair
        retries behind untouched revisions.
        """
        if project != _REVIEW_PROJECT:
            raise StateConflictError("review pre-seal failures require the fixed private project")
        safe_session_id = _source_id(session_id)
        if started_at.tzinfo is None or last_activity_at.tzinfo is None:
            raise StateConflictError("review pre-seal revision timestamps must be timezone-aware")
        safe_started_at = started_at.astimezone(UTC)
        safe_last_activity_at = last_activity_at.astimezone(UTC)
        if safe_started_at > safe_last_activity_at:
            raise StateConflictError("review pre-seal revision coordinates are malformed")
        if error_code not in REVIEW_PRESEAL_FAILURE_CODES:
            raise StateConflictError("review pre-seal failure code is not allowlisted")

        started_text = isoformat_z(safe_started_at)
        activity_text = isoformat_z(safe_last_activity_at)
        try:
            self._db.execute("BEGIN IMMEDIATE")
            existing_row = self._db.execute(
                """
                SELECT * FROM review_preseal_failures
                WHERE project = ? AND session_id = ?
                  AND started_at = ? AND last_activity_at = ?
                """,
                (project, safe_session_id, started_text, activity_text),
            ).fetchone()
            now = datetime.now(UTC)
            if existing_row is None:
                now_text = isoformat_z(now)
                self._db.execute(
                    """
                    INSERT INTO review_preseal_failures (
                        project, session_id, started_at, last_activity_at,
                        first_error_code, last_error_code, attempt_count,
                        first_attempt_at, last_attempt_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        project,
                        safe_session_id,
                        started_text,
                        activity_text,
                        error_code,
                        error_code,
                        now_text,
                        now_text,
                    ),
                )
            else:
                existing = self._preseal_failure(existing_row)
                monotonic_now = max(now, existing.last_attempt_at)
                self._db.execute(
                    """
                    UPDATE review_preseal_failures
                    SET last_error_code = ?,
                        attempt_count = CASE
                            WHEN attempt_count < ? THEN attempt_count + 1
                            ELSE ?
                        END,
                        last_attempt_at = ?
                    WHERE project = ? AND session_id = ?
                      AND started_at = ? AND last_activity_at = ?
                    """,
                    (
                        error_code,
                        _MAX_PRESEAL_ATTEMPTS,
                        _MAX_PRESEAL_ATTEMPTS,
                        isoformat_z(monotonic_now),
                        project,
                        safe_session_id,
                        started_text,
                        activity_text,
                    ),
                )
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        saved = self._db.execute(
            """
            SELECT * FROM review_preseal_failures
            WHERE project = ? AND session_id = ?
              AND started_at = ? AND last_activity_at = ?
            """,
            (project, safe_session_id, started_text, activity_text),
        ).fetchone()
        if saved is None:  # pragma: no cover - guarded by the transaction.
            raise StateConflictError("review pre-seal failure was not stored")
        return self._preseal_failure(saved)

    def preseal_failures(self, project: str) -> tuple[ReviewPresealFailure, ...]:
        """Return validated content-free preparation retry evidence."""
        if project != _REVIEW_PROJECT:
            raise StateConflictError("review pre-seal failures require the fixed private project")
        rows = self._db.execute(
            """
            SELECT * FROM review_preseal_failures
            WHERE project = ?
            ORDER BY last_attempt_at, session_id, started_at, last_activity_at
            """,
            (project,),
        ).fetchall()
        return tuple(self._preseal_failure(row) for row in rows)

    def retry_session_attempts(
        self,
        project: str,
    ) -> dict[tuple[str, datetime, datetime], ReviewRetryAttempt]:
        """Aggregate all recognized retry attempts by exact source revision."""
        if project != _REVIEW_PROJECT:
            raise StateConflictError("review retry scheduling requires the fixed private project")
        attempts: dict[tuple[str, datetime, datetime], ReviewRetryAttempt] = {}

        def add(
            key: tuple[str, datetime, datetime],
            *,
            count: int,
            attempted_at: datetime,
        ) -> None:
            previous = attempts.get(key)
            if previous is None:
                attempts[key] = ReviewRetryAttempt(
                    attempt_count=min(count, _MAX_PRESEAL_ATTEMPTS),
                    last_attempt_at=attempted_at,
                )
                return
            attempts[key] = ReviewRetryAttempt(
                attempt_count=min(
                    previous.attempt_count + count,
                    _MAX_PRESEAL_ATTEMPTS,
                ),
                last_attempt_at=max(previous.last_attempt_at, attempted_at),
            )

        for failure in self.preseal_failures(project):
            add(
                (failure.session_id, failure.started_at, failure.last_activity_at),
                count=failure.attempt_count,
                attempted_at=failure.last_attempt_at,
            )

        terminal_rows = self._db.execute(
            """
            SELECT session.session_id, session.started_at, session.last_activity_at,
                   retired.retired_at AS attempted_at
            FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            JOIN review_plan_retirements AS retired ON retired.plan_id = plan.plan_id
            WHERE plan.project = ?
            UNION ALL
            SELECT session.session_id, session.started_at, session.last_activity_at,
                   revalidated.revalidated_at AS attempted_at
            FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            JOIN review_plan_revalidations AS revalidated ON revalidated.plan_id = plan.plan_id
            WHERE plan.project = ?
            ORDER BY attempted_at, session_id, started_at, last_activity_at
            """,
            (project, project),
        ).fetchall()
        for row in terminal_rows:
            started_at = _canonical_saved_timestamp(row["started_at"], label="retry session start")
            last_activity_at = _canonical_saved_timestamp(
                row["last_activity_at"], label="retry session activity"
            )
            attempted_at = _canonical_saved_timestamp(
                row["attempted_at"], label="terminal attempt time"
            )
            if started_at > last_activity_at:
                raise StateConflictError("saved review retry revision is malformed")
            add(
                (_source_id(row["session_id"]), started_at, last_activity_at),
                count=1,
                attempted_at=attempted_at,
            )
        return attempts

    def pending_retry_session_attempts(
        self,
        project: str,
    ) -> dict[tuple[str, datetime, datetime], ReviewRetryAttempt]:
        """Return retry evidence not already owned by a nonterminal plan.

        Pre-seal evidence is immutable and therefore remains in the journal
        after an exact revision later seals or completes successfully.  Such a
        revision is no longer queued.  A retired or revalidated plan is a
        terminal attempt, however, so its revision remains eligible for the
        fair retry tier until a later nonterminal plan takes ownership.
        """
        attempts = self.retry_session_attempts(project)
        active_rows = self._db.execute(
            """
            SELECT DISTINCT session.session_id, session.started_at,
                            session.last_activity_at
            FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            WHERE plan.project = ?
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = plan.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = plan.plan_id
              )
            """,
            (project,),
        ).fetchall()
        active_revisions = {
            (
                _source_id(row["session_id"]),
                _timestamp(row["started_at"], label="active retry session start"),
                _timestamp(row["last_activity_at"], label="active retry session activity"),
            )
            for row in active_rows
        }
        return {key: attempt for key, attempt in attempts.items() if key not in active_revisions}

    def unfinished_plan_for_window(
        self,
        *,
        project: str,
        since_utc: datetime,
        until_utc: datetime,
    ) -> ReviewPlan | None:
        rows = self._db.execute(
            """
            SELECT * FROM review_plans
            WHERE project = ? AND since_utc = ? AND until_utc = ? AND status != 'completed'
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = review_plans.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = review_plans.plan_id
              )
            ORDER BY created_at, plan_id LIMIT 2
            """,
            (project, isoformat_z(since_utc), isoformat_z(until_utc)),
        ).fetchall()
        if len(rows) > 1:
            raise StateConflictError("multiple unfinished review plans share one window")
        return None if not rows else self._plan(rows[0])

    def assert_project_writes_unblocked(self, project: str) -> None:
        unresolved = int(
            self._db.execute(
                """
                SELECT COUNT(*) FROM review_turn_ledger
                WHERE project = ? AND status IN ('uncertain', 'conflict')
                """,
                (project,),
            ).fetchone()[0]
        )
        if unresolved:
            raise StateConflictError(
                "review project has unresolved turn evidence; reconcile before later writes"
            )

    def create_plan(
        self,
        *,
        plan: ReviewPlan,
        sessions: list[tuple[str, datetime, datetime]],
        filters: list[tuple[str, str]],
        turns: list[ReviewTurnCertificate],
    ) -> ReviewPlan:
        if (
            not _SHA256.fullmatch(plan.plan_id)
            or plan.source_scope_sha256 != REVIEW_SOURCE_SCOPE_SHA256
            or not _SHA256.fullmatch(plan.universe_sha256)
        ):
            raise StateConflictError("review plan identity is malformed")
        if self.is_plan_terminal(plan.plan_id):
            raise StateConflictError(
                "terminal review plan identity requires a deterministic successor"
            )
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
            or item.logical_key
            != review_logical_key(
                plan.project,
                f"hivemind:{item.session_id}",
                item.turn_key,
            )
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
                plan.source_scope_sha256,
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
                existing.source_scope_sha256,
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
                    plan.source_scope_sha256,
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
        if self.is_plan_terminal(plan_id):
            raise StateConflictError("terminal review plans cannot be applied")
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
        if self.is_plan_terminal(cohort.plan_id):
            raise StateConflictError("terminal review plans cannot be applied")
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
        if self.is_plan_terminal(plan_id):
            return
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
        expected_logical_key = review_logical_key(
            project,
            f"hivemind:{certificate.session_id}",
            certificate.turn_key,
        )
        if certificate.logical_key != expected_logical_key:
            raise StateConflictError("review ledger logical key is malformed")
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

    def preflight_conflicts(self, plan_id: str) -> list[ReviewLedgerTurn]:
        """List zero-write source-drift conflicts eligible for explicit retirement."""
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        rows = self._db.execute(
            """
            SELECT ledger.* FROM review_plan_turns AS planned
            JOIN review_plan_sessions AS session
              ON session.plan_id = planned.plan_id
             AND session.session_id = planned.session_id
            JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
            JOIN review_turn_ledger AS ledger
              ON ledger.project = plan.project
             AND ledger.session_id = planned.session_id
             AND ledger.turn_key = planned.turn_key
            WHERE planned.plan_id = ?
              AND plan.status = 'blocked'
              AND ledger.status = 'conflict'
              AND ledger.error_code IN (
                  'preflight_session_conflict', 'preflight_source_drift'
              )
              AND ledger.revision = 1
              AND ledger.chunk_refs_json = '[]'
              AND ledger.chunk_hashes_json = '[]'
              AND ledger.chunk_sizes_json = '[]'
              AND ledger.index_ref = ''
              AND ledger.index_sha256 = ''
              AND ledger.index_size = 0
              AND ledger.trace_id = ''
              AND ledger.root_span_id = ''
              AND ledger.visible_at IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = planned.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = planned.plan_id
              )
            ORDER BY session.ordinal, planned.ordinal
            """,
            (plan_id,),
        ).fetchall()
        return [self._ledger(row) for row in rows]

    def retire_preflight_plan(
        self,
        plan_id: str,
        *,
        proof_sha256: str,
        importer_version: str,
    ) -> int:
        """Archive and retire a proven zero-write source-drift plan atomically.

        The caller must independently prove source stability and remote absence.
        Only a SHA-256 proof certificate and a constrained package version are
        accepted here; neither source nor hosted content is persisted.
        """
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        if not _SHA256.fullmatch(proof_sha256):
            raise StateConflictError("review retirement proof is malformed")
        if not _IMPORTER_VERSION.fullmatch(importer_version):
            raise StateConflictError("review importer version is malformed")

        existing = self._db.execute(
            "SELECT * FROM review_plan_retirements WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["reason"]) != "preflight_source_drift"
                or int(existing["remote_match_count"]) != 0
                or str(existing["proof_sha256"]) != proof_sha256
                or str(existing["importer_version"]) != importer_version
            ):
                raise StateConflictError("review plan already has different retirement evidence")
            return int(existing["archived_turn_count"])

        plan = self._db.execute(
            "SELECT plan_id, project, status, selected_count FROM review_plans WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if plan is None:
            raise StateConflictError("review plan was not found")
        if str(plan["status"]) != "blocked":
            raise StateConflictError("only a blocked review plan can be retired")
        if int(plan["selected_count"]) != 1:
            raise StateConflictError("multi-session review plans cannot use preflight resolution")

        cohort_rows = self._db.execute(
            """
            SELECT status, session_count, visible_turns, skipped_turns
            FROM review_cohorts WHERE plan_id = ? ORDER BY ordinal
            """,
            (plan_id,),
        ).fetchall()
        if len(cohort_rows) != 1 or any(
            str(row["status"]) != "blocked"
            or int(row["session_count"]) != 1
            or int(row["visible_turns"]) != 0
            or int(row["skipped_turns"]) != 0
            for row in cohort_rows
        ):
            raise StateConflictError("review plan retirement requires a zero-write blocked cohort")

        ledger_rows = self._db.execute(
            """
            SELECT ledger.* FROM review_plan_turns AS planned
            JOIN review_plan_sessions AS session
              ON session.plan_id = planned.plan_id
             AND session.session_id = planned.session_id
            JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
            JOIN review_turn_ledger AS ledger
              ON ledger.project = plan.project
             AND ledger.session_id = planned.session_id
             AND ledger.turn_key = planned.turn_key
            WHERE planned.plan_id = ?
            ORDER BY session.ordinal, planned.ordinal
            """,
            (plan_id,),
        ).fetchall()
        if not ledger_rows:
            raise StateConflictError("review plan retirement requires preflight conflict evidence")
        for row in ledger_rows:
            if not (
                str(row["status"]) == "conflict"
                and str(row["error_code"])
                in {"preflight_session_conflict", "preflight_source_drift"}
                and int(row["revision"]) == 1
                and str(row["chunk_refs_json"]) == "[]"
                and str(row["chunk_hashes_json"]) == "[]"
                and str(row["chunk_sizes_json"]) == "[]"
                and str(row["index_ref"]) == ""
                and str(row["index_sha256"]) == ""
                and int(row["index_size"]) == 0
                and str(row["trace_id"]) == ""
                and str(row["root_span_id"]) == ""
                and row["visible_at"] is None
            ):
                raise StateConflictError("review plan contains non-retirable turn evidence")

        project = str(plan["project"])
        shared_ledger = self._db.execute(
            """
            SELECT 1
            FROM review_plan_turns AS retiring
            JOIN review_plan_turns AS other
              ON other.session_id = retiring.session_id
             AND other.turn_key = retiring.turn_key
             AND other.plan_id != retiring.plan_id
            JOIN review_plans AS other_plan ON other_plan.plan_id = other.plan_id
            WHERE retiring.plan_id = ?
              AND other_plan.project = ?
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = other.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = other.plan_id
              )
            LIMIT 1
            """,
            (plan_id, project),
        ).fetchone()
        if shared_ledger is not None:
            raise StateConflictError(
                "review plan shares conflict evidence with another active plan"
            )
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.executemany(
                """
                INSERT INTO review_preflight_conflict_archive (
                    plan_id, project, session_id, turn_key,
                    source_payload_sha256, manifest_sha256, logical_key,
                    preview_signature, manifest_bytes, chunk_count,
                    ledger_revision, ledger_created_at, ledger_updated_at,
                    ledger_error_code, proof_sha256, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        plan_id,
                        project,
                        str(row["session_id"]),
                        str(row["turn_key"]),
                        str(row["source_payload_sha256"]),
                        str(row["manifest_sha256"]),
                        str(row["logical_key"]),
                        str(row["preview_signature"]),
                        int(row["manifest_bytes"]),
                        int(row["chunk_count"]),
                        int(row["revision"]),
                        str(row["created_at"]),
                        str(row["updated_at"]),
                        str(row["error_code"]),
                        proof_sha256,
                        now,
                    )
                    for row in ledger_rows
                ],
            )
            self._db.execute(
                """
                INSERT INTO review_plan_retirements (
                    plan_id, project, reason, archived_turn_count,
                    remote_match_count, proof_sha256, importer_version, retired_at
                ) VALUES (?, ?, 'preflight_source_drift', ?, 0, ?, ?, ?)
                """,
                (plan_id, project, len(ledger_rows), proof_sha256, importer_version, now),
            )
            deleted = 0
            for row in ledger_rows:
                cursor = self._db.execute(
                    """
                    DELETE FROM review_turn_ledger
                    WHERE project = ? AND session_id = ? AND turn_key = ?
                      AND source_payload_sha256 = ? AND manifest_sha256 = ?
                      AND logical_key = ? AND preview_signature = ?
                      AND manifest_bytes = ? AND chunk_count = ?
                      AND status = 'conflict' AND revision = ? AND error_code = ?
                    """,
                    (
                        project,
                        str(row["session_id"]),
                        str(row["turn_key"]),
                        str(row["source_payload_sha256"]),
                        str(row["manifest_sha256"]),
                        str(row["logical_key"]),
                        str(row["preview_signature"]),
                        int(row["manifest_bytes"]),
                        int(row["chunk_count"]),
                        int(row["revision"]),
                        str(row["error_code"]),
                    ),
                )
                deleted += cursor.rowcount
            if deleted != len(ledger_rows):
                raise StateConflictError("review conflict evidence changed during retirement")
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        return len(ledger_rows)

    def revalidate_preflight_plan(
        self,
        plan_id: str,
        *,
        proof_sha256: str,
        importer_version: str,
    ) -> int:
        """Terminally resolve a zero-write attempt after its source is stable again."""
        if not _SHA256.fullmatch(plan_id):
            raise StateConflictError("review plan identity is malformed")
        if not _SHA256.fullmatch(proof_sha256):
            raise StateConflictError("review revalidation proof is malformed")
        if not _IMPORTER_VERSION.fullmatch(importer_version):
            raise StateConflictError("review importer version is malformed")

        existing = self._db.execute(
            "SELECT * FROM review_plan_revalidations WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["reason"]) != "transient_preflight_export"
                or int(existing["remote_match_count"]) != 0
                or str(existing["proof_sha256"]) != proof_sha256
                or str(existing["importer_version"]) != importer_version
            ):
                raise StateConflictError("review plan already has different revalidation evidence")
            return int(existing["archived_turn_count"])
        if self.is_plan_retired(plan_id):
            raise StateConflictError("retired review plans cannot be revalidated")

        plan = self._db.execute(
            "SELECT plan_id, project, status, selected_count FROM review_plans WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if plan is None:
            raise StateConflictError("review plan was not found")
        if str(plan["status"]) != "blocked":
            raise StateConflictError("only a blocked review plan can be revalidated")
        if int(plan["selected_count"]) != 1:
            raise StateConflictError("multi-session review plans cannot use preflight resolution")

        cohort_rows = self._db.execute(
            """
            SELECT status, session_count, visible_turns, skipped_turns
            FROM review_cohorts WHERE plan_id = ? ORDER BY ordinal
            """,
            (plan_id,),
        ).fetchall()
        if len(cohort_rows) != 1 or any(
            str(row["status"]) != "blocked"
            or int(row["session_count"]) != 1
            or int(row["visible_turns"]) != 0
            or int(row["skipped_turns"]) != 0
            for row in cohort_rows
        ):
            raise StateConflictError(
                "review plan revalidation requires a zero-write blocked cohort"
            )

        ledger_rows = self._db.execute(
            """
            SELECT ledger.* FROM review_plan_turns AS planned
            JOIN review_plan_sessions AS session
              ON session.plan_id = planned.plan_id
             AND session.session_id = planned.session_id
            JOIN review_plans AS plan ON plan.plan_id = planned.plan_id
            JOIN review_turn_ledger AS ledger
              ON ledger.project = plan.project
             AND ledger.session_id = planned.session_id
             AND ledger.turn_key = planned.turn_key
            WHERE planned.plan_id = ?
            ORDER BY session.ordinal, planned.ordinal
            """,
            (plan_id,),
        ).fetchall()
        if not ledger_rows:
            raise StateConflictError(
                "review plan revalidation requires preflight conflict evidence"
            )
        for row in ledger_rows:
            if not (
                str(row["status"]) == "conflict"
                and str(row["error_code"])
                in {"preflight_session_conflict", "preflight_source_drift"}
                and int(row["revision"]) == 1
                and str(row["chunk_refs_json"]) == "[]"
                and str(row["chunk_hashes_json"]) == "[]"
                and str(row["chunk_sizes_json"]) == "[]"
                and str(row["index_ref"]) == ""
                and str(row["index_sha256"]) == ""
                and int(row["index_size"]) == 0
                and str(row["trace_id"]) == ""
                and str(row["root_span_id"]) == ""
                and row["visible_at"] is None
            ):
                raise StateConflictError("review plan contains non-revalidatable turn evidence")

        project = str(plan["project"])
        shared_ledger = self._db.execute(
            """
            SELECT 1
            FROM review_plan_turns AS revalidating
            JOIN review_plan_turns AS other
              ON other.session_id = revalidating.session_id
             AND other.turn_key = revalidating.turn_key
             AND other.plan_id != revalidating.plan_id
            JOIN review_plans AS other_plan ON other_plan.plan_id = other.plan_id
            WHERE revalidating.plan_id = ?
              AND other_plan.project = ?
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_retirements AS retired
                  WHERE retired.plan_id = other.plan_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = other.plan_id
              )
            LIMIT 1
            """,
            (plan_id, project),
        ).fetchone()
        if shared_ledger is not None:
            raise StateConflictError(
                "review plan shares conflict evidence with another active plan"
            )

        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.executemany(
                """
                INSERT INTO review_preflight_conflict_archive (
                    plan_id, project, session_id, turn_key,
                    source_payload_sha256, manifest_sha256, logical_key,
                    preview_signature, manifest_bytes, chunk_count,
                    ledger_revision, ledger_created_at, ledger_updated_at,
                    ledger_error_code, proof_sha256, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        plan_id,
                        project,
                        str(row["session_id"]),
                        str(row["turn_key"]),
                        str(row["source_payload_sha256"]),
                        str(row["manifest_sha256"]),
                        str(row["logical_key"]),
                        str(row["preview_signature"]),
                        int(row["manifest_bytes"]),
                        int(row["chunk_count"]),
                        int(row["revision"]),
                        str(row["created_at"]),
                        str(row["updated_at"]),
                        str(row["error_code"]),
                        proof_sha256,
                        now,
                    )
                    for row in ledger_rows
                ],
            )
            self._db.execute(
                """
                INSERT INTO review_plan_revalidations (
                    plan_id, project, reason, archived_turn_count,
                    remote_match_count, proof_sha256, importer_version, revalidated_at
                ) VALUES (?, ?, 'transient_preflight_export', ?, 0, ?, ?, ?)
                """,
                (plan_id, project, len(ledger_rows), proof_sha256, importer_version, now),
            )
            deleted = 0
            for row in ledger_rows:
                cursor = self._db.execute(
                    """
                    DELETE FROM review_turn_ledger
                    WHERE project = ? AND session_id = ? AND turn_key = ?
                      AND source_payload_sha256 = ? AND manifest_sha256 = ?
                      AND logical_key = ? AND preview_signature = ?
                      AND manifest_bytes = ? AND chunk_count = ?
                      AND status = 'conflict' AND revision = ? AND error_code = ?
                    """,
                    (
                        project,
                        str(row["session_id"]),
                        str(row["turn_key"]),
                        str(row["source_payload_sha256"]),
                        str(row["manifest_sha256"]),
                        str(row["logical_key"]),
                        str(row["preview_signature"]),
                        int(row["manifest_bytes"]),
                        int(row["chunk_count"]),
                        int(row["revision"]),
                        str(row["error_code"]),
                    ),
                )
                deleted += cursor.rowcount
            if deleted != len(ledger_rows):
                raise StateConflictError("review conflict evidence changed during revalidation")
            self._commit()
        except Exception:
            self._db.rollback()
            raise
        return len(ledger_rows)

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
        args: tuple[Any, ...] = () if project is None else (project,)
        plan_where = "" if project is None else " AND plan.project = ?"
        plans = int(
            self._db.execute(
                """
                SELECT COUNT(*) FROM review_plans AS plan
                WHERE NOT EXISTS (
                    SELECT 1 FROM review_plan_retirements AS retired
                    WHERE retired.plan_id = plan.plan_id
                )
                  AND NOT EXISTS (
                      SELECT 1 FROM review_plan_revalidations AS revalidated
                      WHERE revalidated.plan_id = plan.plan_id
                  )
                """
                + plan_where,
                args,
            ).fetchone()[0]
        )
        session_rows = self._db.execute(
            """
            SELECT session.status, COUNT(*) AS count FROM review_plan_sessions AS session
            JOIN review_plans AS plan ON plan.plan_id = session.plan_id
            WHERE NOT EXISTS (
                SELECT 1 FROM review_plan_retirements AS retired
                WHERE retired.plan_id = plan.plan_id
            )
              AND NOT EXISTS (
                  SELECT 1 FROM review_plan_revalidations AS revalidated
                  WHERE revalidated.plan_id = plan.plan_id
              )
            """
            + (" AND plan.project = ?" if project is not None else "")
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
        retry_project = _REVIEW_PROJECT if project is None else project
        preseal_retries = len(self.pending_retry_session_attempts(retry_project))
        return ReviewStatus(
            plans=plans,
            queued_sessions=sessions.get("pending", 0) + sessions.get("blocked", 0),
            completed_sessions=sessions.get("completed", 0),
            preseal_retries=preseal_retries,
            planned_turns=turns.get("planned", 0),
            objects_publishing=turns.get("objects_publishing", 0),
            objects_verified=turns.get("objects_verified", 0),
            root_submitting=turns.get("root_submitting", 0),
            visible=turns.get("visible", 0),
            uncertain=turns.get("uncertain", 0),
            conflicted=turns.get("conflict", 0),
        )
