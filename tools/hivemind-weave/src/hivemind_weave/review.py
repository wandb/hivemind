"""Sealed planning and bounded execution for the noncanonical review mirror."""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .atif import map_atif
from .backfill import (
    BackfillPreviewConfig,
    BackfillWindow,
    _filter_rows,
    _normalized_filters,
    _same_session_snapshot,
    _select_sessions,
    _server_lookback_days,
    resolve_backfill_window,
)
from .errors import (
    ATIFSchemaError,
    ReviewMirrorConflictError,
    ReviewMirrorError,
    ReviewMirrorUncertainError,
)
from .hivemind import HiveMindClient
from .importer import ImportConfig
from .models import MappedConversation, MappedTurn, Session
from .pii import sanitize_mapped_conversation
from .review_manifest import (
    MAX_REVIEW_CHUNK_BYTES,
    ReviewManifestBundle,
    ReviewManifestError,
    build_review_manifest,
)
from .review_sink import ReviewRuntime, preflight_review_bundle, preflight_review_runtime
from .review_state import (
    REVIEW_SOURCE_SCOPE_SHA256,
    ReviewCohort,
    ReviewLedgerTurn,
    ReviewPlan,
    ReviewPlanSession,
    ReviewStateStore,
    ReviewStatus,
    ReviewTurnCertificate,
    review_filter_summary,
    review_logical_key,
    review_plan_id,
    valid_review_span_id,
    valid_review_trace_id,
)
from .source_identity import is_opaque_source_coordinate
from .utils import isoformat_z

REVIEW_PROJECT = "wandb/hivemind-chats-review"
REVIEW_SETTLE_MINUTES = 60
REVIEW_WEAVE_COMMIT = "0b58f67e1539bfaa2c705e35bed2d9896a319c6a"
_CANARY_TRANSCRIPT_BUDGET = 25
_CANARY_SUMMARY_TOKEN_BUDGET = 100_000
_CANARY_TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "cached_read_tokens",
    "cached_write_tokens",
)
_PLAN_REFERENCE = re.compile(r"^[0-9a-f]{32,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReviewPreviewConfig:
    since: str
    project: str
    state_path: Path
    until: str | None = None
    canary: bool = False
    agents: tuple[str, ...] = ()
    repositories: tuple[str, ...] = ()
    session_ids: tuple[str, ...] = ()
    exclude_subagents: bool = False
    now: datetime | None = None
    progress: Callable[[str], None] | None = None


@dataclass(frozen=True)
class ReviewApplyConfig:
    plan_id: str
    confirm_project: str
    state_path: Path
    max_sessions: int = 1


@dataclass(frozen=True)
class ReviewReconcileConfig:
    plan_id: str
    state_path: Path


@dataclass(frozen=True)
class ReviewReport:
    phase: str
    project: str
    plan_id: str
    status: str
    since_utc: datetime
    until_utc: datetime
    selector: str
    discovered: int = 0
    eligible: int = 0
    deferred: int = 0
    invalid: int = 0
    selected_sessions: int = 0
    completed_sessions: int = 0
    remaining_sessions: int = 0
    turns: int = 0
    visible_turns: int = 0
    skipped_turns: int = 0
    uncertain_turns: int = 0
    conflicted_turns: int = 0
    failed_items: int = 0
    manifest_bytes: int = 0
    max_manifest_bytes: int = 0
    chunk_count: int = 0
    max_chunks_per_turn: int = 0
    max_chunk_bytes: int = 0
    index_bytes: int = 0
    manifests_le_1m: int = 0
    manifests_le_8m: int = 0
    manifests_le_64m: int = 0
    manifests_gt_64m: int = 0

    @property
    def ok(self) -> bool:
        return (
            self.status != "blocked"
            and not self.uncertain_turns
            and not self.conflicted_turns
            and not self.failed_items
        )

    def render(self) -> str:
        lines = [
            f"Review {self.phase}:",
            f"  project:              {self.project}",
            f"  plan alias:           {self.plan_id[:32]}",
            "  UTC window:           "
            f"[{isoformat_z(self.since_utc)}, {isoformat_z(self.until_utc)})",
            f"  selector:             {self.selector}",
            f"  status:               {self.status}",
            f"  selected sessions:    {self.selected_sessions}",
            f"  completed sessions:   {self.completed_sessions}",
            f"  remaining sessions:   {self.remaining_sessions}",
        ]
        if self.phase == "preview":
            lines.extend(
                [
                    f"  discovered sessions:  {self.discovered}",
                    f"  eligible sessions:    {self.eligible}",
                    f"  deferred sessions:    {self.deferred}",
                    f"  invalid summaries:    {self.invalid}",
                    f"  certified turns:      {self.turns}",
                    f"  manifest bytes:       {self.manifest_bytes}",
                    f"  max manifest bytes:   {self.max_manifest_bytes}",
                    f"  content chunks:       {self.chunk_count}",
                    f"  max chunks/turn:      {self.max_chunks_per_turn}",
                    f"  max chunk bytes:      {self.max_chunk_bytes}",
                    f"  index bytes:          {self.index_bytes}",
                    "  manifest buckets:     "
                    f"<=1MiB {self.manifests_le_1m}, "
                    f"1-8MiB {self.manifests_le_8m}, "
                    f"8-64MiB {self.manifests_le_64m}, >64MiB {self.manifests_gt_64m}",
                ]
            )
        else:
            lines.extend(
                [
                    f"  visible turns:        {self.visible_turns}",
                    f"  skipped turns:        {self.skipped_turns}",
                    f"  uncertain turns:      {self.uncertain_turns}",
                    f"  conflicted turns:     {self.conflicted_turns}",
                    f"  failed items:         {self.failed_items}",
                ]
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class _PreparedTurn:
    turn: MappedTurn
    bundle: ReviewManifestBundle


@dataclass(frozen=True)
class _PreparedSession:
    session: Session
    conversation: MappedConversation


@dataclass(frozen=True)
class _PreparedCohortSession:
    planned: ReviewPlanSession
    prepared: _PreparedSession
    certificates: tuple[ReviewTurnCertificate, ...]


class _CohortPreflightConflict(ReviewMirrorConflictError):
    """Content-free marker identifying the sealed session that drifted."""

    def __init__(self, session_id: str, message: str) -> None:
        super().__init__(message)
        self.session_id = session_id


def _validate_review_project(project: str) -> None:
    ImportConfig(days=1, project=project, dry_run=True).validate()
    if project != REVIEW_PROJECT:
        raise ValueError(
            f"the noncanonical review path is restricted to {REVIEW_PROJECT}; "
            "canonical projects are forbidden"
        )


def _require_opaque_session_id(session_id: object) -> None:
    if not is_opaque_source_coordinate(session_id):
        raise ReviewMirrorError("a selected session has an unsafe source coordinate")


def _validate_session_coordinates(session: Session) -> None:
    _require_opaque_session_id(session.id)
    if session.parent_session_id:
        _require_opaque_session_id(session.parent_session_id)


def _validate_review_bound(value: str, *, label: str) -> None:
    """Require an explicit RFC3339 instant for immutable review-plan bounds."""
    candidate = value.strip()
    if not _RFC3339_TIMESTAMP.fullmatch(candidate):
        raise ValueError(f"{label} must be an RFC3339 timestamp with an explicit UTC offset")
    normalized = f"{candidate[:-1]}+00:00" if candidate[-1:].lower() == "z" else candidate
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{label} must be a valid RFC3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")


def _prepare_session(
    client: HiveMindClient,
    session: Session,
    *,
    runtime: ReviewRuntime | None = None,
) -> _PreparedSession:
    # Empty transcripts have no manifest on which to enforce the final PII
    # fixed point, so validate the state-bearing source coordinate itself.
    _validate_session_coordinates(session)
    before = Session.from_api(client.get_session(session.id))
    if not _same_session_snapshot(session, before):
        raise ReviewMirrorError(
            "a selected session changed before review preparation; no content was uploaded"
        )
    transcript = client.get_atif(session.id)
    after = Session.from_api(client.get_session(session.id))
    if not _same_session_snapshot(session, after):
        raise ReviewMirrorError(
            "a selected session changed during review preparation; no content was uploaded"
        )
    conversation = sanitize_mapped_conversation(map_atif(session, transcript))
    # This pure, credential-free pass validates every bundle's active redaction
    # fixed point and compact root structure.  The caller cannot upload turn 0
    # until every turn in this session has passed.
    active_runtime = runtime or preflight_review_runtime()
    for turn in conversation.turns:
        preflight_review_bundle(
            build_review_manifest(conversation, turn),
            _runtime=active_runtime,
        )
    return _PreparedSession(session=session, conversation=conversation)


def _canary_qualifies(prepared: _PreparedSession, *, now: datetime) -> bool:
    if now - prepared.session.last_activity_at < timedelta(hours=24):
        return False
    if prepared.session.parent_session_id or not 1 <= len(prepared.conversation.turns) <= 3:
        return False
    for turn in prepared.conversation.turns:
        physical_source_spans = 1 + len(turn.llms) + len(turn.tools) + len(turn.subagents)
        if physical_source_spans > 4:
            return False
        warnings = turn.attributes.get("hivemind.mapping_warnings", [])
        if warnings:
            return False
        try:
            bundle = build_review_manifest(prepared.conversation, turn)
        except ReviewManifestError:
            return False
        if len(bundle.chunks) != 1 or bundle.chunks[0].byte_count > MAX_REVIEW_CHUNK_BYTES:
            return False
    return True


def _certificate_payload(
    *,
    project: str,
    prepared: _PreparedSession,
    stats: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for ordinal, turn in enumerate(prepared.conversation.turns):
        bundle = build_review_manifest(prepared.conversation, turn)
        if stats is not None:
            _accumulate_bundle_stats(stats, bundle)
        payload.append(
            {
                "session_id": prepared.session.id,
                "ordinal": ordinal,
                "turn_key": turn.key,
                "source_payload_sha256": bundle.source_payload_sha256,
                "manifest_sha256": bundle.manifest_sha256,
                "index_sha256": bundle.index_sha256,
                "logical_key": review_logical_key(
                    project,
                    prepared.conversation.conversation_id,
                    turn.key,
                ),
                "preview_signature": bundle.preview_signature,
                "started_at": turn.started_at,
                "ended_at": turn.ended_at,
                "manifest_bytes": bundle.manifest_byte_count,
                "chunk_count": len(bundle.chunks),
                "max_chunk_bytes": max(
                    (chunk.byte_count for chunk in bundle.chunks),
                    default=0,
                ),
                "index_bytes": bundle.index_byte_count,
                "atif_schema_version": prepared.conversation.schema_version,
            }
        )
    return payload


def _certificates(
    plan_id: str,
    payloads: list[dict[str, Any]],
) -> list[ReviewTurnCertificate]:
    return [ReviewTurnCertificate(plan_id=plan_id, **payload) for payload in payloads]


def _plan_hash_payload(
    *,
    config: ReviewPreviewConfig,
    window: BackfillWindow,
    universe_sha256: str,
    filters: dict[str, Any],
    sessions: list[tuple[str, datetime, datetime]],
    certificate_payloads: list[dict[str, Any]],
) -> dict[str, Any]:
    return _sealed_plan_hash_payload(
        project=config.project,
        since_utc=window.since_utc,
        until_utc=window.until_utc,
        timezone_name=window.timezone_name,
        selector="canary" if config.canary else "backlog",
        universe_sha256=universe_sha256,
        filter_summary=review_filter_summary(_filter_rows(filters)),
        sessions=sessions,
        certificate_payloads=certificate_payloads,
    )


def _sealed_plan_hash_payload(
    *,
    project: str,
    since_utc: datetime,
    until_utc: datetime,
    timezone_name: str,
    selector: str,
    universe_sha256: str,
    filter_summary: list[tuple[str, str]],
    sessions: list[tuple[str, datetime, datetime]],
    certificate_payloads: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "importer_version": __version__,
        "weave_commit": REVIEW_WEAVE_COMMIT,
        "project": project,
        "source_scope_sha256": REVIEW_SOURCE_SCOPE_SHA256,
        "since_utc": isoformat_z(since_utc),
        "until_utc": isoformat_z(until_utc),
        "timezone_name": timezone_name,
        "selector": selector,
        "settle_seconds": REVIEW_SETTLE_MINUTES * 60,
        "filter_summary": filter_summary,
        "universe_sha256": universe_sha256,
        "sessions": [
            {
                "ordinal": ordinal,
                "session_id": session_id,
                "started_at": isoformat_z(started_at),
                "last_activity_at": isoformat_z(last_activity_at),
            }
            for ordinal, (session_id, started_at, last_activity_at) in enumerate(sessions)
        ],
        "turn_certificates": certificate_payloads,
    }


def _saved_certificate_payload(item: ReviewTurnCertificate) -> dict[str, Any]:
    return {
        "session_id": item.session_id,
        "ordinal": item.ordinal,
        "turn_key": item.turn_key,
        "source_payload_sha256": item.source_payload_sha256,
        "manifest_sha256": item.manifest_sha256,
        "index_sha256": item.index_sha256,
        "logical_key": item.logical_key,
        "preview_signature": item.preview_signature,
        "started_at": item.started_at,
        "ended_at": item.ended_at,
        "manifest_bytes": item.manifest_bytes,
        "chunk_count": item.chunk_count,
        "max_chunk_bytes": item.max_chunk_bytes,
        "index_bytes": item.index_bytes,
        "atif_schema_version": item.atif_schema_version,
    }


def _assert_sealed_plan_identity(state: ReviewStateStore, plan: ReviewPlan) -> None:
    sessions = state.get_sessions(plan.plan_id)
    turns = state.get_turns(plan.plan_id)
    expected_plan_id = review_plan_id(
        _sealed_plan_hash_payload(
            project=plan.project,
            since_utc=plan.since_utc,
            until_utc=plan.until_utc,
            timezone_name=plan.timezone_name,
            selector=plan.selector,
            universe_sha256=plan.universe_sha256,
            filter_summary=state.get_filters(plan.plan_id),
            sessions=[
                (item.session_id, item.started_at, item.last_activity_at) for item in sessions
            ],
            certificate_payloads=[_saved_certificate_payload(item) for item in turns],
        )
    )
    if expected_plan_id != plan.plan_id or len(sessions) != plan.selected_count:
        raise ReviewMirrorConflictError(
            "sealed review plan identity does not match its immutable evidence"
        )


def _empty_report_stats() -> dict[str, int]:
    return {
        "turns": 0,
        "manifest_bytes": 0,
        "max_manifest_bytes": 0,
        "chunk_count": 0,
        "max_chunks_per_turn": 0,
        "max_chunk_bytes": 0,
        "index_bytes": 0,
        "manifests_le_1m": 0,
        "manifests_le_8m": 0,
        "manifests_le_64m": 0,
        "manifests_gt_64m": 0,
    }


def _accumulate_bundle_stats(
    stats: dict[str, int],
    bundle: ReviewManifestBundle,
) -> None:
    manifest_bytes = bundle.manifest_byte_count
    chunk_count = len(bundle.chunks)
    max_chunk_bytes = max((chunk.byte_count for chunk in bundle.chunks), default=0)
    stats["turns"] += 1
    stats["manifest_bytes"] += manifest_bytes
    stats["max_manifest_bytes"] = max(stats["max_manifest_bytes"], manifest_bytes)
    stats["chunk_count"] += chunk_count
    stats["max_chunks_per_turn"] = max(stats["max_chunks_per_turn"], chunk_count)
    stats["max_chunk_bytes"] = max(stats["max_chunk_bytes"], max_chunk_bytes)
    stats["index_bytes"] += bundle.index_byte_count
    if manifest_bytes <= 1024 * 1024:
        stats["manifests_le_1m"] += 1
    elif manifest_bytes <= 8 * 1024 * 1024:
        stats["manifests_le_8m"] += 1
    elif manifest_bytes <= 64 * 1024 * 1024:
        stats["manifests_le_64m"] += 1
    else:
        stats["manifests_gt_64m"] += 1


def _canary_summary_cannot_fit(raw: dict[str, Any]) -> bool:
    """Reject only explicit summary values outside the strict canary budget."""
    turn_count = raw.get("turn_count")
    if type(turn_count) is int and turn_count > 3:
        return True
    tool_call_count = raw.get("tool_call_count")
    if type(tool_call_count) is int and tool_call_count > 6:
        return True
    token_values = [raw.get(key) for key in _CANARY_TOKEN_FIELDS]
    if all(type(value) is int and value >= 0 for value in token_values):
        return sum(token_values) > _CANARY_SUMMARY_TOKEN_BUDGET
    return False


def preview_review(
    config: ReviewPreviewConfig,
    *,
    hivemind: HiveMindClient | None = None,
) -> ReviewReport:
    """Discover, redact, serialize, and seal a content-free immutable plan."""
    _validate_review_project(config.project)
    _validate_review_bound(config.since, label="--since")
    if config.until is not None:
        _validate_review_bound(config.until, label="--until")
    # A moving or incompatible Weave install is a run-level failure, not a
    # canary-candidate defect. Prove the exact local SDK contract before HiveMind
    # discovery or any sealed-plan mutation.
    runtime = preflight_review_runtime()
    captured_now = (config.now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    window = resolve_backfill_window(
        since=config.since,
        until=config.until,
        days=None,
        timezone_name="UTC",
        now=captured_now,
    )
    filter_config = BackfillPreviewConfig(
        project=config.project,
        state_path=config.state_path,
        since=config.since,
        until=config.until,
        timezone_name="UTC",
        agents=config.agents,
        repositories=config.repositories,
        session_ids=config.session_ids,
        exclude_subagents=config.exclude_subagents,
    )
    filters = _normalized_filters(filter_config)
    for session_id in filters["session_ids"]:
        if not is_opaque_source_coordinate(session_id):
            raise ValueError("--session-id must be an opaque HiveMind machine identifier")
    client = hivemind or HiveMindClient()
    client.preflight()
    raw_sessions = client.list_sessions(
        days=_server_lookback_days(window, captured_now),
        include_subagents=True,
    )
    # Current HiveMind summaries expose a cheap aggregate turn count. Use it
    # only to reject sessions that cannot satisfy the strict canary bound; a
    # missing or unfamiliar value falls back to the complete transcript check.
    # This keeps a one-chat canary from first downloading/redacting a known
    # many-turn transcript while preserving tolerant compatibility.
    summaries_by_id: dict[str, dict[str, Any]] = {}
    for raw in raw_sessions:
        raw_id = raw.get("id")
        if isinstance(raw_id, str):
            summaries_by_id[raw_id] = raw
    selection = _select_sessions(
        raw_sessions,
        window=window,
        filters=filters,
        settled_before=captured_now - timedelta(minutes=REVIEW_SETTLE_MINUTES),
    )
    if selection.invalid:
        raise ReviewMirrorError(
            "HiveMind returned invalid session summaries; no review plan was saved"
        )
    # The stable-universe digest and sealed plan both depend on these IDs. Do
    # not hash or persist a name-like coordinate merely because Presidio failed
    # to classify it in context.
    for session in selection.sessions:
        _validate_session_coordinates(session)

    selected_sessions: list[tuple[str, datetime, datetime]] = []
    certificate_payloads: list[dict[str, Any]] = []
    stats = _empty_report_stats()
    if config.canary:
        plausible_count = sum(
            1
            for session in selection.sessions
            if captured_now - session.last_activity_at >= timedelta(hours=24)
            and not session.parent_session_id
            and not (
                (summary := summaries_by_id.get(session.id)) is not None
                and _canary_summary_cannot_fit(summary)
            )
        )
        if config.progress is not None:
            config.progress(
                "Canary summary preflight: "
                f"{plausible_count} plausible session(s); "
                f"at most {_CANARY_TRANSCRIPT_BUDGET} transcript(s) will be examined"
            )
        examined_transcripts = 0
        for session in selection.sessions:
            if captured_now - session.last_activity_at < timedelta(hours=24):
                continue
            if session.parent_session_id:
                continue
            summary = summaries_by_id.get(session.id)
            if summary is not None and _canary_summary_cannot_fit(summary):
                continue
            if examined_transcripts >= _CANARY_TRANSCRIPT_BUDGET:
                break
            examined_transcripts += 1
            if config.progress is not None:
                config.progress(
                    "Canary transcript preflight: "
                    f"{examined_transcripts}/{min(plausible_count, _CANARY_TRANSCRIPT_BUDGET)}"
                )
            try:
                prepared = _prepare_session(client, session, runtime=runtime)
            except (ReviewMirrorError, ATIFSchemaError, ReviewManifestError):
                # A deterministic mapping/size failure disqualifies this
                # candidate; canary limits are never loosened automatically.
                continue
            if _canary_qualifies(prepared, now=captured_now):
                selected_sessions.append(
                    (
                        prepared.session.id,
                        prepared.session.started_at,
                        prepared.session.last_activity_at,
                    )
                )
                certificate_payloads.extend(
                    _certificate_payload(
                        project=config.project,
                        prepared=prepared,
                        stats=stats,
                    )
                )
                del prepared
                break
            del prepared
        if not selected_sessions:
            raise ReviewMirrorError(
                "no session qualified within the bounded deterministic review canary; "
                "use an exact --session-id after inspecting the source"
            )
    else:
        for session in selection.sessions:
            prepared = _prepare_session(client, session, runtime=runtime)
            selected_sessions.append(
                (
                    prepared.session.id,
                    prepared.session.started_at,
                    prepared.session.last_activity_at,
                )
            )
            certificate_payloads.extend(
                _certificate_payload(
                    project=config.project,
                    prepared=prepared,
                    stats=stats,
                )
            )
            # A 21-day backlog may contain very large transcripts.  Only the
            # content-free certificate survives into the next iteration.
            del prepared

    plan_id = review_plan_id(
        _plan_hash_payload(
            config=config,
            window=window,
            universe_sha256=selection.universe_sha256,
            filters=filters,
            sessions=selected_sessions,
            certificate_payloads=certificate_payloads,
        )
    )
    certificates = _certificates(plan_id, certificate_payloads)
    initial_status = "completed" if not selected_sessions else "planned"
    expected_plan = ReviewPlan(
        plan_id=plan_id,
        project=config.project,
        source_scope_sha256=REVIEW_SOURCE_SCOPE_SHA256,
        since_utc=window.since_utc,
        until_utc=window.until_utc,
        timezone_name=window.timezone_name,
        selector="canary" if config.canary else "backlog",
        universe_sha256=selection.universe_sha256,
        status=initial_status,
        discovered_count=selection.discovered,
        eligible_count=selection.eligible,
        deferred_count=selection.deferred,
        invalid_count=selection.invalid,
        selected_count=len(selected_sessions),
        last_error_code="",
    )
    with ReviewStateStore(config.state_path) as state:
        plan = state.create_plan(
            plan=expected_plan,
            sessions=selected_sessions,
            filters=_filter_rows(filters),
            turns=certificates,
        )
        completed, remaining = state.progress(plan.plan_id)
    return ReviewReport(
        phase="preview",
        project=plan.project,
        plan_id=plan.plan_id,
        status=plan.status,
        since_utc=plan.since_utc,
        until_utc=plan.until_utc,
        selector=plan.selector,
        discovered=plan.discovered_count,
        eligible=plan.eligible_count,
        deferred=plan.deferred_count,
        invalid=plan.invalid_count,
        selected_sessions=plan.selected_count,
        completed_sessions=completed,
        remaining_sessions=remaining,
        **stats,
    )


def _certificate_identity(certificate: ReviewTurnCertificate) -> tuple[Any, ...]:
    return (
        certificate.session_id,
        certificate.ordinal,
        certificate.turn_key,
        certificate.source_payload_sha256,
        certificate.manifest_sha256,
        certificate.index_sha256,
        certificate.logical_key,
        certificate.preview_signature,
        certificate.started_at,
        certificate.ended_at,
        certificate.manifest_bytes,
        certificate.chunk_count,
        certificate.max_chunk_bytes,
        certificate.index_bytes,
        certificate.atif_schema_version,
    )


def _prepare_cohort(
    *,
    client: HiveMindClient,
    plan: ReviewPlan,
    cohort_sessions: list[ReviewPlanSession],
    expected_turns: list[ReviewTurnCertificate],
    runtime: ReviewRuntime,
) -> list[_PreparedCohortSession]:
    prepared: list[_PreparedCohortSession] = []
    expected_by_session = {
        item.session_id: [turn for turn in expected_turns if turn.session_id == item.session_id]
        for item in cohort_sessions
    }
    for planned in cohort_sessions:
        observed = Session.from_api(client.get_session(planned.session_id))
        expected_session = Session(
            id=planned.session_id,
            agent_session_id=observed.agent_session_id,
            title=observed.title,
            agent_type=observed.agent_type,
            model=observed.model,
            started_at=planned.started_at,
            last_activity_at=planned.last_activity_at,
            last_activity_known=True,
            repository=observed.repository,
            branch=observed.branch,
            parent_session_id=observed.parent_session_id,
            user=observed.user,
        )
        if not _same_session_snapshot(expected_session, observed):
            raise _CohortPreflightConflict(
                planned.session_id,
                "a sealed review session changed before apply; no root was submitted",
            )
        try:
            current = _prepare_session(client, observed, runtime=runtime)
        except (ReviewMirrorError, ATIFSchemaError, ReviewManifestError) as error:
            raise _CohortPreflightConflict(
                planned.session_id,
                "a sealed review session failed deterministic apply preflight; "
                "no root was submitted",
            ) from error
        payloads = _certificate_payload(project=plan.project, prepared=current)
        actual = _certificates(plan.plan_id, payloads)
        expected = expected_by_session[planned.session_id]
        if [_certificate_identity(item) for item in actual] != [
            _certificate_identity(item) for item in expected
        ]:
            raise _CohortPreflightConflict(
                planned.session_id,
                "a sealed review turn changed before apply; no root was submitted",
            )
        prepared.append(
            _PreparedCohortSession(
                planned=planned,
                prepared=current,
                certificates=tuple(actual),
            )
        )
    return prepared


def _assert_plan_source_universe_access(
    client: HiveMindClient,
    planned_sessions: list[ReviewPlanSession],
) -> None:
    """Prove the active login still owns every sealed session summary."""
    planned_ids = {item.session_id for item in planned_sessions}
    observed_by_id: dict[str, Session] = {}
    try:
        raw_sessions = client.list_sessions(days=365, include_subagents=True)
        for raw in raw_sessions:
            # The proof concerns only the immutable sessions in this plan. An
            # unrelated legacy coordinate elsewhere in the account must not
            # prevent a valid sealed cohort from being applied.
            raw_id = raw.get("id")
            if not isinstance(raw_id, str) or raw_id not in planned_ids:
                continue
            observed = Session.from_api(raw)
            _validate_session_coordinates(observed)
            previous = observed_by_id.get(observed.id)
            if previous is not None and previous != observed:
                raise ReviewMirrorConflictError(
                    "HiveMind returned inconsistent source-universe evidence"
                )
            observed_by_id[observed.id] = observed
    except ReviewMirrorConflictError:
        raise
    except Exception as error:
        raise ReviewMirrorConflictError(
            "the authenticated HiveMind source universe could not be verified"
        ) from error

    for planned in planned_sessions:
        observed = observed_by_id.get(planned.session_id)
        if (
            observed is None
            or observed.started_at != planned.started_at
            or observed.last_activity_at != planned.last_activity_at
        ):
            raise ReviewMirrorConflictError(
                "the authenticated HiveMind source universe does not match the sealed plan"
            )


def _publication_evidence(publication: Any) -> dict[str, Any]:
    try:
        index_size = publication.index.size
        if type(index_size) is not int or index_size <= 0:
            raise TypeError("invalid hosted index size")
        return {
            "chunk_refs": tuple(publication.chunk_refs),
            "chunk_hashes": tuple(publication.chunk_hashes),
            "chunk_sizes": tuple(publication.chunk_sizes),
            "index_ref": str(publication.index_ref),
            "index_sha256": str(publication.index_sha256),
            "index_size": index_size,
        }
    except (AttributeError, TypeError) as error:
        raise ReviewMirrorError("review object publication returned incomplete evidence") from error


def _validate_publication(
    publication: Any,
    *,
    conversation_id: str,
    turn: MappedTurn,
    bundle: ReviewManifestBundle,
    certificate: ReviewTurnCertificate,
) -> dict[str, Any]:
    """Bind remotely read-back object evidence to the sealed turn certificate."""
    evidence = _publication_evidence(publication)
    expected_chunk_hashes = tuple(item.sha256 for item in bundle.chunks)
    expected_chunk_sizes = tuple(item.byte_count for item in bundle.chunks)
    identity = (
        str(getattr(publication, "conversation_id", "")),
        str(getattr(publication, "manifest_sha256", "")),
        str(getattr(publication, "logical_key", "")),
        str(getattr(publication, "root_turn_key", "")),
        str(getattr(publication, "preview_signature", "")),
        str(getattr(publication, "planning_index_sha256", "")),
        getattr(publication, "started_at", None),
        getattr(publication, "ended_at", None),
    )
    expected_identity = (
        conversation_id,
        certificate.manifest_sha256,
        certificate.logical_key,
        f"review:{certificate.logical_key}",
        certificate.preview_signature,
        certificate.index_sha256,
        turn.started_at,
        turn.ended_at,
    )
    if (
        identity != expected_identity
        or not _SHA256.fullmatch(str(getattr(publication, "root_payload_sha256", "")))
        or evidence["chunk_hashes"] != expected_chunk_hashes
        or evidence["chunk_sizes"] != expected_chunk_sizes
        or len(evidence["chunk_refs"]) != certificate.chunk_count
    ):
        raise ReviewMirrorConflictError(
            "published review objects do not match the sealed turn certificate"
        )
    return evidence


def _validate_rebuilt_bundle(
    bundle: ReviewManifestBundle,
    *,
    turn: MappedTurn,
    certificate: ReviewTurnCertificate,
) -> None:
    """Prove the one-turn rebuild still matches the completed session preflight."""
    if (
        bundle.source_payload_sha256 != certificate.source_payload_sha256
        or bundle.manifest_sha256 != certificate.manifest_sha256
        or bundle.index_sha256 != certificate.index_sha256
        or bundle.preview_signature != certificate.preview_signature
        or bundle.manifest_byte_count != certificate.manifest_bytes
        or len(bundle.chunks) != certificate.chunk_count
        or max((item.byte_count for item in bundle.chunks), default=0)
        != certificate.max_chunk_bytes
        or bundle.index_byte_count != certificate.index_bytes
        or turn.key != certificate.turn_key
        or turn.started_at != certificate.started_at
        or turn.ended_at != certificate.ended_at
    ):
        raise ReviewMirrorConflictError(
            "rebuilt review turn does not match its completed session preflight"
        )


def _root_evidence(result: Any) -> tuple[str, str]:
    trace_id = getattr(result, "trace_id", "")
    root_span_id = getattr(result, "root_span_id", "")
    if not valid_review_trace_id(trace_id) or not valid_review_span_id(root_span_id):
        trace_ids = tuple(getattr(result, "trace_ids", ()))
        root_span_ids = tuple(getattr(result, "root_span_ids", ()))
        if len(trace_ids) == len(root_span_ids) == 1:
            trace_id, root_span_id = trace_ids[0], root_span_ids[0]
    if not valid_review_trace_id(trace_id) or not valid_review_span_id(root_span_id):
        raise ReviewMirrorConflictError("review root returned malformed identity evidence")
    return trace_id, root_span_id


def _finish_before_root(sink: Any) -> None:
    """Close a transport that has not crossed the root-attempt barrier."""
    try:
        sink.finish()
    except Exception as error:
        raise ReviewMirrorError(
            "review transport could not close before any root submission"
        ) from error


def _mark_current_uncertain(
    state: ReviewStateStore,
    *,
    project: str,
    certificate: ReviewTurnCertificate,
    error_code: str,
) -> None:
    current = state.get_ledger(project, certificate.session_id, certificate.turn_key)
    if current is None:  # pragma: no cover - guarded by the preceding journal transition.
        raise ReviewMirrorError("review root journal evidence disappeared")
    if current.status not in {"uncertain", "conflict", "visible"}:
        state.mark_uncertain(current, error_code)


def _submit_and_verify_root(
    *,
    state: ReviewStateStore,
    sink: Any,
    project: str,
    conversation: MappedConversation,
    prepared_turn: _PreparedTurn,
    publication: Any,
    certificate: ReviewTurnCertificate,
    ledger: ReviewLedgerTurn,
) -> tuple[str, str]:
    """Cross the one-way root barrier once, flush, then require exact visibility."""
    submission: Any | None = None
    submit_error: Exception | None = None
    # Persisting this state is the no-retry barrier.  Every later invocation must
    # reconcile by immutable evidence instead of calling submit_root again.
    ledger = state.mark_root_submitting(ledger)
    try:
        submission = sink.submit_root(
            conversation,
            prepared_turn.turn,
            prepared_turn.bundle,
            publication,
            logical_key=certificate.logical_key,
        )
    except Exception as error:  # The call boundary itself makes delivery ambiguous.
        submit_error = error

    finish_error: Exception | None = None
    try:
        sink.finish()
    except Exception as error:
        finish_error = error

    try:
        outcome = sink.verify_root(publication, submission)
        trace_id, root_span_id = _root_evidence(outcome)
    except ReviewMirrorConflictError as error:
        current = state.get_ledger(project, certificate.session_id, certificate.turn_key)
        if current is None:  # pragma: no cover - guarded by the barrier transition.
            raise ReviewMirrorError("review root journal evidence disappeared") from error
        state.mark_conflict(current, "root_evidence_conflict")
        raise
    except Exception as error:
        if submit_error is not None:
            error_code = "root_submission_uncertain"
        elif finish_error is not None:
            error_code = "root_flush_uncertain"
        else:
            error_code = "root_visibility_uncertain"
        _mark_current_uncertain(
            state,
            project=project,
            certificate=certificate,
            error_code=error_code,
        )
        cause = error
        if submit_error is not None:
            cause = submit_error
        elif finish_error is not None:
            cause = finish_error
        raise ReviewMirrorUncertainError(
            "review root delivery is uncertain; automatic retry is forbidden"
        ) from cause

    # Exact query evidence is authoritative even if the transport acknowledgement
    # or flush failed: it proves that this one immutable root is durably visible.
    current = state.get_ledger(project, certificate.session_id, certificate.turn_key)
    if current is None:  # pragma: no cover - guarded by the barrier transition.
        raise ReviewMirrorError("review root journal evidence disappeared")
    state.mark_visible(current, trace_id=trace_id, root_span_id=root_span_id)
    return trace_id, root_span_id


def _new_sink(factory: Callable[[], Any] | None) -> Any:
    if factory is not None:
        return factory()
    from .review_sink import HostedReviewSink

    return HostedReviewSink()


def _apply_prepared_turn(
    *,
    state: ReviewStateStore,
    project: str,
    session: _PreparedCohortSession,
    ordinal: int,
    sink: Any | None,
    sink_factory: Callable[[], Any] | None,
) -> tuple[Any | None, str]:
    """Apply one already-preflighted turn and release its large locals on return."""
    turn = session.prepared.conversation.turns[ordinal]
    bundle = build_review_manifest(session.prepared.conversation, turn)
    prepared_turn = _PreparedTurn(turn=turn, bundle=bundle)
    certificate = session.certificates[ordinal]
    ledger, disposition = state.ensure_ledger(project, certificate)
    if disposition == "conflict" or ledger.status == "conflict":
        raise ReviewMirrorConflictError(
            "changed historical review content conflicts with saved evidence"
        )
    try:
        _validate_rebuilt_bundle(bundle, turn=turn, certificate=certificate)
    except ReviewMirrorConflictError:
        state.mark_conflict(ledger, "turn_rebuild_mismatch")
        raise
    if ledger.status == "visible":
        return sink, "skipped"
    if ledger.status in {"root_submitting", "uncertain"}:
        raise ReviewMirrorUncertainError(
            "a prior review root submission requires exact reconciliation"
        )
    if ledger.status == "planned":
        ledger = state.mark_objects_publishing(ledger)

    if sink is None:
        sink = _new_sink(sink_factory)
    sink.start(project)
    try:
        publication = sink.publish_objects(prepared_turn.bundle)
        evidence = _validate_publication(
            publication,
            conversation_id=session.prepared.conversation.conversation_id,
            turn=prepared_turn.turn,
            bundle=prepared_turn.bundle,
            certificate=certificate,
        )
        ledger = state.mark_objects_verified(ledger, **evidence)
        if ledger.status == "conflict":
            raise ReviewMirrorConflictError(
                "published review object evidence conflicts with private state"
            )
    except ReviewMirrorConflictError:
        _finish_before_root(sink)
        current = state.get_ledger(project, certificate.session_id, certificate.turn_key)
        if current is not None and current.status != "conflict":
            state.mark_conflict(current, "publication_certificate_mismatch")
        raise
    except Exception:
        _finish_before_root(sink)
        raise

    _submit_and_verify_root(
        state=state,
        sink=sink,
        project=project,
        conversation=session.prepared.conversation,
        prepared_turn=prepared_turn,
        publication=publication,
        certificate=certificate,
        ledger=ledger,
    )
    return sink, "visible"


def _mark_failed_cohort(
    state: ReviewStateStore,
    cohort: ReviewCohort,
    *,
    visible: int,
    skipped: int,
    conflicts: int,
    failures: int,
    error_code: str,
) -> None:
    current = state.get_cohort(cohort.cohort_id)
    if current.status == "applying":
        state.finish_cohort(
            current,
            success=False,
            visible_turns=visible,
            skipped_turns=skipped,
            conflicted_turns=conflicts,
            failed_items=failures,
            error_code=error_code,
        )


def _mark_session_preflight_conflict(
    state: ReviewStateStore,
    *,
    project: str,
    session_id: str,
    expected_turns: list[ReviewTurnCertificate],
) -> int:
    """Persist sealed-source drift without storing any source content."""
    marked = 0
    for certificate in expected_turns:
        if certificate.session_id != session_id:
            continue
        ledger, _disposition = state.ensure_ledger(project, certificate)
        if ledger.status != "conflict":
            state.mark_conflict(ledger, "preflight_session_conflict")
        marked += 1
    # Empty ATIF sessions have no turn ledger row.  The blocked cohort remains
    # the durable stop in that rare case.
    return max(1, marked)


def apply_review(
    config: ReviewApplyConfig,
    *,
    hivemind: HiveMindClient | None = None,
    sink_factory: Callable[[], Any] | None = None,
) -> ReviewReport:
    """Apply at most ``max_sessions`` whole sessions from one sealed plan."""
    _validate_review_project(config.confirm_project)
    if not _PLAN_REFERENCE.fullmatch(config.plan_id):
        raise ValueError("review plan reference must be 32 to 64 lowercase hex characters")
    if not 1 <= config.max_sessions <= 10_000:
        raise ValueError("--max-sessions must be between 1 and 10000")
    # Do not turn a machine-level SDK/provenance problem into a durable source
    # conflict or begin a cohort that could never reach the reviewed transport.
    runtime = preflight_review_runtime()

    client = hivemind or HiveMindClient()
    with ReviewStateStore(config.state_path) as state:
        plan = state.resolve_plan(config.plan_id)
        if plan is None:
            raise ReviewMirrorError("review plan was not found in private state")
        if plan.project != config.confirm_project:
            raise ReviewMirrorError("--confirm-project does not match the sealed review plan")
        _assert_sealed_plan_identity(state, plan)
        plan_sessions = state.get_sessions(plan.plan_id)
        cohort = state.get_or_create_cohort(plan.plan_id, config.max_sessions)
        if cohort is None:
            completed, remaining = state.progress(plan.plan_id)
            return ReviewReport(
                phase="apply",
                project=plan.project,
                plan_id=plan.plan_id,
                status=plan.status,
                since_utc=plan.since_utc,
                until_utc=plan.until_utc,
                selector=plan.selector,
                selected_sessions=plan.selected_count,
                completed_sessions=completed,
                remaining_sessions=remaining,
            )
        if cohort.status == "blocked":
            raise ReviewMirrorError("review cohort is blocked; run review reconcile")
        cohort_sessions = state.get_cohort_sessions(cohort.cohort_id)
        expected_turns = state.get_turns(
            plan.plan_id,
            session_ids={item.session_id for item in cohort_sessions},
        )

        client.preflight()
        _assert_plan_source_universe_access(client, plan_sessions)
        cohort = state.begin_cohort(cohort)
        expected_by_session: dict[str, list[ReviewTurnCertificate]] = {
            planned.session_id: [] for planned in cohort_sessions
        }
        for turn in expected_turns:
            expected_by_session[turn.session_id].append(turn)

        visible = 0
        skipped = 0
        conflicts = 0
        sink: Any | None = None
        try:
            # Prove source access and every immutable certificate across the
            # complete cohort before the first sink or hosted object exists.
            # Re-fetch one session at a time to keep peak memory bounded.
            for planned in cohort_sessions:
                try:
                    checked = _prepare_cohort(
                        client=client,
                        plan=plan,
                        cohort_sessions=[planned],
                        expected_turns=expected_by_session[planned.session_id],
                        runtime=runtime,
                    )[0]
                except _CohortPreflightConflict as error:
                    conflicts += _mark_session_preflight_conflict(
                        state,
                        project=plan.project,
                        session_id=error.session_id,
                        expected_turns=expected_by_session[planned.session_id],
                    )
                    raise
                del checked
            for planned in cohort_sessions:
                # Bound peak memory to one source transcript.  Every turn in this
                # session is mapped, redacted, serialized, and certificate-checked
                # before the first object from this session is uploaded.
                try:
                    session = _prepare_cohort(
                        client=client,
                        plan=plan,
                        cohort_sessions=[planned],
                        expected_turns=expected_by_session[planned.session_id],
                        runtime=runtime,
                    )[0]
                except _CohortPreflightConflict as error:
                    conflicts += _mark_session_preflight_conflict(
                        state,
                        project=plan.project,
                        session_id=error.session_id,
                        expected_turns=expected_by_session[planned.session_id],
                    )
                    raise
                for ordinal in range(len(session.prepared.conversation.turns)):
                    sink, disposition = _apply_prepared_turn(
                        state=state,
                        project=plan.project,
                        session=session,
                        ordinal=ordinal,
                        sink=sink,
                        sink_factory=sink_factory,
                    )
                    if disposition == "visible":
                        visible += 1
                    else:
                        skipped += 1
                del session
            plan = state.finish_cohort(
                cohort,
                success=True,
                visible_turns=visible,
                skipped_turns=skipped,
                conflicted_turns=0,
                failed_items=0,
            )
        except ReviewMirrorUncertainError:
            _mark_failed_cohort(
                state,
                cohort,
                visible=visible,
                skipped=skipped,
                conflicts=conflicts,
                failures=1,
                error_code="root_uncertain",
            )
            raise
        except ReviewMirrorConflictError:
            _mark_failed_cohort(
                state,
                cohort,
                visible=visible,
                skipped=skipped,
                conflicts=max(1, conflicts),
                failures=0,
                error_code="review_conflict",
            )
            raise
        finally:
            if sink is not None:
                with suppress(Exception):
                    sink.finish()
        completed, remaining = state.progress(plan.plan_id)
        return ReviewReport(
            phase="apply",
            project=plan.project,
            plan_id=plan.plan_id,
            status=plan.status,
            since_utc=plan.since_utc,
            until_utc=plan.until_utc,
            selector=plan.selector,
            selected_sessions=plan.selected_count,
            completed_sessions=completed,
            remaining_sessions=remaining,
            visible_turns=visible,
            skipped_turns=skipped,
        )


def _match_count(result: Any) -> tuple[int, str, str]:
    matches = getattr(result, "matches", None)
    trace_ids = tuple(getattr(result, "trace_ids", ()))
    root_span_ids = tuple(getattr(result, "root_span_ids", ()))
    if matches is None:
        matches = len(trace_ids)
    if type(matches) is not int or matches < 0:
        raise ReviewMirrorUncertainError("review root query returned malformed match evidence")
    span_count = getattr(result, "span_count", matches)
    if type(span_count) is not int or span_count < 0:
        raise ReviewMirrorUncertainError("review root query returned malformed span evidence")
    if matches == 1 and (span_count != 1 or len(trace_ids) != 1 or len(root_span_ids) != 1):
        raise ReviewMirrorConflictError(
            "review root query returned inconsistent exact-match evidence"
        )
    if matches == 1:
        if not valid_review_trace_id(trace_ids[0]) or not valid_review_span_id(root_span_ids[0]):
            raise ReviewMirrorConflictError(
                "review root query returned malformed identity evidence"
            )
        return matches, trace_ids[0], root_span_ids[0]
    return matches, "", ""


def _ledger_matches_certificate(
    ledger: ReviewLedgerTurn,
    certificate: ReviewTurnCertificate,
) -> bool:
    return (
        ledger.session_id == certificate.session_id
        and ledger.turn_key == certificate.turn_key
        and ledger.source_payload_sha256 == certificate.source_payload_sha256
        and ledger.manifest_sha256 == certificate.manifest_sha256
        and ledger.logical_key == certificate.logical_key
        and ledger.preview_signature == certificate.preview_signature
        and ledger.manifest_bytes == certificate.manifest_bytes
        and ledger.chunk_count == certificate.chunk_count
        and len(ledger.chunk_refs)
        == len(ledger.chunk_hashes)
        == len(ledger.chunk_sizes)
        == certificate.chunk_count
        and bool(ledger.index_ref)
        and ledger.index_size > 0
        and ledger.index_sha256 in ledger.index_ref
        and all(
            digest in reference
            for reference, digest in zip(
                ledger.chunk_refs,
                ledger.chunk_hashes,
                strict=True,
            )
        )
    )


def reconcile_review(
    config: ReviewReconcileConfig,
    *,
    sink_factory: Callable[[], Any] | None = None,
) -> ReviewReport:
    """Resolve ambiguous roots by exact read-only Agents queries; never retry them."""
    _validate_review_project(REVIEW_PROJECT)
    if not _PLAN_REFERENCE.fullmatch(config.plan_id):
        raise ValueError("review plan reference must be 32 to 64 lowercase hex characters")
    with ReviewStateStore(config.state_path) as state:
        plan = state.resolve_plan(config.plan_id)
        if plan is None:
            raise ReviewMirrorError("review plan was not found in private state")
        if plan.project != REVIEW_PROJECT:
            raise ReviewMirrorError("sealed review plan does not target the fixed review project")
        _assert_sealed_plan_identity(state, plan)
        pending = state.reconcilable_turns(plan.plan_id)
        uncertain = 0
        conflicts = 0
        visible = 0
        if pending:
            sink = _new_sink(sink_factory)
            try:
                sink.start_read_only(plan.project)
                certificates = {
                    (item.session_id, item.turn_key): item for item in state.get_turns(plan.plan_id)
                }
                for ledger in pending:
                    certificate = certificates.get((ledger.session_id, ledger.turn_key))
                    if certificate is None or not _ledger_matches_certificate(ledger, certificate):
                        state.mark_conflict(ledger, "reconcile_certificate_mismatch")
                        conflicts += 1
                        continue
                    try:
                        result = sink.find_roots(
                            conversation_id=f"hivemind:{ledger.session_id}",
                            logical_key=ledger.logical_key,
                            manifest_ref=ledger.index_ref,
                            preview_signature=ledger.preview_signature,
                            started_at=certificate.started_at,
                            ended_at=certificate.ended_at,
                        )
                        matches, trace_id, root_span_id = _match_count(result)
                    except ReviewMirrorConflictError:
                        state.mark_conflict(ledger, "root_evidence_conflict")
                        conflicts += 1
                        continue
                    except ReviewMirrorUncertainError:
                        if ledger.status == "root_submitting":
                            state.mark_uncertain(ledger, "root_query_unresolved")
                        uncertain += 1
                        continue
                    if matches == 1:
                        state.mark_visible(ledger, trace_id=trace_id, root_span_id=root_span_id)
                        visible += 1
                    elif matches == 0:
                        if ledger.status == "root_submitting":
                            state.mark_uncertain(ledger, "root_absence_unresolved")
                        uncertain += 1
                    else:
                        state.mark_conflict(ledger, "multiple_root_matches")
                        conflicts += 1
            finally:
                sink.finish()
        if plan.last_error_code == "root_uncertain":
            state.resume_after_reconcile(plan.plan_id)
        refreshed = state.resolve_plan(plan.plan_id)
        assert refreshed is not None
        completed, remaining = state.progress(plan.plan_id)
        return ReviewReport(
            phase="reconcile",
            project=refreshed.project,
            plan_id=refreshed.plan_id,
            status=refreshed.status,
            since_utc=refreshed.since_utc,
            until_utc=refreshed.until_utc,
            selector=refreshed.selector,
            selected_sessions=refreshed.selected_count,
            completed_sessions=completed,
            remaining_sessions=remaining,
            visible_turns=visible,
            uncertain_turns=uncertain,
            conflicted_turns=conflicts,
        )


def review_status(state_path: Path, *, project: str = REVIEW_PROJECT) -> str:
    _validate_review_project(project)
    try:
        state_path.lstat()
    except FileNotFoundError:
        # Status is observational. An empty machine must not acquire a lock,
        # create a private directory, or materialize a new SQLite journal just
        # to report that no review work exists yet.
        status = ReviewStatus(
            plans=0,
            queued_sessions=0,
            completed_sessions=0,
            planned_turns=0,
            objects_publishing=0,
            objects_verified=0,
            root_submitting=0,
            visible=0,
            uncertain=0,
            conflicted=0,
        )
    else:
        with ReviewStateStore(state_path) as state:
            status = state.status(project)
    return "\n".join(
        [
            "Review mirror status:",
            f"  project:              {project}",
            f"  sealed plans:         {status.plans}",
            f"  queued sessions:      {status.queued_sessions}",
            f"  completed sessions:   {status.completed_sessions}",
            f"  planned turns:        {status.planned_turns}",
            f"  objects publishing:   {status.objects_publishing}",
            f"  objects verified:     {status.objects_verified}",
            f"  roots submitting:     {status.root_submitting}",
            f"  visible turns:        {status.visible}",
            f"  uncertain turns:      {status.uncertain}",
            f"  conflicted turns:     {status.conflicted}",
        ]
    )
