"""Exact, content-free planning for bounded HiveMind historical backfills."""

from __future__ import annotations

import hashlib
import math
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .atif import map_atif
from .errors import ATIFSchemaError, BackfillError, StateConflictError
from .historical_sink import HistoricalTurnSink, PreparedOutcome
from .hivemind import HiveMindClient
from .importer import ImportConfig, run_import
from .models import MappedConversation, RunReport, Session
from .pii import sanitize_mapped_conversation
from .redaction import redact_string
from .state import (
    BackfillCohort,
    BackfillPlan,
    BackfillPlanSession,
    BackfillPlanStats,
    BackfillPlanTurn,
    StateStore,
)
from .utils import isoformat_z, sha256_json

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AGENT_FILTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_REPOSITORY_FILTER = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
_SESSION_FILTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_MAX_WINDOW = timedelta(days=365)
_IDLE_GRACE = timedelta(minutes=10)


@dataclass(frozen=True)
class BackfillWindow:
    since_utc: datetime
    until_utc: datetime
    timezone_name: str


@dataclass(frozen=True)
class BackfillPreviewConfig:
    project: str
    state_path: Path
    since: str | None = None
    until: str | None = None
    days: int | None = None
    timezone_name: str | None = None
    canary: bool = False
    agents: tuple[str, ...] = ()
    repositories: tuple[str, ...] = ()
    session_ids: tuple[str, ...] = ()
    exclude_subagents: bool = False
    now: datetime | None = None


@dataclass(frozen=True)
class BackfillApplyConfig:
    project: str
    confirm_project: str
    plan_id: str
    state_path: Path
    max_sessions: int = 1


@dataclass(frozen=True)
class BackfillReport:
    phase: str
    project: str
    plan_id: str
    since_utc: datetime
    until_utc: datetime
    selector: str
    status: str
    discovered: int = 0
    eligible: int = 0
    deferred: int = 0
    invalid: int = 0
    selected: int = 0
    completed_sessions: int = 0
    remaining_sessions: int = 0
    cohort_id: str = ""
    cohort_sessions: int = 0
    imported_turns: int = 0
    skipped_turns: int = 0
    conflicted_turns: int = 0
    failed_items: int = 0
    emitted_spans: int = 0
    certified_turns: int = 0
    compressed_bytes: int = 0
    max_compressed_bytes: int = 0
    uncompressed_bytes: int = 0
    max_uncompressed_bytes: int = 0
    reference_count: int = 0
    max_span_count: int = 0
    compressed_le_64k: int = 0
    compressed_le_256k: int = 0
    compressed_le_1m: int = 0
    compressed_gt_1m: int = 0
    uncompressed_le_256k: int = 0
    uncompressed_le_1m: int = 0
    uncompressed_le_5m: int = 0
    uncompressed_gt_5m: int = 0

    @property
    def ok(self) -> bool:
        return self.conflicted_turns == 0 and self.failed_items == 0

    def render(self) -> str:
        """Render only identifiers, timestamps, and aggregate counters."""
        lines = [
            f"Backfill {self.phase}:",
            f"  project:              {self.project}",
            f"  plan alias:           {self.plan_id[:12]}",
            "  UTC window:           "
            f"[{isoformat_z(self.since_utc)}, {isoformat_z(self.until_utc)})",
            f"  selector:             {self.selector}",
            f"  status:               {self.status}",
            f"  selected sessions:    {self.selected}",
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
                    f"  certified turns:      {self.certified_turns}",
                    f"  compressed bytes:     {self.compressed_bytes}",
                    f"  max compressed bytes: {self.max_compressed_bytes}",
                    f"  uncompressed bytes:   {self.uncompressed_bytes}",
                    f"  max raw bytes:        {self.max_uncompressed_bytes}",
                    f"  content references:   {self.reference_count}",
                    f"  max spans per turn:   {self.max_span_count}",
                    "  compressed buckets:   "
                    f"<=64KiB {self.compressed_le_64k}, "
                    f"64-256KiB {self.compressed_le_256k}, "
                    f"256KiB-1MiB {self.compressed_le_1m}, >1MiB {self.compressed_gt_1m}",
                    "  raw-size buckets:     "
                    f"<=256KiB {self.uncompressed_le_256k}, "
                    f"256KiB-1MiB {self.uncompressed_le_1m}, "
                    f"1-5MiB {self.uncompressed_le_5m}, >5MiB {self.uncompressed_gt_5m}",
                ]
            )
        else:
            lines.extend(
                [
                    f"  cohort alias:         {self.cohort_id[:12] if self.cohort_id else '-'}",
                    f"  cohort sessions:      {self.cohort_sessions}",
                    f"  imported turns:       {self.imported_turns}",
                    f"  skipped turns:        {self.skipped_turns}",
                    f"  conflicted turns:     {self.conflicted_turns}",
                    f"  failed items:         {self.failed_items}",
                    f"  emitted spans:        {self.emitted_spans}",
                ]
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class _Selection:
    sessions: list[Session]
    discovered: int
    eligible: int
    deferred: int
    invalid: int
    universe_sha256: str


@dataclass(frozen=True)
class _TurnCertificate:
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
class _PreparedSession:
    session: Session
    conversation: MappedConversation
    certificates: tuple[_TurnCertificate, ...]


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(UTC)


def _parse_bound(value: str, *, label: str, timezone: ZoneInfo) -> tuple[datetime, bool]:
    candidate = value.strip()
    if _DATE_ONLY.fullmatch(candidate):
        try:
            parsed_date = date.fromisoformat(candidate)
        except ValueError as error:
            raise ValueError(f"{label} is not a valid calendar date") from error
        local = datetime.combine(parsed_date, time.min, tzinfo=timezone)
        round_trip = local.astimezone(UTC).astimezone(timezone)
        if round_trip.date() != parsed_date or round_trip.time().replace(tzinfo=None) != time.min:
            raise ValueError(f"{label} does not have a stable local midnight")
        return local.astimezone(UTC), True
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 date or offset timestamp") from error
    return _aware_utc(parsed, label=label), False


def _local_iana_timezone_name() -> str:
    local_tz = datetime.now().astimezone().tzinfo
    key = getattr(local_tz, "key", None)
    if isinstance(key, str) and key:
        try:
            ZoneInfo(key)
        except ZoneInfoNotFoundError:
            pass
        else:
            return key
    try:
        localtime = Path("/etc/localtime").resolve(strict=True)
    except OSError:
        localtime = None
    if localtime is not None:
        marker = "zoneinfo/"
        resolved = str(localtime)
        if marker in resolved:
            candidate = resolved.split(marker, 1)[1]
            try:
                ZoneInfo(candidate)
            except ZoneInfoNotFoundError:
                pass
            else:
                return candidate
    raise ValueError(
        "the machine's local IANA timezone could not be determined; pass --timezone explicitly"
    )


def resolve_backfill_window(
    *,
    since: str | None,
    until: str | None,
    days: int | None,
    timezone_name: str | None,
    now: datetime | None = None,
) -> BackfillWindow:
    """Resolve an inclusive-lower/exclusive-upper window exactly once.

    Date-only values denote local midnight in ``timezone_name``. ``--days`` is
    calendar-day arithmetic when paired with a date-only ``--until`` and exact
    24-hour arithmetic when paired with an offset timestamp or the current time.
    """
    if (since is None) == (days is None):
        raise ValueError("exactly one of --since or --days is required")
    if days is not None and not 1 <= days <= 365:
        raise ValueError("--days must be between 1 and 365")
    resolved_timezone_name = timezone_name.strip() if timezone_name is not None else ""
    if not resolved_timezone_name:
        resolved_timezone_name = _local_iana_timezone_name()
    try:
        timezone = ZoneInfo(resolved_timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValueError("--timezone must name an installed IANA timezone") from error

    captured_now = _aware_utc(now or datetime.now(UTC), label="current time").replace(microsecond=0)
    if until is None:
        until_utc = captured_now
        until_is_date = False
    else:
        until_utc, until_is_date = _parse_bound(
            until,
            label="--until",
            timezone=timezone,
        )
    if until_utc > captured_now:
        raise ValueError("--until cannot be in the future")

    if since is not None:
        since_utc, _since_is_date = _parse_bound(
            since,
            label="--since",
            timezone=timezone,
        )
    elif until_is_date:
        local_until = until_utc.astimezone(timezone)
        since_utc = (local_until - timedelta(days=days or 0)).astimezone(UTC)
    else:
        since_utc = until_utc - timedelta(days=days or 0)

    if since_utc >= until_utc:
        raise ValueError("backfill window must have --since earlier than --until")
    if until_utc - since_utc > _MAX_WINDOW:
        raise ValueError("backfill window cannot exceed 365 exact days")
    if since_utc < captured_now - _MAX_WINDOW:
        raise ValueError("--since is outside HiveMind's supported 365-day lookback")
    return BackfillWindow(
        since_utc=since_utc,
        until_utc=until_utc,
        timezone_name=resolved_timezone_name,
    )


def _principal_sha256(user_id: str) -> str:
    return hashlib.sha256(f"hivemind-user-v1\0{user_id}".encode()).hexdigest()


def _server_lookback_days(window: BackfillWindow, now: datetime) -> int:
    age = max(timedelta(0), now - window.since_utc)
    return min(365, max(1, math.ceil(age.total_seconds() / 86_400) + 1))


def _normalize_filter_values(
    values: tuple[str, ...],
    *,
    option: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> tuple[str, ...]:
    if len(values) > maximum:
        raise ValueError(f"{option} has too many values")
    normalized = tuple(value.strip() for value in values)
    if any(
        not value
        or not pattern.fullmatch(value)
        or value.startswith("-")
        or redact_string(value) != value
        for value in normalized
    ):
        raise ValueError(f"{option} values must use bounded, credential-free ASCII identifiers")
    return tuple(sorted(set(normalized)))


def _normalized_filters(config: BackfillPreviewConfig) -> dict[str, Any]:
    return {
        "agents": _normalize_filter_values(
            config.agents,
            option="--agent",
            pattern=_AGENT_FILTER,
            maximum=64,
        ),
        "repositories": _normalize_filter_values(
            config.repositories,
            option="--repo",
            pattern=_REPOSITORY_FILTER,
            maximum=512,
        ),
        "session_ids": _normalize_filter_values(
            config.session_ids,
            option="--session-id",
            pattern=_SESSION_FILTER,
            maximum=10_000,
        ),
        "exclude_subagents": bool(config.exclude_subagents),
    }


def _filter_rows(filters: dict[str, Any]) -> list[tuple[str, str]]:
    rows = [
        *(("agent", value) for value in filters["agents"]),
        *(("repository", value) for value in filters["repositories"]),
        *(("session", value) for value in filters["session_ids"]),
    ]
    if filters["exclude_subagents"]:
        rows.append(("exclude_subagents", "true"))
    return sorted(rows)


def _select_sessions(
    raw_sessions: list[dict[str, Any]],
    *,
    window: BackfillWindow,
    filters: dict[str, Any],
    settled_before: datetime,
) -> _Selection:
    parsed_by_id: dict[str, Session] = {}
    invalid = 0
    deferred = 0
    for raw in raw_sessions:
        try:
            session = Session.from_api(raw)
        except ATIFSchemaError:
            invalid += 1
            continue
        previous = parsed_by_id.get(session.id)
        if previous is not None:
            if previous != session:
                raise BackfillError(
                    "HiveMind returned inconsistent duplicate session summaries; no plan was saved"
                )
            continue
        parsed_by_id[session.id] = session

    eligible: list[Session] = []
    for session in parsed_by_id.values():
        if not session.last_activity_known:
            deferred += 1
            continue
        if not (window.since_utc <= session.last_activity_at < window.until_utc):
            continue
        if session.last_activity_at > settled_before:
            deferred += 1
            continue
        if filters["agents"] and session.agent_type not in filters["agents"]:
            continue
        if filters["repositories"] and session.repository not in filters["repositories"]:
            continue
        if filters["session_ids"] and session.id not in filters["session_ids"]:
            continue
        if filters["exclude_subagents"] and session.parent_session_id:
            continue
        eligible.append(session)
    eligible.sort(key=lambda item: (item.last_activity_at, item.id))
    requested_ids = set(filters["session_ids"])
    matched_ids = {item.id for item in eligible}
    if requested_ids - matched_ids:
        raise BackfillError(
            "one or more exact --session-id filters did not match the sealed window and "
            "other filters; no plan was saved"
        )
    universe_payload = [
        {
            "session_id": item.id,
            "started_at": isoformat_z(item.started_at),
            "last_activity_at": isoformat_z(item.last_activity_at),
        }
        for item in eligible
    ]
    universe_sha256 = sha256_json(universe_payload)
    return _Selection(
        sessions=list(eligible),
        discovered=len(raw_sessions),
        eligible=len(eligible),
        deferred=deferred,
        invalid=invalid,
        universe_sha256=universe_sha256,
    )


def _plan_id(
    *,
    config: BackfillPreviewConfig,
    window: BackfillWindow,
    source_principal_sha256: str,
    selection: _Selection,
    filters: dict[str, Any],
    certificates: list[_TurnCertificate],
    stats_payload: dict[str, int],
) -> str:
    return sha256_json(
        {
            "schema": "hivemind-weave-backfill-plan-v2",
            "importer_version": __version__,
            "project": config.project,
            "source_principal_sha256": source_principal_sha256,
            "since_utc": isoformat_z(window.since_utc),
            "until_utc": isoformat_z(window.until_utc),
            "timezone_name": window.timezone_name,
            "selector": "canary" if config.canary else "backlog",
            "idle_grace_seconds": int(_IDLE_GRACE.total_seconds()),
            "filters": filters,
            "universe_sha256": selection.universe_sha256,
            "sessions": [
                {
                    "ordinal": ordinal,
                    "session_id": item.id,
                    "started_at": isoformat_z(item.started_at),
                    "last_activity_at": isoformat_z(item.last_activity_at),
                }
                for ordinal, item in enumerate(selection.sessions)
            ],
            "turn_certificates": [
                {
                    "session_id": item.session_id,
                    "ordinal": item.ordinal,
                    "turn_key": item.turn_key,
                    "source_payload_sha256": item.source_payload_sha256,
                    "wire_sha256": item.wire_sha256,
                    "logical_key": item.logical_key,
                    "span_count": item.span_count,
                    "compressed_bytes": item.compressed_bytes,
                    "uncompressed_bytes": item.uncompressed_bytes,
                    "reference_count": item.reference_count,
                    "capability_version": item.capability_version,
                    "atif_schema_version": item.atif_schema_version,
                }
                for item in certificates
            ],
            "size_distribution": stats_payload,
        }
    )


def _validate_prepared_outcome(outcome: PreparedOutcome) -> None:
    if (
        not _HEX_SHA256.fullmatch(outcome.wire_sha256)
        or not _HEX_SHA256.fullmatch(outcome.logical_key)
        or outcome.span_count <= 0
        or outcome.compressed_bytes <= 0
        or outcome.uncompressed_bytes <= 0
        or outcome.reference_count < 0
        or not outcome.capability_version
    ):
        raise BackfillError("historical-turn preparation returned incomplete content-free evidence")


def _prepare_session(
    client: HiveMindClient,
    sink: HistoricalTurnSink,
    session: Session,
    *,
    wrapper: dict[str, Any] | None = None,
) -> _PreparedSession:
    if wrapper is None:
        before = Session.from_api(client.get_session(session.id))
        if not _same_session_snapshot(session, before):
            raise BackfillError(
                "a selected session changed before transcript preparation; no plan was saved"
            )
        transcript = client.get_atif(session.id)
    else:
        transcript = wrapper
    after = Session.from_api(client.get_session(session.id))
    if not _same_session_snapshot(session, after):
        raise BackfillError(
            "a selected session changed during transcript preparation; no plan was saved"
        )
    conversation = sanitize_mapped_conversation(map_atif(session, transcript))
    certificates: list[_TurnCertificate] = []
    for ordinal, turn in enumerate(conversation.turns):
        outcome = sink.prepare_turn(conversation, turn)
        _validate_prepared_outcome(outcome)
        source_hash = str(
            turn.attributes.get("hivemind.source_payload_sha256") or turn.payload_sha256
        )
        if not _HEX_SHA256.fullmatch(source_hash):
            raise BackfillError("mapped turn did not retain a stable source hash")
        certificates.append(
            _TurnCertificate(
                session_id=session.id,
                ordinal=ordinal,
                turn_key=turn.key,
                source_payload_sha256=source_hash,
                wire_sha256=outcome.wire_sha256,
                logical_key=outcome.logical_key,
                span_count=outcome.span_count,
                compressed_bytes=outcome.compressed_bytes,
                uncompressed_bytes=outcome.uncompressed_bytes,
                reference_count=outcome.reference_count,
                capability_version=outcome.capability_version,
                atif_schema_version=conversation.schema_version,
            )
        )
    return _PreparedSession(
        session=session,
        conversation=conversation,
        certificates=tuple(certificates),
    )


def _same_session_snapshot(expected: Session, observed: Session) -> bool:
    return (
        observed.id == expected.id
        and observed.last_activity_known
        and observed.started_at == expected.started_at
        and observed.last_activity_at == expected.last_activity_at
    )


def _advertised_limit(capabilities: Any, *names: str) -> int | None:
    for name in names:
        value = getattr(capabilities, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _within_advertised_budgets(
    sink: HistoricalTurnSink,
    certificates: tuple[_TurnCertificate, ...],
) -> bool:
    capabilities = getattr(sink, "capabilities", None)
    if capabilities is None:
        return False
    limits = (
        (
            _advertised_limit(
                capabilities,
                "max_turn_compressed_bytes",
                "max_compressed_bytes",
                "max_request_compressed_bytes",
            ),
            (item.compressed_bytes for item in certificates),
        ),
        (
            _advertised_limit(
                capabilities,
                "max_turn_uncompressed_bytes",
                "max_uncompressed_bytes",
                "max_decompressed_bytes",
                "max_envelope_bytes",
            ),
            (item.uncompressed_bytes for item in certificates),
        ),
        (
            _advertised_limit(
                capabilities,
                "max_turn_span_count",
                "max_span_count",
                "max_spans",
            ),
            (item.span_count for item in certificates),
        ),
        (
            _advertised_limit(
                capabilities,
                "max_turn_reference_count",
                "max_reference_count",
                "max_references",
            ),
            (item.reference_count for item in certificates),
        ),
    )
    return all(
        limit is not None and all(value <= limit for value in values) for limit, values in limits
    )


def _canary_qualifies(
    prepared: _PreparedSession,
    *,
    sink: HistoricalTurnSink,
    now: datetime,
) -> bool:
    if now - prepared.session.last_activity_at < timedelta(hours=24):
        return False
    if prepared.session.parent_session_id:
        return False
    if not 1 <= len(prepared.conversation.turns) <= 3:
        return False
    if any(item.span_count > 4 for item in prepared.certificates):
        return False
    if any(
        bool(turn.attributes.get("hivemind.mapping_warnings"))
        for turn in prepared.conversation.turns
    ):
        return False
    return _within_advertised_budgets(sink, prepared.certificates)


def _size_stats_payload(certificates: list[_TurnCertificate]) -> dict[str, int]:
    compressed = [item.compressed_bytes for item in certificates]
    uncompressed = [item.uncompressed_bytes for item in certificates]
    references = [item.reference_count for item in certificates]
    spans = [item.span_count for item in certificates]
    return {
        "turn_count": len(certificates),
        "total_compressed_bytes": sum(compressed),
        "max_compressed_bytes": max(compressed, default=0),
        "total_uncompressed_bytes": sum(uncompressed),
        "max_uncompressed_bytes": max(uncompressed, default=0),
        "total_reference_count": sum(references),
        "max_reference_count": max(references, default=0),
        "max_span_count": max(spans, default=0),
        "compressed_le_64k": sum(value <= 64 * 1024 for value in compressed),
        "compressed_le_256k": sum(64 * 1024 < value <= 256 * 1024 for value in compressed),
        "compressed_le_1m": sum(256 * 1024 < value <= 1024 * 1024 for value in compressed),
        "compressed_gt_1m": sum(value > 1024 * 1024 for value in compressed),
        "uncompressed_le_256k": sum(value <= 256 * 1024 for value in uncompressed),
        "uncompressed_le_1m": sum(256 * 1024 < value <= 1024 * 1024 for value in uncompressed),
        "uncompressed_le_5m": sum(1024 * 1024 < value <= 5 * 1024 * 1024 for value in uncompressed),
        "uncompressed_gt_5m": sum(value > 5 * 1024 * 1024 for value in uncompressed),
    }


def _state_stats(plan_id: str, payload: dict[str, int]) -> BackfillPlanStats:
    return BackfillPlanStats(plan_id=plan_id, **payload)


def _state_turns(
    plan_id: str,
    certificates: list[_TurnCertificate],
) -> list[BackfillPlanTurn]:
    return [
        BackfillPlanTurn(
            plan_id=plan_id,
            session_id=item.session_id,
            ordinal=item.ordinal,
            turn_key=item.turn_key,
            source_payload_sha256=item.source_payload_sha256,
            wire_sha256=item.wire_sha256,
            logical_key=item.logical_key,
            span_count=item.span_count,
            compressed_bytes=item.compressed_bytes,
            uncompressed_bytes=item.uncompressed_bytes,
            reference_count=item.reference_count,
            capability_version=item.capability_version,
            atif_schema_version=item.atif_schema_version,
        )
        for item in certificates
    ]


def _report_from_plan(
    plan: BackfillPlan,
    *,
    phase: str,
    completed: int,
    remaining: int,
    stats: BackfillPlanStats,
    cohort: BackfillCohort | None = None,
    run_report: RunReport | None = None,
) -> BackfillReport:
    result = run_report or RunReport()
    return BackfillReport(
        phase=phase,
        project=plan.project,
        plan_id=plan.plan_id,
        since_utc=plan.since_utc,
        until_utc=plan.until_utc,
        selector=plan.selector,
        status=plan.status,
        discovered=plan.discovered_count,
        eligible=plan.eligible_count,
        deferred=plan.deferred_count,
        invalid=plan.invalid_count,
        selected=plan.selected_count,
        completed_sessions=completed,
        remaining_sessions=remaining,
        cohort_id="" if cohort is None else cohort.cohort_id,
        cohort_sessions=0 if cohort is None else cohort.session_count,
        imported_turns=result.imported,
        skipped_turns=result.skipped,
        conflicted_turns=result.conflicted,
        failed_items=result.failed,
        emitted_spans=result.emitted_spans,
        certified_turns=stats.turn_count,
        compressed_bytes=stats.total_compressed_bytes,
        max_compressed_bytes=stats.max_compressed_bytes,
        uncompressed_bytes=stats.total_uncompressed_bytes,
        max_uncompressed_bytes=stats.max_uncompressed_bytes,
        reference_count=stats.total_reference_count,
        max_span_count=stats.max_span_count,
        compressed_le_64k=stats.compressed_le_64k,
        compressed_le_256k=stats.compressed_le_256k,
        compressed_le_1m=stats.compressed_le_1m,
        compressed_gt_1m=stats.compressed_gt_1m,
        uncompressed_le_256k=stats.uncompressed_le_256k,
        uncompressed_le_1m=stats.uncompressed_le_1m,
        uncompressed_le_5m=stats.uncompressed_le_5m,
        uncompressed_gt_5m=stats.uncompressed_gt_5m,
    )


def preview_backfill(
    config: BackfillPreviewConfig,
    *,
    hivemind: HiveMindClient | None = None,
    sink: HistoricalTurnSink | None = None,
) -> BackfillReport:
    ImportConfig(days=1, project=config.project, dry_run=True).validate()
    captured_now = _aware_utc(
        config.now or datetime.now(UTC),
        label="current time",
    ).replace(microsecond=0)
    window = resolve_backfill_window(
        since=config.since,
        until=config.until,
        days=config.days,
        timezone_name=config.timezone_name,
        now=captured_now,
    )
    filters = _normalized_filters(config)
    client = hivemind or HiveMindClient()
    client.preflight()
    if not client.user_id:
        raise BackfillError("HiveMind authentication did not expose a stable source identity")
    principal_hash = _principal_sha256(client.user_id)
    raw_sessions = client.list_sessions(
        days=_server_lookback_days(window, captured_now),
        include_subagents=True,
    )
    selection = _select_sessions(
        raw_sessions,
        window=window,
        filters=filters,
        settled_before=captured_now - _IDLE_GRACE,
    )
    if selection.invalid:
        raise BackfillError(
            "HiveMind returned one or more invalid session summaries; no plan was saved"
        )

    active_sink = sink or HistoricalTurnSink()
    prepared_sessions: list[_PreparedSession] = []
    started = False
    preparation_error: Exception | None = None
    try:
        active_sink.start(config.project)
        started = True
        if config.canary:
            for session in selection.sessions:
                if captured_now - session.last_activity_at < timedelta(hours=24):
                    continue
                if session.parent_session_id:
                    continue
                prepared = _prepare_session(client, active_sink, session)
                if _canary_qualifies(prepared, sink=active_sink, now=captured_now):
                    prepared_sessions = [prepared]
                    break
            if not prepared_sessions:
                raise BackfillError(
                    "no session qualified for the conservative canary; use an exact "
                    "--session-id filter after reviewing the source session"
                )
        else:
            for session in selection.sessions:
                prepared_sessions.append(_prepare_session(client, active_sink, session))
    except Exception as error:
        preparation_error = error
    finally:
        if started:
            try:
                active_sink.finish()
            except Exception as error:
                preparation_error = preparation_error or error
    if preparation_error is not None:
        if isinstance(preparation_error, BackfillError):
            raise preparation_error
        raise BackfillError(
            "one or more selected sessions could not be mapped and prepared exactly; "
            "no plan was saved"
        ) from preparation_error

    selected_sessions = [item.session for item in prepared_sessions]
    selection = _Selection(
        sessions=selected_sessions,
        discovered=selection.discovered,
        eligible=selection.eligible,
        deferred=selection.deferred,
        invalid=selection.invalid,
        universe_sha256=selection.universe_sha256,
    )
    certificates = [
        certificate for prepared in prepared_sessions for certificate in prepared.certificates
    ]
    stats_payload = _size_stats_payload(certificates)
    plan_id = _plan_id(
        config=config,
        window=window,
        source_principal_sha256=principal_hash,
        selection=selection,
        filters=filters,
        certificates=certificates,
        stats_payload=stats_payload,
    )
    state_turns = _state_turns(plan_id, certificates)
    state_stats = _state_stats(plan_id, stats_payload)
    with StateStore(config.state_path) as state:
        plan = state.create_backfill_plan(
            plan_id=plan_id,
            project=config.project,
            source_principal_sha256=principal_hash,
            since_utc=window.since_utc,
            until_utc=window.until_utc,
            timezone_name=window.timezone_name,
            selector="canary" if config.canary else "backlog",
            universe_sha256=selection.universe_sha256,
            sessions=[
                (item.id, item.started_at, item.last_activity_at) for item in selection.sessions
            ],
            filters=_filter_rows(filters),
            turns=state_turns,
            stats=state_stats,
            discovered_count=selection.discovered,
            eligible_count=selection.eligible,
            deferred_count=selection.deferred,
            invalid_count=selection.invalid,
        )
        completed, remaining = state.backfill_progress(plan.plan_id)
    return _report_from_plan(
        plan,
        phase="preview",
        completed=completed,
        remaining=remaining,
        stats=state_stats,
    )


class _PlannedHiveMindClient:
    """Expose only one sealed cohort to the existing importer discovery path."""

    def __init__(
        self,
        summaries: list[dict[str, Any]],
        transcripts: dict[str, dict[str, Any]],
    ) -> None:
        self.summaries = summaries
        self.transcripts = transcripts

    def preflight(self) -> None:
        return None

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        del days, include_subagents
        return list(self.summaries)

    def get_session(self, session_id: str) -> dict[str, Any]:
        for summary in self.summaries:
            if summary.get("id") == session_id:
                return summary
        raise BackfillError("import requested a session outside the sealed cohort")

    def get_atif(self, session_id: str) -> dict[str, Any]:
        try:
            return self.transcripts[session_id]
        except KeyError as error:
            raise BackfillError(
                "import requested a transcript outside the sealed cohort"
            ) from error


def _load_exact_summaries(
    client: HiveMindClient,
    sessions: list[BackfillPlanSession],
    *,
    plan: BackfillPlan,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for expected in sessions:
        raw = client.get_session(expected.session_id)
        current = Session.from_api(raw)
        if (
            current.id != expected.session_id
            or not current.last_activity_known
            or current.started_at != expected.started_at
            or current.last_activity_at != expected.last_activity_at
            or not (plan.since_utc <= current.last_activity_at < plan.until_utc)
        ):
            raise BackfillError(
                "a planned HiveMind session changed after preview; the cohort was not uploaded"
            )
        summaries.append(raw)
    return summaries


def _certificate_identity(item: _TurnCertificate | BackfillPlanTurn) -> tuple[Any, ...]:
    return (
        item.session_id,
        item.ordinal,
        item.turn_key,
        item.source_payload_sha256,
        item.wire_sha256,
        item.logical_key,
        item.span_count,
        item.compressed_bytes,
        item.uncompressed_bytes,
        item.reference_count,
        item.capability_version,
        item.atif_schema_version,
    )


def _reprepare_cohort(
    client: HiveMindClient,
    sink: HistoricalTurnSink,
    summaries: list[dict[str, Any]],
    expected_turns: list[BackfillPlanTurn],
    *,
    project: str,
) -> dict[str, dict[str, Any]]:
    prepared_turns: list[_TurnCertificate] = []
    transcripts: dict[str, dict[str, Any]] = {}
    started = False
    try:
        sink.start(project)
        started = True
        for raw in summaries:
            session = Session.from_api(raw)
            wrapper = client.get_atif(session.id)
            transcripts[session.id] = wrapper
            prepared = _prepare_session(client, sink, session, wrapper=wrapper)
            prepared_turns.extend(prepared.certificates)
    except Exception as error:
        if started:
            with suppress(Exception):
                sink.finish()
        raise BackfillError(
            "the sealed cohort could not be prepared exactly; no upload was attempted"
        ) from error
    if [_certificate_identity(item) for item in prepared_turns] != [
        _certificate_identity(item) for item in expected_turns
    ]:
        with suppress(Exception):
            sink.finish()
        raise BackfillError(
            "prepared historical-turn evidence changed after preview; no upload was attempted"
        )
    # Keep this exact initialized capability snapshot and its cached prepared
    # envelopes alive.  ``run_import`` calls ``start`` again, which is an
    # idempotent same-project no-op, and owns the final teardown.
    return transcripts


def _safe_finish_failure(
    *,
    state_path: Path,
    cohort: BackfillCohort,
    error_code: str,
    report: RunReport | None = None,
) -> None:
    result = report or RunReport(failed=1)
    with StateStore(state_path) as state:
        state.finish_backfill_cohort(
            cohort=cohort,
            success=False,
            imported_turns=result.imported,
            skipped_turns=result.skipped,
            conflicted_turns=result.conflicted,
            failed_items=max(1, result.failed),
            emitted_spans=result.emitted_spans,
            error_code=error_code,
        )


def apply_backfill(
    config: BackfillApplyConfig,
    *,
    hivemind: HiveMindClient | None = None,
    sink: HistoricalTurnSink | None = None,
) -> BackfillReport:
    ImportConfig(days=1, project=config.project, dry_run=True).validate()
    if config.confirm_project != config.project:
        raise ValueError("backfill apply requires --confirm-project to exactly match --project")
    if not re.fullmatch(r"[0-9a-f]{12,64}", config.plan_id):
        raise ValueError("--plan must be a 12-64 character hexadecimal plan reference")
    if not 1 <= config.max_sessions <= 10_000:
        raise ValueError("--max-sessions must be between 1 and 10000")

    with StateStore(config.state_path) as state:
        plan = state.resolve_backfill_plan(config.plan_id)
        if plan is None:
            raise StateConflictError(
                "backfill plan was not found in the selected private state database"
            )
        if plan.project != config.project:
            raise StateConflictError("backfill plan destination does not match --project")
        stats = state.get_backfill_plan_stats(plan.plan_id)
        cohort = state.get_or_create_backfill_cohort(
            plan_id=plan.plan_id,
            max_sessions=config.max_sessions,
        )
        if cohort is None:
            completed, remaining = state.backfill_progress(plan.plan_id)
            return _report_from_plan(
                plan,
                phase="apply",
                completed=completed,
                remaining=remaining,
                stats=stats,
            )
        cohort_sessions = state.get_backfill_cohort_sessions(cohort.cohort_id)
        expected_turns = state.get_backfill_plan_turns(
            plan.plan_id,
            session_ids={item.session_id for item in cohort_sessions},
        )
        cohort = state.begin_backfill_cohort(cohort)

    client = hivemind or HiveMindClient()
    try:
        client.preflight()
        if not client.user_id or _principal_sha256(client.user_id) != plan.source_principal_sha256:
            raise BackfillError(
                "authenticated HiveMind identity does not match the sealed backfill plan"
            )
        summaries = _load_exact_summaries(client, cohort_sessions, plan=plan)
    except Exception as error:
        _safe_finish_failure(
            state_path=config.state_path,
            cohort=cohort,
            error_code="source_drift",
        )
        if isinstance(error, BackfillError):
            raise
        raise BackfillError(
            "the sealed backfill cohort could not be revalidated; no upload was attempted"
        ) from error

    active_sink = sink or HistoricalTurnSink()
    try:
        transcripts = _reprepare_cohort(
            client,
            active_sink,
            summaries,
            expected_turns,
            project=plan.project,
        )
    except Exception as error:
        _safe_finish_failure(
            state_path=config.state_path,
            cohort=cohort,
            error_code="certificate_drift",
        )
        if isinstance(error, BackfillError):
            raise
        raise BackfillError(
            "the sealed cohort certificate could not be revalidated; no upload was attempted"
        ) from error

    duration_days = max(
        1,
        min(365, math.ceil((plan.until_utc - plan.since_utc).total_seconds() / 86_400)),
    )
    import_config = ImportConfig(
        days=duration_days,
        project=plan.project,
        idle_minutes=0,
        state_path=config.state_path,
        confirm_project=config.confirm_project,
        cutoff=plan.until_utc,
        session_ids=frozenset(item.session_id for item in cohort_sessions),
    )
    try:
        run_report = run_import(
            import_config,
            hivemind=_PlannedHiveMindClient(  # type: ignore[arg-type]
                summaries,
                transcripts,
            ),
            sink=active_sink,
        )
        # ``run_import`` normally owns teardown once it submits work.  It may
        # legitimately discover that every certified turn is already committed,
        # in which case it never claims the pre-initialized sink.  Finish that
        # same client here without changing the prepared/apply boundary.
        active_sink.finish()
    except BaseException as error:
        with suppress(Exception):
            active_sink.finish()
        _safe_finish_failure(
            state_path=config.state_path,
            cohort=cohort,
            error_code="import_exception",
        )
        if isinstance(error, KeyboardInterrupt):
            raise
        raise BackfillError(
            "the backfill cohort stopped during import; details remain in private state"
        ) from error

    success = run_report.ok
    error_code = ""
    if run_report.conflicted:
        error_code = "import_conflict"
    elif run_report.failed:
        error_code = "import_failed"
    with StateStore(config.state_path) as state:
        plan = state.finish_backfill_cohort(
            cohort=cohort,
            success=success,
            imported_turns=run_report.imported,
            skipped_turns=run_report.skipped,
            conflicted_turns=run_report.conflicted,
            failed_items=run_report.failed,
            emitted_spans=run_report.emitted_spans,
            error_code=error_code,
        )
        completed, remaining = state.backfill_progress(plan.plan_id)
    return _report_from_plan(
        plan,
        phase="apply",
        completed=completed,
        remaining=remaining,
        stats=stats,
        cohort=cohort,
        run_report=run_report,
    )
