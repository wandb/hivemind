"""End-to-end import orchestration."""

from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .atif import map_atif
from .errors import (
    ATIFSchemaError,
    ImporterError,
    StateConflictError,
    StateStoreError,
    VerificationError,
    WeaveImportError,
)
from .hivemind import HiveMindClient
from .models import MappedConversation, MappedTurn, RunReport, Session
from .pii import configure_weave_pii, sanitize_mapped_conversation
from .state import ImportRun, ImportRunSession, StateRow, StateStore
from .verify import (
    VerificationExpectation,
    WeaveVerifier,
    disabled_weave_error_reporting,
    enforce_weave_error_reporting_disabled,
    resolve_trace_server_url,
    resolve_wandb_base_url,
    validate_live_transport_environment,
)
from .weave_sink import LogOutcome, WeaveSink, expected_turn_span_count

_PROJECT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)


@dataclass(frozen=True)
class ImportConfig:
    days: int
    project: str
    idle_minutes: int = 10
    state_path: Path = Path("~/.hivemind/weave-importer/state.sqlite3")
    dry_run: bool = False
    confirm_project: str = ""
    trace_server_url: str = "https://trace.wandb.ai"
    wandb_base_url: str = "https://api.wandb.ai"
    verification_timeout: float = 60.0
    cutoff: datetime | None = None
    session_ids: frozenset[str] = frozenset()

    def validate(self) -> None:
        if not 1 <= self.days <= 365:
            raise ValueError("--days must be between 1 and 365")
        if self.idle_minutes < 0:
            raise ValueError("--idle-minutes cannot be negative")
        if not _PROJECT.fullmatch(self.project):
            raise ValueError("--project must use a bounded ASCII entity/project slug")
        if not self.dry_run and self.confirm_project != self.project:
            raise ValueError(
                "live import requires --confirm-project to exactly match --project"
            )
        if self.verification_timeout <= 0:
            raise ValueError("verification timeout must be positive")


@dataclass(frozen=True)
class _Candidate:
    conversation: MappedConversation
    turn: MappedTurn
    existing: StateRow | None


@dataclass(frozen=True)
class _Emitted:
    conversation_id: str
    session_id: str
    turn_key: str
    payload_sha256: str
    verification_signature: str
    outcome: LogOutcome
    state_row: StateRow


def _expected_span_count(turn: MappedTurn, *, recorded_span_count: int = 0) -> int:
    # A successfully journaled emission is authoritative even if transport
    # thresholds change in a future importer. Crash recovery before that write
    # uses the deterministic plan for the currently mapped payload.
    return recorded_span_count or expected_turn_span_count(turn)


def _safe_error(error: Exception) -> str:
    # Domain errors are already constructed without transcript bodies.
    if isinstance(error, ImporterError):
        return str(error)[:500]
    return error.__class__.__name__


def _record_error_best_effort(
    state: StateStore,
    *,
    row: StateRow,
    error: str,
) -> None:
    """Journal an error without masking the failure that prompted the write."""
    with suppress(sqlite3.Error, StateConflictError):
        state.record_error(row=row, error=error)


def _select_sessions(
    raw_sessions: list[dict[str, Any]],
    *,
    config: ImportConfig,
    cutoff: datetime,
    report: RunReport,
) -> list[Session]:
    lower_bound = cutoff - timedelta(days=config.days)
    idle_bound = cutoff - timedelta(minutes=config.idle_minutes)
    selected: list[Session] = []
    for raw in raw_sessions:
        try:
            session = Session.from_api(raw)
        except ATIFSchemaError as error:
            report.failed += 1
            report.errors.append(str(error))
            continue
        if config.session_ids and session.id not in config.session_ids:
            continue
        if not session.last_activity_known:
            report.deferred += 1
            continue
        if session.last_activity_at < lower_bound:
            continue
        if session.last_activity_at > idle_bound:
            report.deferred += 1
            continue
        selected.append(session)
    selected.sort(key=lambda item: (item.started_at, item.id))
    report.eligible = len(selected)
    return selected


def _map_sessions(
    client: HiveMindClient,
    sessions: list[Session],
    report: RunReport,
) -> Iterator[MappedConversation]:
    """Map one session at a time so transcript memory is bounded per session."""
    for session in sessions:
        try:
            wrapper = client.get_atif(session.id)
            conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
        except ImporterError as error:
            report.failed += 1
            report.errors.append(f"session {session.id}: {_safe_error(error)}")
            continue
        except Exception as error:
            report.failed += 1
            report.errors.append(
                f"session {session.id}: required PII redaction failed ({error.__class__.__name__})"
            )
            continue
        # The raw wrapper can be much larger than the mapped turn graph. Do not
        # retain both objects while the caller uploads this session.
        del wrapper
        report.planned += len(conversation.turns)
        yield conversation
        # A suspended generator otherwise keeps its most recently yielded
        # conversation alive while the next transcript is fetched and mapped.
        del conversation


def _prepend_conversation(
    first: MappedConversation,
    remaining: Iterator[MappedConversation],
) -> Iterator[MappedConversation]:
    """Prepend one item without an itertools args tuple retaining it forever."""
    yield first
    del first
    yield from remaining


def _next_nonempty_conversation(
    conversations: Iterator[MappedConversation],
) -> MappedConversation | None:
    for conversation in conversations:
        if conversation.turns:
            return conversation
        del conversation
    return None


def _has_recorded_emission(row: StateRow) -> bool:
    return bool(row.trace_ids or row.root_span_ids or row.span_count)


def _source_payload_hash(row: StateRow) -> str:
    return row.source_payload_sha256 or row.payload_sha256


def _recover_unemitted_payload(
    *,
    conversation: MappedConversation,
    turn: MappedTurn,
    existing: StateRow,
    config: ImportConfig,
    state: StateStore,
    verifier: WeaveVerifier,
    report: RunReport,
) -> _Candidate | None:
    """Reconcile and replace a changed journal entry that has no emission IDs.

    A local validation failure can leave a pending row before the SDK is called.
    The source transcript may then finish changing, or an importer fix may alter
    its redacted payload. Confirm absence of the old and new hashes remotely
    before replacing that journal row. This uses the same bounded absence proof
    as ordinary crash recovery and never rewrites a row with emission evidence.
    """
    session_id = conversation.conversation_id.removeprefix("hivemind:")
    old_hash = existing.payload_sha256
    new_hash = turn.payload_sha256
    try:
        old_remote = verifier.reconcile(
            conversation_id=conversation.conversation_id,
            expected_trace_ids=[],
            turn_key=turn.key,
            payload_sha256=old_hash,
            verification_signature=existing.verification_signature,
            expected_span_count=0,
            timeout_seconds=config.verification_timeout,
        )
        if old_hash != new_hash and old_remote.matches:
            state.mark_conflict(
                row=existing,
                new_payload_sha256=new_hash,
                error="the previously journaled payload is visible remotely",
            )
            report.conflicted += 1
            report.errors.append(
                f"session {session_id} turn {turn.key} changed after remote emission"
            )
            return None

        new_remote = (
            old_remote
            if old_hash == new_hash
            else verifier.reconcile(
                conversation_id=conversation.conversation_id,
                expected_trace_ids=[],
                turn_key=turn.key,
                payload_sha256=new_hash,
                verification_signature=turn.verification_signature,
                expected_span_count=_expected_span_count(turn),
                timeout_seconds=config.verification_timeout,
            )
        )
    except VerificationError as error:
        report.failed += 1
        report.errors.append(
            f"session {session_id} turn {turn.key} could not prove remote absence: {error}"
        )
        return None

    if new_remote.matches > 1:
        state.mark_conflict(
            row=existing,
            new_payload_sha256=new_hash,
            error="multiple remote turns matched during pending-payload recovery",
        )
        report.conflicted += 1
        report.errors.append(f"session {session_id} turn {turn.key} matched multiple remote turns")
        return None

    refreshed = state.replace_unemitted_pending_payload(
        row=existing,
        payload_sha256=new_hash,
        verification_signature=turn.verification_signature,
        source_last_activity_at=conversation.source_last_activity_at,
        atif_schema_version=conversation.schema_version,
    )
    if new_remote.matches == 1:
        state.mark_committed(
            row=refreshed,
            trace_ids=new_remote.trace_ids,
            root_span_ids=new_remote.root_span_ids or None,
            span_count=new_remote.span_count,
        )
        report.skipped += 1
        return None
    return _Candidate(conversation, turn, refreshed)


def _classify_candidates(
    *,
    conversations: list[MappedConversation],
    config: ImportConfig,
    state: StateStore,
    verifier: WeaveVerifier | None,
    report: RunReport,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for conversation in conversations:
        session_id = conversation.conversation_id.removeprefix("hivemind:")
        for turn in conversation.turns:
            existing = state.get(config.project, session_id, turn.key)
            if existing is None:
                candidates.append(_Candidate(conversation, turn, None))
                continue
            # A legacy row without stable source identity cannot prove that the
            # currently fetched history is what was originally uploaded. Never
            # bless current content merely because the remote correlator exists.
            if not existing.source_payload_sha256:
                state.mark_conflict(
                    row=existing,
                    new_payload_sha256=turn.payload_sha256,
                    error="legacy turn lacks a provable stable source identity",
                )
                report.conflicted += 1
                report.errors.append(
                    f"session {session_id} turn {turn.key} has unprovable legacy history"
                )
                continue
            if _source_payload_hash(existing) != turn.payload_sha256:
                if existing.status in {"pending", "conflict"} and not _has_recorded_emission(
                    existing
                ):
                    if verifier is None:
                        raise WeaveImportError(
                            "WANDB_API_KEY is not set; changed pending uploads require remote "
                            "reconciliation"
                        )
                    recovered = _recover_unemitted_payload(
                        conversation=conversation,
                        turn=turn,
                        existing=existing,
                        config=config,
                        state=state,
                        verifier=verifier,
                        report=report,
                    )
                    if recovered is not None:
                        candidates.append(recovered)
                    continue
                state.mark_conflict(
                    row=existing,
                    new_payload_sha256=turn.payload_sha256,
                )
                report.conflicted += 1
                report.errors.append(
                    f"session {session_id} turn {turn.key} changed after its first import"
                )
                continue
            if existing.status == "committed":
                report.skipped += 1
                continue
            if existing.status == "conflict":
                if not _has_recorded_emission(existing):
                    if verifier is None:
                        raise WeaveImportError(
                            "WANDB_API_KEY is not set; conflicted pending uploads require remote "
                            "reconciliation"
                        )
                    recovered = _recover_unemitted_payload(
                        conversation=conversation,
                        turn=turn,
                        existing=existing,
                        config=config,
                        state=state,
                        verifier=verifier,
                        report=report,
                    )
                    if recovered is not None:
                        candidates.append(recovered)
                    continue
                report.conflicted += 1
                report.errors.append(f"session {session_id} turn {turn.key} remains in conflict")
                continue
            if verifier is None:
                raise WeaveImportError(
                    "WANDB_API_KEY is not set; pending uploads require remote reconciliation"
                )
            try:
                reconciled = verifier.reconcile(
                    conversation_id=conversation.conversation_id,
                    expected_trace_ids=existing.trace_ids,
                    turn_key=turn.key,
                    payload_sha256=existing.payload_sha256,
                    verification_signature=existing.verification_signature,
                    # 0.1.0 journals created before exact SDK-boundary
                    # signatures contain the prior local-pass hash.  Source
                    # identity was checked above, so the freshly derived hash
                    # is a safe alternate only when the remote root itself,
                    # recorded trace ID, chat index, and span count all agree.
                    alternate_verification_signatures=(turn.verification_signature,),
                    expected_span_count=_expected_span_count(
                        turn,
                        recorded_span_count=existing.span_count,
                    ),
                    timeout_seconds=config.verification_timeout,
                )
            except VerificationError as error:
                report.failed += 1
                report.errors.append(
                    f"session {session_id} turn {turn.key} could not be reconciled: {error}"
                )
                continue
            if reconciled.matches == 1:
                state.mark_committed(
                    row=existing,
                    trace_ids=reconciled.trace_ids,
                    root_span_ids=reconciled.root_span_ids or None,
                    span_count=reconciled.span_count,
                )
                report.skipped += 1
            elif reconciled.matches > 1:
                state.mark_remote_conflict(
                    row=existing,
                    error="multiple remote turns matched during reconciliation",
                )
                report.conflicted += 1
                report.errors.append(
                    f"session {session_id} turn {turn.key} matched multiple remote turns"
                )
            else:
                candidates.append(_Candidate(conversation, turn, existing))
    return candidates


def _emit_candidates(
    *,
    run_id: str,
    candidates: list[_Candidate],
    config: ImportConfig,
    state: StateStore,
    sink: WeaveSink,
    report: RunReport,
) -> tuple[list[_Emitted], bool]:
    if not candidates:
        return ([], True)
    emitted: list[_Emitted] = []
    for index, candidate in enumerate(candidates):
        conversation = candidate.conversation
        turn = candidate.turn
        session_id = conversation.conversation_id.removeprefix("hivemind:")
        journal_row = candidate.existing
        try:
            if journal_row is None:
                journal_row = state.begin_pending(
                    run_id=run_id,
                    project=config.project,
                    session_id=session_id,
                    turn_key=turn.key,
                    payload_sha256=turn.payload_sha256,
                    verification_signature=turn.verification_signature,
                    source_last_activity_at=conversation.source_last_activity_at,
                    atif_schema_version=conversation.schema_version,
                )
            outcome = sink.log_turn(conversation, turn)
            journal_row = state.record_emitted(
                row=journal_row,
                trace_ids=outcome.trace_ids,
                root_span_ids=outcome.root_span_ids,
                span_count=outcome.span_count,
            )
            report.emitted_spans += outcome.span_count
            emitted.append(
                _Emitted(
                    conversation_id=conversation.conversation_id,
                    session_id=session_id,
                    turn_key=turn.key,
                    payload_sha256=turn.payload_sha256,
                    verification_signature=turn.verification_signature,
                    outcome=outcome,
                    state_row=journal_row,
                )
            )
        except (ImporterError, OSError, sqlite3.Error) as error:
            message = _safe_error(error)
            if journal_row is not None:
                _record_error_best_effort(state, row=journal_row, error=message)
            report.failed += 1
            report.errors.append(f"session {session_id} turn {turn.key}: {message}")
            remaining = len(candidates) - index - 1
            if remaining:
                report.failed += remaining
                report.errors.append(
                    f"{remaining} later turn(s) were not attempted after the upload/journal failure"
                )
            return (emitted, False)
    return (emitted, True)


def _verify_emitted(
    *,
    emitted: list[_Emitted],
    config: ImportConfig,
    state: StateStore,
    verifier: WeaveVerifier,
    report: RunReport,
) -> None:
    by_conversation: dict[str, list[_Emitted]] = {}
    for item in emitted:
        by_conversation.setdefault(item.conversation_id, []).append(item)

    for conversation_id, conversation_items in by_conversation.items():
        try:
            result = verifier.verify_many(
                conversation_id=conversation_id,
                expectations=[
                    VerificationExpectation(
                        turn_key=item.turn_key,
                        payload_sha256=item.payload_sha256,
                        trace_ids=tuple(item.outcome.trace_ids),
                        verification_signature=item.verification_signature,
                        span_count=item.outcome.span_count,
                    )
                    for item in conversation_items
                ],
                timeout_seconds=config.verification_timeout,
            )
        except VerificationError as error:
            for item in conversation_items:
                _record_error_best_effort(
                    state,
                    row=item.state_row,
                    error=str(error),
                )
                report.failed += 1
            report.errors.append(f"conversation {conversation_id}: {error}")
            continue

        for item in conversation_items:
            if item.turn_key in result.conflicts:
                with suppress(sqlite3.Error, StateConflictError):
                    state.mark_remote_conflict(
                        row=item.state_row,
                        error="multiple remote traces matched the emitted turn",
                    )
                report.conflicted += 1
                report.errors.append(
                    f"session {item.session_id} turn {item.turn_key} matched multiple remote traces"
                )
                continue
            if item.turn_key in result.missing:
                detail = "turn was not visible before the verification deadline"
                if result.last_error:
                    detail = f"{detail}: {result.last_error}"
                _record_error_best_effort(
                    state,
                    row=item.state_row,
                    error=detail,
                )
                report.failed += 1
                report.errors.append(f"session {item.session_id} turn {item.turn_key}: {detail}")
                continue
            try:
                state.mark_committed(row=item.state_row)
            except (sqlite3.Error, StateConflictError) as error:
                report.failed += 1
                report.errors.append(
                    f"session {item.session_id} turn {item.turn_key}: {_safe_error(error)}"
                )
                continue
            report.imported += 1


def _run_config_payload(config: ImportConfig) -> dict[str, Any]:
    """Return the immutable compatibility boundary for an unfinished run."""
    return {
        "days": config.days,
        "idle_minutes": config.idle_minutes,
        "project": config.project,
        "trace_server_url": config.trace_server_url,
        "wandb_base_url": config.wandb_base_url,
        "session_ids": sorted(config.session_ids),
        "verification_timeout": config.verification_timeout,
    }


def _configure_required_pii() -> None:
    try:
        enforce_weave_error_reporting_disabled()
        configure_weave_pii()
    except Exception as error:
        raise WeaveImportError(
            f"could not initialize required offline PII redaction ({error.__class__.__name__})"
        ) from error


def _discover_sessions(
    *,
    client: HiveMindClient,
    config: ImportConfig,
    cutoff: datetime,
    report: RunReport,
) -> list[Session]:
    raw_sessions = client.list_sessions(
        days=min(365, config.days + 1),
        include_subagents=True,
    )
    report.discovered = len(raw_sessions)
    return _select_sessions(raw_sessions, config=config, cutoff=cutoff, report=report)


def _fetch_certifiable_conversation(
    *,
    client: HiveMindClient,
    entry: ImportRunSession,
) -> tuple[MappedConversation, bool]:
    """Fetch one transcript bracketed by exact activity-summary reads."""
    before = Session.from_api(client.get_session(entry.session_id))
    wrapper = client.get_atif(entry.session_id)
    after = Session.from_api(client.get_session(entry.session_id))
    activity_matches = (
        before.last_activity_known
        and after.last_activity_known
        and before.last_activity_at == entry.summary_last_activity_at
        and after.last_activity_at == entry.summary_last_activity_at
    )
    pinned = replace(
        before,
        last_activity_at=entry.summary_last_activity_at,
        last_activity_known=True,
    )
    conversation = sanitize_mapped_conversation(map_atif(pinned, wrapper))
    del wrapper
    return conversation, activity_matches


def _conversation_turn_certificate(conversation: MappedConversation) -> list[tuple[str, str]]:
    return [(turn.key, turn.payload_sha256) for turn in conversation.turns]


def _record_session_fetch_failure(
    *,
    state: StateStore,
    entry: ImportRunSession,
    error: Exception,
    report: RunReport,
    certifying: bool,
) -> None:
    message = _safe_error(error)
    if not isinstance(error, ImporterError):
        message = f"required PII redaction failed ({error.__class__.__name__})"
    report.failed += 1
    report.errors.append(f"session {entry.session_id}: {message}")
    if entry.turn_count < 0:
        state.record_uncertified_error(
            run_id=entry.run_id,
            session_id=entry.session_id,
            expected_revision=entry.revision,
            error=message,
        )
    else:
        state.mark_run_session_issue(
            entry=entry,
            status="failed",
            error=message,
        )


def _certify_manifest_run(
    *,
    state: StateStore,
    run: ImportRun,
    client: HiveMindClient,
    report: RunReport,
) -> ImportRun:
    """Certify every compact ordered turn set before the first upload."""
    for entry in state.get_run_sessions(run.run_id):
        try:
            conversation, activity_matches = _fetch_certifiable_conversation(
                client=client,
                entry=entry,
            )
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            _record_session_fetch_failure(
                state=state,
                entry=entry,
                error=error,
                report=report,
                certifying=True,
            )
            continue

        turns = _conversation_turn_certificate(conversation)
        if entry.turn_count < 0:
            entry = state.certify_run_session(
                run_id=run.run_id,
                session_id=entry.session_id,
                expected_revision=entry.revision,
                turns=turns,
            )
        certificate_matches = state.certificate_matches(entry, turns)
        if not activity_matches or not certificate_matches:
            state.mark_run_session_issue(
                entry=entry,
                status="conflict",
                error="source activity or ordered turn set changed during certification",
            )
            report.conflicted += 1
            report.errors.append(
                f"session {entry.session_id} changed while its fixed snapshot was certified"
            )
        elif entry.status in {"failed", "conflict"}:
            state.restore_certified_session(entry=entry)
        del turns
        del conversation

    entries = state.get_run_sessions(run.run_id)
    if all(entry.status == "certified" for entry in entries):
        return state.seal_run(run)
    return run


def _session_turn_evidence_status(
    *,
    state: StateStore,
    entry: ImportRunSession,
    project: str,
) -> str:
    run_turns = state.get_run_turns(entry.run_id, entry.session_id)
    if len(run_turns) != entry.turn_count:
        return "conflict"
    rows = [state.get(project, entry.session_id, turn.turn_key) for turn in run_turns]
    if any(row is not None and row.status == "conflict" for row in rows):
        return "conflict"
    if any(row is None or row.status != "committed" for row in rows):
        return "failed"
    return "committed"


def _process_ready_run(
    *,
    state: StateStore,
    run: ImportRun,
    config: ImportConfig,
    client: HiveMindClient,
    report: RunReport,
    sink: WeaveSink | None,
    verifier: WeaveVerifier | None,
) -> None:
    entries = state.get_run_sessions(run.run_id)
    work = [entry for entry in entries if entry.status not in {"empty", "imported", "skipped"}]
    if not work:
        state.complete_run(run)
        return

    api_key = os.environ.get("WANDB_API_KEY", "")
    active_verifier = verifier
    active_sink = sink or WeaveSink(
        trace_server_url=config.trace_server_url,
        wandb_base_url=config.wandb_base_url,
    )
    sink_started = False
    sink_finished = False
    upload_aborted = False
    try:
        for entry in work:
            if upload_aborted:
                break
            try:
                conversation, activity_matches = _fetch_certifiable_conversation(
                    client=client,
                    entry=entry,
                )
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                _record_session_fetch_failure(
                    state=state,
                    entry=entry,
                    error=error,
                    report=report,
                    certifying=False,
                )
                continue

            turns = _conversation_turn_certificate(conversation)
            if not activity_matches or not state.certificate_matches(entry, turns):
                state.mark_run_session_issue(
                    entry=entry,
                    status="conflict",
                    error="source activity or ordered turn set differs from the sealed snapshot",
                )
                report.conflicted += 1
                report.errors.append(
                    f"session {entry.session_id} changed after its fixed snapshot was sealed"
                )
                del turns
                del conversation
                continue
            if entry.status in {"failed", "conflict"}:
                entry = state.restore_certified_session(entry=entry)

            report.planned += len(conversation.turns)
            if not conversation.turns:
                state.mark_run_session_terminal(entry=entry, status="empty")
                del turns
                del conversation
                continue

            if active_verifier is None:
                reconciliation_needed = any(
                    (existing := state.get(config.project, entry.session_id, turn.key)) is not None
                    and (
                        existing.status == "pending"
                        or (existing.status == "conflict" and not _has_recorded_emission(existing))
                    )
                    for turn in conversation.turns
                )
                if reconciliation_needed:
                    if not api_key:
                        raise WeaveImportError(
                            "WANDB_API_KEY is not set; pending uploads require remote "
                            "reconciliation before they can be resumed"
                        )
                    active_verifier = WeaveVerifier(
                        project=config.project,
                        api_key=api_key,
                        base_url=config.trace_server_url,
                    )

            before_failed = report.failed
            before_conflicted = report.conflicted
            candidates = _classify_candidates(
                conversations=[conversation],
                config=config,
                state=state,
                verifier=active_verifier,
                report=report,
            )
            if report.conflicted > before_conflicted:
                state.mark_run_session_issue(
                    entry=entry,
                    status="conflict",
                    error="one or more certified turns conflicted during reconciliation",
                )
                del candidates
                del turns
                del conversation
                continue
            if report.failed > before_failed:
                state.mark_run_session_issue(
                    entry=entry,
                    status="failed",
                    error="one or more certified turns failed reconciliation",
                )
                del candidates
                del turns
                del conversation
                continue
            if not candidates:
                state.mark_run_session_terminal(entry=entry, status="skipped")
                del candidates
                del turns
                del conversation
                continue

            if not api_key:
                raise WeaveImportError(
                    "WANDB_API_KEY is not set; export it in the process environment and retry"
                )
            if active_verifier is None:
                active_verifier = WeaveVerifier(
                    project=config.project,
                    api_key=api_key,
                    base_url=config.trace_server_url,
                )
            if not sink_started:
                try:
                    active_sink.start(config.project)
                except WeaveImportError as error:
                    report.failed += len(candidates)
                    report.errors.append(str(error))
                    state.mark_run_session_issue(
                        entry=entry,
                        status="failed",
                        error=_safe_error(error),
                    )
                    del candidates
                    del turns
                    del conversation
                    upload_aborted = True
                    break
                sink_started = True

            emitted, emission_completed = _emit_candidates(
                run_id=run.run_id,
                candidates=candidates,
                config=config,
                state=state,
                sink=active_sink,
                report=report,
            )
            flush_failed = False
            if emitted:
                try:
                    active_sink.flush()
                except WeaveImportError as error:
                    for item in emitted:
                        _record_error_best_effort(state, row=item.state_row, error=str(error))
                    report.failed += len(emitted)
                    report.errors.append(str(error))
                    flush_failed = True
                else:
                    _verify_emitted(
                        emitted=emitted,
                        config=config,
                        state=state,
                        verifier=active_verifier,
                        report=report,
                    )

            evidence = _session_turn_evidence_status(
                state=state,
                entry=entry,
                project=config.project,
            )
            if evidence == "conflict":
                state.mark_run_session_issue(
                    entry=entry,
                    status="conflict",
                    error="one or more certified turns remain conflicted",
                )
            elif evidence != "committed" or not emission_completed or flush_failed:
                state.mark_run_session_issue(
                    entry=entry,
                    status="failed",
                    error="one or more certified turns remain pending or failed",
                )
            else:
                state.mark_run_session_terminal(entry=entry, status="imported")

            upload_aborted = not emission_completed or flush_failed
            del emitted
            del candidates
            del turns
            del conversation

        if sink_started:
            try:
                active_sink.finish()
            except WeaveImportError as error:
                report.failed += 1
                report.errors.append(str(error))
            else:
                sink_finished = True
        else:
            sink_finished = True
    except BaseException:
        if sink_started and not sink_finished:
            with suppress(Exception):
                active_sink.finish()
        raise

    if sink_finished:
        final_entries = state.get_run_sessions(run.run_id)
        if all(entry.status in {"empty", "imported", "skipped"} for entry in final_entries):
            state.complete_run(run)


def run_import(
    config: ImportConfig,
    *,
    hivemind: HiveMindClient | None = None,
    sink: WeaveSink | None = None,
    verifier: WeaveVerifier | None = None,
) -> RunReport:
    config.validate()
    with disabled_weave_error_reporting():
        if config.dry_run:
            return _run_import_impl(
                config,
                hivemind=hivemind,
                sink=sink,
                verifier=verifier,
            )
        validate_live_transport_environment()
        config = replace(
            config,
            trace_server_url=resolve_trace_server_url(),
            wandb_base_url=resolve_wandb_base_url(),
        )
        return _run_import_impl(
            config,
            hivemind=hivemind,
            sink=sink,
            verifier=verifier,
        )


def _run_import_impl(
    config: ImportConfig,
    *,
    hivemind: HiveMindClient | None,
    sink: WeaveSink | None,
    verifier: WeaveVerifier | None,
) -> RunReport:
    report = RunReport()
    cutoff = config.cutoff or datetime.now(UTC)
    cutoff = cutoff.replace(tzinfo=UTC) if cutoff.tzinfo is None else cutoff.astimezone(UTC)
    client = hivemind or HiveMindClient()
    client.preflight()

    if config.dry_run:
        sessions = _discover_sessions(
            client=client,
            config=config,
            cutoff=cutoff,
            report=report,
        )
        if sessions:
            _configure_required_pii()
        for conversation in _map_sessions(client, sessions, report):
            del conversation
        return report

    state_path = config.state_path.expanduser()
    preselected: list[Session] | None = None
    if not state_path.exists():
        # Preserve the historical no-work behavior: an empty first invocation
        # does not create a journal solely to record an empty discovery.
        preselected = _discover_sessions(
            client=client,
            config=config,
            cutoff=cutoff,
            report=report,
        )
        if not preselected:
            return report

    try:
        with StateStore(config.state_path) as state:
            run = state.find_resumable_run(
                project=config.project,
                config=_run_config_payload(config),
            )
            if run is None:
                sessions = preselected
                if sessions is None:
                    sessions = _discover_sessions(
                        client=client,
                        config=config,
                        cutoff=cutoff,
                        report=report,
                    )
                    if not sessions:
                        return report
                run = state.create_run(
                    project=config.project,
                    cutoff=cutoff,
                    days=config.days,
                    idle_minutes=config.idle_minutes,
                    config=_run_config_payload(config),
                    sessions=[(session.id, session.last_activity_at) for session in sessions],
                    discovered_count=report.discovered,
                    deferred_count=report.deferred,
                )
            else:
                # Report the immutable discovery snapshot, not a new moving
                # window. Successful entries are not fetched again.
                report.discovered = run.discovered_count
                report.eligible = run.session_count
                report.deferred = run.deferred_count

            entries = state.get_run_sessions(run.run_id)
            has_work = any(
                entry.status not in {"empty", "imported", "skipped"} for entry in entries
            )
            if has_work:
                _configure_required_pii()
            if run.phase == "certifying":
                run = _certify_manifest_run(
                    state=state,
                    run=run,
                    client=client,
                    report=report,
                )
            if run.phase != "ready":
                return report
            _process_ready_run(
                state=state,
                run=run,
                config=config,
                client=client,
                report=report,
                sink=sink,
                verifier=verifier,
            )
    except (OSError, sqlite3.Error) as error:
        raise StateStoreError(f"local import journal failed: {_safe_error(error)}") from error
    return report
