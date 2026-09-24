from __future__ import annotations

import gc
import hashlib
import os
import weakref
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave import importer as importer_module
from hivemind_weave.atif import map_atif
from hivemind_weave.errors import StateConflictError
from hivemind_weave.historical_sink import PreparedOutcome
from hivemind_weave.importer import ImportConfig, run_import
from hivemind_weave.models import Session
from hivemind_weave.pii import sanitize_mapped_conversation
from hivemind_weave.state import StateStore
from hivemind_weave.verify import (
    BatchVerificationResult,
    ReconcileResult,
    VerificationExpectation,
)
from hivemind_weave.weave_sink import LogOutcome, expected_turn_span_count


class FakeHiveMind:
    def __init__(
        self,
        sessions: list[dict[str, Any]],
        wrappers: dict[str, dict[str, Any]],
    ) -> None:
        self.sessions = sessions
        self.wrappers = wrappers
        self.preflight_calls = 0
        self.requested_days: list[int] = []
        self.fetched: list[str] = []
        self.direct_fetched: list[str] = []

    def preflight(self) -> None:
        self.preflight_calls += 1

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        self.requested_days.append(days)
        assert include_subagents is True
        return self.sessions

    def get_atif(self, session_id: str) -> dict[str, Any]:
        self.fetched.append(session_id)
        return self.wrappers[session_id]

    def get_session(self, session_id: str) -> dict[str, Any]:
        self.direct_fetched.append(session_id)
        for session in self.sessions:
            if session.get("id") == session_id:
                return session
        raise AssertionError(f"unknown direct session {session_id}")


class FakeSink:
    def __init__(self, *, fail_finish: bool = False, fail_flush: bool = False) -> None:
        self.started = False
        self.start_calls = 0
        self.flush_calls = 0
        self.finish_calls = 0
        self.logged: list[tuple[Any, Any]] = []
        self.fail_finish = fail_finish
        self.fail_flush = fail_flush

    def start(self, project: str) -> None:
        self.start_calls += 1
        self.started = True

    def log_turn(self, conversation: Any, turn: Any) -> LogOutcome:
        self.logged.append((conversation, turn))
        index = len(self.logged)
        return LogOutcome(
            trace_ids=[f"trace-{index}"],
            root_span_ids=[f"root-{index}"],
            span_count=1 + len(turn.llms) + len(turn.tools) + len(turn.subagents),
            commit_id=f"commit-{index}",
        )

    def finish(self) -> None:
        self.finish_calls += 1
        if self.fail_finish:
            from hivemind_weave.errors import WeaveImportError

            raise WeaveImportError("flush failed")
        self.started = False

    def flush(self) -> None:
        self.flush_calls += 1
        if self.fail_flush:
            from hivemind_weave.errors import WeaveImportError

            raise WeaveImportError("per-session flush failed")


class FakeAtomicSink(FakeSink):
    supports_atomic_replay = True

    def __init__(
        self,
        *,
        fail_preflight: bool = False,
        reconcile_outcome: LogOutcome | None = None,
    ) -> None:
        super().__init__()
        self.fail_preflight = fail_preflight
        self.reconcile_outcome = reconcile_outcome
        self.prepared: list[tuple[Any, Any]] = []
        self.atomic_reconciliations = 0

    @staticmethod
    def outcome_for(conversation: Any, turn: Any) -> PreparedOutcome:
        identity = f"{conversation.conversation_id}\0{turn.key}\0{turn.payload_sha256}"
        return PreparedOutcome(
            logical_key=hashlib.sha256(f"logical\0{identity}".encode()).hexdigest(),
            wire_sha256=hashlib.sha256(f"wire\0{identity}".encode()).hexdigest(),
            span_count=1 + len(turn.llms) + len(turn.tools) + len(turn.subagents),
            compressed_bytes=123,
            uncompressed_bytes=456,
            reference_count=0,
            capability_version="historical-turn-test-v1",
            sdk_prepared=object(),
        )

    def prepare_turn(self, conversation: Any, turn: Any) -> PreparedOutcome:
        self.prepared.append((conversation, turn))
        if self.fail_preflight:
            from hivemind_weave.errors import WeaveImportError

            raise WeaveImportError("deterministic atomic preflight rejection")
        return self.outcome_for(conversation, turn)

    def reconcile_prepared(self, prepared: PreparedOutcome) -> LogOutcome | None:
        del prepared
        self.atomic_reconciliations += 1
        return self.reconcile_outcome


class FakeVerifier:
    def __init__(
        self,
        *,
        reconcile_result: ReconcileResult | None = None,
        reconcile_results: list[ReconcileResult] | None = None,
    ) -> None:
        self.reconcile_result = reconcile_result or ReconcileResult(matches=0, trace_ids=[])
        self.reconcile_results = list(reconcile_results or [])
        self.verified: list[tuple[str, list[str]]] = []
        self.reconciled: list[str] = []
        self.reconciled_hashes: list[str] = []
        self.reconcile_signatures: list[tuple[str, int]] = []
        self.reconcile_alternate_signatures: list[tuple[str, ...]] = []

    def reconcile(
        self,
        *,
        conversation_id: str,
        expected_trace_ids: list[str],
        turn_key: str,
        payload_sha256: str,
        verification_signature: str,
        alternate_verification_signatures: tuple[str, ...] = (),
        expected_span_count: int,
        timeout_seconds: float,
    ) -> ReconcileResult:
        del expected_trace_ids, turn_key, timeout_seconds
        self.reconciled.append(conversation_id)
        self.reconciled_hashes.append(payload_sha256)
        self.reconcile_signatures.append((verification_signature, expected_span_count))
        self.reconcile_alternate_signatures.append(alternate_verification_signatures)
        if self.reconcile_results:
            return self.reconcile_results.pop(0)
        return self.reconcile_result

    def verify(
        self,
        *,
        conversation_id: str,
        expected_trace_ids: list[str],
        turn_key: str,
        payload_sha256: str,
        timeout_seconds: float,
    ) -> None:
        self.verified.append((conversation_id, expected_trace_ids))

    def verify_many(
        self,
        *,
        conversation_id: str,
        expectations: list[VerificationExpectation],
        timeout_seconds: float,
    ) -> BatchVerificationResult:
        del timeout_seconds
        self.verified.extend(
            (conversation_id, list(expectation.trace_ids)) for expectation in expectations
        )
        return BatchVerificationResult(
            verified=frozenset(expectation.turn_key for expectation in expectations),
            conflicts=frozenset(),
            missing=frozenset(),
        )


def _config(tmp_path: Path, *, dry_run: bool = False) -> ImportConfig:
    return ImportConfig(
        days=3,
        project="wandb/hivemind-chats",
        state_path=tmp_path / "state.sqlite3",
        dry_run=dry_run,
        confirm_project="" if dry_run else "wandb/hivemind-chats",
        cutoff=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
    )


def _seed_certified_run(
    state: StateStore,
    config: ImportConfig,
    session: Session,
    conversation: Any,
) -> Any:
    assert config.cutoff is not None
    run = state.create_run(
        project=config.project,
        cutoff=config.cutoff,
        days=config.days,
        idle_minutes=config.idle_minutes,
        config=importer_module._run_config_payload(config),
        sessions=[(session.id, session.last_activity_at)],
        discovered_count=1,
        deferred_count=0,
    )
    entry = state.get_run_sessions(run.run_id)[0]
    state.certify_run_session(
        run_id=run.run_id,
        session_id=session.id,
        expected_revision=entry.revision,
        turns=[(turn.key, turn.payload_sha256) for turn in conversation.turns],
    )
    return state.seal_run(run)


def test_dry_run_filters_window_and_writes_no_state(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    error_reporting_values: list[str | None] = []
    configure_required_pii = importer_module._configure_required_pii

    def tracked_configure_required_pii() -> None:
        error_reporting_values.append(os.environ.get("WANDB_ERROR_REPORTING"))
        configure_required_pii()

    monkeypatch.setattr(
        importer_module,
        "_configure_required_pii",
        tracked_configure_required_pii,
    )
    eligible = session_payload(id="eligible", last_activity_at="2026-08-01T12:20:00Z")
    deferred = session_payload(id="deferred", last_activity_at="2026-08-03T11:55:00Z")
    old = session_payload(id="old", last_activity_at="2026-07-01T12:00:00Z")
    client = FakeHiveMind(
        [eligible, deferred, old],
        {"eligible": atif_wrapper(wrapper_session_id="eligible")},
    )

    report = run_import(_config(tmp_path, dry_run=True), hivemind=client)

    assert report.discovered == 3
    assert report.eligible == 1
    assert report.deferred == 1
    assert report.planned == 1
    assert report.imported == 0
    assert client.requested_days == [4]
    assert client.fetched == ["eligible"]
    assert not (tmp_path / "state.sqlite3").exists()
    assert error_reporting_values == ["false"]


def test_no_work_succeeds_without_wandb_credentials(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    report = run_import(_config(tmp_path), hivemind=FakeHiveMind([], {}))
    assert report.ok
    assert report.discovered == 0
    assert report.planned == 0
    assert not (tmp_path / "state.sqlite3").exists()


def test_successful_import_and_identical_rerun_skip(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    session = session_payload()
    client = FakeHiveMind([session], {session["id"]: atif_wrapper()})
    first_sink = FakeSink()
    first_verifier = FakeVerifier()

    first = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=first_sink,
        verifier=first_verifier,
    )
    assert first.ok
    assert first.imported == 1
    assert first.emitted_spans == 4
    assert len(first_sink.logged) == 1
    assert len(first_verifier.verified) == 1

    monkeypatch.delenv("WANDB_API_KEY")
    second = run_import(_config(tmp_path), hivemind=client)
    assert second.ok
    assert second.imported == 0
    assert second.skipped == 1
    with StateStore(tmp_path / "state.sqlite3") as state:
        assert (
            state.connection.execute(
                "SELECT COUNT(*) FROM import_runs WHERE status = 'completed'"
            ).fetchone()[0]
            == 2
        )
        assert state.connection.execute("SELECT COUNT(*) FROM imported_turns").fetchone()[0] == 1


def test_live_import_releases_each_session_before_fetching_the_next(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    first_session = session_payload(
        id="session-a",
        started_at="2026-08-01T12:00:00Z",
    )
    second_session = session_payload(
        id="session-b",
        started_at="2026-08-01T13:00:00Z",
    )
    processed_conversations: list[str] = []
    lifecycle: list[str] = []

    class StreamingSink(FakeSink):
        def log_turn(self, conversation: Any, turn: Any) -> LogOutcome:
            processed_conversations.append(conversation.conversation_id)
            lifecycle.append(f"log:{conversation.conversation_id}")
            return LogOutcome(
                trace_ids=[f"trace-{len(processed_conversations)}"],
                root_span_ids=[f"root-{len(processed_conversations)}"],
                span_count=1 + len(turn.llms) + len(turn.tools) + len(turn.subagents),
            )

        def flush(self) -> None:
            super().flush()
            lifecycle.append(f"flush:{processed_conversations[-1]}")

    class OrderingVerifier(FakeVerifier):
        def verify_many(
            self,
            *,
            conversation_id: str,
            expectations: list[VerificationExpectation],
            timeout_seconds: float,
        ) -> BatchVerificationResult:
            result = super().verify_many(
                conversation_id=conversation_id,
                expectations=expectations,
                timeout_seconds=timeout_seconds,
            )
            lifecycle.append(f"verify:{conversation_id}")
            return result

    sink = StreamingSink()
    first_conversation_ref: weakref.ReferenceType[Any] | None = None
    real_sanitize = importer_module.sanitize_mapped_conversation

    def track_sanitized_conversation(conversation: Any) -> Any:
        nonlocal first_conversation_ref
        sanitized = real_sanitize(conversation)
        if sanitized.conversation_id == "hivemind:session-a":
            first_conversation_ref = weakref.ref(sanitized)
        return sanitized

    monkeypatch.setattr(
        importer_module,
        "sanitize_mapped_conversation",
        track_sanitized_conversation,
    )

    class OrderingHiveMind(FakeHiveMind):
        def get_atif(self, session_id: str) -> dict[str, Any]:
            fetch_number = self.fetched.count(session_id) + 1
            if session_id == "session-b" and fetch_number == 2:
                # Pass one certifies every compact turn set before upload. On
                # pass two, session A must be flushed, verified, terminalized,
                # and released before B is fetched.
                assert processed_conversations == ["hivemind:session-a"]
                assert lifecycle[-1] == "terminal:session-a:imported"
                gc.collect()
                assert first_conversation_ref is not None
                assert first_conversation_ref() is None
            return super().get_atif(session_id)

    client = OrderingHiveMind(
        [first_session, second_session],
        {
            "session-a": atif_wrapper(wrapper_session_id="session-a"),
            "session-b": atif_wrapper(wrapper_session_id="session-b"),
        },
    )
    verifier = OrderingVerifier()
    real_terminal = StateStore.mark_run_session_terminal

    def track_terminal(
        state: StateStore,
        *,
        entry: Any,
        status: str,
        error: str = "",
    ) -> Any:
        result = real_terminal(state, entry=entry, status=status, error=error)
        lifecycle.append(f"terminal:{entry.session_id}:{status}")
        return result

    monkeypatch.setattr(StateStore, "mark_run_session_terminal", track_terminal)

    report = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=sink,
        verifier=verifier,
    )

    assert report.ok
    assert report.planned == 2
    assert report.imported == 2
    assert client.fetched == ["session-a", "session-b", "session-a", "session-b"]
    assert sink.start_calls == 1
    assert sink.finish_calls == 1
    assert sink.flush_calls == 2
    assert len(verifier.verified) == 2


def test_appended_turn_imports_without_rewriting_history(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    session = session_payload()
    first_wrapper = atif_wrapper()
    client = FakeHiveMind([session], {session["id"]: first_wrapper})
    run_import(
        _config(tmp_path),
        hivemind=client,
        sink=FakeSink(),
        verifier=FakeVerifier(),
    )
    new_steps = list(first_wrapper["trajectory"]["steps"])
    new_steps.extend(
        [
            {
                "step_id": 5,
                "timestamp": "2026-08-01T12:10:00Z",
                "source": "user",
                "message": "Now read it",
            },
            {
                "step_id": 6,
                "timestamp": "2026-08-01T12:10:01Z",
                "source": "agent",
                "message": "It contains hello.",
            },
        ]
    )
    client.wrappers[session["id"]] = atif_wrapper(steps=new_steps)
    sink = FakeSink()

    report = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=sink,
        verifier=FakeVerifier(),
    )
    assert report.ok
    assert report.skipped == 1
    assert report.imported == 1
    assert len(sink.logged) == 1
    assert sink.logged[0][1].key == "atif:step:5"


def test_changed_historical_turn_becomes_conflict(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    session = session_payload()
    original = atif_wrapper()
    client = FakeHiveMind([session], {session["id"]: original})
    run_import(
        _config(tmp_path),
        hivemind=client,
        sink=FakeSink(),
        verifier=FakeVerifier(),
    )
    changed_steps = list(original["trajectory"]["steps"])
    changed_steps[1] = {**changed_steps[1], "message": "Changed historical prompt"}
    client.wrappers[session["id"]] = atif_wrapper(steps=changed_steps)
    sink = FakeSink()

    report = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=sink,
        verifier=FakeVerifier(),
    )
    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []


def test_pending_turn_is_reconciled_after_crash(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    turn = conversation.turns[0]
    assert expected_turn_span_count(turn) == 4
    config = _config(tmp_path)
    with StateStore(config.state_path) as state:
        run = _seed_certified_run(state, config, session, conversation)
        pending = state.begin_pending(
            run_id=run.run_id,
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            payload_sha256=turn.payload_sha256,
            # The journaled signature describes the exact redacted upload from
            # before the crash, even if a later Presidio run makes a different
            # statistical redaction choice for the same stable source.
            verification_signature="legacy-signature",
            source_last_activity_at=session.last_activity_at,
            atif_schema_version=conversation.schema_version,
        )
        state.record_emitted(
            row=pending,
            trace_ids=["trace-existing"],
            root_span_ids=["root-existing"],
            span_count=3,
        )
    sink = FakeSink()
    verifier = FakeVerifier(
        reconcile_result=ReconcileResult(
            matches=1,
            trace_ids=["trace-existing"],
            root_span_ids=["root-reconciled"],
            span_count=3,
        )
    )

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=verifier,
    )
    assert report.ok
    assert report.skipped == 1
    assert sink.logged == []
    assert verifier.reconcile_signatures == [("legacy-signature", 3)]
    assert verifier.reconcile_alternate_signatures == [(turn.verification_signature,)]
    with StateStore(config.state_path) as state:
        row = state.get(config.project, session.id, turn.key)
        assert row is not None and row.status == "committed"
        assert row.root_span_ids == ["root-reconciled"]


def test_pending_turn_is_reemitted_only_after_remote_absence_is_confirmed(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    turn = conversation.turns[0]
    config = _config(tmp_path)
    with StateStore(config.state_path) as state:
        run = _seed_certified_run(state, config, session, conversation)
        pending = state.begin_pending(
            run_id=run.run_id,
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            payload_sha256=turn.payload_sha256,
            verification_signature=turn.verification_signature,
            source_last_activity_at=session.last_activity_at,
            atif_schema_version=conversation.schema_version,
        )
        state.record_emitted(
            row=pending,
            trace_ids=["trace-delayed"],
            root_span_ids=["root-delayed"],
            span_count=4,
        )
    sink = FakeSink()

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=FakeVerifier(reconcile_result=ReconcileResult(matches=0, trace_ids=[])),
    )

    assert report.ok
    assert report.imported == 1
    assert len(sink.logged) == 1


def test_pending_atomic_turn_checks_exact_status_before_safe_replay(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    turn = conversation.turns[0]
    config = _config(tmp_path)
    sink = FakeAtomicSink()
    prepared = sink.outcome_for(conversation, turn)
    with StateStore(config.state_path) as state:
        run = _seed_certified_run(state, config, session, conversation)
        state.begin_pending(
            run_id=run.run_id,
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            payload_sha256=turn.payload_sha256,
            verification_signature=turn.verification_signature,
            source_last_activity_at=session.last_activity_at,
            atif_schema_version=conversation.schema_version,
        )
        attempt = state.plan_atomic_turn(
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            source_payload_sha256=turn.payload_sha256,
        )
        attempt = state.record_atomic_turn_prepared(
            attempt,
            wire_sha256=prepared.wire_sha256,
            logical_key=prepared.logical_key,
            capability_version=prepared.capability_version,
            reference_count=prepared.reference_count,
            span_count=prepared.span_count,
        )
        attempt = state.begin_atomic_turn_submit(attempt)
        state.mark_atomic_turn_uncertain(attempt)
    verifier = FakeVerifier()

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=verifier,
    )

    assert report.ok
    assert report.imported == 1
    assert len(sink.logged) == 1
    assert sink.atomic_reconciliations == 1
    assert verifier.reconciled == []
    with StateStore(config.state_path) as state:
        attempt = state.get_atomic_turn(config.project, session.id, turn.key)
    assert attempt is not None and attempt.status == "committed"


def test_pending_atomic_turn_uses_exact_remote_commit_without_second_put(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    turn = conversation.turns[0]
    config = _config(tmp_path)
    prepared = FakeAtomicSink.outcome_for(conversation, turn)
    remote = LogOutcome(
        trace_ids=["trace-existing"],
        root_span_ids=["root-existing"],
        span_count=prepared.span_count,
        logical_key=prepared.logical_key,
        wire_sha256=prepared.wire_sha256,
        commit_id="commit-existing",
        capability_version=prepared.capability_version,
    )
    sink = FakeAtomicSink(reconcile_outcome=remote)
    with StateStore(config.state_path) as state:
        run = _seed_certified_run(state, config, session, conversation)
        state.begin_pending(
            run_id=run.run_id,
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            payload_sha256=turn.payload_sha256,
            verification_signature=turn.verification_signature,
            source_last_activity_at=session.last_activity_at,
            atif_schema_version=conversation.schema_version,
        )
        attempt = state.plan_atomic_turn(
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            source_payload_sha256=turn.payload_sha256,
        )
        attempt = state.record_atomic_turn_prepared(
            attempt,
            wire_sha256=prepared.wire_sha256,
            logical_key=prepared.logical_key,
            capability_version=prepared.capability_version,
            reference_count=prepared.reference_count,
            span_count=prepared.span_count,
        )
        attempt = state.begin_atomic_turn_submit(attempt)
        state.mark_atomic_turn_uncertain(attempt)

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert report.ok
    assert report.imported == 1
    assert report.emitted_spans == 0
    assert sink.logged == []
    assert sink.atomic_reconciliations == 1
    with StateStore(config.state_path) as state:
        attempt = state.get_atomic_turn(config.project, session.id, turn.key)
    assert attempt is not None and attempt.status == "committed"
    assert attempt.commit_id == "commit-existing"


def test_pre_v6_pending_turn_is_not_replayed_into_atomic_endpoint(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    turn = conversation.turns[0]
    config = _config(tmp_path)
    with StateStore(config.state_path) as state:
        run = _seed_certified_run(state, config, session, conversation)
        state.begin_pending(
            run_id=run.run_id,
            project=config.project,
            session_id=session.id,
            turn_key=turn.key,
            payload_sha256=turn.payload_sha256,
            verification_signature=turn.verification_signature,
            source_last_activity_at=session.last_activity_at,
            atif_schema_version=conversation.schema_version,
        )
    sink = FakeAtomicSink()

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    with StateStore(config.state_path) as state:
        row = state.get(config.project, session.id, turn.key)
    assert row is not None and row.status == "conflict"


def test_atomic_session_preflight_fails_before_any_turn_is_uploaded(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    sink = FakeAtomicSink(fail_preflight=True)

    report = run_import(
        _config(tmp_path),
        hivemind=FakeHiveMind(
            [raw_session],
            {str(raw_session["id"]): atif_wrapper()},
        ),
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.failed == 1
    assert len(sink.prepared) == 1
    assert sink.logged == []
    with StateStore(_config(tmp_path).state_path) as state:
        entry = state.connection.execute("SELECT status FROM import_run_sessions").fetchone()
        assert entry is not None and entry["status"] == "failed"


def test_changed_unemitted_conflict_is_repaired_only_after_both_hashes_are_absent(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    current = conversation.turns[0]
    config = _config(tmp_path)
    with StateStore(config.state_path) as state:
        _seed_certified_run(state, config, session, conversation)
        old_hash = "c" * 64
        now = "2026-08-03T12:00:00Z"
        state.connection.execute(
            """
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at,
                atif_schema_version, importer_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, '0.1.0', ?, ?)
            """,
            (
                config.project,
                session.id,
                current.key,
                old_hash,
                old_hash,
                "old-signature",
                "2026-08-01T12:00:00Z",
                "ATIF-v1.7",
                now,
                now,
            ),
        )
        state.connection.commit()
        pending = state.get(config.project, session.id, current.key)
        assert pending is not None
        state.mark_conflict(
            row=pending,
            new_payload_sha256=current.payload_sha256,
        )
    verifier = FakeVerifier(
        reconcile_results=[
            ReconcileResult(matches=0, trace_ids=[]),
            ReconcileResult(matches=0, trace_ids=[]),
        ]
    )
    sink = FakeSink()
    verifier_construction: list[tuple[str, str]] = []

    def verifier_factory(*, project: str, api_key: str, base_url: str) -> FakeVerifier:
        assert base_url == "https://trace.wandb.ai"
        verifier_construction.append((project, api_key))
        return verifier

    monkeypatch.setattr("hivemind_weave.importer.WeaveVerifier", verifier_factory)

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
    )

    assert report.ok
    assert report.imported == 1
    assert len(sink.logged) == 1
    assert verifier_construction == [(config.project, "test-key")]
    assert verifier.reconciled_hashes == [old_hash, current.payload_sha256]
    assert [count for _signature, count in verifier.reconcile_signatures] == [
        0,
        expected_turn_span_count(current),
    ]
    with StateStore(config.state_path) as state:
        row = state.get(config.project, session.id, current.key)
        assert row is not None
        assert row.status == "committed"
        assert row.payload_sha256 == current.payload_sha256


def test_changed_unemitted_payload_conflicts_when_old_hash_exists_remotely(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    session = Session.from_api(raw_session)
    wrapper = atif_wrapper()
    conversation = sanitize_mapped_conversation(map_atif(session, wrapper))
    current = conversation.turns[0]
    config = _config(tmp_path)
    with StateStore(config.state_path) as state:
        _seed_certified_run(state, config, session, conversation)
        old_hash = "d" * 64
        now = "2026-08-03T12:00:00Z"
        state.connection.execute(
            """
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at,
                atif_schema_version, importer_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, '0.1.0', ?, ?)
            """,
            (
                config.project,
                session.id,
                current.key,
                old_hash,
                old_hash,
                "old-signature",
                "2026-08-01T12:00:00Z",
                "ATIF-v1.7",
                now,
                now,
            ),
        )
        state.connection.commit()
    sink = FakeSink()

    report = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {session.id: wrapper}),
        sink=sink,
        verifier=FakeVerifier(
            reconcile_result=ReconcileResult(
                matches=1,
                trace_ids=["remote-old"],
                root_span_ids=["root-old"],
            )
        ),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    with StateStore(config.state_path) as state:
        row = state.get(config.project, session.id, current.key)
        assert row is not None
        assert row.status == "conflict"
        assert row.payload_sha256 == old_hash


def test_legacy_committed_hash_without_source_identity_fails_closed(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload()
    wrapper = atif_wrapper()
    config = _config(tmp_path)
    first = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {raw_session["id"]: wrapper}),
        sink=FakeSink(),
        verifier=FakeVerifier(),
    )
    assert first.ok
    current = sanitize_mapped_conversation(map_atif(Session.from_api(raw_session), wrapper)).turns[
        0
    ]
    with StateStore(config.state_path) as state:
        state.connection.execute(
            """
            UPDATE imported_turns
            SET payload_sha256 = 'legacy-presidio-hash', source_payload_sha256 = '',
                revision = revision + 1
            """
        )
        state.connection.commit()

    monkeypatch.delenv("WANDB_API_KEY")
    rerun = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {raw_session["id"]: wrapper}),
    )

    assert not rerun.ok
    assert rerun.conflicted == 1
    assert "unprovable legacy history" in rerun.errors[0]
    with StateStore(config.state_path) as state:
        row = state.get(config.project, raw_session["id"], current.key)
        assert row is not None
        assert row.status == "conflict"
        assert row.payload_sha256 == "legacy-presidio-hash"
        assert row.source_payload_sha256 == ""


def test_unknown_schema_is_reported_without_upload(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session = session_payload()
    report = run_import(
        _config(tmp_path, dry_run=True),
        hivemind=FakeHiveMind(
            [session],
            {session["id"]: atif_wrapper(version="ATIF-v2.0")},
        ),
    )
    assert not report.ok
    assert report.failed == 1
    assert "ATIFSchemaError" in report.errors[0]
    assert session["id"] not in report.render()


def test_cutoff_boundaries_and_unknown_activity(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    lower = session_payload(
        id="lower",
        started_at="2026-07-31T11:00:00Z",
        last_activity_at="2026-07-31T12:00:00Z",
    )
    idle = session_payload(id="idle", last_activity_at="2026-08-03T11:50:00Z")
    active = session_payload(id="active", last_activity_at="2026-08-03T11:50:00.000001Z")
    unknown = session_payload(id="unknown", last_activity_at=None)
    config = ImportConfig(
        days=3,
        project="wandb/hivemind-chats",
        idle_minutes=10,
        state_path=tmp_path / "state.sqlite3",
        dry_run=True,
        cutoff=datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
    )
    client = FakeHiveMind(
        [lower, idle, active, unknown],
        {
            "lower": atif_wrapper(wrapper_session_id="lower"),
            "idle": atif_wrapper(wrapper_session_id="idle"),
        },
    )

    report = run_import(config, hivemind=client)

    assert report.discovered == 4
    assert report.eligible == 2
    assert report.deferred == 2
    assert report.planned == 2
    assert client.fetched == ["lower", "idle"]


def test_discovery_to_atif_activity_race_conflicts_before_any_upload(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    discovered = session_payload(id="racing")
    moved = {**discovered, "last_activity_at": "2026-08-01T12:21:00Z"}

    class RacingHiveMind(FakeHiveMind):
        def get_session(self, session_id: str) -> dict[str, Any]:
            self.direct_fetched.append(session_id)
            return moved

    client = RacingHiveMind(
        [discovered],
        {"racing": atif_wrapper(wrapper_session_id="racing")},
    )
    sink = FakeSink()
    report = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    assert sink.start_calls == 0
    assert client.direct_fetched == ["racing", "racing"]
    with StateStore(tmp_path / "state.sqlite3") as state:
        run = state.connection.execute("SELECT phase FROM import_runs").fetchone()
        entry = state.connection.execute("SELECT status FROM import_run_sessions").fetchone()
        assert run is not None and run["phase"] == "certifying"
        assert entry is not None and entry["status"] == "conflict"


@pytest.mark.parametrize("mutation", ["append", "delete"])
def test_turn_set_drift_between_certification_and_upload_is_rejected(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    mutation: str,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    session = session_payload(id=f"drift-{mutation}")
    original = atif_wrapper(wrapper_session_id=session["id"])
    if mutation == "append":
        changed_steps = [
            *original["trajectory"]["steps"],
            {
                "step_id": 5,
                "timestamp": "2026-08-01T12:10:00Z",
                "source": "user",
                "message": "A late appended turn",
            },
            {
                "step_id": 6,
                "timestamp": "2026-08-01T12:10:01Z",
                "source": "agent",
                "message": "Late answer",
            },
        ]
    else:
        changed_steps = original["trajectory"]["steps"][:1]
    changed = atif_wrapper(wrapper_session_id=session["id"], steps=changed_steps)

    class DriftingHiveMind(FakeHiveMind):
        def get_atif(self, session_id: str) -> dict[str, Any]:
            self.fetched.append(session_id)
            return original if len(self.fetched) == 1 else changed

    client = DriftingHiveMind([session], {session["id"]: original})
    sink = FakeSink()
    report = run_import(
        _config(tmp_path),
        hivemind=client,
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    assert sink.start_calls == 0
    assert client.fetched == [session["id"], session["id"]]


def test_resumed_manifest_rejects_summary_activity_drift(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    config = _config(tmp_path)
    discovered = Session.from_api(session_payload(id="resume-activity"))
    with StateStore(config.state_path) as state:
        assert config.cutoff is not None
        state.create_run(
            project=config.project,
            cutoff=config.cutoff,
            days=config.days,
            idle_minutes=config.idle_minutes,
            config=importer_module._run_config_payload(config),
            sessions=[(discovered.id, discovered.last_activity_at)],
            discovered_count=1,
            deferred_count=0,
        )
    moved = session_payload(
        id=discovered.id,
        last_activity_at="2026-08-01T12:21:00Z",
    )

    class ResumeHiveMind(FakeHiveMind):
        def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
            raise AssertionError("resume must use the saved manifest")

    client = ResumeHiveMind(
        [moved],
        {discovered.id: atif_wrapper(wrapper_session_id=discovered.id)},
    )
    sink = FakeSink()
    report = run_import(
        replace(config, cutoff=datetime(2026, 9, 2, tzinfo=UTC)),
        hivemind=client,
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    assert client.requested_days == []
    assert client.direct_fetched == [discovered.id, discovered.id]


def test_interrupted_manifest_resumes_fixed_boundary_by_direct_fetch(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload(
        id="boundary",
        started_at="2026-07-31T11:00:00Z",
        last_activity_at="2026-07-31T12:00:00Z",
    )
    wrapper = atif_wrapper(wrapper_session_id="boundary")
    config = _config(tmp_path)
    real_sanitize = importer_module.sanitize_mapped_conversation

    def interrupt_before_first_turn(_conversation: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        importer_module,
        "sanitize_mapped_conversation",
        interrupt_before_first_turn,
    )
    with pytest.raises(KeyboardInterrupt):
        run_import(
            config,
            hivemind=FakeHiveMind([raw_session], {"boundary": wrapper}),
            sink=FakeSink(),
            verifier=FakeVerifier(),
        )

    with StateStore(config.state_path) as state:
        run_row = state.connection.execute(
            "SELECT run_id, cutoff, status FROM import_runs"
        ).fetchone()
        assert run_row is not None
        assert run_row["cutoff"] == "2026-08-03T12:00:00Z"
        assert run_row["status"] == "active"
        session_row = state.connection.execute(
            "SELECT status FROM import_run_sessions WHERE session_id = 'boundary'"
        ).fetchone()
        assert session_row is not None and session_row["status"] == "uncertified"
        assert state.connection.execute("SELECT COUNT(*) FROM imported_turns").fetchone()[0] == 0

    monkeypatch.setattr(importer_module, "sanitize_mapped_conversation", real_sanitize)

    class ResumeHiveMind(FakeHiveMind):
        def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
            raise AssertionError("resume must not rediscover a moving time window")

    resume_client = ResumeHiveMind([raw_session], {"boundary": wrapper})
    sink = FakeSink()
    advanced_config = replace(
        config,
        cutoff=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )
    report = run_import(
        advanced_config,
        hivemind=resume_client,
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert report.ok
    assert report.discovered == 1
    assert report.eligible == 1
    assert resume_client.direct_fetched == ["boundary"] * 4
    assert resume_client.requested_days == []
    assert sink.logged[0][0].source_last_activity_at == datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
    with StateStore(config.state_path) as state:
        assert (
            state.connection.execute("SELECT status FROM import_runs").fetchone()[0] == "completed"
        )
        assert (
            state.connection.execute("SELECT status FROM import_run_sessions").fetchone()[0]
            == "imported"
        )


def test_resumed_content_mutation_conflicts_without_rediscovery(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload(id="mutated")
    original = atif_wrapper(wrapper_session_id="mutated")
    config = _config(tmp_path)
    first = run_import(
        config,
        hivemind=FakeHiveMind([raw_session], {"mutated": original}),
        sink=FakeSink(fail_flush=True),
        verifier=FakeVerifier(),
    )
    assert not first.ok

    changed_steps = list(original["trajectory"]["steps"])
    changed_steps[1] = {**changed_steps[1], "message": "mutated after upload"}
    changed = atif_wrapper(wrapper_session_id="mutated", steps=changed_steps)

    class ResumeHiveMind(FakeHiveMind):
        def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
            raise AssertionError("resume must use the saved manifest")

    sink = FakeSink()
    report = run_import(
        replace(config, cutoff=datetime(2026, 9, 2, 12, 0, tzinfo=UTC)),
        hivemind=ResumeHiveMind([raw_session], {"mutated": changed}),
        sink=sink,
        verifier=FakeVerifier(),
    )

    assert not report.ok
    assert report.conflicted == 1
    assert sink.logged == []
    with StateStore(config.state_path) as state:
        assert state.connection.execute("SELECT status FROM import_runs").fetchone()[0] == "active"
        assert (
            state.connection.execute("SELECT status FROM import_run_sessions").fetchone()[0]
            == "conflict"
        )


def test_unfinished_run_rejects_config_drift_before_rediscovery(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "test-key")
    raw_session = session_payload(id="drift")
    config = _config(tmp_path)

    def interrupt_before_first_turn(_conversation: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        importer_module,
        "sanitize_mapped_conversation",
        interrupt_before_first_turn,
    )
    with pytest.raises(KeyboardInterrupt):
        run_import(
            config,
            hivemind=FakeHiveMind(
                [raw_session],
                {"drift": atif_wrapper(wrapper_session_id="drift")},
            ),
            sink=FakeSink(),
            verifier=FakeVerifier(),
        )

    class NoDiscoveryHiveMind(FakeHiveMind):
        def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
            raise AssertionError("incompatible resume must fail before discovery")

    with pytest.raises(StateConflictError, match="configuration does not match"):
        run_import(
            replace(config, days=4),
            hivemind=NoDiscoveryHiveMind([raw_session], {}),
        )


def test_empty_session_is_terminal_and_completes_manifest(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    monkeypatch.delenv("WANDB_API_KEY", raising=False)
    raw_session = session_payload(id="empty")
    report = run_import(
        _config(tmp_path),
        hivemind=FakeHiveMind(
            [raw_session],
            {"empty": atif_wrapper(wrapper_session_id="empty", steps=[])},
        ),
    )

    assert report.ok
    assert report.planned == 0
    with StateStore(tmp_path / "state.sqlite3") as state:
        assert (
            state.connection.execute("SELECT status FROM import_runs").fetchone()[0] == "completed"
        )
        assert (
            state.connection.execute("SELECT status FROM import_run_sessions").fetchone()[0]
            == "empty"
        )
