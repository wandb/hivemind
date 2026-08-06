from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hivemind_weave import state as state_module
from hivemind_weave.errors import StateConflictError
from hivemind_weave.review_state import (
    REVIEW_SOURCE_SCOPE_SHA256,
    ReviewPlan,
    ReviewStateStore,
    ReviewTurnCertificate,
    review_logical_key,
    review_successor_plan_id,
)
from hivemind_weave.state import DB_APPLICATION_ID, DB_SCHEMA_VERSION, StateStore

PROJECT = "wandb/hivemind-chats-review"
PLAN_ID = "1" * 64
SESSION_ID = "11111111-1111-4111-8111-111111111111"
TURN_KEY = "turn-1"
TRACE_ID = "a" * 32
ROOT_SPAN_ID = "b" * 16
START = datetime(2026, 7, 1, tzinfo=UTC)
ACTIVITY = datetime(2026, 7, 2, tzinfo=UTC)


def _object_ref(name: str, content_sha256: str) -> str:
    return f"weave:///wandb/hivemind-chats-review/object/{name}-{content_sha256}:{'Z' * 43}"


def _plan(*, status: str = "planned") -> ReviewPlan:
    return ReviewPlan(
        plan_id=PLAN_ID,
        project=PROJECT,
        source_scope_sha256=REVIEW_SOURCE_SCOPE_SHA256,
        since_utc=datetime(2026, 7, 1, tzinfo=UTC),
        until_utc=datetime(2026, 8, 1, tzinfo=UTC),
        timezone_name="UTC",
        selector="backlog",
        universe_sha256="3" * 64,
        status=status,
        discovered_count=1,
        eligible_count=1,
        deferred_count=0,
        invalid_count=0,
        selected_count=1,
        last_error_code="",
    )


def _certificate(*, manifest_sha256: str = "5" * 64) -> ReviewTurnCertificate:
    return ReviewTurnCertificate(
        plan_id=PLAN_ID,
        session_id=SESSION_ID,
        ordinal=0,
        turn_key=TURN_KEY,
        source_payload_sha256="4" * 64,
        manifest_sha256=manifest_sha256,
        index_sha256="6" * 64,
        logical_key=review_logical_key(
            PROJECT,
            f"hivemind:{SESSION_ID}",
            TURN_KEY,
        ),
        preview_signature="8" * 64,
        started_at=START,
        ended_at=ACTIVITY,
        manifest_bytes=100,
        chunk_count=2,
        max_chunk_bytes=60,
        index_bytes=90,
        atif_schema_version="ATIF-v1.7",
    )


def _create(state: ReviewStateStore) -> None:
    state.create_plan(
        plan=_plan(),
        sessions=[(SESSION_ID, START, ACTIVITY)],
        filters=[("agent", "codex")],
        turns=[_certificate()],
    )


def _block_with_preflight_conflict(state: ReviewStateStore) -> None:
    _create(state)
    cohort = state.get_or_create_cohort(PLAN_ID, 1)
    assert cohort is not None
    cohort = state.begin_cohort(cohort)
    ledger, outcome = state.ensure_ledger(PROJECT, _certificate())
    assert outcome == "new"
    state.mark_conflict(ledger, "preflight_session_conflict")
    state.finish_cohort(
        cohort,
        success=False,
        visible_turns=0,
        skipped_turns=0,
        conflicted_turns=1,
        failed_items=0,
        error_code="preflight_session_conflict",
    )


def test_review_state_lifecycle_keeps_only_content_free_evidence(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    with ReviewStateStore(state_path) as state:
        _create(state)
        cohort = state.get_or_create_cohort(PLAN_ID, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)

        row, outcome = state.ensure_ledger(PROJECT, _certificate())
        assert outcome == "new"
        row = state.mark_objects_publishing(row)
        row = state.mark_objects_verified(
            row,
            chunk_refs=(
                _object_ref("chunk-a", "a" * 64),
                _object_ref("chunk-b", "b" * 64),
            ),
            chunk_hashes=("a" * 64, "b" * 64),
            chunk_sizes=(40, 60),
            index_ref=_object_ref("index", "6" * 64),
            index_sha256="6" * 64,
            index_size=90,
        )
        row = state.mark_root_submitting(row)
        row = state.mark_visible(row, trace_id=TRACE_ID, root_span_id=ROOT_SPAN_ID)
        assert row.status == "visible"

        state.finish_cohort(
            cohort,
            success=True,
            visible_turns=1,
            skipped_turns=0,
            conflicted_turns=0,
            failed_items=0,
        )
        status = state.status(PROJECT)
        assert status.visible == 1
        assert status.completed_sessions == 1
        assert state.resolve_plan(PLAN_ID[:12]).status == "completed"  # type: ignore[union-attr]
        saved_filters = state.get_filters(PLAN_ID)
        assert saved_filters == [("agent", "1")]

    raw = state_path.read_bytes()
    assert b"private prompt" not in raw
    assert b"tool result" not in raw
    assert b"codex" not in raw


def test_low_entropy_filter_values_and_their_dictionary_hashes_never_reach_state(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    repository = "private/acquisition"
    legacy_digest = hashlib.sha256(
        f"hivemind-review-filter-v1\0repository\0{repository}".encode()
    ).hexdigest()

    with ReviewStateStore(state_path) as state:
        state.create_plan(
            plan=_plan(),
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("repository", repository)],
            turns=[_certificate()],
        )
        assert state.get_filters(PLAN_ID) == [("repository", "1")]

    raw = state_path.read_bytes()
    assert repository.encode() not in raw
    assert legacy_digest.encode() not in raw


@pytest.mark.parametrize(
    "unsafe_id",
    ["sk-proj-1234567890abcdef", "session-AliceJohnson", "child-JohnSmith"],
)
def test_unsafe_source_id_never_reaches_sqlite(tmp_path: Path, unsafe_id: str) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    with (
        ReviewStateStore(state_path) as state,
        pytest.raises(StateConflictError, match="unsafe session identity"),
    ):
        state.create_plan(
            plan=_plan(),
            sessions=[(unsafe_id, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[replace(_certificate(), session_id=unsafe_id)],
        )

    assert unsafe_id.encode() not in state_path.read_bytes()


def test_state_decoder_rejects_a_tampered_name_like_session_coordinate() -> None:
    with pytest.raises(StateConflictError, match="session identity is unsafe"):
        ReviewStateStore._session(
            {
                "plan_id": PLAN_ID,
                "ordinal": 0,
                "session_id": "session-AliceJohnson",
                "started_at": START.isoformat(),
                "last_activity_at": ACTIVITY.isoformat(),
                "status": "planned",
            }
        )


def test_changed_historical_manifest_becomes_conflict_without_replacement(
    tmp_path: Path,
) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _create(state)
        original, _ = state.ensure_ledger(PROJECT, _certificate())
        changed, outcome = state.ensure_ledger(
            PROJECT,
            _certificate(manifest_sha256="9" * 64),
        )

        assert outcome == "conflict"
        assert changed.status == "conflict"
        assert changed.manifest_sha256 == original.manifest_sha256
        assert changed.error_code == "inflight_manifest_changed"


def test_review_logical_key_is_enforced_at_plan_and_ledger_admission(tmp_path: Path) -> None:
    first_path = tmp_path / "plan" / "state.sqlite3"
    with (
        ReviewStateStore(first_path) as state,
        pytest.raises(StateConflictError, match="invalid turn certificate"),
    ):
        state.create_plan(
            plan=_plan(),
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[replace(_certificate(), logical_key="7" * 64)],
        )

    second_path = tmp_path / "ledger" / "state.sqlite3"
    with ReviewStateStore(second_path) as state:
        _create(state)
        with pytest.raises(StateConflictError, match="logical key is malformed"):
            state.ensure_ledger(
                PROJECT,
                replace(_certificate(), logical_key="7" * 64),
            )
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is None


def test_visible_same_source_keeps_original_immutable_manifest(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _create(state)
        original, _ = state.ensure_ledger(PROJECT, _certificate())
        original = state.mark_objects_publishing(original)
        original = state.mark_objects_verified(
            original,
            chunk_refs=(
                _object_ref("chunk-a", "a" * 64),
                _object_ref("chunk-b", "b" * 64),
            ),
            chunk_hashes=("a" * 64, "b" * 64),
            chunk_sizes=(40, 60),
            index_ref=_object_ref("index", "6" * 64),
            index_sha256="6" * 64,
            index_size=90,
        )
        original = state.mark_root_submitting(original)
        original = state.mark_visible(
            original,
            trace_id=TRACE_ID,
            root_span_id=ROOT_SPAN_ID,
        )

        replay, outcome = state.ensure_ledger(
            PROJECT,
            _certificate(manifest_sha256="9" * 64),
        )

        assert outcome == "same_source_visible"
        assert replay.status == "visible"
        assert replay.manifest_sha256 == original.manifest_sha256


def test_uncertain_root_cannot_be_retried_but_can_be_reconciled(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _create(state)
        row, _ = state.ensure_ledger(PROJECT, _certificate())
        row = state.mark_objects_publishing(row)
        row = state.mark_objects_verified(
            row,
            chunk_refs=(
                _object_ref("chunk-a", "a" * 64),
                _object_ref("chunk-b", "b" * 64),
            ),
            chunk_hashes=("a" * 64, "b" * 64),
            chunk_sizes=(40, 60),
            index_ref=_object_ref("index", "6" * 64),
            index_sha256="6" * 64,
            index_size=90,
        )
        row = state.mark_root_submitting(row)
        row = state.mark_uncertain(row, "visibility_timeout")

        with pytest.raises(sqlite3.IntegrityError, match="state transition"):
            state.mark_root_submitting(row)

        reconciled = state.mark_visible(row, trace_id=TRACE_ID, root_span_id=ROOT_SPAN_ID)
        assert reconciled.status == "visible"


@pytest.mark.parametrize(
    ("trace_id", "root_span_id"),
    [
        ("alice@example.com", ROOT_SPAN_ID),
        (TRACE_ID, "Bearer-secret"),
        ("0" * 32, ROOT_SPAN_ID),
        (TRACE_ID, "0" * 16),
        ("A" * 32, ROOT_SPAN_ID),
    ],
)
def test_remote_root_ids_must_be_nonzero_lowercase_w3c_hex(
    tmp_path: Path,
    trace_id: str,
    root_span_id: str,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    with ReviewStateStore(state_path) as state:
        _create(state)
        row, _ = state.ensure_ledger(PROJECT, _certificate())
        with pytest.raises(StateConflictError, match="invalid identity evidence"):
            state.mark_visible(row, trace_id=trace_id, root_span_id=root_span_id)

    raw = state_path.read_bytes()
    if trace_id != TRACE_ID:
        assert trace_id.encode() not in raw
    if root_span_id != ROOT_SPAN_ID:
        assert root_span_id.encode() not in raw


def test_remote_object_ref_cannot_persist_credential_shaped_digest(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    sentinel = "sk-proj-1234567890abcdef"
    with ReviewStateStore(state_path) as state:
        _create(state)
        row, _ = state.ensure_ledger(PROJECT, _certificate())
        row = state.mark_objects_publishing(row)
        with pytest.raises(StateConflictError, match="invalid evidence"):
            state.mark_objects_verified(
                row,
                chunk_refs=(
                    _object_ref("chunk-a", "a" * 64),
                    f"weave:///wandb/hivemind-chats-review/object/chunk-b-{'b' * 64}:{sentinel}",
                ),
                chunk_hashes=("a" * 64, "b" * 64),
                chunk_sizes=(40, 60),
                index_ref=_object_ref("index", "6" * 64),
                index_sha256="6" * 64,
                index_size=90,
            )

    assert sentinel.encode() not in state_path.read_bytes()


def test_object_evidence_mismatch_is_a_conflict(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _create(state)
        row, _ = state.ensure_ledger(PROJECT, _certificate())
        row = state.mark_objects_publishing(row)
        row = state.mark_objects_verified(
            row,
            chunk_refs=(
                _object_ref("chunk-a", "a" * 64),
                _object_ref("chunk-b", "b" * 64),
            ),
            chunk_hashes=("a" * 64, "b" * 64),
            chunk_sizes=(40, 60),
            index_ref=_object_ref("index", "6" * 64),
            index_sha256="6" * 64,
            index_size=90,
        )

        conflicted = state.mark_objects_verified(
            row,
            chunk_refs=(
                _object_ref("chunk-a", "a" * 64),
                _object_ref("changed", "b" * 64),
            ),
            chunk_hashes=("a" * 64, "b" * 64),
            chunk_sizes=(40, 60),
            index_ref=_object_ref("index", "6" * 64),
            index_sha256="6" * 64,
            index_size=90,
        )
        assert conflicted.status == "conflict"


def test_preflight_conflict_retirement_is_atomic_immutable_and_reusable(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    proof = "c" * 64
    with ReviewStateStore(state_path) as state:
        _block_with_preflight_conflict(state)

        conflicts = state.preflight_conflicts(PLAN_ID)
        assert len(conflicts) == 1
        assert conflicts[0].error_code == "preflight_session_conflict"
        assert (
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256=proof,
                importer_version="0.4.0",
            )
            == 1
        )
        assert state.is_plan_retired(PLAN_ID)
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is None
        assert state.preflight_conflicts(PLAN_ID) == []
        retired_evidence = state.retired_preflight_evidence(
            project=PROJECT,
            session_id=SESSION_ID,
            turn_key=TURN_KEY,
        )
        assert len(retired_evidence) == 1
        assert retired_evidence[0].plan_id == PLAN_ID
        assert retired_evidence[0].logical_key == _certificate().logical_key
        assert retired_evidence[0].proof_sha256 == proof
        assert (
            state.retired_preflight_evidence(
                project=PROJECT,
                session_id=SESSION_ID,
                turn_key="other-turn",
            )
            == ()
        )
        assert (
            state.unfinished_plan_for_window(
                project=PROJECT,
                since_utc=datetime(2026, 7, 1, tzinfo=UTC),
                until_utc=datetime(2026, 8, 1, tzinfo=UTC),
            )
            is None
        )
        assert state.status(PROJECT).plans == 0
        assert state.status(PROJECT).queued_sessions == 0
        state.assert_project_writes_unblocked(PROJECT)
        terminal_snapshots = state.terminal_session_snapshots(PROJECT)
        assert terminal_snapshots == {(SESSION_ID, START, ACTIVITY)}
        assert (SESSION_ID, START, ACTIVITY.replace(day=3)) not in terminal_snapshots

        with pytest.raises(StateConflictError, match="cannot be applied"):
            state.get_or_create_cohort(PLAN_ID, 1)
        with pytest.raises(StateConflictError, match="deterministic successor"):
            state.create_plan(
                plan=_plan(),
                sessions=[(SESSION_ID, START, ACTIVITY)],
                filters=[("agent", "codex")],
                turns=[_certificate()],
            )
        assert (
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256=proof,
                importer_version="0.4.0",
            )
            == 1
        )
        with pytest.raises(StateConflictError, match="different retirement evidence"):
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256="d" * 64,
                importer_version="0.4.0",
            )

        replacement_plan_id = state.successor_plan_id(PLAN_ID)
        assert replacement_plan_id == review_successor_plan_id(
            PLAN_ID,
            outcome="retired",
            resolution_proof_sha256=proof,
        )
        replacement_certificate = replace(
            _certificate(),
            plan_id=replacement_plan_id,
        )
        state.create_plan(
            plan=replace(
                _plan(),
                plan_id=replacement_plan_id,
            ),
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[replacement_certificate],
        )
        replacement, outcome = state.ensure_ledger(PROJECT, replacement_certificate)
        assert outcome == "new"
        assert replacement.status == "planned"

        archive = state._db.execute(
            "SELECT * FROM review_preflight_conflict_archive WHERE plan_id = ?",
            (PLAN_ID,),
        ).fetchone()
        retirement = state._db.execute(
            "SELECT * FROM review_plan_retirements WHERE plan_id = ?",
            (PLAN_ID,),
        ).fetchone()
        assert archive is not None
        assert retirement is not None
        with pytest.raises(sqlite3.IntegrityError, match="archives are immutable"):
            state._db.execute(
                "UPDATE review_preflight_conflict_archive SET proof_sha256 = ? WHERE plan_id = ?",
                ("f" * 64, PLAN_ID),
            )
        state._db.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="retirements cannot be deleted"):
            state._db.execute(
                "DELETE FROM review_plan_retirements WHERE plan_id = ?",
                (PLAN_ID,),
            )
        state._db.rollback()


def test_transient_preflight_conflict_revalidation_creates_a_terminal_attempt(
    tmp_path: Path,
) -> None:
    proof = "d" * 64
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _block_with_preflight_conflict(state)
        blocked_cohort = state.get_cohort(
            state._db.execute(
                "SELECT cohort_id FROM review_cohorts WHERE plan_id = ?",
                (PLAN_ID,),
            ).fetchone()[0]
        )
        assert blocked_cohort.status == "blocked"
        assert len(state.preflight_conflicts(PLAN_ID)) == 1

        assert (
            state.revalidate_preflight_plan(
                PLAN_ID,
                proof_sha256=proof,
                importer_version="0.4.0",
            )
            == 1
        )
        assert state.is_plan_revalidated(PLAN_ID)
        assert not state.is_plan_retired(PLAN_ID)
        assert state.preflight_conflicts(PLAN_ID) == []
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is None
        state.assert_project_writes_unblocked(PROJECT)

        terminal = state.resolve_plan(PLAN_ID)
        assert terminal is not None
        assert terminal.status == "blocked"
        cohort = state.get_cohort(blocked_cohort.cohort_id)
        assert cohort.status == "blocked"
        assert cohort.visible_turns == 0
        assert cohort.skipped_turns == 0
        assert cohort.conflicted_turns == 1
        assert cohort.failed_items == 0
        sessions = state.get_sessions(PLAN_ID)
        assert [item.status for item in sessions] == ["blocked"]
        assert state.status(PROJECT).plans == 0
        assert state.status(PROJECT).queued_sessions == 0

        evidence = state.retired_preflight_evidence(
            project=PROJECT,
            session_id=SESSION_ID,
            turn_key=TURN_KEY,
        )
        assert len(evidence) == 1
        assert evidence[0].plan_id == PLAN_ID
        assert evidence[0].logical_key == _certificate().logical_key
        assert evidence[0].proof_sha256 == proof

        assert (
            state.revalidate_preflight_plan(
                PLAN_ID,
                proof_sha256=proof,
                importer_version="0.4.0",
            )
            == 1
        )
        with pytest.raises(StateConflictError, match="different revalidation evidence"):
            state.revalidate_preflight_plan(
                PLAN_ID,
                proof_sha256="e" * 64,
                importer_version="0.4.0",
            )

        with pytest.raises(StateConflictError, match="terminal review plans"):
            state.get_or_create_cohort(PLAN_ID, 1)

        successor_id = state.successor_plan_id(PLAN_ID)
        assert successor_id == review_successor_plan_id(
            PLAN_ID,
            outcome="revalidated",
            resolution_proof_sha256=proof,
        )
        assert state.successor_plan_id(PLAN_ID) == successor_id
        assert state.plan_id_in_successor_chain(PLAN_ID, PLAN_ID)
        assert state.plan_id_in_successor_chain(PLAN_ID, successor_id)
        successor_certificate = replace(_certificate(), plan_id=successor_id)
        state.create_plan(
            plan=replace(_plan(), plan_id=successor_id),
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[successor_certificate],
        )
        ledger, outcome = state.ensure_ledger(PROJECT, successor_certificate)
        assert outcome == "new"
        assert ledger.status == "planned"


def test_revalidation_rejects_non_preflight_and_retired_evidence(tmp_path: Path) -> None:
    first_path = tmp_path / "advanced" / "state.sqlite3"
    with ReviewStateStore(first_path) as state:
        _create(state)
        cohort = state.get_or_create_cohort(PLAN_ID, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, _ = state.ensure_ledger(PROJECT, _certificate())
        ledger = state.mark_objects_publishing(ledger)
        state.mark_conflict(ledger, "preflight_session_conflict")
        state.finish_cohort(
            cohort,
            success=False,
            visible_turns=0,
            skipped_turns=0,
            conflicted_turns=1,
            failed_items=0,
            error_code="preflight_session_conflict",
        )
        with pytest.raises(StateConflictError, match="non-revalidatable turn evidence"):
            state.revalidate_preflight_plan(
                PLAN_ID,
                proof_sha256="d" * 64,
                importer_version="0.4.0",
            )

    second_path = tmp_path / "retired" / "state.sqlite3"
    with ReviewStateStore(second_path) as state:
        _block_with_preflight_conflict(state)
        state.retire_preflight_plan(
            PLAN_ID,
            proof_sha256="c" * 64,
            importer_version="0.4.0",
        )
        with pytest.raises(StateConflictError, match="cannot be revalidated"):
            state.revalidate_preflight_plan(
                PLAN_ID,
                proof_sha256="d" * 64,
                importer_version="0.4.0",
            )


def test_old_archive_cannot_clear_a_later_identical_active_conflict(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _block_with_preflight_conflict(state)
        first_proof = "c" * 64
        state.revalidate_preflight_plan(
            PLAN_ID,
            proof_sha256=first_proof,
            importer_version="0.4.0",
        )
        successor_id = state.successor_plan_id(PLAN_ID)
        successor_plan = replace(_plan(), plan_id=successor_id)
        successor_certificate = replace(_certificate(), plan_id=successor_id)
        state.create_plan(
            plan=successor_plan,
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[successor_certificate],
        )
        cohort = state.get_or_create_cohort(successor_id, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, outcome = state.ensure_ledger(PROJECT, successor_certificate)
        assert outcome == "new"
        ledger = state.mark_conflict(ledger, "preflight_session_conflict")
        state.finish_cohort(
            cohort,
            success=False,
            visible_turns=0,
            skipped_turns=0,
            conflicted_turns=1,
            failed_items=0,
            error_code="preflight_session_conflict",
        )

        with pytest.raises(StateConflictError, match="unresolved turn evidence"):
            state.assert_project_writes_unblocked(PROJECT)
        with pytest.raises(sqlite3.IntegrityError, match="evidence cannot be deleted"):
            state._db.execute(
                "DELETE FROM review_turn_ledger "
                "WHERE project = ? AND session_id = ? AND turn_key = ?",
                (PROJECT, SESSION_ID, TURN_KEY),
            )
        state._db.rollback()
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) == ledger
        assert len(state.preflight_conflicts(successor_id)) == 1

        second_proof = "e" * 64
        state.retire_preflight_plan(
            successor_id,
            proof_sha256=second_proof,
            importer_version="0.4.0",
        )
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is None
        second_successor = state.successor_plan_id(PLAN_ID)
        assert second_successor == review_successor_plan_id(
            successor_id,
            outcome="retired",
            resolution_proof_sha256=second_proof,
        )
        assert second_successor != successor_id
        assert state.successor_plan_id(PLAN_ID) == second_successor
        assert (
            len(
                state.retired_preflight_evidence(
                    project=PROJECT,
                    session_id=SESSION_ID,
                    turn_key=TURN_KEY,
                )
            )
            == 2
        )


def test_successor_derivation_is_domain_separated_and_cycle_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    predecessor = "a" * 64
    proof = "b" * 64
    retired = review_successor_plan_id(
        predecessor,
        outcome="retired",
        resolution_proof_sha256=proof,
    )
    revalidated = review_successor_plan_id(
        predecessor,
        outcome="revalidated",
        resolution_proof_sha256=proof,
    )
    assert retired != revalidated
    assert retired == review_successor_plan_id(
        predecessor,
        outcome="retired",
        resolution_proof_sha256=proof,
    )
    with pytest.raises(StateConflictError, match="outcome is malformed"):
        review_successor_plan_id(
            predecessor,
            outcome="unknown",
            resolution_proof_sha256=proof,
        )

    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _block_with_preflight_conflict(state)
        state.retire_preflight_plan(
            PLAN_ID,
            proof_sha256="c" * 64,
            importer_version="0.4.0",
        )
        monkeypatch.setattr(
            "hivemind_weave.review_state.review_successor_plan_id",
            lambda predecessor_plan_id, **_kwargs: predecessor_plan_id,
        )
        with pytest.raises(StateConflictError, match="contains a cycle"):
            state.successor_plan_id(PLAN_ID)


def test_retirement_rejects_non_preflight_and_advanced_turn_evidence(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _create(state)
        cohort = state.get_or_create_cohort(PLAN_ID, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, _ = state.ensure_ledger(PROJECT, _certificate())
        ledger = state.mark_objects_publishing(ledger)
        state.mark_conflict(ledger, "preflight_session_conflict")
        state.finish_cohort(
            cohort,
            success=False,
            visible_turns=0,
            skipped_turns=0,
            conflicted_turns=1,
            failed_items=0,
            error_code="preflight_session_conflict",
        )

        assert state.preflight_conflicts(PLAN_ID) == []
        with pytest.raises(StateConflictError, match="non-retirable turn evidence"):
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256="c" * 64,
                importer_version="0.4.0",
            )
        assert not state.is_plan_retired(PLAN_ID)
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is not None


def test_retirement_rejects_a_live_ledger_shared_with_another_plan(tmp_path: Path) -> None:
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        _block_with_preflight_conflict(state)
        other_plan_id = "2" * 64
        state.create_plan(
            plan=replace(
                _plan(),
                plan_id=other_plan_id,
                universe_sha256="e" * 64,
            ),
            sessions=[(SESSION_ID, START, ACTIVITY)],
            filters=[("agent", "codex")],
            turns=[replace(_certificate(), plan_id=other_plan_id)],
        )

        with pytest.raises(StateConflictError, match="another active plan"):
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256="c" * 64,
                importer_version="0.4.0",
            )
        assert not state.is_plan_retired(PLAN_ID)
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is not None


def test_preflight_resolution_fails_closed_for_a_partial_multi_session_cohort(
    tmp_path: Path,
) -> None:
    second_session_id = "22222222-2222-4222-8222-222222222222"
    second_certificate = replace(
        _certificate(),
        session_id=second_session_id,
        logical_key=review_logical_key(
            PROJECT,
            f"hivemind:{second_session_id}",
            TURN_KEY,
        ),
    )
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        state.create_plan(
            plan=replace(
                _plan(),
                selected_count=2,
                discovered_count=2,
                eligible_count=2,
            ),
            sessions=[
                (SESSION_ID, START, ACTIVITY),
                (second_session_id, START, ACTIVITY),
            ],
            filters=[("agent", "codex")],
            turns=[_certificate(), second_certificate],
        )
        cohort = state.get_or_create_cohort(PLAN_ID, 2)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, _ = state.ensure_ledger(PROJECT, _certificate())
        state.mark_conflict(ledger, "preflight_session_conflict")
        state.finish_cohort(
            cohort,
            success=False,
            visible_turns=0,
            skipped_turns=0,
            conflicted_turns=1,
            failed_items=0,
            error_code="preflight_session_conflict",
        )

        for resolve in (state.retire_preflight_plan, state.revalidate_preflight_plan):
            with pytest.raises(StateConflictError, match="multi-session"):
                resolve(
                    PLAN_ID,
                    proof_sha256="c" * 64,
                    importer_version="0.4.0",
                )
        assert not state.is_plan_terminal(PLAN_ID)
        assert state.get_ledger(PROJECT, SESSION_ID, TURN_KEY) is not None


@pytest.mark.parametrize(
    ("proof", "version", "message"),
    [
        ("not-a-proof", "0.4.0", "proof is malformed"),
        ("c" * 64, "Alice Johnson", "version is malformed"),
    ],
)
def test_retirement_rejects_content_bearing_metadata(
    tmp_path: Path,
    proof: str,
    version: str,
    message: str,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    with ReviewStateStore(state_path) as state:
        _block_with_preflight_conflict(state)
        with pytest.raises(StateConflictError, match=message):
            state.retire_preflight_plan(
                PLAN_ID,
                proof_sha256=proof,
                importer_version=version,
            )

    assert b"Alice Johnson" not in state_path.read_bytes()


def test_schema_v6_migrates_atomically_to_review_schema(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    review_statements = set(state_module._REVIEW_SCHEMA_SQL)
    for statement in state_module._SCHEMA_SQL:
        if statement not in review_statements:
            connection.execute(statement)
    connection.execute("PRAGMA user_version=6")
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        assert state.connection is not None
        assert state.connection.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
        assert state.connection.execute(
            "SELECT name FROM sqlite_schema WHERE name = 'review_turn_ledger'"
        ).fetchone()


def test_schema_v7_adds_hosted_index_size_atomically(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    recovery_statements = {
        *state_module._REVIEW_PREFLIGHT_RECOVERY_SCHEMA_SQL,
        *state_module._REVIEW_REVALIDATION_SCHEMA_SQL,
    }
    for statement in state_module._SCHEMA_SQL:
        if statement in recovery_statements:
            continue
        if statement == state_module._REVIEW_TURN_LEDGER_SQL:
            statement = statement.replace(
                "    index_size INTEGER NOT NULL DEFAULT 0 CHECK(index_size >= 0),\n",
                "",
            )
        elif statement == state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL:
            statement = """
                CREATE TRIGGER review_turn_ledger_no_delete
                BEFORE DELETE ON review_turn_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'review turn evidence cannot be deleted');
                END
            """
        connection.execute(statement)
    connection.execute("PRAGMA user_version=7")
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        columns = {
            str(row["name"]): row
            for row in state.connection.execute("PRAGMA table_info(review_turn_ledger)")
        }
        assert state.connection.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
        assert "index_size" in columns


def test_schema_v8_adds_preflight_retirement_evidence_atomically(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    recovery_statements = {
        *state_module._REVIEW_PREFLIGHT_RECOVERY_SCHEMA_SQL,
        *state_module._REVIEW_REVALIDATION_SCHEMA_SQL,
    }
    for statement in state_module._SCHEMA_SQL:
        if statement in recovery_statements:
            continue
        if statement == state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL:
            statement = """
                CREATE TRIGGER review_turn_ledger_no_delete
                BEFORE DELETE ON review_turn_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'review turn evidence cannot be deleted');
                END
            """
        connection.execute(statement)
    connection.execute("PRAGMA user_version=8")
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        names = {
            str(row[0])
            for row in state.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        assert state.connection.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
        assert "review_preflight_conflict_archive" in names
        assert "review_plan_retirements" in names
        assert "review_plan_revalidations" in names


def test_schema_v9_adds_preflight_revalidation_evidence_atomically(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    revalidation_statements = set(state_module._REVIEW_REVALIDATION_SCHEMA_SQL)
    old_retirement_guard = state_module._REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL.replace(
        "    AND NOT EXISTS (\n"
        "        SELECT 1 FROM review_plan_revalidations\n"
        "        WHERE plan_id = NEW.plan_id\n"
        "    )\n",
        "",
    )
    old_ledger_guard = """
        CREATE TRIGGER review_turn_ledger_no_delete
        BEFORE DELETE ON review_turn_ledger
        WHEN NOT EXISTS (
            SELECT 1
            FROM review_preflight_conflict_archive AS archive
            JOIN review_plan_retirements AS retirement
              ON retirement.plan_id = archive.plan_id
             AND retirement.project = archive.project
             AND retirement.proof_sha256 = archive.proof_sha256
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
        )
        BEGIN
            SELECT RAISE(ABORT, 'review turn evidence cannot be deleted');
        END
    """
    for statement in state_module._SCHEMA_SQL:
        if statement in revalidation_statements:
            continue
        if statement == state_module._REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL:
            statement = old_retirement_guard
        elif statement == state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL:
            statement = old_ledger_guard
        connection.execute(statement)
    connection.execute("PRAGMA user_version=9")
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        assert state.connection.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
        assert state.connection.execute(
            "SELECT name FROM sqlite_schema WHERE name = 'review_plan_revalidations'"
        ).fetchone()


def test_schema_v10_tightens_review_ledger_delete_authority_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    active_attempt_guard = """
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
"""
    old_trigger = state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL.replace(
        active_attempt_guard,
        "",
    ).replace(
        "      AND archive.ledger_created_at = OLD.created_at\n"
        "      AND archive.ledger_updated_at = OLD.updated_at\n",
        "",
    )
    assert old_trigger != state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL
    old_retirement_guard = (
        state_module._REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL.replace(
            "          AND selected_count = 1\n",
            "",
        )
        .replace(
            " OR session_count != 1",
            "",
        )
        .replace(
            "    AND 1 = (SELECT COUNT(*) FROM review_cohorts WHERE plan_id = NEW.plan_id)\n",
            "",
        )
    )
    old_revalidation_guard = (
        state_module._REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL.replace(
            "          AND selected_count = 1\n",
            "",
        )
        .replace(
            " OR session_count != 1",
            "",
        )
        .replace(
            "    AND 1 = (SELECT COUNT(*) FROM review_cohorts WHERE plan_id = NEW.plan_id)\n",
            "",
        )
    )
    connection = sqlite3.connect(path)
    for statement in state_module._SCHEMA_SQL:
        if statement == state_module._REVIEW_LEDGER_NO_DELETE_TRIGGER_SQL:
            statement = old_trigger
        elif statement == state_module._REVIEW_PLAN_RETIREMENT_INSERT_GUARD_SQL:
            statement = old_retirement_guard
        elif statement == state_module._REVIEW_PLAN_REVALIDATION_INSERT_GUARD_SQL:
            statement = old_revalidation_guard
        connection.execute(statement)
    connection.execute("PRAGMA user_version=10")
    connection.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
    connection.commit()
    connection.close()
    path.chmod(0o600)

    with StateStore(path) as state:
        assert state.connection.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
        trigger_sql = str(
            state.connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name = 'review_turn_ledger_no_delete'"
            ).fetchone()[0]
        )
        assert "active_turn" in trigger_sql
        assert "active_revalidation" in trigger_sql
        retirement_sql = str(
            state.connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name = 'review_plan_retirements_insert_guard'"
            ).fetchone()[0]
        )
        revalidation_sql = str(
            state.connection.execute(
                "SELECT sql FROM sqlite_schema "
                "WHERE name = 'review_plan_revalidations_insert_guard'"
            ).fetchone()[0]
        )
        assert "selected_count = 1" in retirement_sql
        assert "selected_count = 1" in revalidation_sql
