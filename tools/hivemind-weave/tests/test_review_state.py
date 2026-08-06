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
    ReviewPlan,
    ReviewStateStore,
    ReviewTurnCertificate,
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
        source_principal_sha256="2" * 64,
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
        logical_key="7" * 64,
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
    for statement in state_module._SCHEMA_SQL:
        if statement == state_module._REVIEW_TURN_LEDGER_SQL:
            statement = statement.replace(
                "    index_size INTEGER NOT NULL DEFAULT 0 CHECK(index_size >= 0),\n",
                "",
            )
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
