from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import hivemind_weave.review_audit as audit_module
from hivemind_weave import cli
from hivemind_weave.errors import ReviewMirrorError
from hivemind_weave.review import REVIEW_PROJECT
from hivemind_weave.review_audit import (
    AuditCounts,
    ReviewAuditConfig,
    ReviewAuditReport,
    audit_review,
)
from hivemind_weave.review_state import (
    REVIEW_SOURCE_SCOPE_SHA256,
    ReviewPlan,
    ReviewStateStore,
    ReviewTurnCertificate,
    review_logical_key,
)
from hivemind_weave.utils import canonical_json

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
SINCE = "2026-08-01T00:00:00Z"
UNTIL = "2026-08-07T12:00:00Z"
CLOSED_UNTIL = "2026-08-07T10:00:00Z"
ROOT_ID = "11111111-1111-4111-8111-111111111111"
CHILD_ID = "22222222-2222-4222-8222-222222222222"
THIRD_ID = "33333333-3333-4333-8333-333333333333"
CHUNK_SHA256 = "e" * 64
INDEX_SHA256 = "6" * 64


class FakeAuditHiveMind:
    def __init__(self, snapshots: list[list[dict[str, Any]]]) -> None:
        self.snapshots = snapshots
        self.calls: list[tuple[int, bool]] = []
        self.preflights = 0

    def preflight(self) -> None:
        self.preflights += 1

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        self.calls.append((days, include_subagents))
        return list(self.snapshots[len(self.calls) - 1])


def _source(
    session_id: str,
    *,
    started_at: str = "2026-08-02T10:00:00Z",
    last_activity_at: str = "2026-08-02T11:00:00Z",
    parent_session_id: str = "",
    title: str = "private transcript title",
) -> dict[str, Any]:
    return {
        "id": session_id,
        "started_at": started_at,
        "last_activity_at": last_activity_at,
        "parent_session_id": parent_session_id,
        "title": title,
        "agent_type": "codex",
        "git_repo": "private/repository",
    }


def _config(
    state_path: Path,
    *,
    exclude_subagents: bool = False,
    until: str = CLOSED_UNTIL,
) -> ReviewAuditConfig:
    return ReviewAuditConfig(
        since=SINCE,
        until=until,
        project=REVIEW_PROJECT,
        state_path=state_path,
        exclude_subagents=exclude_subagents,
        now=NOW,
    )


def _plan(label: str, revisions: list[tuple[str, datetime, datetime]]) -> ReviewPlan:
    digest = hashlib.sha256(label.encode()).hexdigest()
    return ReviewPlan(
        plan_id=digest,
        project=REVIEW_PROJECT,
        source_scope_sha256=REVIEW_SOURCE_SCOPE_SHA256,
        since_utc=datetime(2026, 8, 1, tzinfo=UTC),
        until_utc=NOW,
        timezone_name="UTC",
        selector="backlog",
        universe_sha256=hashlib.sha256(f"universe:{label}".encode()).hexdigest(),
        status="planned",
        discovered_count=len(revisions),
        eligible_count=len(revisions),
        deferred_count=0,
        invalid_count=0,
        selected_count=len(revisions),
        last_error_code="",
    )


def _seed_plan(
    state_path: Path,
    *,
    label: str,
    revisions: list[tuple[str, datetime, datetime]],
    completed: bool,
) -> None:
    with ReviewStateStore(state_path) as state:
        saved = state.create_plan(
            plan=_plan(label, revisions),
            sessions=revisions,
            filters=[],
            turns=[],
        )
        if completed:
            cohort = state.get_or_create_cohort(saved.plan_id, len(revisions))
            assert cohort is not None
            cohort = state.begin_cohort(cohort)
            state.finish_cohort(
                cohort,
                success=True,
                visible_turns=0,
                skipped_turns=0,
                conflicted_turns=0,
                failed_items=0,
            )


def _certificate(
    plan: ReviewPlan,
    *,
    session_id: str,
    started_at: datetime,
    ended_at: datetime,
    source_sha256: str = "a" * 64,
    manifest_sha256: str = "b" * 64,
    preview_signature: str = "d" * 64,
    manifest_bytes: int = 10,
) -> ReviewTurnCertificate:
    turn_key = "turn-000001"
    return ReviewTurnCertificate(
        plan_id=plan.plan_id,
        session_id=session_id,
        ordinal=0,
        turn_key=turn_key,
        source_payload_sha256=source_sha256,
        manifest_sha256=manifest_sha256,
        index_sha256="c" * 64,
        logical_key=review_logical_key(
            REVIEW_PROJECT,
            f"hivemind:{session_id}",
            turn_key,
        ),
        preview_signature=preview_signature,
        started_at=started_at,
        ended_at=ended_at,
        manifest_bytes=manifest_bytes,
        chunk_count=1,
        max_chunk_bytes=manifest_bytes,
        index_bytes=10,
        atif_schema_version="ATIF-v1.0",
    )


def _seed_visible_plan(
    state_path: Path,
    *,
    label: str,
    revision: tuple[str, datetime, datetime],
) -> tuple[ReviewPlan, ReviewTurnCertificate]:
    plan = _plan(label, [revision])
    certificate = _certificate(
        plan,
        session_id=revision[0],
        started_at=revision[1],
        ended_at=revision[2],
    )
    chunk_name = f"hm-review-v1-{'b' * 24}-c01-of-01-{CHUNK_SHA256}.txt"
    index_name = f"hivemind-hosted-review-index-v1-{INDEX_SHA256}.json"
    chunk_ref = f"weave:///wandb/hivemind-chats-review/object/{chunk_name}:{CHUNK_SHA256}"
    index_ref = f"weave:///wandb/hivemind-chats-review/object/{index_name}:{INDEX_SHA256}"
    with ReviewStateStore(state_path) as state:
        state.create_plan(
            plan=plan,
            sessions=[revision],
            filters=[],
            turns=[certificate],
        )
        cohort = state.get_or_create_cohort(plan.plan_id, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, outcome = state.ensure_ledger(REVIEW_PROJECT, certificate)
        assert outcome == "new"
        ledger = state.mark_objects_publishing(ledger)
        ledger = state.mark_objects_verified(
            ledger,
            chunk_refs=(chunk_ref,),
            chunk_hashes=(CHUNK_SHA256,),
            chunk_sizes=(certificate.manifest_bytes,),
            index_ref=index_ref,
            index_sha256=INDEX_SHA256,
            index_size=10,
        )
        ledger = state.mark_root_submitting(ledger)
        state.mark_visible(
            ledger,
            trace_id="0" * 31 + "1",
            root_span_id="0" * 15 + "1",
        )
        state.finish_cohort(
            cohort,
            success=True,
            visible_turns=1,
            skipped_turns=0,
            conflicted_turns=0,
            failed_items=0,
        )
    return plan, certificate


def _audit(
    tmp_path: Path,
    sessions: list[dict[str, Any]],
    *,
    state_path: Path | None = None,
    exclude_subagents: bool = False,
    until: str = CLOSED_UNTIL,
) -> tuple[ReviewAuditReport, FakeAuditHiveMind]:
    client = FakeAuditHiveMind([sessions, sessions])
    report = audit_review(
        _config(
            state_path or tmp_path / "missing" / "state.sqlite3",
            exclude_subagents=exclude_subagents,
            until=until,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )
    return report, client


def test_audit_uses_two_full_supported_subagent_scans(tmp_path: Path) -> None:
    report, client = _audit(tmp_path, [])

    assert report.ok
    assert client.preflights == 1
    assert client.calls == [(365, True), (365, True)]


def test_audit_requires_a_closed_settled_window_for_complete_verdict(tmp_path: Path) -> None:
    report, _client = _audit(tmp_path, [], until=UNTIL)

    assert report.deferred.total == 0
    assert not report.window_final
    assert not report.ok
    assert "closed window final:  no" in report.render()


def test_audit_rejects_mismatched_filtered_source_universes(tmp_path: Path) -> None:
    first = [_source(ROOT_ID)]
    second = [_source(ROOT_ID), _source(CHILD_ID, parent_session_id=ROOT_ID)]
    client = FakeAuditHiveMind([first, second])

    with pytest.raises(ReviewMirrorError, match="source scans did not agree"):
        audit_review(_config(tmp_path / "missing" / "state.sqlite3"), hivemind=client)  # type: ignore[arg-type]


def test_audit_applies_exact_window_and_settle_boundaries(tmp_path: Path) -> None:
    sessions = [
        _source(ROOT_ID, started_at=SINCE, last_activity_at=SINCE),
        _source(CHILD_ID, last_activity_at="2026-08-07T11:00:00Z"),
        _source(THIRD_ID, last_activity_at="2026-08-07T11:00:00.000001Z"),
        _source("44444444-4444-4444-8444-444444444444", last_activity_at=UNTIL),
        _source(
            "55555555-5555-4555-8555-555555555555",
            started_at="2026-07-31T22:00:00Z",
            last_activity_at="2026-07-31T23:59:59Z",
        ),
    ]

    report, _client = _audit(tmp_path, sessions, until=UNTIL)

    assert report.never_planned.total == 2
    assert report.deferred.total == 1
    assert report.eligible == 2
    assert not report.window_final
    assert not report.ok


def test_audit_reports_root_and_subagent_coverage_separately(tmp_path: Path) -> None:
    sessions = [_source(ROOT_ID), _source(CHILD_ID, parent_session_id=ROOT_ID)]

    report, _client = _audit(tmp_path, sessions)
    roots_only, _client = _audit(tmp_path, sessions, exclude_subagents=True)

    assert report.never_planned == AuditCounts(roots=1, subagents=1)
    assert roots_only.never_planned == AuditCounts(roots=1)
    assert "subagents in scope:   yes" in report.render()
    assert "subagents in scope:   no" in roots_only.render()
    assert "unbounded source completeness: UNPROVEN" in roots_only.render()


def test_audit_recognizes_exact_completed_revision(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    started = datetime(2026, 8, 2, 10, tzinfo=UTC)
    activity = datetime(2026, 8, 2, 11, tzinfo=UTC)
    _seed_visible_plan(
        state_path,
        label="completed",
        revision=(ROOT_ID, started, activity),
    )
    assert state_path.read_bytes()[18:20] == b"\x02\x02"
    before = {
        item.name: (item.read_bytes(), item.stat().st_mtime_ns)
        for item in state_path.parent.iterdir()
    }

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)
    after = {
        item.name: (item.read_bytes(), item.stat().st_mtime_ns)
        for item in state_path.parent.iterdir()
    }

    assert report.completed_exact.total == 1
    assert report.ok
    assert after == before
    assert set(after) == {"state.sqlite3", "state.sqlite3.lock"}


def test_audit_accepts_completed_empty_mapping_as_source_coverage(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    started = datetime(2026, 8, 2, 10, tzinfo=UTC)
    activity = datetime(2026, 8, 2, 11, tzinfo=UTC)
    _seed_plan(
        state_path,
        label="completed-empty-mapping",
        revisions=[(ROOT_ID, started, activity)],
        completed=True,
    )

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert report.completed_exact == AuditCounts(roots=1)
    assert report.ok


def test_audit_validates_complete_visible_turn_evidence(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="visible", revision=revision)

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert report.completed_exact.total == 1
    assert report.ok


def test_audit_accepts_base64url_weave_reference_versions(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="base64-references", revision=revision)
    chunk_version = base64.urlsafe_b64encode(bytes.fromhex(CHUNK_SHA256)).decode().rstrip("=")
    index_version = base64.urlsafe_b64encode(bytes.fromhex(INDEX_SHA256)).decode().rstrip("=")
    chunk_name = f"hm-review-v1-{'b' * 24}-c01-of-01-{CHUNK_SHA256}.txt"
    index_name = f"hivemind-hosted-review-index-v1-{INDEX_SHA256}.json"
    chunk_ref = f"weave:///wandb/hivemind-chats-review/object/{chunk_name}:{chunk_version}"
    index_ref = f"weave:///wandb/hivemind-chats-review/object/{index_name}:{index_version}"
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE review_turn_ledger
            SET chunk_refs_json = ?, index_ref = ?, revision = revision + 1
            WHERE project = ? AND session_id = ?
            """,
            (canonical_json([chunk_ref]), index_ref, REVIEW_PROJECT, ROOT_ID),
        )
        database.commit()
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert report.completed_exact.total == 1
    assert report.ok


def test_audit_rejects_valid_reference_not_bound_to_saved_content_hash(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="unrelated-reference", revision=revision)
    unrelated = "f" * 64
    unrelated_name = f"hm-review-v1-{'b' * 24}-c01-of-01-{unrelated}.txt"
    unrelated_ref = f"weave:///wandb/hivemind-chats-review/object/{unrelated_name}:{CHUNK_SHA256}"
    with sqlite3.connect(state_path) as database:
        database.execute(
            """
            UPDATE review_turn_ledger
            SET chunk_refs_json = ?, revision = revision + 1
            WHERE project = ? AND session_id = ?
            """,
            (canonical_json([unrelated_ref]), REVIEW_PROJECT, ROOT_ID),
        )
        database.commit()
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with pytest.raises(ReviewMirrorError, match="inconsistent completed-session evidence"):
        _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)


def test_audit_mirrors_same_source_visible_append_reuse(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    started = datetime(2026, 8, 2, 10, tzinfo=UTC)
    first_activity = datetime(2026, 8, 2, 11, tzinfo=UTC)
    appended_activity = datetime(2026, 8, 3, 11, tzinfo=UTC)
    _first_plan, first_certificate = _seed_visible_plan(
        state_path,
        label="append-first",
        revision=(ROOT_ID, started, first_activity),
    )
    appended_plan = _plan("append-second", [(ROOT_ID, started, appended_activity)])
    appended_certificate = _certificate(
        appended_plan,
        session_id=ROOT_ID,
        started_at=started,
        ended_at=first_activity,
        source_sha256=first_certificate.source_payload_sha256,
        manifest_sha256="1" * 64,
        preview_signature="2" * 64,
        manifest_bytes=20,
    )
    with ReviewStateStore(state_path) as state:
        state.create_plan(
            plan=appended_plan,
            sessions=[(ROOT_ID, started, appended_activity)],
            filters=[],
            turns=[appended_certificate],
        )
        cohort = state.get_or_create_cohort(appended_plan.plan_id, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        ledger, outcome = state.ensure_ledger(REVIEW_PROJECT, appended_certificate)
        assert outcome == "same_source_visible"
        assert ledger.status == "visible"
        state.finish_cohort(
            cohort,
            success=True,
            visible_turns=0,
            skipped_turns=1,
            conflicted_turns=0,
            failed_items=0,
        )

    report, _client = _audit(
        tmp_path,
        [
            _source(
                ROOT_ID,
                started_at="2026-08-02T10:00:00Z",
                last_activity_at="2026-08-03T11:00:00Z",
            )
        ],
        state_path=state_path,
    )

    assert report.completed_exact.total == 1
    assert report.ok


@pytest.mark.parametrize(
    ("assignment", "value"),
    [
        ("trace_id", ""),
        ("index_size", 8 * 1024 * 1024 + 1),
        (
            "index_ref",
            "not-an-immutable-weave-reference",
        ),
    ],
)
def test_audit_rejects_corrupt_visible_evidence(
    tmp_path: Path,
    assignment: str,
    value: object,
) -> None:
    state_path = tmp_path / assignment / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label=f"corrupt-{assignment}", revision=revision)
    with sqlite3.connect(state_path) as database:
        database.execute(
            f"""
            UPDATE review_turn_ledger
            SET {assignment} = ?, revision = revision + 1
            WHERE project = ? AND session_id = ?
            """,
            (value, REVIEW_PROJECT, ROOT_ID),
        )
        database.commit()
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with pytest.raises(ReviewMirrorError, match="inconsistent completed-session evidence"):
        _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)


@pytest.mark.parametrize("turn_key", ["x" * 4_097, "turn\x00private"])
def test_audit_rejects_turn_keys_outside_worker_contract(turn_key: str) -> None:
    assert not audit_module._valid_turn_key(turn_key)


def test_audit_rejects_atif_version_outside_worker_contract(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="invalid-atif-version", revision=revision)
    with sqlite3.connect(state_path) as database:
        trigger_sql = database.execute(
            """
            SELECT sql FROM sqlite_schema
            WHERE type = 'trigger' AND name = 'review_plan_turns_immutable'
            """
        ).fetchone()[0]
        database.execute("DROP TRIGGER review_plan_turns_immutable")
        database.execute(
            """
            UPDATE review_plan_turns
            SET atif_schema_version = 'ATIF-v2.0'
            WHERE session_id = ?
            """,
            (ROOT_ID,),
        )
        database.execute(trigger_sql)
        database.commit()
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with pytest.raises(ReviewMirrorError, match="inconsistent completed-session evidence"):
        _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)


def test_audit_rejects_completed_session_with_missing_visible_turn_evidence(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    started = datetime(2026, 8, 2, 10, tzinfo=UTC)
    activity = datetime(2026, 8, 2, 11, tzinfo=UTC)
    plan = _plan("inconsistent-completed", [(ROOT_ID, started, activity)])
    turn_key = "turn-000001"
    digest = "a" * 64
    certificate = ReviewTurnCertificate(
        plan_id=plan.plan_id,
        session_id=ROOT_ID,
        ordinal=0,
        turn_key=turn_key,
        source_payload_sha256=digest,
        manifest_sha256="b" * 64,
        index_sha256="c" * 64,
        logical_key=review_logical_key(REVIEW_PROJECT, f"hivemind:{ROOT_ID}", turn_key),
        preview_signature="d" * 64,
        started_at=started,
        ended_at=activity,
        manifest_bytes=10,
        chunk_count=1,
        max_chunk_bytes=10,
        index_bytes=10,
        atif_schema_version="ATIF-v1.0",
    )
    with ReviewStateStore(state_path) as state:
        state.create_plan(
            plan=plan,
            sessions=[(ROOT_ID, started, activity)],
            filters=[],
            turns=[certificate],
        )
        cohort = state.get_or_create_cohort(plan.plan_id, 1)
        assert cohort is not None
        cohort = state.begin_cohort(cohort)
        state.finish_cohort(
            cohort,
            success=True,
            visible_turns=0,
            skipped_turns=0,
            conflicted_turns=0,
            failed_items=0,
        )

    with pytest.raises(ReviewMirrorError, match="inconsistent completed-session evidence"):
        _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)


def test_audit_groups_planned_and_retry_exact_revisions(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    started = datetime(2026, 8, 2, 10, tzinfo=UTC)
    activity = datetime(2026, 8, 2, 11, tzinfo=UTC)
    _seed_plan(
        state_path,
        label="planned",
        revisions=[(ROOT_ID, started, activity)],
        completed=False,
    )
    with ReviewStateStore(state_path) as state:
        state.record_preseal_failure(
            project=REVIEW_PROJECT,
            session_id=CHILD_ID,
            started_at=started,
            last_activity_at=activity,
            error_code="preparation_timeout",
        )

    report, _client = _audit(
        tmp_path,
        [_source(ROOT_ID), _source(CHILD_ID, parent_session_id=ROOT_ID)],
        state_path=state_path,
    )

    assert report.planned_retry_exact == AuditCounts(roots=1, subagents=1)
    assert not report.ok


def test_audit_distinguishes_advanced_known_id_from_never_planned(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_visible_plan(
        state_path,
        label="old-revision",
        revision=(
            ROOT_ID,
            datetime(2026, 8, 2, 10, tzinfo=UTC),
            datetime(2026, 8, 2, 10, 30, tzinfo=UTC),
        ),
    )

    report, _client = _audit(
        tmp_path,
        [_source(ROOT_ID), _source(CHILD_ID, parent_session_id=ROOT_ID)],
        state_path=state_path,
    )

    assert report.advanced_known_id == AuditCounts(roots=1)
    assert report.never_planned == AuditCounts(subagents=1)
    assert not report.ok


@pytest.mark.parametrize(
    ("source_started", "source_activity"),
    [
        ("2026-08-02T09:00:00Z", "2026-08-02T11:00:00Z"),
        ("2026-08-02T10:00:00Z", "2026-08-02T10:00:00Z"),
    ],
)
def test_audit_does_not_call_id_reuse_or_regressed_activity_advanced(
    tmp_path: Path,
    source_started: str,
    source_activity: str,
) -> None:
    state_path = tmp_path / source_activity.replace(":", "-") / "private" / "state.sqlite3"
    _seed_visible_plan(
        state_path,
        label=f"known-{source_started}-{source_activity}",
        revision=(
            ROOT_ID,
            datetime(2026, 8, 2, 10, tzinfo=UTC),
            datetime(2026, 8, 2, 10, 30, tzinfo=UTC),
        ),
    )

    report, _client = _audit(
        tmp_path,
        [
            _source(
                ROOT_ID,
                started_at=source_started,
                last_activity_at=source_activity,
            )
        ],
        state_path=state_path,
    )

    assert report.advanced_known_id.total == 0
    assert report.invalid_unclassifiable.total == 1
    assert not report.ok


@pytest.mark.parametrize(
    "other_revision",
    [
        (
            ROOT_ID,
            datetime(2026, 8, 2, 10, tzinfo=UTC),
            datetime(2026, 8, 3, 11, tzinfo=UTC),
        ),
        (
            ROOT_ID,
            datetime(2026, 8, 1, 10, tzinfo=UTC),
            datetime(2026, 8, 2, 11, tzinfo=UTC),
        ),
    ],
)
def test_audit_does_not_let_older_exact_completion_mask_regression_or_id_reuse(
    tmp_path: Path,
    other_revision: tuple[str, datetime, datetime],
) -> None:
    state_path = (
        tmp_path / hashlib.sha256(str(other_revision).encode()).hexdigest() / "state.sqlite3"
    )
    exact_revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="older-exact", revision=exact_revision)
    _seed_plan(
        state_path,
        label=f"other-{other_revision}",
        revisions=[other_revision],
        completed=False,
    )

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert report.completed_exact.total == 0
    assert report.invalid_unclassifiable == AuditCounts(unclassifiable=1)
    assert not report.ok


def test_missing_database_is_never_created_and_all_eligible_are_never_planned(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "absent-private" / "state.sqlite3"

    report, _client = _audit(
        tmp_path,
        [_source(ROOT_ID)],
        state_path=state_path,
    )

    assert report.never_planned.total == 1
    assert not state_path.parent.exists()


def test_audit_wraps_state_path_errors_without_exposing_the_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "PRIVATE-STATE-PATH-DO-NOT-PRINT"

    def reject_lstat(_path: Path) -> Any:
        raise PermissionError(sentinel)

    monkeypatch.setattr(audit_module.Path, "lstat", reject_lstat)

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [], state_path=tmp_path / sentinel / "state.sqlite3")

    assert str(captured.value) == "review audit state path is unavailable"
    assert sentinel not in str(captured.value)


def test_audit_wraps_ancestry_metadata_errors_without_exposing_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="ancestry-error", revisions=[], completed=False)
    sentinel = "PRIVATE-ANCESTRY-ERROR-DO-NOT-PRINT"

    def reject_fstat(_descriptor: int) -> Any:
        raise PermissionError(sentinel)

    monkeypatch.setattr(audit_module.os, "fstat", reject_fstat)

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [], state_path=state_path)

    assert str(captured.value) == "review audit state ancestry is unsafe"
    assert sentinel not in str(captured.value)


def test_audit_wraps_file_identity_errors_without_exposing_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="identity-error", revisions=[], completed=False)
    sentinel = "PRIVATE-IDENTITY-ERROR-DO-NOT-PRINT"
    real_stat = audit_module.os.stat

    def reject_lock_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path == f"{state_path.name}.lock":
            raise PermissionError(sentinel)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(audit_module.os, "stat", reject_lock_stat)

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [], state_path=state_path)

    assert str(captured.value) == "review audit state lock is unavailable"
    assert sentinel not in str(captured.value)


def test_audit_wraps_flock_errors_without_exposing_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="flock-error", revisions=[], completed=False)
    sentinel = "PRIVATE-FLOCK-ERROR-DO-NOT-PRINT"

    def reject_flock(_descriptor: int, _operation: int) -> None:
        raise OSError(sentinel)

    monkeypatch.setattr(audit_module.fcntl, "flock", reject_flock)

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [], state_path=state_path)

    assert str(captured.value) == "review audit state lock is unavailable"
    assert sentinel not in str(captured.value)


def test_audit_wraps_sidecar_probe_errors_without_exposing_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="sidecar-error", revisions=[], completed=False)
    sentinel = "PRIVATE-SIDECAR-ERROR-DO-NOT-PRINT"
    real_stat = audit_module.os.stat

    def reject_wal_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if path == f"{state_path.name}-wal":
            raise PermissionError(sentinel)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(audit_module.os, "stat", reject_wal_stat)

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [], state_path=state_path)

    assert str(captured.value) == "review audit state sidecar is unavailable"
    assert sentinel not in str(captured.value)


def test_audit_descriptor_binding_survives_user_path_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="directory-swap", revision=revision)
    original_connect = audit_module._ReadOnlyJournal._connect
    swapped = False

    def swap_then_connect(reader: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            moved = tmp_path / "pinned-original"
            state_path.parent.rename(moved)
            state_path.parent.mkdir(mode=0o700)
            state_path.write_bytes(b"replacement path is not a sqlite database")
            state_path.chmod(0o600)
            swapped = True
        return original_connect(reader)

    monkeypatch.setattr(audit_module._ReadOnlyJournal, "_connect", swap_then_connect)

    report, _client = _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert swapped
    assert report.completed_exact.total == 1
    assert report.ok


def test_audit_fails_closed_if_pinned_database_is_unlinked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="unlink", revisions=[], completed=False)
    original_connect = audit_module._ReadOnlyJournal._connect

    def unlink_then_connect(reader: Any) -> sqlite3.Connection:
        os.unlink(reader.path.name, dir_fd=reader._directory_fd)
        return original_connect(reader)

    monkeypatch.setattr(audit_module._ReadOnlyJournal, "_connect", unlink_then_connect)

    with pytest.raises(ReviewMirrorError, match="changed during inspection"):
        _audit(tmp_path, [], state_path=state_path)


def test_audit_fails_closed_if_pinned_lock_entry_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    _seed_plan(state_path, label="lock-replacement", revisions=[], completed=False)
    original_connect = audit_module._ReadOnlyJournal._connect

    def replace_lock_then_connect(reader: Any) -> sqlite3.Connection:
        lock_name = f"{reader.path.name}.lock"
        os.unlink(lock_name, dir_fd=reader._directory_fd)
        replacement = os.open(
            lock_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=reader._directory_fd,
        )
        os.close(replacement)
        return original_connect(reader)

    monkeypatch.setattr(audit_module._ReadOnlyJournal, "_connect", replace_lock_then_connect)

    with pytest.raises(ReviewMirrorError, match="lock changed during inspection"):
        _audit(tmp_path, [], state_path=state_path)


def test_audit_rejects_text_turn_ordinal_without_echoing_it(tmp_path: Path) -> None:
    state_path = tmp_path / "private" / "state.sqlite3"
    revision = (
        ROOT_ID,
        datetime(2026, 8, 2, 10, tzinfo=UTC),
        datetime(2026, 8, 2, 11, tzinfo=UTC),
    )
    _seed_visible_plan(state_path, label="text-ordinal", revision=revision)
    sentinel = "PRIVATE-ORDINAL-DO-NOT-PRINT"
    with sqlite3.connect(state_path) as database:
        trigger_sql = database.execute(
            """
            SELECT sql FROM sqlite_schema
            WHERE type = 'trigger' AND name = 'review_plan_turns_immutable'
            """
        ).fetchone()[0]
        database.execute("DROP TRIGGER review_plan_turns_immutable")
        database.execute("PRAGMA ignore_check_constraints=ON")
        database.execute(
            """
            UPDATE review_plan_turns
            SET ordinal = ?
            WHERE session_id = ?
            """,
            (sentinel, ROOT_ID),
        )
        database.execute(trigger_sql)
        database.commit()
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with pytest.raises(ReviewMirrorError) as captured:
        _audit(tmp_path, [_source(ROOT_ID)], state_path=state_path)

    assert str(captured.value) == "review audit journal has inconsistent completed-session evidence"
    assert sentinel not in str(captured.value)


def test_audit_opens_untrusted_database_candidate_nonblocking_before_fifo_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    state_path = private / "state.sqlite3"
    lock_path = private / "state.sqlite3.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    os.mkfifo(state_path, mode=0o600)
    real_open = audit_module.os.open
    observed_nonblocking = False

    def guarded_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal observed_nonblocking
        if path == state_path.name:
            assert flags & os.O_NONBLOCK
            observed_nonblocking = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(audit_module.os, "open", guarded_open)

    with pytest.raises(ReviewMirrorError, match="database is unsafe"):
        _audit(tmp_path, [], state_path=state_path)
    assert observed_nonblocking


def test_audit_output_is_content_free(tmp_path: Path) -> None:
    sentinel = "PRIVATE-TITLE-DO-NOT-PRINT"
    session = _source(ROOT_ID, title=sentinel)

    report, _client = _audit(tmp_path, [session])
    rendered = report.render()

    assert sentinel not in rendered
    assert ROOT_ID not in rendered
    assert "private/repository" not in rendered
    assert "never planned" in rendered
    assert "INCOMPLETE" in rendered


def test_audit_counts_invalid_source_rows_without_rendering_them(tmp_path: Path) -> None:
    sentinel = "PRIVATE-INVALID-SUMMARY"
    invalid = _source(ROOT_ID, title=sentinel)
    invalid["id"] = "not-an-opaque-id"

    report, _client = _audit(tmp_path, [invalid])

    assert report.invalid_unclassifiable == AuditCounts(unclassifiable=1)
    assert not report.ok
    assert sentinel not in report.render()


def test_cli_audit_returns_nonzero_for_incomplete_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: Any,
) -> None:
    captured: list[ReviewAuditConfig] = []

    def fake_audit(config: ReviewAuditConfig) -> ReviewAuditReport:
        captured.append(config)
        return ReviewAuditReport(
            project=REVIEW_PROJECT,
            since_utc=datetime(2026, 8, 1, tzinfo=UTC),
            until_utc=NOW,
            settled_before=NOW - timedelta(minutes=60),
            completed_exact=AuditCounts(),
            planned_retry_exact=AuditCounts(),
            advanced_known_id=AuditCounts(),
            never_planned=AuditCounts(roots=1),
            deferred=AuditCounts(),
            invalid_unclassifiable=AuditCounts(),
        )

    monkeypatch.setattr(cli, "audit_review", fake_audit)
    state_path = tmp_path / "state.sqlite3"
    exit_code = cli.main(
        [
            "review",
            "audit",
            "--since",
            SINCE,
            "--until",
            UNTIL,
            "--project",
            REVIEW_PROJECT,
            "--state-path",
            str(state_path),
        ]
    )

    assert exit_code == 1
    assert captured[0].state_path == state_path
    output = capsys.readouterr().out
    assert "365-day feed coverage: INCOMPLETE" in output
    assert "unbounded source completeness: UNPROVEN" in output
