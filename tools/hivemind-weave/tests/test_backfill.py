from __future__ import annotations

import hashlib
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from hivemind_weave import backfill
from hivemind_weave.backfill import (
    BackfillApplyConfig,
    BackfillPreviewConfig,
    apply_backfill,
    preview_backfill,
    resolve_backfill_window,
)
from hivemind_weave.errors import BackfillError
from hivemind_weave.historical_sink import PreparedOutcome
from hivemind_weave.models import RunReport
from hivemind_weave.state import StateStore

PROJECT = "wandb/hivemind-backfill-test"
NOW = datetime(2026, 8, 5, 16, 0, tzinfo=UTC)


class FakeHiveMind:
    def __init__(self, sessions: list[dict[str, Any]], *, user_id: str = "user-1") -> None:
        self.sessions = sessions
        self.user_id: str | None = user_id
        self.list_days: list[int] = []
        self.direct_fetches: list[str] = []

    def preflight(self) -> None:
        return None

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        assert include_subagents is True
        self.list_days.append(days)
        return list(self.sessions)

    def get_session(self, session_id: str) -> dict[str, Any]:
        self.direct_fetches.append(session_id)
        for session in self.sessions:
            if session.get("id") == session_id:
                return dict(session)
        raise AssertionError("unknown planned session")

    def get_atif(self, session_id: str) -> dict[str, Any]:
        raw = self.get_session(session_id)
        timestamp = str(raw["started_at"])
        steps = [
            {
                "step_id": 1,
                "timestamp": timestamp,
                "source": "user",
                "message": f"source message for {session_id}",
            },
            {
                "step_id": 2,
                "timestamp": timestamp,
                "source": "agent",
                "message": f"source response for {session_id}",
            },
        ]
        return {
            "session_id": session_id,
            "trajectory": {
                "schema_version": "ATIF-v1.7",
                "session_id": f"atif-{session_id}",
                "agent": {
                    "name": raw.get("agent_type", "codex"),
                    "version": "test",
                    "model_name": raw.get("model", "gpt-test"),
                },
                "steps": steps,
            },
            "step_count": len(steps),
            "metadata": {},
        }


class FakeHistoricalSink:
    instances: ClassVar[list[FakeHistoricalSink]] = []

    def __init__(self) -> None:
        self.capabilities = SimpleNamespace(
            capability_version="historical-turn-test-v1",
            max_turn_compressed_bytes=10_000_000,
            max_turn_uncompressed_bytes=20_000_000,
            max_turn_span_count=100,
            max_turn_reference_count=100,
        )
        self.started = False
        self.prepared: list[tuple[str, str]] = []
        self.__class__.instances.append(self)

    def start(self, project: str) -> None:
        assert project == PROJECT
        self.started = True

    def prepare_turn(self, conversation: Any, turn: Any) -> PreparedOutcome:
        assert self.started
        identity = f"{conversation.conversation_id}\0{turn.key}\0{turn.payload_sha256}"
        self.prepared.append((conversation.conversation_id, turn.key))
        return PreparedOutcome(
            logical_key=hashlib.sha256(f"logical\0{identity}".encode()).hexdigest(),
            wire_sha256=hashlib.sha256(f"wire\0{identity}".encode()).hexdigest(),
            span_count=1 + len(turn.llms) + len(turn.tools) + len(turn.subagents),
            compressed_bytes=321,
            uncompressed_bytes=654,
            reference_count=0,
            capability_version="historical-turn-test-v1",
            sdk_prepared=None,
        )

    def finish(self) -> None:
        assert self.started
        self.started = False


@pytest.fixture(autouse=True)
def _fake_historical_sink(monkeypatch: Any) -> None:
    FakeHistoricalSink.instances.clear()
    monkeypatch.setattr(backfill, "HistoricalTurnSink", FakeHistoricalSink)


def test_date_only_bounds_are_exact_local_midnights_across_dst() -> None:
    window = resolve_backfill_window(
        since="2026-03-08",
        until="2026-03-10",
        days=None,
        timezone_name="America/New_York",
        now=datetime(2026, 4, 1, tzinfo=UTC),
    )
    alias = resolve_backfill_window(
        since=None,
        until="2026-03-10",
        days=2,
        timezone_name="America/New_York",
        now=datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert window.since_utc == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)
    assert window.until_utc == datetime(2026, 3, 10, 4, 0, tzinfo=UTC)
    assert alias == window
    assert (window.until_utc - window.since_utc).total_seconds() == 47 * 60 * 60


def test_date_only_bounds_default_to_detected_local_iana_timezone(monkeypatch: Any) -> None:
    monkeypatch.setattr(backfill, "_local_iana_timezone_name", lambda: "America/New_York")

    window = resolve_backfill_window(
        since="2026-03-08",
        until="2026-03-10",
        days=None,
        timezone_name=None,
        now=datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert window.timezone_name == "America/New_York"
    assert window.since_utc == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("since", "until", "days", "message"),
    [
        ("2026-08-01T12:00:00", None, None, "UTC offset"),
        ("2026-08-01", None, 2, "exactly one"),
        (None, None, None, "exactly one"),
        (None, None, 0, "between 1 and 365"),
    ],
)
def test_window_rejects_ambiguous_or_conflicting_inputs(
    since: str | None,
    until: str | None,
    days: int | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        resolve_backfill_window(
            since=since,
            until=until,
            days=days,
            timezone_name="UTC",
            now=NOW,
        )


def test_preview_seals_exact_exclusive_window_and_content_free_report(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    lower = session_payload(
        id="lower-bound",
        title="private lower title",
        started_at="2026-07-01T00:00:00Z",
        last_activity_at="2026-07-20T00:00:00Z",
    )
    middle = session_payload(
        id="middle-session",
        title="private middle title",
        started_at="2026-07-10T00:00:00Z",
        last_activity_at="2026-07-25T00:00:00Z",
    )
    upper = session_payload(
        id="exclusive-upper",
        started_at="2026-07-15T00:00:00Z",
        last_activity_at="2026-08-01T00:00:00Z",
    )
    unknown = session_payload(id="unknown-activity", last_activity_at=None)
    old = session_payload(id="old-session", last_activity_at="2026-07-19T23:59:59Z")
    client = FakeHiveMind([middle, upper, unknown, old, lower, dict(middle)])
    state_path = tmp_path / "private" / "state.sqlite3"

    report = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=state_path,
            since="2026-07-20",
            until="2026-08-01",
            timezone_name="UTC",
            now=NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )

    assert report.discovered == 6
    assert report.eligible == 2
    assert report.selected == 2
    assert report.deferred == 1
    assert report.remaining_sessions == 2
    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    rendered = report.render()
    assert report.plan_id not in rendered
    assert report.plan_id[:12] in rendered
    assert "lower-bound" not in rendered
    assert "middle-session" not in rendered
    assert "private lower title" not in rendered

    with StateStore(state_path) as state:
        sessions = state.get_backfill_plan_sessions(report.plan_id)
        turns = state.get_backfill_plan_turns(report.plan_id)
        stats = state.get_backfill_plan_stats(report.plan_id)
    assert [item.session_id for item in sessions] == ["lower-bound", "middle-session"]
    assert [item.session_id for item in turns] == ["lower-bound", "middle-session"]
    assert stats.turn_count == 2
    assert stats.total_compressed_bytes == 642
    assert stats.compressed_le_64k == 2
    assert all("source message" not in repr(item) for item in turns)


def test_preview_defers_activity_inside_idle_grace_at_exact_boundary(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    eligible = session_payload(
        id="settled-at-boundary",
        last_activity_at="2026-08-05T15:50:00Z",
    )
    deferred = session_payload(
        id="still-active",
        last_activity_at="2026-08-05T15:50:01Z",
    )

    report = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=tmp_path / "state.sqlite3",
            since="2026-08-01",
            timezone_name="UTC",
            now=NOW,
        ),
        hivemind=FakeHiveMind([deferred, eligible]),  # type: ignore[arg-type]
    )

    assert report.eligible == 1
    assert report.selected == 1
    assert report.deferred == 1


def test_canary_membership_and_plan_id_are_deterministic_across_api_order(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    sessions = [
        session_payload(
            id=f"session-{index}",
            last_activity_at=f"2026-07-{20 + index:02d}T00:00:00Z",
        )
        for index in range(1, 5)
    ]
    config = dict(
        project=PROJECT,
        since="2026-07-01",
        until="2026-08-01",
        timezone_name="UTC",
        canary=True,
        now=NOW,
    )
    first = preview_backfill(
        BackfillPreviewConfig(state_path=tmp_path / "one.sqlite3", **config),
        hivemind=FakeHiveMind(sessions),  # type: ignore[arg-type]
    )
    second = preview_backfill(
        BackfillPreviewConfig(state_path=tmp_path / "two.sqlite3", **config),
        hivemind=FakeHiveMind(list(reversed(sessions))),  # type: ignore[arg-type]
    )

    assert first.plan_id == second.plan_id
    assert first.selected == second.selected == 1
    assert first.selector == second.selector == "canary"


def test_apply_advances_sealed_plan_in_order_with_apply_time_budget(
    monkeypatch: Any,
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    sessions = [
        session_payload(id="third", last_activity_at="2026-07-23T00:00:00Z"),
        session_payload(id="first", last_activity_at="2026-07-21T00:00:00Z"),
        session_payload(id="second", last_activity_at="2026-07-22T00:00:00Z"),
    ]
    client = FakeHiveMind(sessions)
    state_path = tmp_path / "state.sqlite3"
    preview = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=state_path,
            since="2026-07-01",
            until="2026-08-01",
            now=NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )
    applied_membership: list[list[str]] = []

    def fake_run(config: Any, *, hivemind: Any, sink: Any) -> RunReport:
        assert sink is not None
        assert sink.started is True
        summaries = hivemind.list_sessions(days=1, include_subagents=True)
        applied_membership.append([item["id"] for item in summaries])
        assert config.session_ids == frozenset(applied_membership[-1])
        return RunReport(imported=len(applied_membership[-1]), emitted_spans=2)

    monkeypatch.setattr(backfill, "run_import", fake_run)
    common = dict(
        project=PROJECT,
        confirm_project=PROJECT,
        plan_id=preview.plan_id[:12],
        state_path=state_path,
    )
    first = apply_backfill(
        BackfillApplyConfig(max_sessions=1, **common),
        hivemind=client,  # type: ignore[arg-type]
    )
    second = apply_backfill(
        BackfillApplyConfig(max_sessions=2, **common),
        hivemind=client,  # type: ignore[arg-type]
    )
    finished = apply_backfill(
        BackfillApplyConfig(max_sessions=2, **common),
        hivemind=client,  # type: ignore[arg-type]
    )

    assert applied_membership == [["first"], ["second", "third"]]
    assert first.completed_sessions == 1
    assert first.remaining_sessions == 2
    assert second.completed_sessions == 3
    assert second.remaining_sessions == 0
    assert second.status == "completed"
    assert finished.status == "completed"
    assert finished.cohort_sessions == 0


def test_apply_blocks_without_upload_when_planned_source_activity_changes(
    monkeypatch: Any,
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    original = session_payload(id="drift", last_activity_at="2026-07-22T00:00:00Z")
    client = FakeHiveMind([original])
    state_path = tmp_path / "state.sqlite3"
    preview = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=state_path,
            since="2026-07-01",
            until="2026-08-01",
            now=NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )
    client.sessions[0] = session_payload(
        id="drift",
        last_activity_at="2026-07-22T00:00:01Z",
    )
    monkeypatch.setattr(
        backfill,
        "run_import",
        lambda *_args, **_kwargs: pytest.fail("source drift must block before upload"),
    )

    with pytest.raises(BackfillError, match="changed after preview"):
        apply_backfill(
            BackfillApplyConfig(
                project=PROJECT,
                confirm_project=PROJECT,
                plan_id=preview.plan_id,
                state_path=state_path,
            ),
            hivemind=client,  # type: ignore[arg-type]
        )

    with StateStore(state_path) as state:
        plan = state.get_backfill_plan(preview.plan_id)
    assert plan is not None and plan.status == "blocked"
    assert plan.last_error_code == "source_drift"


def test_exact_filters_are_canonical_and_part_of_plan_identity(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    selected = session_payload(
        id="selected",
        agent_type="codex",
        git_repo="wandb/hivemind",
        last_activity_at="2026-07-21T00:00:00Z",
    )
    child = session_payload(
        id="child",
        parent_session_id="selected",
        agent_type="codex",
        git_repo="wandb/hivemind",
        last_activity_at="2026-07-22T00:00:00Z",
    )
    sessions = [selected, child]
    common = dict(
        project=PROJECT,
        since="2026-07-01",
        until="2026-08-01",
        timezone_name="UTC",
        agents=("codex",),
        repositories=("wandb/hivemind",),
        session_ids=("selected",),
        exclude_subagents=True,
        now=NOW,
    )
    first = preview_backfill(
        BackfillPreviewConfig(state_path=tmp_path / "one.sqlite3", **common),
        hivemind=FakeHiveMind(sessions),  # type: ignore[arg-type]
    )
    duplicate_order = preview_backfill(
        BackfillPreviewConfig(
            state_path=tmp_path / "two.sqlite3",
            **{
                **common,
                "agents": ("codex", "codex"),
                "session_ids": ("selected", "selected"),
            },
        ),
        hivemind=FakeHiveMind(list(reversed(sessions))),  # type: ignore[arg-type]
    )
    expanded_filter = preview_backfill(
        BackfillPreviewConfig(
            state_path=tmp_path / "three.sqlite3",
            **{**common, "agents": ("claude", "codex")},
        ),
        hivemind=FakeHiveMind(sessions),  # type: ignore[arg-type]
    )

    assert first.plan_id == duplicate_order.plan_id
    assert expanded_filter.plan_id != first.plan_id
    with StateStore(tmp_path / "one.sqlite3") as state:
        assert state.get_backfill_plan_filters(first.plan_id) == [
            ("agent", "codex"),
            ("exclude_subagents", "true"),
            ("repository", "wandb/hivemind"),
            ("session", "selected"),
        ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repositories", ("ghp_abcdefghijklmnopqrstuvwxyz/repo",)),
        ("session_ids", ("ghp_abcdefghijklmnopqrstuvwxyz",)),
        ("agents", ("line\nbreak",)),
    ],
)
def test_preview_rejects_credential_bearing_or_unbounded_filters_before_source_access(
    field: str,
    value: tuple[str, ...],
    tmp_path: Path,
) -> None:
    client = FakeHiveMind([])
    config = BackfillPreviewConfig(
        project=PROJECT,
        state_path=tmp_path / "state.sqlite3",
        since="2026-07-01",
        until="2026-08-01",
        timezone_name="UTC",
        now=NOW,
        **{field: value},
    )

    with pytest.raises(ValueError, match="credential-free ASCII"):
        preview_backfill(config, hivemind=client)  # type: ignore[arg-type]

    assert client.list_days == []
    assert not config.state_path.exists()


def test_backlog_prepare_failure_saves_no_plan(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    class FailingSink(FakeHistoricalSink):
        def prepare_turn(self, conversation: Any, turn: Any) -> PreparedOutcome:
            del conversation, turn
            raise RuntimeError("private transport diagnostic")

    state_path = tmp_path / "not-created.sqlite3"
    with pytest.raises(BackfillError, match="no plan was saved"):
        preview_backfill(
            BackfillPreviewConfig(
                project=PROJECT,
                state_path=state_path,
                since="2026-07-01",
                until="2026-08-01",
                timezone_name="UTC",
                now=NOW,
            ),
            hivemind=FakeHiveMind(
                [session_payload(id="cannot-prepare", last_activity_at="2026-07-20T00:00:00Z")]
            ),  # type: ignore[arg-type]
            sink=FailingSink(),  # type: ignore[arg-type]
        )

    assert not state_path.exists()


def test_canary_preparation_error_fails_closed_without_selecting_a_later_session(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    class FailingFirstSink(FakeHistoricalSink):
        def prepare_turn(self, conversation: Any, turn: Any) -> PreparedOutcome:
            if conversation.conversation_id.endswith("first-candidate"):
                raise RuntimeError("private transient detail")
            return super().prepare_turn(conversation, turn)

    sessions = [
        session_payload(id="first-candidate", last_activity_at="2026-07-20T00:00:00Z"),
        session_payload(id="later-candidate", last_activity_at="2026-07-21T00:00:00Z"),
    ]
    state_path = tmp_path / "state.sqlite3"

    with pytest.raises(BackfillError, match="no plan was saved"):
        preview_backfill(
            BackfillPreviewConfig(
                project=PROJECT,
                state_path=state_path,
                since="2026-07-01",
                until="2026-08-01",
                timezone_name="UTC",
                canary=True,
                now=NOW,
            ),
            hivemind=FakeHiveMind(sessions),  # type: ignore[arg-type]
            sink=FailingFirstSink(),  # type: ignore[arg-type]
        )

    assert not state_path.exists()


def test_canary_uses_first_stable_whole_session_that_passes_all_rules(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    class CanaryHiveMind(FakeHiveMind):
        def get_atif(self, session_id: str) -> dict[str, Any]:
            wrapper = super().get_atif(session_id)
            if session_id == "too-many-turns":
                steps: list[dict[str, Any]] = []
                for index in range(4):
                    steps.extend(
                        [
                            {
                                "step_id": index * 2 + 1,
                                "timestamp": "2026-07-20T00:00:00Z",
                                "source": "user",
                                "message": f"user {index}",
                            },
                            {
                                "step_id": index * 2 + 2,
                                "timestamp": "2026-07-20T00:00:01Z",
                                "source": "agent",
                                "message": f"agent {index}",
                            },
                        ]
                    )
                wrapper["trajectory"]["steps"] = steps
                wrapper["step_count"] = len(steps)
            return wrapper

    sessions = [
        session_payload(
            id="parented-first",
            parent_session_id="parent",
            last_activity_at="2026-07-19T00:00:00Z",
        ),
        session_payload(id="too-many-turns", last_activity_at="2026-07-20T00:00:00Z"),
        session_payload(id="qualifying", last_activity_at="2026-07-21T00:00:00Z"),
    ]
    state_path = tmp_path / "state.sqlite3"
    report = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=state_path,
            since="2026-07-01",
            until="2026-08-01",
            timezone_name="UTC",
            canary=True,
            now=NOW,
        ),
        hivemind=CanaryHiveMind(sessions),  # type: ignore[arg-type]
    )

    with StateStore(state_path) as state:
        sealed = state.get_backfill_plan_sessions(report.plan_id)
    assert [item.session_id for item in sealed] == ["qualifying"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_turn_compressed_bytes", None),
        ("max_turn_span_count", 0),
    ],
)
def test_canary_requires_explicit_sufficient_server_budgets(
    field: str,
    value: int | None,
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    sink = FakeHistoricalSink()
    if value is None:
        delattr(sink.capabilities, field)
    else:
        setattr(sink.capabilities, field, value)

    with pytest.raises(BackfillError, match="no session qualified"):
        preview_backfill(
            BackfillPreviewConfig(
                project=PROJECT,
                state_path=tmp_path / "state.sqlite3",
                since="2026-07-01",
                until="2026-08-01",
                timezone_name="UTC",
                canary=True,
                now=NOW,
            ),
            hivemind=FakeHiveMind(
                [session_payload(id="candidate", last_activity_at="2026-07-20T00:00:00Z")]
            ),  # type: ignore[arg-type]
            sink=sink,  # type: ignore[arg-type]
        )


def test_apply_blocks_before_import_when_exact_wire_certificate_drifts(
    monkeypatch: Any,
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    session = session_payload(id="wire-drift", last_activity_at="2026-07-22T00:00:00Z")
    client = FakeHiveMind([session])
    state_path = tmp_path / "state.sqlite3"
    preview = preview_backfill(
        BackfillPreviewConfig(
            project=PROJECT,
            state_path=state_path,
            since="2026-07-01",
            until="2026-08-01",
            timezone_name="UTC",
            now=NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )

    class DriftSink(FakeHistoricalSink):
        def prepare_turn(self, conversation: Any, turn: Any) -> PreparedOutcome:
            outcome = super().prepare_turn(conversation, turn)
            return PreparedOutcome(
                logical_key=outcome.logical_key,
                wire_sha256="f" * 64,
                span_count=outcome.span_count,
                compressed_bytes=outcome.compressed_bytes,
                uncompressed_bytes=outcome.uncompressed_bytes,
                reference_count=outcome.reference_count,
                capability_version=outcome.capability_version,
                sdk_prepared=None,
            )

    monkeypatch.setattr(
        backfill,
        "run_import",
        lambda *_args, **_kwargs: pytest.fail("certificate drift must upload zero turns"),
    )
    with pytest.raises(BackfillError, match="evidence changed"):
        apply_backfill(
            BackfillApplyConfig(
                project=PROJECT,
                confirm_project=PROJECT,
                plan_id=preview.plan_id,
                state_path=state_path,
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink=DriftSink(),  # type: ignore[arg-type]
        )

    with StateStore(state_path) as state:
        plan = state.get_backfill_plan(preview.plan_id)
    assert plan is not None and plan.status == "blocked"
    assert plan.last_error_code == "certificate_drift"
