from __future__ import annotations

import gc
import hashlib
import json
import sqlite3
import weakref
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

import hivemind_weave.review as review_module
from hivemind_weave.errors import (
    ATIFSchemaError,
    ReviewMirrorConflictError,
    ReviewMirrorError,
    ReviewMirrorUncertainError,
)
from hivemind_weave.review import (
    REVIEW_PROJECT,
    ReviewApplyConfig,
    ReviewPreviewConfig,
    ReviewReconcileConfig,
    apply_review,
    preview_review,
    reconcile_review,
    review_status,
)
from hivemind_weave.review_manifest import ReviewManifestError
from hivemind_weave.review_state import ReviewStateStore, review_logical_key
from hivemind_weave.utils import canonical_json, isoformat_z, parse_datetime

NOW = datetime(2026, 8, 6, 16, 0, tzinfo=UTC)
REVIEW_USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REVIEW_SESSION_IDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)


def _trace_id(value: int) -> str:
    return f"{value:032x}"


def _span_id(value: int) -> str:
    return f"{value:016x}"


class FakeHiveMind:
    def __init__(
        self,
        sessions: list[dict[str, Any]],
        transcripts: dict[str, dict[str, Any]],
        *,
        user_id: str = REVIEW_USER_ID,
    ) -> None:
        self.sessions = sessions
        self.transcripts = transcripts
        self.user_id: str | None = user_id
        self.fetches: list[str] = []

    def preflight(self) -> None:
        return None

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        assert 1 <= days <= 365
        assert include_subagents is True
        return list(self.sessions)

    def get_session(self, session_id: str) -> dict[str, Any]:
        self.fetches.append(session_id)
        return dict(next(item for item in self.sessions if item["id"] == session_id))

    def get_atif(self, session_id: str) -> dict[str, Any]:
        self.fetches.append(session_id)
        return self.transcripts[session_id]


class FakeSink:
    instances: ClassVar[list[FakeSink]] = []
    fail_root = False
    fail_finish = False
    bad_publication = False
    reconcile_matches = 1
    verify_callback: ClassVar[Callable[[], None] | None] = None

    def __init__(self) -> None:
        self.project = ""
        self.published = 0
        self.submitted = 0
        self.finished = False
        self.active = False
        self.read_only = False
        self.events: list[str] = []
        self.manifests: list[dict[str, Any]] = []
        self.find_expectations: list[dict[str, Any]] = []
        self.__class__.instances.append(self)

    def start(self, project: str) -> None:
        assert project == REVIEW_PROJECT
        assert not self.active
        self.project = project
        self.active = True
        self.events.append("start")

    def start_read_only(self, project: str) -> None:
        assert project == REVIEW_PROJECT
        assert not self.active and not self.read_only
        self.project = project
        self.read_only = True
        self.events.append("start_read_only")

    def publish_objects(self, bundle: Any) -> Any:
        assert self.project and self.active
        payload = json.loads(bundle.manifest_json)
        self.manifests.append(payload)
        conversation_id = payload["conversation"]["conversation_id"]
        source_turn_key = payload["turn"]["key"]
        started_at = parse_datetime(payload["turn"]["started_at"])
        ended_at = parse_datetime(payload["turn"]["ended_at"])
        assert started_at is not None and ended_at is not None
        hosted_index_sha256 = hashlib.sha256(f"hosted:{bundle.index_sha256}".encode()).hexdigest()
        logical_key = review_logical_key(self.project, conversation_id, source_turn_key)
        self.published += 1
        self.events.append("publish")
        return SimpleNamespace(
            conversation_id=conversation_id,
            manifest_sha256=bundle.manifest_sha256,
            root_turn_key=f"review:{logical_key}",
            root_payload_sha256="e" * 64,
            logical_key=logical_key,
            preview_signature=bundle.preview_signature,
            planning_index_sha256=("0" * 64 if self.bad_publication else bundle.index_sha256),
            started_at=started_at,
            ended_at=ended_at,
            chunk_refs=tuple(
                f"weave:///wandb/hivemind-chats-review/object/{item.name}:{item.sha256}"
                for item in bundle.chunks
            ),
            chunk_hashes=tuple(item.sha256 for item in bundle.chunks),
            chunk_sizes=tuple(item.byte_count for item in bundle.chunks),
            index_ref=(
                "weave:///wandb/hivemind-chats-review/object/"
                f"hosted-index-{hosted_index_sha256}:{hosted_index_sha256}"
            ),
            index_sha256=hosted_index_sha256,
            index=SimpleNamespace(size=len(bundle.index_json.encode("utf-8")) + 97),
        )

    def submit_root(
        self,
        conversation: Any,
        turn: Any,
        bundle: Any,
        publication: Any,
        *,
        logical_key: str,
    ) -> Any:
        assert conversation.conversation_id.startswith("hivemind:")
        assert turn.started_at <= turn.ended_at
        assert bundle.index_sha256 == publication.planning_index_sha256
        assert publication.index_sha256 in publication.index_ref
        assert len(logical_key) == 64
        self.submitted += 1
        self.events.append("submit")
        if self.fail_root:
            raise OSError("ambiguous fake transport")
        return SimpleNamespace(
            manifest_sha256=publication.manifest_sha256,
            attempted=True,
            acknowledged=True,
            trace_ids=(_trace_id(self.submitted),),
            root_span_ids=(_span_id(1),),
            error_code="",
        )

    def verify_root(self, publication: Any, submission: Any | None = None) -> Any:
        assert not self.active
        self.events.append("verify")
        callback = type(self).verify_callback
        if callback is not None:
            callback()
        if self.reconcile_matches != 1:
            if self.reconcile_matches == 0:
                raise ReviewMirrorUncertainError("no exact root match")
            raise ReviewMirrorConflictError("multiple exact root matches")
        if submission is not None:
            assert submission.manifest_sha256 == publication.manifest_sha256
        return SimpleNamespace(
            trace_id=_trace_id(self.submitted),
            root_span_id=_span_id(1),
        )

    def find_roots(self, **expectation: Any) -> Any:
        assert self.read_only
        assert expectation["conversation_id"].startswith("hivemind:")
        self.find_expectations.append(expectation)
        if self.reconcile_matches == 1:
            return SimpleNamespace(
                matches=1,
                trace_ids=(_trace_id(99),),
                root_span_ids=(_span_id(99),),
                span_count=1,
            )
        return SimpleNamespace(
            matches=self.reconcile_matches,
            trace_ids=(),
            root_span_ids=(),
            span_count=self.reconcile_matches,
        )

    def finish(self) -> None:
        if self.read_only:
            self.events.append("finish_read_only")
            self.read_only = False
            self.finished = True
            return
        if not self.active:
            return
        self.events.append("finish")
        self.active = False
        self.finished = True
        if self.fail_finish:
            raise OSError("ambiguous fake flush")


@pytest.fixture(autouse=True)
def _reset_sink() -> None:
    FakeSink.instances.clear()
    FakeSink.fail_root = False
    FakeSink.fail_finish = False
    FakeSink.bad_publication = False
    FakeSink.reconcile_matches = 1
    FakeSink.verify_callback = None


def _client(
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    *,
    count: int = 1,
) -> FakeHiveMind:
    sessions: list[dict[str, Any]] = []
    transcripts: dict[str, dict[str, Any]] = {}
    for index in range(count):
        session_id = REVIEW_SESSION_IDS[index]
        session = session_payload(
            id=session_id,
            title=f"private title {index}",
            started_at=f"2026-07-{20 + index:02d}T12:00:00Z",
            last_activity_at=f"2026-07-{20 + index:02d}T12:30:00Z",
        )
        sessions.append(session)
        transcripts[session_id] = atif_wrapper(
            wrapper_session_id=session_id,
            session_id=f"atif-{session_id}",
        )
    return FakeHiveMind(sessions, transcripts)


def _preview(
    tmp_path: Path,
    client: FakeHiveMind,
    *,
    canary: bool = False,
    progress: Callable[[str], None] | None = None,
) -> Any:
    return preview_review(
        ReviewPreviewConfig(
            since="2026-07-16T00:00:00Z",
            until="2026-08-06T16:00:00Z",
            project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
            canary=canary,
            now=NOW,
            progress=progress,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )


def test_preview_seals_complete_content_free_plan_and_canary(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    report = _preview(tmp_path, client, canary=True)

    assert report.selected_sessions == 1
    assert report.turns == 1
    assert report.chunk_count >= 1
    assert report.max_chunk_bytes <= 8 * 1024 * 1024
    rendered = report.render()
    assert report.plan_id not in rendered
    assert "private title" not in rendered
    assert REVIEW_SESSION_IDS[0] not in rendered

    raw_state = (tmp_path / "private" / "state.sqlite3").read_bytes()
    assert b"Create hello.txt" not in raw_state
    assert b"Created hello.txt" not in raw_state
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        turns = state.get_turns(report.plan_id)
    assert turns
    assert all(isinstance(item.started_at, datetime) for item in turns)
    assert all(isinstance(item.ended_at, datetime) for item in turns)


def test_preview_never_persists_or_reports_private_content(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = _client(session_payload, atif_wrapper)
    sentinels = (
        "alice@example.com",
        "FAKE_PRIVATE_KEY_SENTINEL",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "/Users/Alice Johnson/private-repository",
    )
    client.sessions[0].update(
        {
            "title": f"Private chat for {sentinels[0]}",
            "agent_session_id": sentinels[3],
            "git_repo": sentinels[3],
            "git_branch": sentinels[2],
            "parent_session_id": REVIEW_SESSION_IDS[1],
        }
    )
    transcript = client.transcripts[REVIEW_SESSION_IDS[0]]
    transcript["metadata"] = {"contact": sentinels[0]}
    transcript["trajectory"]["extra"] = {
        "credential": sentinels[2],
        "private_key": (f"-----BEGIN PRIVATE KEY-----\n{sentinels[1]}\n-----END PRIVATE KEY-----"),
    }
    transcript["trajectory"]["steps"][0]["message"] = "Alice Johnson secret request"

    report = _preview(tmp_path, client)
    print(report.render())
    rendered = capsys.readouterr()
    state_bytes = (tmp_path / "private" / "state.sqlite3").read_bytes()

    for sentinel in sentinels:
        encoded = sentinel.encode()
        assert encoded not in state_bytes
        assert sentinel not in rendered.out
        assert sentinel not in rendered.err


def test_canary_stably_skips_a_multichunk_session_for_the_next_candidate(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    original = review_module.build_review_manifest

    def make_first_candidate_multichunk(conversation: Any, turn: Any, **kwargs: Any) -> Any:
        if conversation.conversation_id == f"hivemind:{REVIEW_SESSION_IDS[0]}":
            bundle = original(conversation, turn, max_chunk_bytes=512)
            assert len(bundle.chunks) > 1
            return bundle
        return original(conversation, turn, **kwargs)

    monkeypatch.setattr(
        review_module,
        "build_review_manifest",
        make_first_candidate_multichunk,
    )
    report = _preview(tmp_path, client, canary=True)

    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        selected = state.get_sessions(report.plan_id)
    assert [item.session_id for item in selected] == [REVIEW_SESSION_IDS[1]]
    assert report.chunk_count == report.turns == 1
    assert client.fetches == [REVIEW_SESSION_IDS[0]] * 3 + [REVIEW_SESSION_IDS[1]] * 3


@pytest.mark.parametrize("failure", [ReviewManifestError("too large"), ATIFSchemaError("bad ATIF")])
def test_canary_skips_deterministically_unrepresentable_candidate(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    original_prepare = review_module._prepare_session

    def fail_first_candidate(client_arg: Any, session: Any, **kwargs: Any) -> Any:
        if session.id == REVIEW_SESSION_IDS[0]:
            raise failure
        return original_prepare(client_arg, session, **kwargs)

    monkeypatch.setattr(review_module, "_prepare_session", fail_first_candidate)
    report = _preview(tmp_path, client, canary=True)

    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        selected = state.get_sessions(report.plan_id)
    assert [item.session_id for item in selected] == [REVIEW_SESSION_IDS[1]]


def test_preview_rejects_canonical_destination_before_discovery(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    with pytest.raises(ValueError, match="canonical projects are forbidden"):
        preview_review(
            ReviewPreviewConfig(
                since="2026-07-16T00:00:00Z",
                project="wandb/hivemind-chats-v2",
                state_path=tmp_path / "state.sqlite3",
                now=NOW,
            ),
            hivemind=client,  # type: ignore[arg-type]
        )
    assert not client.fetches


def test_preview_rejects_unreviewed_sdk_before_source_discovery_or_state(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    source_preflight_called = False

    def source_preflight() -> None:
        nonlocal source_preflight_called
        source_preflight_called = True

    def reject_runtime() -> None:
        raise ReviewMirrorError("installed Weave is not the reviewed commit")

    client.preflight = source_preflight  # type: ignore[method-assign]
    monkeypatch.setattr(review_module, "preflight_review_runtime", reject_runtime)
    state_path = tmp_path / "private" / "state.sqlite3"

    with pytest.raises(ReviewMirrorError, match="reviewed commit"):
        preview_review(
            ReviewPreviewConfig(
                since="2026-07-16T00:00:00Z",
                project=REVIEW_PROJECT,
                state_path=state_path,
                now=NOW,
            ),
            hivemind=client,  # type: ignore[arg-type]
        )

    assert source_preflight_called is False
    assert client.fetches == []
    assert not state_path.exists()


@pytest.mark.parametrize("bound", ["since", "until"])
def test_preview_rejects_date_only_review_bounds(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    bound: str,
) -> None:
    client = _client(session_payload, atif_wrapper)
    values = {
        "since": "2026-07-16T00:00:00Z",
        "until": "2026-08-06T16:00:00Z",
    }
    values[bound] = "2026-07-16"
    with pytest.raises(ValueError, match="RFC3339 timestamp"):
        preview_review(
            ReviewPreviewConfig(
                since=values["since"],
                until=values["until"],
                project=REVIEW_PROJECT,
                state_path=tmp_path / "state.sqlite3",
                now=NOW,
            ),
            hivemind=client,  # type: ignore[arg-type]
        )
    assert not client.fetches


def test_preview_default_until_is_captured_now_and_exclusive(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    client.sessions[0]["last_activity_at"] = "2026-08-06T16:00:00Z"

    report = preview_review(
        ReviewPreviewConfig(
            since="2026-07-16T00:00:00Z",
            project=REVIEW_PROJECT,
            state_path=tmp_path / "state.sqlite3",
            now=NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )

    assert report.until_utc == NOW
    assert report.selected_sessions == 0
    assert report.eligible == 0
    assert not client.fetches


def test_canary_summary_turn_count_skips_known_large_transcript_before_fetch(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    client.sessions[0]["turn_count"] = 500
    client.sessions[1]["turn_count"] = 1

    progress: list[str] = []
    report = _preview(tmp_path, client, canary=True, progress=progress.append)

    assert report.selected_sessions == 1
    assert REVIEW_SESSION_IDS[0] not in client.fetches
    assert client.fetches == [REVIEW_SESSION_IDS[1]] * 3
    assert progress == [
        "Canary summary preflight: 1 plausible session(s); "
        "at most 25 transcript(s) will be examined",
        "Canary transcript preflight: 1/1",
    ]
    assert REVIEW_SESSION_IDS[0] not in repr(progress)
    assert "private title" not in repr(progress)


def test_canary_summary_token_budget_skips_expensive_small_turn_transcript(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    for session in client.sessions:
        session.update(
            {
                "turn_count": 1,
                "tool_call_count": 1,
                "input_tokens": 10,
                "output_tokens": 10,
                "reasoning_tokens": 10,
                "cached_read_tokens": 10,
                "cached_write_tokens": 10,
            }
        )
    client.sessions[0]["input_tokens"] = 100_001

    report = _preview(tmp_path, client, canary=True)

    assert report.selected_sessions == 1
    assert REVIEW_SESSION_IDS[0] not in client.fetches
    assert client.fetches == [REVIEW_SESSION_IDS[1]] * 3


def test_uuidv7_session_survives_redaction_and_seals_end_to_end(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    old_id = REVIEW_SESSION_IDS[0]
    uuid_v7 = "019f3df9-dc78-72c1-a9f0-60b9477a98db"
    client.sessions[0]["id"] = uuid_v7
    transcript = client.transcripts.pop(old_id)
    transcript["session_id"] = uuid_v7
    client.transcripts[uuid_v7] = transcript

    report = _preview(tmp_path, client)

    assert report.selected_sessions == 1
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        assert state.get_sessions(report.plan_id)[0].session_id == uuid_v7


def test_uuidv5_internal_session_survives_end_to_end_but_untrusted_v5_is_redacted(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    source = "11111111-1111-5111-8111-111111111111"
    parent = "22222222-2222-5222-8222-222222222222"
    untrusted = "33333333-3333-5333-8333-333333333333"
    client = _client(session_payload, atif_wrapper)
    old_id = REVIEW_SESSION_IDS[0]
    client.sessions[0].update(
        {
            "id": source,
            "parent_session_id": parent,
            "agent_session_id": untrusted,
        }
    )
    transcript = client.transcripts.pop(old_id)
    transcript["session_id"] = source
    transcript["metadata"] = {"session_id": untrusted}
    steps = transcript["trajectory"]["steps"]
    steps[1]["message"] = f"Inspect coordinate {untrusted}"
    steps[2]["tool_calls"][0]["arguments"]["session_id"] = untrusted
    client.transcripts[source] = transcript

    preview = _preview(tmp_path, client)
    report = apply_review(
        ReviewApplyConfig(
            plan_id=preview.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    assert report.visible_turns == 1
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        assert state.get_sessions(preview.plan_id)[0].session_id == source
    payload = FakeSink.instances[-1].manifests[0]
    assert payload["conversation"]["conversation_id"] == f"hivemind:{source}"
    assert payload["session"]["session_id"] == source
    assert payload["session"]["parent_session_id"] == parent
    assert untrusted not in canonical_json(payload)


def test_apply_publishes_one_root_then_identical_rerun_emits_nothing(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    config = ReviewApplyConfig(
        plan_id=preview.plan_id[:32],
        confirm_project=REVIEW_PROJECT,
        state_path=tmp_path / "private" / "state.sqlite3",
        max_sessions=1,
    )

    def assert_not_visible_before_exact_verification() -> None:
        with sqlite3.connect(config.state_path) as database:
            status = database.execute("SELECT status FROM review_turn_ledger").fetchone()[0]
        assert status == "root_submitting"

    FakeSink.verify_callback = assert_not_visible_before_exact_verification

    first = apply_review(config, hivemind=client, sink_factory=FakeSink)
    second = apply_review(config, hivemind=client, sink_factory=FakeSink)

    assert first.visible_turns == 1
    assert first.remaining_sessions == 0
    assert second.visible_turns == 0
    assert len(FakeSink.instances) == 1
    assert FakeSink.instances[0].published == 1
    assert FakeSink.instances[0].submitted == 1
    assert FakeSink.instances[0].events == [
        "start",
        "publish",
        "submit",
        "finish",
        "verify",
    ]
    assert "private title" not in first.render()
    status = review_status(config.state_path)
    assert "visible turns:        1" in status
    with ReviewStateStore(config.state_path) as state:
        certificate = state.get_turns(preview.plan_id)[0]
        ledger = state.get_ledger(REVIEW_PROJECT, certificate.session_id, certificate.turn_key)
    assert ledger is not None
    assert ledger.index_size > 0
    assert ledger.index_sha256 != certificate.index_sha256


def test_review_status_without_state_is_read_only(tmp_path: Path) -> None:
    state_path = tmp_path / "missing-private-directory" / "state.sqlite3"

    status = review_status(state_path)

    assert "sealed plans:         0" in status
    assert "visible turns:        0" in status
    assert "uncertain turns:      0" in status
    assert not state_path.parent.exists()


def test_apply_sdk_failure_does_not_begin_or_poison_a_sealed_cohort(
    tmp_path: Path,
    monkeypatch: Any,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)

    def reject_runtime() -> None:
        raise ReviewMirrorError("installed Weave is not the reviewed commit")

    monkeypatch.setattr(review_module, "preflight_review_runtime", reject_runtime)
    with pytest.raises(ReviewMirrorError, match="reviewed commit"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
                max_sessions=1,
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert FakeSink.instances == []
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        plan = state.resolve_plan(preview.plan_id)
        assert plan is not None and plan.status == "planned"
    with sqlite3.connect(tmp_path / "private" / "state.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM review_cohorts").fetchone()[0] == 0


def test_appended_turn_skips_visible_history_and_imports_only_the_append(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    initial_steps = list(client.transcripts[REVIEW_SESSION_IDS[0]]["trajectory"]["steps"])
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        session_id=f"atif-{REVIEW_SESSION_IDS[0]}",
        steps=[
            *initial_steps,
            {
                "step_id": 99,
                "timestamp": "2026-07-20T12:00:03Z",
                "source": "user",
                "message": "copied context for the later append",
                "is_copied_context": True,
            },
        ],
    )
    first_plan = _preview(tmp_path, client)
    first_apply = apply_review(
        ReviewApplyConfig(
            plan_id=first_plan.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )
    assert first_apply.visible_turns == 1

    client.sessions[0]["last_activity_at"] = "2026-08-02T12:30:00Z"
    client.sessions[0]["git_branch"] = "feature/appended-turn"
    original_steps = list(client.transcripts[REVIEW_SESSION_IDS[0]]["trajectory"]["steps"])
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        session_id=f"atif-{REVIEW_SESSION_IDS[0]}",
        steps=[
            *original_steps,
            {
                "step_id": 5,
                "timestamp": "2026-08-02T12:00:00Z",
                "source": "user",
                "message": "Now add a second file.",
            },
            {
                "step_id": 6,
                "timestamp": "2026-08-02T12:00:01Z",
                "source": "agent",
                "message": "Added the second file.",
            },
        ],
    )
    second_plan = _preview(tmp_path, client)
    assert second_plan.plan_id != first_plan.plan_id

    second_apply = apply_review(
        ReviewApplyConfig(
            plan_id=second_plan.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    assert second_apply.skipped_turns == 1
    assert second_apply.visible_turns == 1
    assert len(FakeSink.instances) == 2
    assert [item.submitted for item in FakeSink.instances] == [1, 1]
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        status = state.status(REVIEW_PROJECT)
    assert status.visible == 2
    assert status.conflicted == 0


def test_entire_cohort_is_preflighted_before_its_first_upload(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    preview = _preview(tmp_path, client)
    client.transcripts[REVIEW_SESSION_IDS[1]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[1],
        steps=[
            {
                "step_id": 1,
                "timestamp": "2026-07-21T12:00:00Z",
                "source": "user",
                "message": "changed history",
            }
        ],
    )

    with pytest.raises(ReviewMirrorError, match="sealed review turn changed"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
                max_sessions=2,
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )
    assert FakeSink.instances == []
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        status = state.status(REVIEW_PROJECT)
        saved_plan = state.resolve_plan(preview.plan_id[:32])
    assert saved_plan is not None and saved_plan.status == "blocked"
    assert status.visible == 0
    assert status.conflicted == 1


def test_changed_login_must_own_the_complete_sealed_session_universe(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper, count=2)
    preview = _preview(tmp_path, client)
    client.fetches.clear()
    client.user_id = "another-authenticated-account"
    removed = client.sessions.pop()
    client.transcripts.pop(str(removed["id"]))

    with pytest.raises(ReviewMirrorConflictError, match="source universe"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
                max_sessions=1,
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert FakeSink.instances == []
    assert client.fetches == []


def test_changed_account_label_with_the_exact_source_universe_is_allowed(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    client.user_id = "renamed-authenticated-account"

    report = apply_review(
        ReviewApplyConfig(
            plan_id=preview.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
            max_sessions=1,
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    assert report.visible_turns == 1


def test_unrelated_legacy_source_coordinates_do_not_block_a_sealed_plan(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    client.sessions.append(
        session_payload(
            id="legacy-AliceJohnson",
            parent_session_id="child-JohnSmith",
            started_at="2026-01-01T00:00:00Z",
            last_activity_at="2026-01-01T00:01:00Z",
        )
    )

    report = apply_review(
        ReviewApplyConfig(
            plan_id=preview.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
            max_sessions=1,
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    assert report.visible_turns == 1


def test_tampered_valid_session_and_certificates_cannot_reuse_a_plan_id(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    original_client = _client(session_payload, atif_wrapper)
    original = _preview(tmp_path / "original", original_client)

    replacement_client = _client(session_payload, atif_wrapper)
    old_session_id = str(replacement_client.sessions[0]["id"])
    replacement_session_id = "33333333-3333-4333-8333-333333333333"
    replacement_client.sessions[0]["id"] = replacement_session_id
    replacement_transcript = replacement_client.transcripts.pop(old_session_id)
    replacement_transcript["session_id"] = replacement_session_id
    replacement_client.transcripts[replacement_session_id] = replacement_transcript
    replacement = _preview(tmp_path / "replacement", replacement_client)
    with ReviewStateStore(
        tmp_path / "replacement" / "private" / "state.sqlite3"
    ) as replacement_state:
        replacement_session = replacement_state.get_sessions(replacement.plan_id)[0]
        replacement_turn = replacement_state.get_turns(replacement.plan_id)[0]
    replacement_client.fetches.clear()

    state_path = tmp_path / "original" / "private" / "state.sqlite3"
    with sqlite3.connect(state_path) as database:
        immutable_triggers = database.execute(
            """
            SELECT name, sql
            FROM sqlite_master
            WHERE type = 'trigger'
              AND name IN ('review_plan_sessions_immutable', 'review_plan_turns_immutable')
            ORDER BY name
            """
        ).fetchall()
        assert len(immutable_triggers) == 2
        database.execute("DROP TRIGGER review_plan_sessions_immutable")
        database.execute("DROP TRIGGER review_plan_turns_immutable")
        database.execute(
            """
            UPDATE review_plan_sessions
            SET session_id = ?, started_at = ?, last_activity_at = ?
            WHERE plan_id = ?
            """,
            (
                replacement_session.session_id,
                isoformat_z(replacement_session.started_at),
                isoformat_z(replacement_session.last_activity_at),
                original.plan_id,
            ),
        )
        database.execute(
            """
            UPDATE review_plan_turns
            SET session_id = ?, ordinal = ?, turn_key = ?, source_payload_sha256 = ?,
                manifest_sha256 = ?, index_sha256 = ?, logical_key = ?,
                preview_signature = ?, started_at = ?, ended_at = ?, manifest_bytes = ?,
                chunk_count = ?, max_chunk_bytes = ?, index_bytes = ?, atif_schema_version = ?
            WHERE plan_id = ?
            """,
            (
                replacement_turn.session_id,
                replacement_turn.ordinal,
                replacement_turn.turn_key,
                replacement_turn.source_payload_sha256,
                replacement_turn.manifest_sha256,
                replacement_turn.index_sha256,
                replacement_turn.logical_key,
                replacement_turn.preview_signature,
                isoformat_z(replacement_turn.started_at),
                isoformat_z(replacement_turn.ended_at),
                replacement_turn.manifest_bytes,
                replacement_turn.chunk_count,
                replacement_turn.max_chunk_bytes,
                replacement_turn.index_bytes,
                replacement_turn.atif_schema_version,
                original.plan_id,
            ),
        )
        for _name, sql in immutable_triggers:
            assert isinstance(sql, str)
            database.execute(sql)

    with pytest.raises(ReviewMirrorConflictError, match="immutable evidence"):
        apply_review(
            ReviewApplyConfig(
                plan_id=original.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=state_path,
                max_sessions=1,
            ),
            hivemind=replacement_client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert replacement_client.fetches == []
    assert FakeSink.instances == []


def test_turn_n_transport_preflight_failure_uploads_zero_from_its_session(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(session_payload, atif_wrapper)
    original_steps = list(client.transcripts[REVIEW_SESSION_IDS[0]]["trajectory"]["steps"])
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        session_id=f"atif-{REVIEW_SESSION_IDS[0]}",
        steps=[
            *original_steps,
            {
                "step_id": 5,
                "timestamp": "2026-08-02T12:00:00Z",
                "source": "user",
                "message": "Second turn.",
            },
            {
                "step_id": 6,
                "timestamp": "2026-08-02T12:00:01Z",
                "source": "agent",
                "message": "Second response.",
            },
        ],
    )
    preview = _preview(tmp_path, client)
    assert preview.turns == 2
    original_preflight = review_module.preflight_review_bundle
    calls = 0

    def fail_second_turn(bundle: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ReviewMirrorError("deterministic root metadata preflight failed")
        return original_preflight(bundle, **kwargs)

    monkeypatch.setattr(review_module, "preflight_review_bundle", fail_second_turn)
    with pytest.raises(ReviewMirrorConflictError, match="deterministic apply preflight"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert not FakeSink.instances
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        status = state.status(REVIEW_PROJECT)
    assert status.conflicted == 2
    assert status.visible == 0


def test_manifest_error_during_apply_preflight_durably_blocks_without_upload(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    monkeypatch.setattr(
        review_module,
        "build_review_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ReviewManifestError("too large")),
    )

    with pytest.raises(ReviewMirrorConflictError, match="deterministic apply preflight"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert not FakeSink.instances
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        status = state.status(REVIEW_PROJECT)
        plan = state.resolve_plan(preview.plan_id)
    assert status.conflicted == 1
    assert plan is not None and plan.status == "blocked"


def test_publication_mismatch_stops_before_root_submission(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    FakeSink.bad_publication = True

    with pytest.raises(ReviewMirrorConflictError, match="sealed turn certificate"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )

    assert FakeSink.instances[0].submitted == 0
    assert FakeSink.instances[0].events == ["start", "publish", "finish"]
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        assert state.status(REVIEW_PROJECT).conflicted == 1
        plan = state.resolve_plan(preview.plan_id[:32])
        assert plan is not None and plan.status == "blocked"


def test_malicious_remote_ids_conflict_without_reaching_sqlite(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    class MaliciousEvidenceSink(FakeSink):
        def verify_root(self, publication: Any, submission: Any | None = None) -> Any:
            del publication, submission
            self.events.append("verify")
            return SimpleNamespace(
                trace_id="alice@example.com",
                root_span_id="Bearer-secret-material",
            )

    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    state_path = tmp_path / "private" / "state.sqlite3"

    with pytest.raises(ReviewMirrorConflictError, match="malformed identity evidence"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=state_path,
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=MaliciousEvidenceSink,
        )

    raw = state_path.read_bytes()
    assert b"alice@example.com" not in raw
    assert b"Bearer-secret-material" not in raw
    with ReviewStateStore(state_path) as state:
        status = state.status(REVIEW_PROJECT)
    assert status.conflicted == 1


def test_zero_turn_preflight_conflict_cannot_be_unblocked_by_root_reconcile(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        steps=[],
    )
    preview = _preview(tmp_path, client)
    assert preview.turns == 0
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        steps=[
            {
                "step_id": 1,
                "timestamp": "2026-07-20T12:00:00Z",
                "source": "user",
                "message": "new history",
            }
        ],
    )

    with pytest.raises(ReviewMirrorConflictError, match="sealed review turn changed"):
        apply_review(
            ReviewApplyConfig(
                plan_id=preview.plan_id[:32],
                confirm_project=REVIEW_PROJECT,
                state_path=tmp_path / "private" / "state.sqlite3",
            ),
            hivemind=client,  # type: ignore[arg-type]
            sink_factory=FakeSink,
        )
    assert not FakeSink.instances

    report = reconcile_review(
        ReviewReconcileConfig(
            plan_id=preview.plan_id[:32],
            state_path=tmp_path / "private" / "state.sqlite3",
        ),
        sink_factory=FakeSink,
    )
    assert report.status == "blocked"
    assert report.ok is False
    assert not FakeSink.instances


@pytest.mark.parametrize(
    "unsafe_id",
    ["AliceJohnson", "session-AliceJohnson", "child-JohnSmith"],
)
def test_zero_turn_pii_shaped_session_id_never_reaches_state(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    unsafe_id: str,
) -> None:
    client = _client(session_payload, atif_wrapper)
    client.sessions[0]["id"] = unsafe_id
    client.transcripts = {
        unsafe_id: atif_wrapper(
            wrapper_session_id=unsafe_id,
            session_id=f"atif-{unsafe_id}",
            steps=[],
        )
    }
    state_path = tmp_path / "private" / "state.sqlite3"

    with pytest.raises(ReviewMirrorError, match="unsafe source coordinate"):
        preview_review(
            ReviewPreviewConfig(
                since="2026-07-16T00:00:00Z",
                until="2026-08-06T16:00:00Z",
                project=REVIEW_PROJECT,
                state_path=state_path,
                now=NOW,
            ),
            hivemind=client,  # type: ignore[arg-type]
        )

    assert not state_path.exists()


def test_name_like_parent_coordinate_never_reaches_state(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    unsafe_parent = "child-JohnSmith"
    client.sessions[0]["parent_session_id"] = unsafe_parent
    state_path = tmp_path / "private" / "state.sqlite3"

    with pytest.raises(ReviewMirrorError, match="unsafe source coordinate"):
        _preview(tmp_path, client)

    assert not state_path.exists()


@pytest.mark.parametrize("account_label", ["AliceJohnson", "alice@example.com", "review-user"])
def test_account_identity_is_never_hashed_or_persisted(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    account_label: str,
) -> None:
    client = _client(session_payload, atif_wrapper)
    client.user_id = account_label
    client.sessions[0]["username"] = account_label
    state_path = tmp_path / "private" / "state.sqlite3"

    report = _preview(tmp_path, client)

    assert report.selected_sessions == 1
    raw = state_path.read_bytes()
    assert account_label.encode() not in raw
    assert hashlib.sha256(account_label.encode()).hexdigest().encode() not in raw
    legacy_digest = hashlib.sha256(f"hivemind-user-v1\0{account_label}".encode()).hexdigest()
    assert legacy_digest.encode() not in raw
    assert account_label not in report.render()


def test_ambiguous_root_pauses_and_reconcile_never_resubmits(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    apply_config = ReviewApplyConfig(
        plan_id=preview.plan_id[:32],
        confirm_project=REVIEW_PROJECT,
        state_path=tmp_path / "private" / "state.sqlite3",
        max_sessions=1,
    )
    FakeSink.fail_root = True
    FakeSink.reconcile_matches = 0
    with pytest.raises(ReviewMirrorUncertainError, match="automatic retry is forbidden"):
        apply_review(apply_config, hivemind=client, sink_factory=FakeSink)
    assert FakeSink.instances[-1].submitted == 1

    with ReviewStateStore(apply_config.state_path) as state:
        status = state.status(REVIEW_PROJECT)
        assert status.uncertain == 1
        ledger = state.reconcilable_turns(preview.plan_id)[0]
        certificate = state.get_turns(preview.plan_id)[0]

    assert FakeSink.instances[-1].events == [
        "start",
        "publish",
        "submit",
        "finish",
        "verify",
    ]

    FakeSink.fail_root = False
    unresolved = reconcile_review(
        ReviewReconcileConfig(
            plan_id=preview.plan_id[:32],
            state_path=apply_config.state_path,
        ),
        sink_factory=FakeSink,
    )
    assert unresolved.uncertain_turns == 1
    assert FakeSink.instances[-1].submitted == 0
    assert FakeSink.instances[-1].events == ["start_read_only", "finish_read_only"]

    FakeSink.reconcile_matches = 1
    reconciled = reconcile_review(
        ReviewReconcileConfig(
            plan_id=preview.plan_id[:32],
            state_path=apply_config.state_path,
        ),
        sink_factory=FakeSink,
    )
    assert reconciled.visible_turns == 1
    assert FakeSink.instances[-1].submitted == 0
    assert FakeSink.instances[-1].events == ["start_read_only", "finish_read_only"]
    expectation = FakeSink.instances[-1].find_expectations[0]
    assert expectation == {
        "conversation_id": f"hivemind:{ledger.session_id}",
        "logical_key": ledger.logical_key,
        "manifest_ref": ledger.index_ref,
        "preview_signature": ledger.preview_signature,
        "started_at": certificate.started_at,
        "ended_at": certificate.ended_at,
    }


def test_exact_remote_verification_can_resolve_an_ambiguous_flush(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    preview = _preview(tmp_path, client)
    FakeSink.fail_finish = True

    report = apply_review(
        ReviewApplyConfig(
            plan_id=preview.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    assert report.visible_turns == 1
    assert FakeSink.instances[0].events == [
        "start",
        "publish",
        "submit",
        "finish",
        "verify",
    ]
    with ReviewStateStore(tmp_path / "private" / "state.sqlite3") as state:
        assert state.status(REVIEW_PROJECT).visible == 1
        assert state.status(REVIEW_PROJECT).uncertain == 0


def test_plan_hash_changes_when_exact_manifest_changes(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    client = _client(session_payload, atif_wrapper)
    first = _preview(tmp_path, client)
    client.transcripts[REVIEW_SESSION_IDS[0]] = atif_wrapper(
        wrapper_session_id=REVIEW_SESSION_IDS[0],
        steps=[
            {
                "step_id": 1,
                "timestamp": "2026-07-20T12:00:00Z",
                "source": "user",
                "message": "different redacted content",
            }
        ],
    )
    second = _preview(tmp_path, client)

    assert first.plan_id != second.plan_id
    assert (
        hashlib.sha256(first.plan_id.encode()).hexdigest()
        != hashlib.sha256(second.plan_id.encode()).hexdigest()
    )


def test_preview_releases_large_session_payloads_before_preparing_the_next(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(session_payload, atif_wrapper, count=3)
    original = review_module._prepare_session
    retained: list[tuple[weakref.ReferenceType[Any], weakref.ReferenceType[Any]]] = []

    def tracked_prepare(client_arg: Any, session_arg: Any, **kwargs: Any) -> Any:
        gc.collect()
        assert all(conversation() is None and holder() is None for conversation, holder in retained)
        prepared = original(client_arg, session_arg, **kwargs)
        retained.append(
            (
                weakref.ref(prepared.conversation),
                weakref.ref(prepared),
            )
        )
        return prepared

    monkeypatch.setattr(review_module, "_prepare_session", tracked_prepare)
    report = _preview(tmp_path, client)

    gc.collect()
    assert report.selected_sessions == 3
    assert all(conversation() is None and holder() is None for conversation, holder in retained)


def test_apply_releases_one_preflighted_session_before_loading_the_next(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(session_payload, atif_wrapper, count=3)
    preview = _preview(tmp_path, client)
    original = review_module._prepare_cohort
    retained: list[tuple[weakref.ReferenceType[Any], weakref.ReferenceType[Any]]] = []

    def tracked_prepare(**kwargs: Any) -> Any:
        gc.collect()
        assert all(conversation() is None and holder() is None for conversation, holder in retained)
        prepared = original(**kwargs)
        retained.append(
            (
                weakref.ref(prepared[0].prepared.conversation),
                weakref.ref(prepared[0]),
            )
        )
        return prepared

    monkeypatch.setattr(review_module, "_prepare_cohort", tracked_prepare)
    report = apply_review(
        ReviewApplyConfig(
            plan_id=preview.plan_id[:32],
            confirm_project=REVIEW_PROJECT,
            state_path=tmp_path / "private" / "state.sqlite3",
            max_sessions=3,
        ),
        hivemind=client,  # type: ignore[arg-type]
        sink_factory=FakeSink,
    )

    gc.collect()
    assert report.visible_turns == 3
    assert all(conversation() is None and holder() is None for conversation, holder in retained)
