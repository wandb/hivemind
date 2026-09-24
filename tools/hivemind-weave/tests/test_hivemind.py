from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

from hivemind_weave import hivemind as hivemind_module
from hivemind_weave.errors import AuthenticationError, HiveMindAPIError
from hivemind_weave.hivemind import HiveMindClient


class QueueRunner:
    def __init__(self, responses: list[tuple[int, Any, str]]) -> None:
        self.responses = list(responses)
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        code, stdout, stderr = self.responses.pop(0)
        rendered = stdout if isinstance(stdout, str) else json.dumps(stdout)
        return subprocess.CompletedProcess(command, code, rendered, stderr)


def test_default_runner_does_not_inherit_destination_or_model_api_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setenv("WANDB_API_KEY", "destination-secret")
    monkeypatch.setenv("WANDB_ENTITY", "destination-entity")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "model-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "model-secret")
    monkeypatch.setenv("GOOGLE_API_KEY", "model-secret")
    monkeypatch.setenv("HIVEMIND_TOKEN", "ambient-login-override")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "unrelated-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "unrelated-secret")
    monkeypatch.setenv("HIVEMIND_TEST_MARKER", "must-not-be-inherited")
    monkeypatch.setenv("HOME", "/private/tmp/untrusted-home")
    monkeypatch.setenv("PATH", "/private/tmp/untrusted-bin")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setattr(hivemind_module.subprocess, "run", fake_run)

    hivemind_module._default_runner(["hivemind", "api", "/auth/me", "--raw"])

    child_env = captured["env"]
    assert captured["timeout"] == 600
    assert captured["stdin"] is subprocess.DEVNULL
    assert child_env["LANG"] == "en_US.UTF-8"
    assert child_env["HOME"] != "/private/tmp/untrusted-home"
    assert "/private/tmp/untrusted-bin" not in child_env["PATH"]
    assert "HIVEMIND_TEST_MARKER" not in child_env
    assert "WANDB_API_KEY" not in child_env
    assert "WANDB_ENTITY" not in child_env
    assert "ANTHROPIC_API_KEY" not in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "GOOGLE_API_KEY" not in child_env
    assert "HIVEMIND_TOKEN" not in child_env
    assert "AWS_SESSION_TOKEN" not in child_env
    assert "GITHUB_TOKEN" not in child_env


def _sessions_page(
    sessions: list[dict[str, Any]],
    *,
    total_count: int,
    has_more: bool,
    page: int,
    page_size: int = 100,
    sort_by: str = "started_at",
    sort_direction: str = "asc",
) -> tuple[int, dict[str, Any], str]:
    return (
        0,
        {
            "sessions": sessions,
            "total_count": total_count,
            "has_more": has_more,
            "page": page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_direction": sort_direction,
        },
        "",
    )


def test_preflight_uses_authenticated_api() -> None:
    runner = QueueRunner(
        [
            (0, {"user_id": "u1", "username": "me", "email": "m@e.io"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.preflight()
    assert runner.commands[0] == ["hivemind", "api", "/auth/me", "--raw"]
    assert "/sessions" in runner.commands[1]
    assert "page_size=10" in runner.commands[1]
    assert "user_id=u1" in runner.commands[1]


def test_user_scope_is_passed_raw_for_the_cli_to_encode() -> None:
    runner = QueueRunner(
        [
            (0, {"user_id": "abc/unsafe", "username": "me"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
        ]
    )
    HiveMindClient(runner=runner).preflight()
    assert "user_id=abc/unsafe" in runner.commands[1]
    assert "user_id=abc%2Funsafe" not in runner.commands[1]


def test_preflight_converts_cli_failure_to_login_instruction() -> None:
    runner = QueueRunner([(1, "", "401 Unauthorized")])
    with pytest.raises(AuthenticationError, match="hivemind login"):
        HiveMindClient(runner=runner).preflight()


def test_session_pagination_deduplicates_and_uses_stable_sort(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one")
    second = session_payload(id="two")
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user", "username": "me"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            (
                0,
                {
                    "sessions": [first, second],
                    "total_count": 2,
                    "has_more": True,
                    "page": 1,
                    "page_size": 100,
                    "sort_by": "started_at",
                    "sort_direction": "asc",
                },
                "",
            ),
            (
                0,
                {
                    "sessions": [second],
                    "total_count": 2,
                    "has_more": False,
                    "page": 2,
                    "page_size": 100,
                    "sort_by": "started_at",
                    "sort_direction": "asc",
                },
                "",
            ),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.preflight()
    sessions = client.list_sessions(days=8)
    assert [item["id"] for item in sessions] == ["one", "two"]
    first_command = runner.commands[2]
    assert "days=8" in first_command
    assert "page_size=100" in first_command
    assert "sort_by=started_at" in first_command
    assert "sort_direction=asc" in first_command
    assert "include_subagents=true" in first_command
    assert "user_id=current-user" in first_command
    assert "page=2" in runner.commands[3]


def test_empty_page_with_has_more_is_rejected() -> None:
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user", "username": "me"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            (
                0,
                {
                    "sessions": [],
                    "total_count": 1,
                    "has_more": True,
                    "page": 1,
                    "page_size": 100,
                    "sort_by": "started_at",
                    "sort_direction": "asc",
                },
                "",
            ),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.preflight()
    with pytest.raises(HiveMindAPIError, match="empty session page"):
        client.list_sessions(days=1)


def test_session_total_drift_restarts_from_primary_sweep(
    session_payload: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_marker = "PRIVATE-SOURCE-MUST-NOT-PRINT"
    first = session_payload(id="one", title=private_marker)
    second = session_payload(id="two")
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            _sessions_page([first], total_count=2, has_more=True, page=1),
            _sessions_page([second], total_count=3, has_more=False, page=2),
            _sessions_page([first, second], total_count=2, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.preflight()
    sessions = client.list_sessions(days=1)

    assert [item["id"] for item in sessions] == ["one", "two"]
    assert sleep_calls == [2.0]
    list_commands = runner.commands[2:]
    assert sum("page=1" in command for command in list_commands) == 2
    assert "page=1" in list_commands[-1]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert private_marker not in captured.out + captured.err


def test_session_snapshot_instability_stops_after_five_attempts(
    session_payload: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_marker = "PRIVATE-EXHAUSTED-SOURCE-MUST-NOT-PRINT"
    deficient = _sessions_page(
        [session_payload(id="one", title=private_marker)],
        total_count=2,
        has_more=False,
        page=1,
    )
    deficient_round = [
        deficient,
        _sessions_page(
            [session_payload(id="one", title=private_marker)],
            total_count=2,
            has_more=False,
            page=1,
            sort_direction="desc",
        ),
        _sessions_page(
            [session_payload(id="one", title=private_marker)],
            total_count=2,
            has_more=False,
            page=1,
            page_size=97,
        ),
        _sessions_page(
            [session_payload(id="one", title=private_marker)],
            total_count=2,
            has_more=False,
            page=1,
            page_size=97,
            sort_direction="desc",
        ),
        _sessions_page(
            [session_payload(id="one", title=private_marker)],
            total_count=2,
            has_more=False,
            page=1,
            page_size=89,
        ),
        _sessions_page(
            [session_payload(id="one", title=private_marker)],
            total_count=2,
            has_more=False,
            page=1,
            page_size=89,
            sort_direction="desc",
        ),
    ]
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            *(deficient_round * 5),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.preflight()

    with pytest.raises(HiveMindAPIError, match="every unique session") as captured_error:
        client.list_sessions(days=1)

    assert len(runner.commands) == 32
    assert all("page=1" in command for command in runner.commands[2:])
    assert sleep_calls == [2.0] * 4
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert private_marker not in str(captured_error.value) + captured.out + captured.err


def test_primary_total_drift_exhaustion_raises_canonical_completeness_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, bool, int, str]] = []
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=QueueRunner([]), sleeper=sleep_calls.append)
    client.user_id = "current-user"

    def unstable_sweep(
        *, days: int, include_subagents: bool, page_size: int, sort_direction: str
    ) -> Any:
        calls.append((days, include_subagents, page_size, sort_direction))
        raise HiveMindAPIError("HiveMind session total_count changed during pagination")

    monkeypatch.setattr(client, "_list_sessions_sweep", unstable_sweep)

    with pytest.raises(HiveMindAPIError, match="every unique session") as captured:
        client.list_sessions(days=9, include_subagents=False)

    assert (
        str(captured.value) == "HiveMind pagination ended before every unique session was returned"
    )
    assert calls == [(9, False, 100, "asc")] * 5
    assert sleep_calls == [2.0] * 4


def test_near_match_total_drift_error_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HiveMindAPIError(
        "HiveMind session total_count changed during pagination (noncanonical)"
    )
    calls = 0
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=QueueRunner([]), sleeper=sleep_calls.append)
    client.user_id = "current-user"

    def unstable_sweep(
        *, days: int, include_subagents: bool, page_size: int, sort_direction: str
    ) -> Any:
        nonlocal calls
        del days, include_subagents, page_size, sort_direction
        calls += 1
        raise error

    monkeypatch.setattr(client, "_list_sessions_sweep", unstable_sweep)

    with pytest.raises(HiveMindAPIError) as captured:
        client.list_sessions(days=1)

    assert captured.value is error
    assert calls == 1
    assert sleep_calls == []


def test_nonretryable_session_schema_error_fails_immediately(
    session_payload: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_marker = "PRIVATE-SCHEMA-SOURCE-MUST-NOT-PRINT"
    item = session_payload(id="one", title=private_marker)
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            _sessions_page(
                [item],
                total_count=1,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page([item], total_count=1, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.preflight()

    with pytest.raises(HiveMindAPIError, match="unexpected session sort order") as error:
        client.list_sessions(days=1)

    assert len(runner.commands) == 3
    assert len(runner.responses) == 1
    assert sleep_calls == []
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert private_marker not in str(error.value) + captured.out + captured.err


def test_duplicate_only_nonempty_page_advances(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one")
    second = session_payload(id="two")
    runner = QueueRunner(
        [
            (0, {"user_id": "current-user"}, ""),
            (0, {"sessions": [], "has_more": False}, ""),
            _sessions_page([first], total_count=2, has_more=True, page=1),
            _sessions_page([first], total_count=2, has_more=True, page=2),
            _sessions_page([second], total_count=2, has_more=False, page=3),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.preflight()

    sessions = client.list_sessions(days=1)

    assert [item["id"] for item in sessions] == ["one", "two"]
    assert "page=3" in runner.commands[-1]
    assert not runner.responses
    assert sleep_calls == []


def test_deficient_sweeps_union_then_confirm_with_exact_matching_ids(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    second = session_payload(id="two", started_at="2026-08-01T02:00:00Z")
    third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    refreshed_second = {**second, "title": "refreshed"}
    runner = QueueRunner(
        [
            _sessions_page([first, second], total_count=3, has_more=False, page=1),
            _sessions_page(
                [third, refreshed_second],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page([first, refreshed_second, third], total_count=3, has_more=False, page=1),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "two", "three"]
    assert sessions[1]["title"] == "refreshed"
    assert [
        next(value for value in command if value.startswith("sort_direction="))
        for command in runner.commands
    ] == ["sort_direction=asc", "sort_direction=desc", "sort_direction=asc"]


def test_deficient_confirmation_subset_forces_a_fresh_primary_sweep(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    second = session_payload(id="two", started_at="2026-08-01T02:00:00Z")
    third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    runner = QueueRunner(
        [
            _sessions_page([first, second], total_count=3, has_more=False, page=1),
            _sessions_page(
                [third],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page([first], total_count=3, has_more=False, page=1),
            _sessions_page([first, second, third], total_count=3, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "two", "three"]
    assert sleep_calls == [2.0]


def test_same_count_membership_churn_cannot_confirm_a_stale_union(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    stale_second = session_payload(id="two", started_at="2026-08-01T02:00:00Z")
    stale_third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    current_fourth = session_payload(id="four", started_at="2026-08-01T04:00:00Z")
    current_fifth = session_payload(id="five", started_at="2026-08-01T05:00:00Z")
    current = [first, current_fourth, current_fifth]
    runner = QueueRunner(
        [
            _sessions_page([first, stale_second], total_count=3, has_more=False, page=1),
            _sessions_page(
                [stale_third],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page(current, total_count=3, has_more=False, page=1),
            _sessions_page(current, total_count=3, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "four", "five"]
    assert sleep_calls == [2.0]


def test_shifted_page_size_can_supply_an_exact_recovery_sweep(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    second = session_payload(id="two", started_at="2026-08-01T02:00:00Z")
    third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    runner = QueueRunner(
        [
            _sessions_page([first], total_count=3, has_more=False, page=1),
            _sessions_page(
                [first],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page(
                [first, second, third],
                total_count=3,
                has_more=False,
                page=1,
                page_size=97,
            ),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "two", "three"]
    assert "page_size=97" in runner.commands[-1]
    assert len(runner.commands) == 3


def test_between_sweep_total_change_resets_the_union_epoch(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    items = [
        session_payload(id=f"session-{number}", started_at=f"2026-08-01T0{number}:00:00Z")
        for number in range(1, 6)
    ]
    runner = QueueRunner(
        [
            _sessions_page([items[0]], total_count=4, has_more=False, page=1),
            _sessions_page(
                [items[4]],
                total_count=5,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page(items[:4], total_count=5, has_more=False, page=1, page_size=97),
            _sessions_page(items, total_count=5, has_more=False, page=1),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == [f"session-{number}" for number in range(1, 6)]
    assert len(runner.commands) == 4


def test_recovery_total_drift_aborts_epoch_and_retries_primary(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    items = [
        session_payload(id=f"session-{number}", started_at=f"2026-08-01T0{number}:00:00Z")
        for number in range(1, 5)
    ]
    runner = QueueRunner(
        [
            _sessions_page([items[0]], total_count=3, has_more=False, page=1),
            _sessions_page(
                [items[2]],
                total_count=3,
                has_more=True,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page(
                [items[1]],
                total_count=4,
                has_more=False,
                page=2,
                sort_direction="desc",
            ),
            _sessions_page(items, total_count=4, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == [f"session-{number}" for number in range(1, 5)]
    assert sleep_calls == [2.0]
    assert "sort_direction=asc" in runner.commands[-1]


def test_novel_confirmation_id_forces_a_fresh_primary_sweep(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    second = session_payload(id="two", started_at="2026-08-01T02:00:00Z")
    third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    replacement = session_payload(id="replacement", started_at="2026-08-01T04:00:00Z")
    runner = QueueRunner(
        [
            _sessions_page([first, second], total_count=3, has_more=False, page=1),
            _sessions_page(
                [third],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page([first, replacement], total_count=3, has_more=False, page=1),
            _sessions_page([first, third, replacement], total_count=3, has_more=False, page=1),
        ]
    )
    sleep_calls: list[float] = []
    client = HiveMindClient(runner=runner, sleeper=sleep_calls.append)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "three", "replacement"]
    assert sleep_calls == [2.0]


def test_same_total_union_overflow_discards_stale_membership(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    first = session_payload(id="one", started_at="2026-08-01T01:00:00Z")
    stale = session_payload(id="stale", started_at="2026-08-01T02:00:00Z")
    third = session_payload(id="three", started_at="2026-08-01T03:00:00Z")
    fourth = session_payload(id="four", started_at="2026-08-01T04:00:00Z")
    runner = QueueRunner(
        [
            _sessions_page([first, stale], total_count=3, has_more=False, page=1),
            _sessions_page(
                [fourth, third],
                total_count=3,
                has_more=False,
                page=1,
                sort_direction="desc",
            ),
            _sessions_page([first], total_count=3, has_more=False, page=1, page_size=97),
            _sessions_page([first, third, fourth], total_count=3, has_more=False, page=1),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.user_id = "current-user"

    sessions = client.list_sessions(days=46)

    assert [item["id"] for item in sessions] == ["one", "three", "four"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("page", 1.0, "unexpected page number"),
        ("page_size", 100.0, "unexpected page_size"),
        ("sort_by", "last_activity_at", "unexpected session sort order"),
        ("sort_direction", "desc", "unexpected session sort order"),
    ],
)
def test_session_sweep_requires_exact_response_echoes(
    session_payload: Callable[..., dict[str, Any]],
    field: str,
    value: Any,
    message: str,
) -> None:
    response = _sessions_page([session_payload(id="one")], total_count=1, has_more=False, page=1)
    response[1][field] = value
    client = HiveMindClient(runner=QueueRunner([response]))
    client.user_id = "current-user"

    with pytest.raises(HiveMindAPIError, match=message):
        client.list_sessions(days=1)


def test_session_sweep_rejects_out_of_order_rows(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    later = session_payload(id="later", started_at="2026-08-01T02:00:00Z")
    earlier = session_payload(id="earlier", started_at="2026-08-01T01:00:00Z")
    client = HiveMindClient(
        runner=QueueRunner(
            [_sessions_page([later, earlier], total_count=2, has_more=False, page=1)]
        )
    )
    client.user_id = "current-user"

    with pytest.raises(HiveMindAPIError, match="outside the requested order"):
        client.list_sessions(days=1)


def test_session_sweep_page_limit_bounds_duplicate_progress(
    monkeypatch: pytest.MonkeyPatch,
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    item = session_payload(id="one")
    runner = QueueRunner(
        [
            _sessions_page([item], total_count=3, has_more=True, page=1),
            _sessions_page([item], total_count=3, has_more=True, page=2),
        ]
    )
    client = HiveMindClient(runner=runner)
    client.user_id = "current-user"
    monkeypatch.setattr(hivemind_module, "_SESSION_PAGE_LIMIT", 2)

    with pytest.raises(HiveMindAPIError, match="safety limit"):
        client.list_sessions(days=1)


def test_list_sessions_requires_authenticated_personal_scope() -> None:
    with pytest.raises(AuthenticationError, match="user scope"):
        HiveMindClient(runner=QueueRunner([])).list_sessions(days=1)


def test_direct_session_request_encodes_and_validates_identity(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    runner = QueueRunner([(0, session_payload(id="abc/unsafe"), "")])

    payload = HiveMindClient(runner=runner).get_session("abc/unsafe")

    assert payload["id"] == "abc/unsafe"
    assert runner.commands == [["hivemind", "api", "/sessions/abc%2Funsafe", "--raw"]]


def test_direct_session_rejects_mismatched_identity(
    session_payload: Callable[..., dict[str, Any]],
) -> None:
    runner = QueueRunner([(0, session_payload(id="different"), "")])

    with pytest.raises(HiveMindAPIError, match="identity does not match"):
        HiveMindClient(runner=runner).get_session("expected")


def test_atif_request_asks_for_every_documented_event_type(
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    runner = QueueRunner([(0, atif_wrapper(wrapper_session_id="abc/unsafe"), "")])
    payload = HiveMindClient(runner=runner).get_atif("abc/unsafe")
    assert "trajectory" in payload
    command = runner.commands[0]
    assert "/sessions/abc%2Funsafe/llm" in command
    assert "format=atif" in command
    assert "event_types=user,assistant,reasoning,tools,files,errors" in command


def test_invalid_json_never_echoes_raw_stdout() -> None:
    private_transcript = "not-json private chat content"
    runner = QueueRunner([(0, private_transcript, "")] * 3)
    sleep_calls: list[float] = []
    with pytest.raises(HiveMindAPIError) as captured:
        HiveMindClient(runner=runner, sleeper=sleep_calls.append).get_atif("abc")
    assert private_transcript not in str(captured.value)
    assert sleep_calls == [2.0, 2.0]


def test_cli_failure_never_echoes_stderr() -> None:
    private_transcript = "ordinary private conversation text"
    runner = QueueRunner([(1, "", private_transcript)] * 3)
    sleep_calls: list[float] = []
    with pytest.raises(HiveMindAPIError) as captured:
        HiveMindClient(runner=runner, sleeper=sleep_calls.append).get_atif("abc")
    assert private_transcript not in str(captured.value)
    assert "exit status 1" in str(captured.value)
    assert sleep_calls == [2.0, 2.0]


def test_atif_fetch_retries_a_transient_cli_failure(
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    runner = QueueRunner(
        [
            (1, "", "private transient server response"),
            (0, atif_wrapper(wrapper_session_id="abc"), ""),
        ]
    )
    sleep_calls: list[float] = []

    payload = HiveMindClient(runner=runner, sleeper=sleep_calls.append).get_atif("abc")

    assert payload["session_id"] == "abc"
    assert len(runner.commands) == 2
    assert sleep_calls == [2.0]


def test_cli_process_os_error_is_reported_as_a_domain_failure() -> None:
    def denied(_: list[str]) -> subprocess.CompletedProcess[str]:
        raise PermissionError("private executable path")

    with pytest.raises(HiveMindAPIError, match="could not start") as captured:
        HiveMindClient(runner=denied).get_atif("abc")
    assert "private executable path" not in str(captured.value)
