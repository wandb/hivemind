from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import hivemind_weave.scheduled_sync as scheduled_sync_module
from hivemind_weave.errors import WeaveImportError
from hivemind_weave.private_io import PrivatePathError, atomic_write_private
from hivemind_weave.scheduled_sync import (
    ScheduledSyncError,
    SyncConfig,
    SyncInspection,
    SyncPaths,
    SyncRunLock,
    SyncStatus,
    configure_scheduled_sync,
    inspect_scheduled_sync,
    install_scheduled_sync,
    load_sync_config,
    load_sync_status,
    reconcile_scheduled_sync,
    run_sync_once,
    set_project_keychain_secret,
    write_sync_config,
    write_sync_status,
)
from hivemind_weave.state import BackfillPlanStats, StateStore
from hivemind_weave.utils import parse_datetime, sha256_json

TEST_SECRET = "unit-test-sentinel-key"


class FakeKeychain:
    def __init__(self, *, present: bool = True, secret: str = TEST_SECRET) -> None:
        self.present = present
        self.secret = secret
        self.reads = 0
        self.installs: list[bool] = []

    def has_secret(self) -> bool:
        return self.present

    def install_interactive(self, *, replace: bool = False) -> None:
        self.installs.append(replace)
        self.present = True

    def read_secret(self) -> str:
        self.reads += 1
        return self.secret


class FailingKeychain(FakeKeychain):
    def read_secret(self) -> str:
        from hivemind_weave.macos_keychain import KeychainError

        raise KeychainError(f"unavailable {TEST_SECRET}")


class FakeLaunchAgent:
    def __init__(self) -> None:
        self.writes: list[dict[str, Any]] = []
        self.reloads = 0
        self.unloads = 0
        self.installed = True
        self.loaded = True

    def write(self, **kwargs: Any) -> None:
        self.writes.append(kwargs)

    def reload(self) -> None:
        self.reloads += 1
        self.loaded = True

    def unload(self) -> None:
        self.unloads += 1
        self.loaded = False

    def is_installed(self) -> bool:
        return self.installed

    def is_loaded(self) -> bool:
        return self.loaded


class FakeHiveMind:
    def __init__(
        self,
        sessions: list[dict[str, Any]],
        *,
        direct_sessions: list[dict[str, Any]] | None = None,
    ) -> None:
        self.sessions = sessions
        self.direct_sessions = direct_sessions if direct_sessions is not None else sessions
        self.user_id = "sync-user"
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
        for session in [*self.sessions, *self.direct_sessions]:
            if session["id"] == session_id:
                return dict(session)
        raise AssertionError("unknown direct session")


def _session(session_id: str, activity: str, **changes: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": session_id,
        "agent_session_id": f"agent-{session_id}",
        "title": "private title",
        "agent_type": "codex",
        "model": "gpt-test",
        "started_at": "2026-07-01T00:00:00Z",
        "last_activity_at": activity,
        "git_repo": "wandb/hivemind",
        "git_branch": "main",
        "parent_session_id": "",
        "username": "developer",
    }
    payload.update(changes)
    return payload


class FakePlanRunner:
    def __init__(self, *, apply_ok: bool = True) -> None:
        self.previews: list[Any] = []
        self.applies: list[Any] = []
        self.apply_ok = apply_ok

    def preview(self, config: Any, *, hivemind: FakeHiveMind) -> Any:
        self.previews.append(config)
        session_id = config.session_ids[0]
        raw = hivemind.get_session(session_id)
        started = parse_datetime(raw["started_at"])
        activity = parse_datetime(raw["last_activity_at"])
        since = parse_datetime(config.since)
        until = parse_datetime(config.until)
        assert started is not None and activity is not None
        assert since is not None and until is not None
        plan_id = sha256_json({"session_id": session_id, "activity": raw["last_activity_at"]})
        stats = BackfillPlanStats(
            plan_id=plan_id,
            turn_count=0,
            total_compressed_bytes=0,
            max_compressed_bytes=0,
            total_uncompressed_bytes=0,
            max_uncompressed_bytes=0,
            total_reference_count=0,
            max_reference_count=0,
            max_span_count=0,
            compressed_le_64k=0,
            compressed_le_256k=0,
            compressed_le_1m=0,
            compressed_gt_1m=0,
            uncompressed_le_256k=0,
            uncompressed_le_1m=0,
            uncompressed_le_5m=0,
            uncompressed_gt_5m=0,
        )
        with StateStore(config.state_path) as state:
            state.create_backfill_plan(
                plan_id=plan_id,
                project=config.project,
                source_principal_sha256="a" * 64,
                since_utc=since,
                until_utc=until,
                timezone_name=config.timezone_name,
                selector="backlog",
                universe_sha256="b" * 64,
                sessions=[(session_id, started, activity)],
                filters=[],
                turns=[],
                stats=stats,
                discovered_count=1,
                eligible_count=1,
                deferred_count=0,
                invalid_count=0,
            )
        return SimpleNamespace(plan_id=plan_id)

    def apply(self, config: Any, *, hivemind: FakeHiveMind) -> Any:
        del hivemind
        self.applies.append(config)
        return SimpleNamespace(
            ok=self.apply_ok,
            remaining_sessions=0,
            imported_turns=1 if self.apply_ok else 0,
            skipped_turns=0,
            conflicted_turns=0 if self.apply_ok else 1,
            failed_items=0,
            emitted_spans=2 if self.apply_ok else 0,
        )


def _paths(tmp_path: Path) -> SyncPaths:
    home = tmp_path / "home"
    (home / "Library" / "Application Support").mkdir(parents=True)
    (home / "Library" / "LaunchAgents").mkdir(mode=0o755)
    return SyncPaths.defaults(home=home)


def _config(tmp_path: Path, **changes: Any) -> SyncConfig:
    values: dict[str, Any] = {
        "project": "wandb/private-hivemind-sync",
        "since": "2026-06-21T04:00:00Z",
        "timezone": "America/New_York",
        "state_path": tmp_path / "state" / "sync.sqlite3",
        "interval_seconds": 3600,
        "settle_minutes": 60,
        "agents": ("codex", "claude"),
        "repositories": ("wandb/hivemind",),
        "session_ids": ("session-1",),
        "include_subagents": True,
    }
    values.update(changes)
    return SyncConfig(**values)


def _clock() -> Any:
    current = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)

    def now() -> datetime:
        nonlocal current
        result = current
        current += timedelta(seconds=1)
        return result

    return now


def _success_report(**changes: Any) -> SimpleNamespace:
    values = {
        "ok": True,
        "discovered": 3,
        "eligible": 2,
        "deferred": 1,
        "planned": 4,
        "imported": 4,
        "skipped": 0,
        "conflicted": 0,
        "failed": 0,
        "emitted_spans": 12,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_config_round_trip_is_content_free_and_private(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    config = _config(tmp_path)

    write_sync_config(paths.config_path, config)
    loaded = load_sync_config(paths.config_path)

    assert loaded == config
    assert stat.S_IMODE(paths.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.config_path.stat().st_mode) == 0o600
    serialized = paths.config_path.read_text()
    assert "WANDB_API_KEY" not in serialized
    assert TEST_SECRET not in serialized
    assert "messages" not in serialized
    assert "reasoning" not in serialized
    assert '"until"' not in serialized


def test_config_includes_only_an_explicit_bounded_until(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    config = _config(tmp_path, until="2026-08-05T12:00:00Z")
    write_sync_config(paths.config_path, config)
    assert load_sync_config(paths.config_path).until == "2026-08-05T12:00:00Z"
    assert '"until":"2026-08-05T12:00:00Z"' in paths.config_path.read_text()


def test_config_rejects_secret_or_unknown_fields(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    payload = _config(tmp_path).to_dict()
    payload["wandb_api_key"] = TEST_SECRET
    atomic_write_private(
        paths.config_path,
        (json.dumps(payload) + "\n").encode(),
    )
    with pytest.raises(ScheduledSyncError, match="unsupported fields"):
        load_sync_config(paths.config_path)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"since": "2026-06-21T00:00:00-04:00"}, "resolved UTC"),
        ({"until": "2026-06-20T04:00:00Z"}, "later than since"),
        ({"timezone": "Not/A_Real_Zone"}, "timezone"),
        ({"settle_minutes": 0}, "settle_minutes"),
        ({"interval_seconds": 100}, "interval_seconds"),
        ({"agents": ("line\nbreak",)}, "agents"),
        ({"repositories": ("-option",)}, "repositories"),
        ({"repositories": ("ghp_abcdefghijklmnopqrstuvwxyz/repo",)}, "repositories"),
        ({"session_ids": ("path/session",)}, "session_ids"),
    ],
)
def test_config_validation_is_fail_closed(
    tmp_path: Path,
    changes: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ScheduledSyncError, match=message):
        _config(tmp_path, **changes)


def test_existing_config_with_broad_permissions_is_not_modified(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    paths.config_path.write_text("{}")
    paths.config_path.chmod(0o644)
    with pytest.raises(PrivatePathError, match="mode 0600"):
        write_sync_config(paths.config_path, _config(tmp_path))
    assert stat.S_IMODE(paths.config_path.stat().st_mode) == 0o644


def test_scheduler_lock_blocks_a_second_process_before_keychain_access(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    keychain = FakeKeychain()
    with SyncRunLock(paths.lock_path):
        outcome = run_sync_once(
            _config(tmp_path),
            paths=paths,
            keychain=keychain,  # type: ignore[arg-type]
            import_runner=lambda _config: _success_report(),
        )
    assert outcome.state == "already_running"
    assert outcome.exit_code == 0
    assert keychain.reads == 0


def test_sync_once_exposes_key_only_to_runner_and_writes_content_free_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    keychain = FakeKeychain()
    monkeypatch.setenv("WANDB_API_KEY", "original-environment-value-123456")
    observed: list[str | None] = []

    def runner(config: SyncConfig) -> SimpleNamespace:
        assert config.project == "wandb/private-hivemind-sync"
        observed.append(os.environ.get("WANDB_API_KEY"))
        return _success_report()

    outcome = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        import_runner=runner,
        clock=_clock(),
    )

    assert outcome.state == "succeeded"
    assert outcome.exit_code == 0
    assert observed == [TEST_SECRET]
    assert os.environ["WANDB_API_KEY"] == "original-environment-value-123456"
    status = load_sync_status(paths.status_path)
    assert status.state == "succeeded"
    assert status.imported == 4
    assert status.emitted_spans == 12
    assert status.last_success_at == "2026-08-05T12:00:01Z"
    serialized = paths.status_path.read_text()
    assert TEST_SECRET not in serialized
    assert "trace" not in serialized
    assert stat.S_IMODE(paths.status_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.lock_path.stat().st_mode) == 0o600


def test_sync_once_records_content_free_backfill_report_aliases(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    report = SimpleNamespace(
        ok=True,
        discovered=9,
        eligible=7,
        deferred=2,
        cohort_sessions=1,
        imported_turns=3,
        skipped_turns=1,
        conflicted_turns=0,
        failed_items=0,
        emitted_spans=8,
    )
    outcome = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=FakeKeychain(),  # type: ignore[arg-type]
        import_runner=lambda _config: report,
        clock=_clock(),
    )
    assert outcome.status is not None
    assert outcome.status.planned == 1
    assert outcome.status.imported == 3
    assert outcome.status.skipped == 1
    assert outcome.status.emitted_spans == 8


def test_failure_status_suppresses_exception_text_and_pauses_later_runs(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    keychain = FakeKeychain()

    def fail(_config: SyncConfig) -> Any:
        raise WeaveImportError(f"transport rejected {TEST_SECRET}")

    first = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        import_runner=fail,
        clock=_clock(),
    )
    second = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        import_runner=lambda _config: _success_report(),
        clock=_clock(),
    )

    assert first.state == "failed"
    assert second.state == "paused"
    assert keychain.reads == 1
    serialized = paths.status_path.read_text()
    assert TEST_SECRET not in serialized
    assert "transport" not in serialized
    assert load_sync_status(paths.status_path).requires_attention is True


def test_attention_cannot_be_blindly_acknowledged(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    write_sync_status(
        paths.status_path,
        SyncStatus(
            state="failed",
            requires_attention=True,
            started_at="2026-08-05T10:00:00Z",
            finished_at="2026-08-05T10:01:00Z",
            error_code="import_failed",
            failed=1,
        ),
    )
    with pytest.raises(ScheduledSyncError, match="evidence-backed"):
        run_sync_once(
            _config(tmp_path),
            paths=paths,
            keychain=FakeKeychain(),  # type: ignore[arg-type]
            import_runner=lambda _config: _success_report(imported=0, skipped=4),
            clock=_clock(),
            acknowledge_attention=True,
        )
    assert load_sync_status(paths.status_path).requires_attention is True


def test_keychain_failure_is_content_free_and_requires_attention(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    outcome = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=FailingKeychain(),  # type: ignore[arg-type]
        import_runner=lambda _config: _success_report(),
        clock=_clock(),
    )
    assert outcome.exit_code == 1
    status = load_sync_status(paths.status_path)
    assert status.error_code == "keychain_unavailable"
    assert TEST_SECRET not in paths.status_path.read_text()


def test_running_status_from_a_crashed_process_trips_the_circuit_breaker(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    write_sync_status(
        paths.status_path,
        SyncStatus(state="running", started_at="2026-08-05T10:00:00Z"),
    )
    keychain = FakeKeychain()
    outcome = run_sync_once(
        _config(tmp_path),
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        import_runner=lambda _config: _success_report(),
    )
    assert outcome.state == "paused"
    assert outcome.status is not None
    assert outcome.status.error_code == "prior_run_incomplete"
    assert keychain.reads == 0


def test_configure_and_keychain_set_are_separate_from_install(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    keychain = FakeKeychain(present=False)
    config = _config(tmp_path)

    configure_scheduled_sync(config, paths=paths)
    set_project_keychain_secret(
        config.project,
        keychain=keychain,  # type: ignore[arg-type]
    )

    assert load_sync_config(paths.config_path) == config
    assert keychain.installs == [True]


def test_configure_refuses_loaded_or_incompatible_policy_mutation(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    original = _config(tmp_path)
    configure_scheduled_sync(original, paths=paths)
    original_status = SyncStatus(
        state="failed",
        requires_attention=True,
        error_code="upload_blocked",
        failed=1,
    )
    write_sync_status(paths.status_path, original_status)
    changed = replace(original, project="wandb/a-different-project")
    loaded_agent = FakeLaunchAgent()

    with pytest.raises(ScheduledSyncError, match="loaded"):
        configure_scheduled_sync(
            changed,
            paths=paths,
            launch_agent=loaded_agent,  # type: ignore[arg-type]
        )
    loaded_agent.loaded = False
    with pytest.raises(ScheduledSyncError, match="incompatible"):
        configure_scheduled_sync(
            changed,
            paths=paths,
            launch_agent=loaded_agent,  # type: ignore[arg-type]
        )

    assert load_sync_config(paths.config_path) == original
    assert load_sync_status(paths.status_path) == original_status


def test_identical_configure_is_idempotent_while_job_is_loaded(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path)
    configure_scheduled_sync(config, paths=paths)

    configure_scheduled_sync(
        config,
        paths=paths,
        launch_agent=FakeLaunchAgent(),  # type: ignore[arg-type]
    )

    assert load_sync_config(paths.config_path) == config


def test_install_requires_existing_key_and_loads_non_run_at_load_agent(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    keychain = FakeKeychain(present=True)
    agent = FakeLaunchAgent()
    config = _config(tmp_path)
    configure_scheduled_sync(config, paths=paths)

    result = install_scheduled_sync(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        launch_agent=agent,  # type: ignore[arg-type]
        python_executable=Path("/usr/bin/python3"),
    )

    assert isinstance(result, SyncInspection)
    assert replace(result, next_scheduled_at="") == SyncInspection(
        configured=True,
        installed=True,
        loaded=True,
        keychain_available=True,
        status=SyncStatus(),
    )
    assert keychain.installs == []
    assert agent.unloads == 1
    assert agent.reloads == 1
    assert agent.writes == [
        {
            "config_path": paths.config_path,
            "interval_seconds": 3600,
            "python_executable": Path("/usr/bin/python3"),
        }
    ]
    assert load_sync_config(paths.config_path) == config
    assert stat.S_IMODE(paths.config_path.stat().st_mode) == 0o600


def test_install_does_not_prompt_when_project_key_is_missing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    keychain = FakeKeychain(present=False)
    agent = FakeLaunchAgent()
    config = _config(tmp_path)
    configure_scheduled_sync(config, paths=paths)

    with pytest.raises(ScheduledSyncError, match="auth keychain set"):
        install_scheduled_sync(
            config,
            paths=paths,
            keychain=keychain,  # type: ignore[arg-type]
            launch_agent=agent,  # type: ignore[arg-type]
            python_executable=Path("/usr/bin/python3"),
        )

    assert keychain.installs == []
    assert agent.writes == []


def test_install_refuses_policy_identity_change_before_unloading(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    original = _config(tmp_path)
    configure_scheduled_sync(original, paths=paths)
    changed = replace(original, project="wandb/a-different-project")
    agent = FakeLaunchAgent()

    with pytest.raises(ScheduledSyncError, match="cannot change"):
        install_scheduled_sync(
            changed,
            paths=paths,
            keychain=FakeKeychain(),  # type: ignore[arg-type]
            launch_agent=agent,  # type: ignore[arg-type]
            python_executable=Path("/usr/bin/python3"),
        )

    assert agent.unloads == 0
    assert load_sync_config(paths.config_path) == original


def test_status_inspection_checks_key_presence_without_reading_it(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    write_sync_config(paths.config_path, _config(tmp_path))
    write_sync_status(paths.status_path, SyncStatus())
    keychain = FakeKeychain()
    result = inspect_scheduled_sync(
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        launch_agent=FakeLaunchAgent(),  # type: ignore[arg-type]
    )
    assert result.keychain_available is True
    assert keychain.reads == 0


def test_config_rejects_symlink_destination(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.directory.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("do not overwrite")
    paths.config_path.symlink_to(victim)
    with pytest.raises(PrivatePathError, match="unsafe owner or file type"):
        write_sync_config(paths.config_path, _config(tmp_path))
    assert victim.read_text() == "do not overwrite"


def test_status_rejects_negative_counts() -> None:
    with pytest.raises(ScheduledSyncError, match="nonnegative"):
        replace(SyncStatus(), imported=-1)


def test_incremental_sync_applies_at_most_one_exact_whole_session(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    client = FakeHiveMind(
        [
            _session("session-b", "2026-08-02T00:00:00Z"),
            _session("session-a", "2026-08-01T00:00:00Z"),
            _session("session-c", "2026-08-03T00:00:00Z"),
        ]
    )
    runner = FakePlanRunner()
    keychain = FakeKeychain()

    outcome = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert outcome.state == "succeeded"
    assert len(runner.previews) == len(runner.applies) == 1
    assert runner.previews[0].session_ids == ("session-a",)
    assert runner.applies[0].max_sessions == 1
    assert keychain.reads == 1
    with StateStore(config.state_path) as state:
        queued, deferred = state.sync_backlog_counts(config.project)
        next_session = state.get_next_sync_session(config.project)
    assert (queued, deferred) == (2, 0)
    assert next_session is not None and next_session.session_id == "session-b"
    for path in (paths.config_path, paths.status_path, config.state_path):
        if path.exists():
            assert TEST_SECRET.encode() not in path.read_bytes()


def test_next_sync_recovers_completed_attempt_after_final_status_write_crash(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    class SimulatedProcessExit(BaseException):
        pass

    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    now = datetime.now(UTC).replace(microsecond=0)
    activity = now - timedelta(days=2)
    client = FakeHiveMind([_session("completed-before-exit", activity.isoformat())])
    runner = FakePlanRunner()
    keychain = FakeKeychain()
    real_write_status = scheduled_sync_module.write_sync_status
    crashed = False

    def crash_before_success_status(path: Path, status: SyncStatus) -> None:
        nonlocal crashed
        if status.state == "succeeded" and not crashed:
            crashed = True
            raise SimulatedProcessExit
        real_write_status(path, status)

    monkeypatch.setattr(
        scheduled_sync_module,
        "write_sync_status",
        crash_before_success_status,
    )
    with pytest.raises(SimulatedProcessExit):
        run_sync_once(
            config,
            paths=paths,
            keychain=keychain,  # type: ignore[arg-type]
            clock=lambda: now,
            hivemind=client,  # type: ignore[arg-type]
            preview_runner=runner.preview,
            apply_runner=runner.apply,
        )
    assert load_sync_status(paths.status_path).state == "running"

    monkeypatch.setattr(scheduled_sync_module, "write_sync_status", real_write_status)
    recovered = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: now + timedelta(minutes=15),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert recovered.state == "succeeded"
    assert recovered.status is not None and not recovered.status.requires_attention
    assert len(runner.applies) == 1


def test_reconcile_recovers_completed_attempt_after_final_status_write_crash(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    class SimulatedProcessExit(BaseException):
        pass

    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    now = datetime.now(UTC).replace(microsecond=0)
    client = FakeHiveMind([_session("reconcile-completed", (now - timedelta(days=2)).isoformat())])
    runner = FakePlanRunner()
    keychain = FakeKeychain()
    real_write_status = scheduled_sync_module.write_sync_status

    def crash_before_success_status(path: Path, status: SyncStatus) -> None:
        if status.state == "succeeded":
            raise SimulatedProcessExit
        real_write_status(path, status)

    monkeypatch.setattr(
        scheduled_sync_module,
        "write_sync_status",
        crash_before_success_status,
    )
    with pytest.raises(SimulatedProcessExit):
        run_sync_once(
            config,
            paths=paths,
            keychain=keychain,  # type: ignore[arg-type]
            clock=lambda: now,
            hivemind=client,  # type: ignore[arg-type]
            preview_runner=runner.preview,
            apply_runner=runner.apply,
        )

    monkeypatch.setattr(scheduled_sync_module, "write_sync_status", real_write_status)
    recovered = reconcile_scheduled_sync(
        config,
        paths=paths,
        clock=lambda: now + timedelta(minutes=1),
    )

    assert recovered.state == "succeeded"
    assert recovered.requires_attention is False


def test_incremental_discovery_uses_successful_watermark_with_24_hour_overlap(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    first_cutoff = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    client = FakeHiveMind([_session("recent", "2026-08-05T11:30:00Z")])
    runner = FakePlanRunner()
    keychain = FakeKeychain()

    first = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: first_cutoff,
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )
    assert first.status is not None and first.status.deferred == 1
    assert keychain.reads == 0

    second_cutoff = datetime(2026, 8, 6, 13, 0, tzinfo=UTC)
    client.sessions = [
        _session("recent", "2026-08-05T11:30:00Z"),
        _session("late-arrival", "2026-08-05T00:00:00Z"),
    ]
    second = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: second_cutoff,
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert second.state == "succeeded"
    assert runner.previews[0].session_ids == ("late-arrival",)
    assert client.list_days[-1] <= 4
    with StateStore(config.state_path) as state:
        feed = state.get_sync_feed(config.project)
    assert feed is not None
    assert feed.successful_scan_watermark == second_cutoff


def test_deferred_session_is_rechecked_after_it_ages_out_of_overlap(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=(), settle_minutes=48 * 60)
    raw = _session("long-settle", "2026-08-05T11:00:00Z")
    client = FakeHiveMind([raw])
    runner = FakePlanRunner()
    keychain = FakeKeychain()

    first = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )
    assert first.status is not None and first.status.deferred == 1

    client.sessions = []
    second = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 7, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert second.state == "succeeded"
    assert client.direct_fetches.count("long-settle") >= 2
    assert runner.previews[-1].session_ids == ("long-settle",)


def test_attention_pauses_upload_but_discovery_and_backlog_continue(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    client = FakeHiveMind([_session("blocked", "2026-08-01T00:00:00Z")])
    runner = FakePlanRunner(apply_ok=False)
    keychain = FakeKeychain()

    first = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )
    assert first.status is not None and first.status.requires_attention is True
    assert keychain.reads == 1

    client.sessions.append(_session("new-backlog", "2026-08-05T00:00:00Z"))
    second = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert second.state == "paused"
    assert keychain.reads == 1
    assert len(runner.previews) == len(runner.applies) == 1
    with StateStore(config.state_path) as state:
        queued, deferred = state.sync_backlog_counts(config.project)
        feed = state.get_sync_feed(config.project)
        assert state.has_unresolved_sync_attempts(config.project) is True
    assert (queued, deferred) == (1, 0)
    assert feed is not None
    assert feed.successful_scan_watermark == datetime(2026, 8, 6, 12, 0, tzinfo=UTC)

    with pytest.raises(ScheduledSyncError, match="evidence"):
        reconcile_scheduled_sync(
            config,
            paths=paths,
            keychain=keychain,  # type: ignore[arg-type]
            hivemind=client,  # type: ignore[arg-type]
            apply_runner=runner.apply,
        )
    assert load_sync_status(paths.status_path).requires_attention is True
    assert len(runner.applies) == 2


def test_activity_advancement_requeues_completed_session_while_upload_is_paused(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    config = _config(tmp_path, session_ids=())
    client = FakeHiveMind([_session("advances", "2026-08-01T00:00:00Z")])
    runner = FakePlanRunner()
    keychain = FakeKeychain()
    run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )
    write_sync_status(
        paths.status_path,
        SyncStatus(
            state="failed",
            requires_attention=True,
            error_code="upload_blocked",
            failed=1,
        ),
    )
    client.sessions = [_session("advances", "2026-08-05T00:00:00Z")]

    paused = run_sync_once(
        config,
        paths=paths,
        keychain=keychain,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
        hivemind=client,  # type: ignore[arg-type]
        preview_runner=runner.preview,
        apply_runner=runner.apply,
    )

    assert paused.state == "paused"
    assert keychain.reads == 1
    with StateStore(config.state_path) as state:
        requeued = state.get_next_sync_session(config.project)
    assert requeued is not None
    assert requeued.session_id == "advances"
    assert requeued.last_activity_at == datetime(2026, 8, 5, tzinfo=UTC)
    assert requeued.plan_id == ""
