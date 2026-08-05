from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hivemind_weave import cli
from hivemind_weave.backfill import BackfillReport
from hivemind_weave.models import RunReport
from hivemind_weave.scheduled_sync import SyncInspection, SyncOnceOutcome, SyncStatus


def test_cli_validates_days_before_source_access(capsys: Any) -> None:
    exit_code = cli.main(
        ["import", "--days", "0", "--project", "wandb/hivemind-chats", "--dry-run"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "between 1 and 365" in captured.err


def test_cli_builds_expected_config(monkeypatch: Any, tmp_path: Path, capsys: Any) -> None:
    captured_config: list[Any] = []

    def fake_run(config: Any) -> RunReport:
        captured_config.append(config)
        return RunReport(discovered=3, eligible=2, planned=4)

    monkeypatch.setattr(cli, "run_import", fake_run)
    state_path = tmp_path / "state.sqlite3"
    exit_code = cli.main(
        [
            "import",
            "--days",
            "7",
            "--project",
            "wandb/hivemind-chats",
            "--idle-minutes",
            "15",
            "--state-path",
            str(state_path),
            "--dry-run",
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert output.startswith("Weave destination (dry run): wandb/hivemind-chats\n")
    assert "Dry run summary" in output
    assert captured_config[0].days == 7
    assert captured_config[0].idle_minutes == 15
    assert captured_config[0].state_path == state_path
    assert captured_config[0].dry_run is True


def test_cli_withholds_private_run_errors(monkeypatch: Any, capsys: Any) -> None:
    private_id = "session-private-123"
    monkeypatch.setattr(
        cli,
        "run_import",
        lambda _config: RunReport(failed=1, errors=[f"failed {private_id}"]),
    )

    assert (
        cli.main(
            [
                "import",
                "--days",
                "1",
                "--project",
                "wandb/hivemind-chats",
                "--dry-run",
            ]
        )
        == 1
    )
    rendered = capsys.readouterr()
    assert private_id not in rendered.out
    assert "withheld error details: 1" in rendered.out


def test_cli_requires_project_bound_confirmation_for_live_import(capsys: Any) -> None:
    exit_code = cli.main(["import", "--days", "7", "--project", "wandb/hivemind-chats"])
    assert exit_code == 1
    assert "--confirm-project" in capsys.readouterr().err


def test_cli_disables_legacy_monolithic_live_import(monkeypatch: Any, capsys: Any) -> None:
    monkeypatch.setattr(
        cli,
        "run_import",
        lambda _config: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    exit_code = cli.main(
        [
            "import",
            "--days",
            "45",
            "--project",
            "wandb/hivemind-chats-v2",
            "--confirm-project",
            "wandb/hivemind-chats-v2",
        ]
    )

    assert exit_code == 1
    assert "legacy live import is disabled" in capsys.readouterr().err


def _backfill_report(*, phase: str = "preview") -> BackfillReport:
    return BackfillReport(
        phase=phase,
        project="wandb/hivemind-chats",
        plan_id="a" * 64,
        since_utc=datetime(2026, 7, 1, tzinfo=UTC),
        until_utc=datetime(2026, 8, 1, tzinfo=UTC),
        selector="backlog",
        status="planned",
        selected=3,
        remaining_sessions=3,
    )


def test_backfill_preview_builds_date_plan_config(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    captured: list[Any] = []

    def fake_preview(config: Any) -> BackfillReport:
        captured.append(config)
        return _backfill_report()

    monkeypatch.setattr(cli, "preview_backfill", fake_preview)
    state_path = tmp_path / "state.sqlite3"
    exit_code = cli.main(
        [
            "backfill",
            "--preview",
            "--days",
            "45",
            "--until",
            "2026-08-01",
            "--timezone",
            "America/New_York",
            "--canary",
            "--agent",
            "codex",
            "--agent",
            "claude",
            "--repo",
            "wandb/hivemind",
            "--session-id",
            "session-1",
            "--session-id",
            "session-2",
            "--exclude-subagents",
            "--project",
            "wandb/hivemind-chats",
            "--state-path",
            str(state_path),
        ]
    )

    assert exit_code == 0
    assert captured[0].days == 45
    assert captured[0].until == "2026-08-01"
    assert captured[0].timezone_name == "America/New_York"
    assert captured[0].canary is True
    assert captured[0].agents == ("codex", "claude")
    assert captured[0].repositories == ("wandb/hivemind",)
    assert captured[0].session_ids == ("session-1", "session-2")
    assert captured[0].exclude_subagents is True
    assert captured[0].state_path == state_path
    output = capsys.readouterr()
    assert output.out.startswith("Weave destination (backfill preview): wandb/hivemind-chats\n")
    assert "--days is deprecated" in output.err


def test_backfill_apply_uses_plan_id_and_apply_time_session_budget(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    captured: list[Any] = []

    def fake_apply(config: Any) -> BackfillReport:
        captured.append(config)
        return _backfill_report(phase="apply")

    monkeypatch.setattr(cli, "apply_backfill", fake_apply)
    plan_id = "b" * 64
    exit_code = cli.main(
        [
            "backfill",
            "--plan",
            plan_id,
            "--max-sessions",
            "5",
            "--confirm-project",
            "wandb/hivemind-chats",
            "--state-path",
            str(tmp_path / "state.sqlite3"),
        ]
    )

    assert exit_code == 0
    assert captured[0].plan_id == plan_id
    assert captured[0].max_sessions == 5
    assert captured[0].project == "wandb/hivemind-chats"


def test_backfill_rejects_terminal_injection_before_printing_project(capsys: Any) -> None:
    unsafe_project = "wandb/good\n\x1b[31minjected"

    exit_code = cli.main(
        [
            "backfill",
            "--preview",
            "--since",
            "2026-07-01",
            "--project",
            unsafe_project,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert unsafe_project not in captured.out
    assert "injected" not in captured.out


def test_backfill_rejects_phase_inapplicable_flags(capsys: Any) -> None:
    preview_exit = cli.main(
        [
            "backfill",
            "--preview",
            "--since",
            "2026-07-01",
            "--project",
            "wandb/hivemind-chats",
            "--max-sessions",
            "1",
        ]
    )
    apply_exit = cli.main(
        [
            "backfill",
            "--plan",
            "a" * 64,
            "--confirm-project",
            "wandb/hivemind-chats",
            "--timezone",
            "UTC",
        ]
    )

    captured = capsys.readouterr()
    assert preview_exit == apply_exit == 1
    assert "apply-only" in captured.err
    assert "sealed timezone" in captured.err


def test_sync_configure_builds_secret_free_incremental_policy(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    captured: list[Any] = []
    monkeypatch.setattr(
        cli,
        "configure_scheduled_sync",
        lambda config, *, paths: captured.append((config, paths)),
    )

    exit_code = cli.main(
        [
            "sync",
            "configure",
            "--since",
            "2026-07-01",
            "--timezone",
            "UTC",
            "--project",
            "wandb/hivemind-chats",
            "--settle-minutes",
            "60",
            "--agent",
            "codex",
            "--repo",
            "wandb/hivemind",
            "--session-id",
            "session-1",
            "--exclude-subagents",
            "--state-path",
            str(tmp_path / "state.sqlite3"),
            "--config",
            str(tmp_path / "sync.json"),
        ]
    )

    assert exit_code == 0
    config, paths = captured[0]
    assert config.project == "wandb/hivemind-chats"
    assert config.since == "2026-07-01T00:00:00Z"
    assert config.settle_minutes == 60
    assert config.agents == ("codex",)
    assert config.repositories == ("wandb/hivemind",)
    assert config.session_ids == ("session-1",)
    assert config.include_subagents is False
    assert paths.config_path == tmp_path / "sync.json"


def test_auth_sync_once_install_status_and_reconcile_commands(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    config = cli.SyncConfig(
        project="wandb/hivemind-chats",
        since="2026-07-01T00:00:00Z",
        timezone="UTC",
        state_path=tmp_path / "state.sqlite3",
    )
    calls: list[Any] = []
    monkeypatch.setattr(cli, "load_sync_config", lambda _path: config)
    monkeypatch.setattr(
        cli,
        "set_project_keychain_secret",
        lambda project: calls.append(("keychain", project)),
    )
    monkeypatch.setattr(
        cli,
        "run_sync_once_from_file",
        lambda _path, *, paths: SyncOnceOutcome(
            state="succeeded", exit_code=0, status=SyncStatus(state="succeeded")
        ),
    )
    monkeypatch.setattr(
        cli,
        "install_scheduled_sync",
        lambda configured, *, paths: (
            calls.append(("install", configured.interval_seconds, paths.config_path))
            or SyncInspection(True, True, True, True)
        ),
    )
    monkeypatch.setattr(
        cli,
        "inspect_scheduled_sync",
        lambda *, paths: SyncInspection(
            True,
            True,
            True,
            True,
            queued_sessions=2,
            deferred_sessions=1,
            successful_scan_watermark="2026-08-05T12:00:00Z",
        ),
    )
    monkeypatch.setattr(
        cli,
        "reconcile_scheduled_sync",
        lambda configured, *, paths: (
            calls.append(("reconcile", configured.project, paths.config_path))
            or SyncStatus(state="succeeded")
        ),
    )
    config_path = str(tmp_path / "sync.json")

    assert cli.main(["auth", "keychain", "set", "--project", config.project]) == 0
    assert cli.main(["sync", "once", "--config", config_path]) == 0
    assert cli.main(["sync", "install", "--every-minutes", "15", "--config", config_path]) == 0
    assert cli.main(["sync", "status", "--config", config_path]) == 0
    assert cli.main(["reconcile", "--config", config_path]) == 0
    assert ("keychain", config.project) in calls
    assert ("install", 900, tmp_path / "sync.json") in calls
    assert ("reconcile", config.project, tmp_path / "sync.json") in calls
