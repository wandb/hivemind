from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave import cli
from hivemind_weave.errors import ReviewMirrorUncertainError
from hivemind_weave.models import RunReport
from hivemind_weave.review import REVIEW_PROJECT, ReviewReport


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


def test_canonical_backfill_preview_is_disabled_before_source_or_state_access(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    def forbidden_preview(_config: Any) -> None:
        raise AssertionError("canonical preview reached source/state code")

    monkeypatch.setattr(cli, "preview_backfill", forbidden_preview)
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

    assert exit_code == 1
    assert not state_path.exists()
    output = capsys.readouterr()
    assert output.out == ""
    assert "canonical backfill preview/apply is disabled" in output.err
    assert "pre-0.4 experimental state" in output.err


def test_canonical_backfill_apply_is_disabled_before_state_or_source_access(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    def forbidden_apply(_config: Any) -> None:
        raise AssertionError("canonical apply reached state/source code")

    monkeypatch.setattr(cli, "apply_backfill", forbidden_apply)
    plan_id = "b" * 64
    state_path = tmp_path / "state.sqlite3"
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
            str(state_path),
        ]
    )

    assert exit_code == 1
    assert not state_path.exists()
    output = capsys.readouterr()
    assert output.out == ""
    assert "canonical backfill preview/apply is disabled" in output.err
    assert "pre-0.4 experimental state" in output.err


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


def test_backfill_phase_validation_cannot_bypass_disabled_gate(capsys: Any) -> None:
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
    assert captured.out == ""
    assert captured.err.count("canonical backfill preview/apply is disabled") == 2


def _review_report(*, phase: str = "preview") -> ReviewReport:
    return ReviewReport(
        phase=phase,
        project=REVIEW_PROJECT,
        plan_id="c" * 64,
        status="planned",
        since_utc=datetime(2026, 7, 16, tzinfo=UTC),
        until_utc=datetime(2026, 8, 6, tzinfo=UTC),
        selector="backlog",
        selected_sessions=2,
        remaining_sessions=2,
    )


def test_review_preview_builds_exact_filters_and_prints_fixed_project_first(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    captured: list[Any] = []

    def fake_preview(config: Any) -> ReviewReport:
        captured.append(config)
        return _review_report()

    monkeypatch.setattr(cli, "preview_review", fake_preview)
    state_path = tmp_path / "state.sqlite3"
    exit_code = cli.main(
        [
            "review",
            "preview",
            "--since",
            "2026-07-16T16:00:00Z",
            "--until",
            "2026-08-06T16:00:00Z",
            "--project",
            REVIEW_PROJECT,
            "--agent",
            "codex",
            "--repo",
            "wandb/hivemind",
            "--session-id",
            "session-1",
            "--exclude-subagents",
            "--canary",
            "--state-path",
            str(state_path),
        ]
    )

    assert exit_code == 0
    assert captured[0].agents == ("codex",)
    assert captured[0].repositories == ("wandb/hivemind",)
    assert captured[0].session_ids == ("session-1",)
    assert captured[0].exclude_subagents is True
    assert captured[0].canary is True
    assert captured[0].state_path == state_path
    output = capsys.readouterr().out
    assert output.startswith(f"Weave destination (review preview): {REVIEW_PROJECT}\n")


def test_review_preview_does_not_expose_a_timezone_option(capsys: Any) -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            [
                "review",
                "preview",
                "--since",
                "2026-07-16T00:00:00Z",
                "--project",
                REVIEW_PROJECT,
                "--timezone",
                "UTC",
            ]
        )
    assert "unrecognized arguments: --timezone UTC" in capsys.readouterr().err


def test_review_apply_requires_fixed_confirmation_and_passes_session_budget(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    captured: list[Any] = []

    def fake_apply(config: Any) -> ReviewReport:
        captured.append(config)
        return _review_report(phase="apply")

    monkeypatch.setattr(cli, "apply_review", fake_apply)
    state_path = tmp_path / "state.sqlite3"
    exit_code = cli.main(
        [
            "review",
            "apply",
            "--plan",
            "c" * 12,
            "--max-sessions",
            "5",
            "--confirm-project",
            REVIEW_PROJECT,
            "--state-path",
            str(state_path),
        ]
    )

    assert exit_code == 0
    assert captured[0].plan_id == "c" * 12
    assert captured[0].max_sessions == 5
    assert captured[0].confirm_project == REVIEW_PROJECT
    assert capsys.readouterr().out.startswith(
        f"Weave destination (review apply): {REVIEW_PROJECT}\n"
    )


def test_review_preflight_recovery_requires_explicit_project_confirmation(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    captured: list[Any] = []
    monkeypatch.setattr(
        cli,
        "recover_preflight_review",
        lambda config: captured.append(config) or _review_report(phase="recover-preflight"),
    )
    state_path = tmp_path / "state.sqlite3"
    assert (
        cli.main(
            [
                "review",
                "recover-preflight",
                "--plan",
                "c" * 12,
                "--confirm-project",
                REVIEW_PROJECT,
                "--state-path",
                str(state_path),
            ]
        )
        == 0
    )
    assert captured[0].plan_id == "c" * 12
    assert captured[0].confirm_project == REVIEW_PROJECT
    assert captured[0].state_path == state_path
    assert capsys.readouterr().out.startswith(
        f"Weave destination (read-only preflight recovery): {REVIEW_PROJECT}\n"
    )

    assert (
        cli.main(
            [
                "review",
                "recover-preflight",
                "--plan",
                "c" * 12,
                "--confirm-project",
                "wandb/hivemind-chats-v2",
            ]
        )
        == 1
    )
    assert len(captured) == 1


def test_review_reconcile_and_status_use_the_fixed_project_without_confirmation(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    reconciled: list[Any] = []
    statuses: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        cli,
        "reconcile_review",
        lambda config: reconciled.append(config) or _review_report(phase="reconcile"),
    )
    monkeypatch.setattr(
        cli,
        "review_status",
        lambda state_path, *, project: statuses.append((state_path, project)) or "status ok",
    )
    state_path = tmp_path / "state.sqlite3"

    assert (
        cli.main(
            [
                "review",
                "reconcile",
                "--plan",
                "c" * 12,
                "--state-path",
                str(state_path),
            ]
        )
        == 0
    )
    assert reconciled[0].plan_id == "c" * 12
    assert not hasattr(reconciled[0], "confirm_project")
    assert cli.main(["review", "status", "--state-path", str(state_path)]) == 0
    assert statuses == [(state_path, REVIEW_PROJECT)]
    output = capsys.readouterr().out
    assert f"Weave destination (review reconcile): {REVIEW_PROJECT}" in output
    assert "status ok" in output

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["review", "status", "--project", REVIEW_PROJECT])


def test_review_commands_reject_non_review_projects_before_dispatch(
    monkeypatch: Any,
    capsys: Any,
) -> None:
    monkeypatch.setattr(
        cli,
        "preview_review",
        lambda _config: (_ for _ in ()).throw(AssertionError("must not dispatch")),
    )
    exit_code = cli.main(
        [
            "review",
            "preview",
            "--since",
            "2026-07-16T00:00:00Z",
            "--project",
            "wandb/hivemind-chats-v2",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "fixed private project" in captured.err
    assert not captured.out


def test_review_uncertainty_prints_content_free_reconciliation_direction(
    monkeypatch: Any,
    capsys: Any,
) -> None:
    monkeypatch.setattr(
        cli,
        "apply_review",
        lambda _config: (_ for _ in ()).throw(
            ReviewMirrorUncertainError("review root delivery is uncertain; run review reconcile")
        ),
    )

    exit_code = cli.main(
        [
            "review",
            "apply",
            "--plan",
            "c" * 12,
            "--max-sessions",
            "1",
            "--confirm-project",
            REVIEW_PROJECT,
        ]
    )

    assert exit_code == 1
    assert "run review reconcile" in capsys.readouterr().err


def test_canonical_scheduler_commands_are_disabled_before_any_hook_or_file_access(
    monkeypatch: Any,
    tmp_path: Path,
    capsys: Any,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("disabled canonical scheduler reached an access hook")

    for hook in (
        "resolve_backfill_window",
        "configure_scheduled_sync",
        "set_project_keychain_secret",
        "load_sync_config",
        "run_sync_once_from_file",
        "install_scheduled_sync",
        "inspect_scheduled_sync",
        "reconcile_scheduled_sync",
    ):
        monkeypatch.setattr(cli, hook, forbidden)

    config_path = tmp_path / "sync.json"
    state_path = tmp_path / "state.sqlite3"
    commands = [
        ["auth", "keychain", "set", "--project", "wandb/hivemind-chats"],
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
            str(state_path),
            "--config",
            str(config_path),
        ],
        ["sync", "once", "--config", str(config_path)],
        [
            "sync",
            "install",
            "--every-minutes",
            "15",
            "--config",
            str(config_path),
        ],
        ["sync", "status", "--config", str(config_path)],
        ["reconcile", "--config", str(config_path)],
    ]

    for command in commands:
        assert cli.main(command) == 1
        assert not any(tmp_path.iterdir())

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.count("canonical scheduled sync") == len(commands)
    assert "unload any previously installed LaunchAgent" in output.err
