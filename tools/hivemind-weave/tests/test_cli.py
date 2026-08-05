from __future__ import annotations

from pathlib import Path
from typing import Any

from hivemind_weave import cli
from hivemind_weave.models import RunReport


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


def test_cli_requires_project_bound_confirmation_for_live_import(capsys: Any) -> None:
    exit_code = cli.main(
        ["import", "--days", "7", "--project", "wandb/hivemind-chats"]
    )
    assert exit_code == 1
    assert "--confirm-project" in capsys.readouterr().err
