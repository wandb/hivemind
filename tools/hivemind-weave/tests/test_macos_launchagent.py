from __future__ import annotations

import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave.macos_launchagent import (
    LAUNCH_AGENT_LABEL,
    LaunchAgentError,
    MacOSLaunchAgent,
    render_launch_agent,
)
from hivemind_weave.private_io import PrivatePathError


class FakeRunner:
    def __init__(self, *returncodes: int) -> None:
        self.returncodes = list(returncodes)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(
            arguments,
            self.returncodes.pop(0),
            stdout=b"",
            stderr=b"",
        )


def _launch_directory(tmp_path: Path) -> Path:
    path = tmp_path / "LaunchAgents"
    path.mkdir(mode=0o755)
    return path


def test_rendered_launch_agent_is_secret_free_and_does_not_run_at_install(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "private" / "sync.json"
    serialized = render_launch_agent(
        config_path=config_path,
        interval_seconds=3600,
        python_executable=Path(sys.executable),
    )
    payload = plistlib.loads(serialized)

    assert payload["Label"] == LAUNCH_AGENT_LABEL
    assert payload["RunAtLoad"] is False
    assert payload["StartInterval"] == 3600
    assert payload["StandardOutPath"] == "/dev/null"
    assert payload["StandardErrorPath"] == "/dev/null"
    assert payload["Umask"] == 0o077
    assert "EnvironmentVariables" not in payload
    arguments = payload["ProgramArguments"]
    assert arguments[0] == str(Path(sys.executable))
    assert arguments[1:] == [
        "-m",
        "hivemind_weave",
        "sync",
        "once",
        "--config",
        str(config_path),
    ]
    assert b"WANDB_API_KEY" not in serialized


def test_write_preserves_symlinked_venv_interpreter_and_healthchecks_it(
    tmp_path: Path,
) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(Path(sys.executable))
    runner = FakeRunner(0)
    agent = MacOSLaunchAgent(
        plist_path,
        runner=runner,
        platform_name="darwin",
    )

    agent.write(
        config_path=tmp_path / "private" / "sync.json",
        interval_seconds=3600,
        python_executable=venv_python,
    )

    payload = plistlib.loads(plist_path.read_bytes())
    assert payload["ProgramArguments"][0] == str(venv_python)
    assert runner.calls[0][0] == [
        str(venv_python),
        "-m",
        "hivemind_weave",
        "--version",
    ]
    healthcheck_kwargs = runner.calls[0][1]
    assert healthcheck_kwargs["stdin"] is subprocess.DEVNULL
    assert healthcheck_kwargs["stdout"] is subprocess.DEVNULL
    assert healthcheck_kwargs["stderr"] is subprocess.DEVNULL
    assert set(healthcheck_kwargs["env"]) == {"HOME", "LOGNAME", "PATH", "USER"}


def test_failed_healthcheck_does_not_write_or_replace_plist(tmp_path: Path) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    original = b"existing private plist"
    plist_path.write_bytes(original)
    plist_path.chmod(0o600)
    runner = FakeRunner(1)
    agent = MacOSLaunchAgent(
        plist_path,
        runner=runner,
        platform_name="darwin",
    )

    with pytest.raises(LaunchAgentError, match="cannot import"):
        agent.write(
            config_path=tmp_path / "private" / "sync.json",
            interval_seconds=3600,
            python_executable=Path(sys.executable),
        )

    assert plist_path.read_bytes() == original


@pytest.mark.parametrize("interval", [0, 299, 86_401])
def test_render_rejects_unreviewed_intervals(tmp_path: Path, interval: int) -> None:
    with pytest.raises(LaunchAgentError, match="interval"):
        render_launch_agent(
            config_path=tmp_path / "sync.json",
            interval_seconds=interval,
            python_executable=Path(sys.executable),
        )


def test_write_uses_mode_0600_even_in_a_normal_launchagents_directory(
    tmp_path: Path,
) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    agent = MacOSLaunchAgent(plist_path, platform_name="darwin")

    agent.write(
        config_path=tmp_path / "private" / "sync.json",
        interval_seconds=3600,
        python_executable=Path(sys.executable),
    )

    assert stat.S_IMODE(plist_path.stat().st_mode) == 0o600
    assert agent.is_installed() is True


def test_reload_boots_out_only_the_fixed_service_then_bootstraps(tmp_path: Path) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    agent_for_file = MacOSLaunchAgent(plist_path, platform_name="darwin")
    agent_for_file.write(
        config_path=tmp_path / "private" / "sync.json",
        interval_seconds=3600,
        python_executable=Path(sys.executable),
    )
    runner = FakeRunner(0, 0, 0)
    agent = MacOSLaunchAgent(plist_path, runner=runner, platform_name="darwin")

    agent.reload()

    uid = os.geteuid()
    assert [call[0] for call in runner.calls] == [
        ["/bin/launchctl", "print", f"gui/{uid}/{LAUNCH_AGENT_LABEL}"],
        ["/bin/launchctl", "bootout", f"gui/{uid}/{LAUNCH_AGENT_LABEL}"],
        ["/bin/launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
    ]
    for _arguments, kwargs in runner.calls:
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"] is subprocess.DEVNULL
        assert set(kwargs["env"]) == {"HOME", "LOGNAME", "PATH", "USER"}


def test_reload_fails_closed_when_bootstrap_fails(tmp_path: Path) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    writer = MacOSLaunchAgent(plist_path, platform_name="darwin")
    writer.write(
        config_path=tmp_path / "private" / "sync.json",
        interval_seconds=3600,
        python_executable=Path(sys.executable),
    )
    runner = FakeRunner(1, 5)
    agent = MacOSLaunchAgent(plist_path, runner=runner, platform_name="darwin")
    with pytest.raises(LaunchAgentError, match="could not be loaded"):
        agent.reload()


def test_existing_unsafe_plist_is_not_repaired(tmp_path: Path) -> None:
    directory = _launch_directory(tmp_path)
    plist_path = directory / "com.wandb.hivemind-weave.sync.plist"
    plist_path.write_bytes(plistlib.dumps({"Label": LAUNCH_AGENT_LABEL}))
    plist_path.chmod(0o644)
    agent = MacOSLaunchAgent(plist_path, platform_name="darwin")

    with pytest.raises(PrivatePathError, match="mode 0600"):
        agent.write(
            config_path=tmp_path / "sync.json",
            interval_seconds=3600,
            python_executable=Path(sys.executable),
        )
    assert stat.S_IMODE(plist_path.stat().st_mode) == 0o644


def test_non_macos_or_alternate_launchctl_is_rejected(tmp_path: Path) -> None:
    plist_path = tmp_path / "agent.plist"
    with pytest.raises(LaunchAgentError, match="macOS"):
        MacOSLaunchAgent(plist_path, platform_name="linux").is_loaded()
    with pytest.raises(LaunchAgentError, match="macOS"):
        MacOSLaunchAgent(
            plist_path,
            platform_name="darwin",
            launchctl=Path("/tmp/launchctl"),
        ).is_loaded()
