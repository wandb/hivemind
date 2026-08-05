"""Create and inspect the per-user macOS LaunchAgent for scheduled sync."""

from __future__ import annotations

import os
import plistlib
import pwd
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from .errors import ImporterError
from .private_io import atomic_write_private, read_private_bytes, validate_private_file

LAUNCH_AGENT_LABEL = "com.wandb.hivemind-weave.sync"
LAUNCHCTL = Path("/bin/launchctl")
_HEALTHCHECK_TIMEOUT_SECONDS = 30

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class LaunchAgentError(ImporterError):
    """The per-user LaunchAgent could not be installed or inspected safely."""


def _launch_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    del source
    user = pwd.getpwuid(os.geteuid())
    return {
        "HOME": user.pw_dir,
        "LOGNAME": user.pw_name,
        "PATH": "/usr/bin:/bin",
        "USER": user.pw_name,
    }


def _validated_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise LaunchAgentError("scheduled Python executable must be absolute")
    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError as error:
        raise LaunchAgentError("scheduled Python executable could not be resolved") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise LaunchAgentError("scheduled Python executable has unsafe ownership or permissions")
    # A virtual environment's ``bin/python`` is commonly a symlink to the base
    # interpreter.  Validate that resolved target, but retain the reviewed venv
    # path so Python discovers the environment that contains hivemind_weave.
    return path


def render_launch_agent(
    *,
    config_path: Path,
    interval_seconds: int,
    python_executable: Path,
) -> bytes:
    """Return a secret-free binary plist with only fixed program arguments."""
    if not config_path.is_absolute():
        raise LaunchAgentError("scheduled config path must be absolute")
    if not 300 <= interval_seconds <= 86_400:
        raise LaunchAgentError("scheduled interval must be between 300 and 86400 seconds")
    executable = _validated_executable(python_executable)
    payload = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            str(executable),
            "-m",
            "hivemind_weave",
            "sync",
            "once",
            "--config",
            str(config_path),
        ],
        "RunAtLoad": False,
        "StartInterval": interval_seconds,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
        "ThrottleInterval": 60,
        "Umask": 0o077,
    }
    serialized = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY, sort_keys=True)
    lowered = serialized.lower()
    if any(marker in lowered for marker in (b"wandb_api_key", b"api-key=", b"bearer ")):
        raise LaunchAgentError("LaunchAgent unexpectedly contained credential material")
    return serialized


class MacOSLaunchAgent:
    """Manage one fixed-label user LaunchAgent without inheriting ambient env."""

    def __init__(
        self,
        plist_path: Path,
        *,
        runner: Runner = subprocess.run,
        platform_name: str = sys.platform,
        launchctl: Path = LAUNCHCTL,
    ) -> None:
        self.plist_path = plist_path
        self.runner = runner
        self.platform_name = platform_name
        self.launchctl = launchctl

    @property
    def domain(self) -> str:
        return f"gui/{os.geteuid()}"

    @property
    def service(self) -> str:
        return f"{self.domain}/{LAUNCH_AGENT_LABEL}"

    def _require_macos(self) -> None:
        if self.platform_name != "darwin" or self.launchctl != LAUNCHCTL:
            raise LaunchAgentError("scheduled sync requires /bin/launchctl on macOS")

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        self._require_macos()
        return self.runner(
            [str(self.launchctl), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_launch_environment(),
            check=False,
        )

    def _healthcheck(self, python_executable: Path) -> Path:
        """Prove the exact scheduled interpreter can import this package."""
        self._require_macos()
        executable = _validated_executable(python_executable)
        try:
            completed = self.runner(
                [str(executable), "-m", "hivemind_weave", "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_launch_environment(),
                check=False,
                timeout=_HEALTHCHECK_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LaunchAgentError(
                "scheduled Python could not run the hivemind-weave healthcheck"
            ) from error
        if completed.returncode != 0:
            raise LaunchAgentError(
                "scheduled Python cannot import the installed hivemind-weave package"
            )
        return executable

    def is_installed(self) -> bool:
        if not self.plist_path.exists() and not self.plist_path.is_symlink():
            return False
        try:
            payload = plistlib.loads(read_private_bytes(self.plist_path, limit=64 * 1024))
        except plistlib.InvalidFileException as error:
            raise LaunchAgentError("installed LaunchAgent plist is invalid") from error
        if not isinstance(payload, dict) or payload.get("Label") != LAUNCH_AGENT_LABEL:
            raise LaunchAgentError("installed LaunchAgent plist does not own the expected label")
        return True

    def is_loaded(self) -> bool:
        return self._run(["print", self.service]).returncode == 0

    def write(
        self,
        *,
        config_path: Path,
        interval_seconds: int,
        python_executable: Path,
    ) -> None:
        executable = self._healthcheck(python_executable)
        serialized = render_launch_agent(
            config_path=config_path,
            interval_seconds=interval_seconds,
            python_executable=executable,
        )
        atomic_write_private(
            self.plist_path,
            serialized,
            require_private_parent=False,
        )

    def reload(self) -> None:
        """Replace the loaded definition after the caller acquires the sync lock."""
        self._require_macos()
        validate_private_file(self.plist_path)
        if self.is_loaded() and self._run(["bootout", self.service]).returncode != 0:
            raise LaunchAgentError("the existing scheduled sync could not be stopped")
        if self._run(["bootstrap", self.domain, str(self.plist_path)]).returncode != 0:
            raise LaunchAgentError("the scheduled sync could not be loaded")

    def unload(self) -> None:
        """Stop the fixed service; file and Keychain deletion require separate consent."""
        self._require_macos()
        if self.is_loaded() and self._run(["bootout", self.service]).returncode != 0:
            raise LaunchAgentError("the scheduled sync could not be stopped")
