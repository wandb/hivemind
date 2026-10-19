"""Minimal, non-logging access to a W&B API key in macOS Keychain."""

from __future__ import annotations

import os
import pwd
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ImporterError

SECURITY_TOOL = Path("/usr/bin/security")
KEYCHAIN_SERVICE = "com.wandb.hivemind-weave.wandb-api-key"
KEYCHAIN_LABEL = "HiveMind Weave scheduled sync"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_API_KEY = re.compile(r"^[A-Za-z0-9_-]{20,256}$")

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class KeychainError(ImporterError):
    """The scheduled importer could not safely use its Keychain item."""


@dataclass(frozen=True)
class KeychainReference:
    """A fixed service plus a project-scoped account identifier."""

    account: str
    service: str = KEYCHAIN_SERVICE

    def __post_init__(self) -> None:
        for value in (self.account, self.service):
            if not _IDENTIFIER.fullmatch(value) or value.startswith("-"):
                raise KeychainError("Keychain identifiers must use bounded visible ASCII")


def _keychain_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the smallest environment needed by Apple's Keychain CLI."""
    del source  # Ambient credentials and loader settings are intentionally ignored.
    user = pwd.getpwuid(os.geteuid())
    return {
        "HOME": user.pw_dir,
        "LOGNAME": user.pw_name,
        "PATH": "/usr/bin:/bin",
        "USER": user.pw_name,
    }


class MacOSKeychain:
    """Read and interactively install one project-scoped W&B API key.

    The insecure ``security ... -w PASSWORD`` form is never used. Installation
    puts a value-less ``-w`` last, causing Apple's tool to prompt on the TTY.
    """

    def __init__(
        self,
        reference: KeychainReference,
        *,
        runner: Runner = subprocess.run,
        platform_name: str = sys.platform,
        security_tool: Path = SECURITY_TOOL,
        is_tty: Callable[[], bool] = lambda: sys.stdin.isatty(),
    ) -> None:
        self.reference = reference
        self.runner = runner
        self.platform_name = platform_name
        self.security_tool = security_tool
        self.is_tty = is_tty

    def _require_macos(self) -> None:
        if self.platform_name != "darwin" or self.security_tool != SECURITY_TOOL:
            raise KeychainError("scheduled Keychain access requires /usr/bin/security on macOS")

    def _base_find_arguments(self) -> list[str]:
        return [
            str(self.security_tool),
            "find-generic-password",
            "-a",
            self.reference.account,
            "-s",
            self.reference.service,
        ]

    def has_secret(self) -> bool:
        """Check item presence without asking Keychain to reveal its value."""
        self._require_macos()
        completed = self.runner(
            self._base_find_arguments(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_keychain_environment(),
            check=False,
        )
        return completed.returncode == 0

    def install_interactive(self, *, replace: bool = False) -> None:
        """Ask Apple's tool to collect the key directly from the controlling TTY."""
        self._require_macos()
        if not self.is_tty():
            raise KeychainError("Keychain installation requires an interactive terminal")
        arguments = [
            str(self.security_tool),
            "add-generic-password",
            "-a",
            self.reference.account,
            "-s",
            self.reference.service,
            "-l",
            KEYCHAIN_LABEL,
        ]
        if replace:
            arguments.append("-U")
        arguments.extend(["-T", str(SECURITY_TOOL), "-w"])
        completed = self.runner(
            arguments,
            stdin=None,
            stdout=subprocess.DEVNULL,
            stderr=None,
            env=_keychain_environment(),
            check=False,
        )
        if completed.returncode != 0:
            raise KeychainError("the W&B API key was not stored in macOS Keychain")

    def read_secret(self) -> str:
        """Read the key into memory without exposing command output on failure."""
        self._require_macos()
        completed = self.runner(
            [*self._base_find_arguments(), "-w"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_keychain_environment(),
            check=False,
        )
        if completed.returncode != 0:
            raise KeychainError("the scheduled W&B API key is unavailable in macOS Keychain")
        raw = bytearray(completed.stdout or b"")
        try:
            while raw and raw[-1] in {10, 13}:
                raw.pop()
            if not raw or b"\n" in raw or b"\r" in raw or b"\x00" in raw:
                raise KeychainError("the scheduled W&B API key has an invalid format")
            try:
                value = raw.decode("ascii")
            except UnicodeDecodeError as error:
                raise KeychainError("the scheduled W&B API key has an invalid format") from error
            if not _API_KEY.fullmatch(value):
                raise KeychainError("the scheduled W&B API key has an invalid format")
            return value
        finally:
            for index in range(len(raw)):
                raw[index] = 0

    def delete(self) -> None:
        """Delete this exact item; intended for an explicit future uninstall command."""
        self._require_macos()
        arguments: Sequence[str] = [
            str(self.security_tool),
            "delete-generic-password",
            "-a",
            self.reference.account,
            "-s",
            self.reference.service,
        ]
        completed: Any = self.runner(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_keychain_environment(),
            check=False,
        )
        if completed.returncode != 0:
            raise KeychainError("the scheduled Keychain item could not be deleted")
