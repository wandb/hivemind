from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from hivemind_weave.macos_keychain import (
    KEYCHAIN_SERVICE,
    KeychainError,
    KeychainReference,
    MacOSKeychain,
)


class FakeRunner:
    def __init__(self, *results: subprocess.CompletedProcess[bytes]) -> None:
        self.results = list(results)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((arguments, kwargs))
        return self.results.pop(0)


def _result(returncode: int = 0, stdout: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"")


def test_keychain_reference_rejects_option_and_control_injection() -> None:
    for account in ("-malicious", "line\nbreak", "x" * 257):
        with pytest.raises(KeychainError, match="bounded visible ASCII"):
            KeychainReference(account=account)


def test_interactive_install_never_puts_the_secret_in_arguments_or_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "unit-test-sentinel-key"
    monkeypatch.setenv("WANDB_API_KEY", secret)
    runner = FakeRunner(_result())
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
        is_tty=lambda: True,
    )

    keychain.install_interactive(replace=True)

    arguments, kwargs = runner.calls[0]
    assert arguments[-1] == "-w"
    assert "-U" in arguments
    assert arguments[0] == "/usr/bin/security"
    assert secret not in " ".join(arguments)
    assert secret not in kwargs["env"].values()
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is None


def test_install_requires_a_terminal() -> None:
    runner = FakeRunner()
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
        is_tty=lambda: False,
    )
    with pytest.raises(KeychainError, match="interactive terminal"):
        keychain.install_interactive()
    assert runner.calls == []


def test_read_secret_captures_only_stdout_and_suppresses_keychain_diagnostics() -> None:
    secret = "unit-test-sentinel-key"
    runner = FakeRunner(_result(stdout=f"{secret}\n".encode()))
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
    )

    assert keychain.read_secret() == secret

    arguments, kwargs = runner.calls[0]
    assert arguments == [
        "/usr/bin/security",
        "find-generic-password",
        "-a",
        "wandb/private-project",
        "-s",
        KEYCHAIN_SERVICE,
        "-w",
    ]
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.DEVNULL


def test_read_secret_failure_never_includes_tool_output() -> None:
    runner = FakeRunner(_result(returncode=44, stdout=b"private-key-material"))
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
    )
    with pytest.raises(KeychainError) as captured:
        keychain.read_secret()
    assert "private-key-material" not in str(captured.value)


@pytest.mark.parametrize("value", [b"short", b"spaces are forbidden", b"abc\x00def", b"\xff" * 40])
def test_read_secret_rejects_unexpected_formats(value: bytes) -> None:
    runner = FakeRunner(_result(stdout=value))
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
    )
    with pytest.raises(KeychainError, match="invalid format"):
        keychain.read_secret()


def test_presence_check_never_requests_the_password() -> None:
    runner = FakeRunner(_result())
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
    )
    assert keychain.has_secret() is True
    arguments, kwargs = runner.calls[0]
    assert "-w" not in arguments
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL


def test_non_macos_and_alternate_security_binary_are_rejected() -> None:
    reference = KeychainReference(account="wandb/private-project")
    with pytest.raises(KeychainError, match="macOS"):
        MacOSKeychain(reference, platform_name="linux").has_secret()
    with pytest.raises(KeychainError, match="macOS"):
        MacOSKeychain(
            reference,
            platform_name="darwin",
            security_tool=Path("/tmp/security"),
        ).has_secret()


def test_keychain_environment_does_not_inherit_loader_or_credential_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "unit-test-sentinel-key")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/untrusted.dylib")
    runner = FakeRunner(_result())
    keychain = MacOSKeychain(
        KeychainReference(account="wandb/private-project"),
        runner=runner,
        platform_name="darwin",
    )
    keychain.has_secret()
    environment = runner.calls[0][1]["env"]
    assert set(environment) == {"HOME", "LOGNAME", "PATH", "USER"}
    assert environment["PATH"] == "/usr/bin:/bin"
    assert os.environ["DYLD_INSERT_LIBRARIES"] not in environment.values()
