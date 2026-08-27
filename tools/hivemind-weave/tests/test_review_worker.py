from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import hivemind_weave.review_worker as worker_module
from hivemind_weave import __version__
from hivemind_weave.models import Session
from hivemind_weave.review_manifest import (
    MAX_REVIEW_CHUNK_BYTES,
    MAX_REVIEW_CHUNKS,
    REVIEW_INDEX_SCHEMA,
    REVIEW_MANIFEST_SCHEMA,
    _chunk_name,
    _manifest_name,
)
from hivemind_weave.review_state import review_logical_key
from hivemind_weave.review_worker import (
    PREPARATION_WORKER_PROTOCOL,
    ReviewPreparationSourceSerialization,
    ReviewPreparationSupervisor,
    ReviewPreparationTimeout,
    ReviewPreparationWorkerError,
    _decode_response,
    _process_group_exists,
    _terminate_process_group,
    _worker_environment,
)
from hivemind_weave.utils import canonical_json, isoformat_z

PROJECT = "wandb/hivemind-chats-review"
SESSION_ID = "11111111-1111-4111-8111-111111111111"


def _session() -> Session:
    return Session(
        id=SESSION_ID,
        agent_session_id="agent-session",
        title="private title",
        agent_type="codex",
        model="gpt-5",
        started_at=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        last_activity_at=datetime(2026, 7, 20, 12, 30, tzinfo=UTC),
        repository="private/repository",
        branch="private-branch",
        user="private-user",
    )


def _prepared_response(session: Session, nonce: str) -> bytes:
    turn_key = "atif:00000000:00000000"
    source_sha256 = "1" * 64
    manifest_sha256 = "2" * 64
    preview_signature = "4" * 64
    chunk_sha256 = "5" * 64
    index_json = canonical_json(
        {
            "schema": REVIEW_INDEX_SCHEMA,
            "manifest": {
                "schema": REVIEW_MANIFEST_SCHEMA,
                "name": _manifest_name(manifest_sha256),
                "sha256": manifest_sha256,
                "source_payload_sha256": source_sha256,
                "preview_signature": preview_signature,
                "byte_count": 100,
                "media_type": "application/json; charset=utf-8",
            },
            "chunking": {
                "encoding": "utf-8",
                "max_chunk_bytes": MAX_REVIEW_CHUNK_BYTES,
                "max_chunks": MAX_REVIEW_CHUNKS,
                "chunk_count": 1,
            },
            "chunks": [
                {
                    "index": 0,
                    "name": _chunk_name(
                        manifest_sha256=manifest_sha256,
                        chunk_sha256=chunk_sha256,
                        index=0,
                        chunk_count=1,
                    ),
                    "sha256": chunk_sha256,
                    "byte_count": 100,
                    "media_type": "text/plain; charset=utf-8",
                }
            ],
        }
    )
    index_sha256 = hashlib.sha256(index_json.encode()).hexdigest()
    return canonical_json(
        {
            "protocol": PREPARATION_WORKER_PROTOCOL,
            "importer_version": __version__,
            "nonce": nonce,
            "status": "prepared",
            "project": PROJECT,
            "session": {
                "id": session.id,
                "started_at": isoformat_z(session.started_at),
                "last_activity_at": isoformat_z(session.last_activity_at),
                "is_subagent": False,
            },
            "certificates": [
                {
                    "session_id": session.id,
                    "ordinal": 0,
                    "turn_key": turn_key,
                    "source_payload_sha256": source_sha256,
                    "manifest_sha256": manifest_sha256,
                    "index_sha256": index_sha256,
                    "logical_key": review_logical_key(
                        PROJECT,
                        f"hivemind:{session.id}",
                        turn_key,
                    ),
                    "preview_signature": preview_signature,
                    "started_at": "2026-07-20T12:00:00Z",
                    "ended_at": "2026-07-20T12:01:00Z",
                    "manifest_bytes": 100,
                    "chunk_count": 1,
                    "max_chunk_bytes": 100,
                    "index_bytes": len(index_json.encode()),
                    "atif_schema_version": "ATIF-v1.7",
                    "worker_index_json": index_json,
                    "worker_physical_span_count": 2,
                    "worker_mapping_warning_count": 0,
                }
            ],
        }
    ).encode()


def test_worker_response_is_content_free_and_strictly_validated() -> None:
    session = _session()
    nonce = "a" * 64
    result = _decode_response(
        _prepared_response(session, nonce),
        expected_nonce=nonce,
        expected_project=PROJECT,
        expected_session=session,
    )

    assert result.session_id == session.id
    assert len(result.certificate_payloads) == 1
    assert result.certificate_payloads[0]["started_at"] == datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
    assert all(
        not key.startswith("worker_")
        for certificate in result.certificate_payloads
        for key in certificate
    )
    assert result.canary_turn_facts[0].physical_span_count == 2
    assert result.canary_turn_facts[0].mapping_warning_count == 0
    decoded = json.loads(_prepared_response(session, nonce))
    assert set(decoded["session"]) == {
        "id",
        "started_at",
        "last_activity_at",
        "is_subagent",
    }
    assert "private title" not in _prepared_response(session, nonce).decode()

    decoded["transcript"] = "must never cross IPC"
    with pytest.raises(ReviewPreparationWorkerError, match="malformed protocol"):
        _decode_response(
            canonical_json(decoded).encode(),
            expected_nonce=nonce,
            expected_project=PROJECT,
            expected_session=session,
        )
    inconsistent = json.loads(_prepared_response(session, nonce))
    inconsistent["certificates"][0]["manifest_bytes"] += 1
    with pytest.raises(ReviewPreparationWorkerError, match="index evidence"):
        _decode_response(
            canonical_json(inconsistent).encode(),
            expected_nonce=nonce,
            expected_project=PROJECT,
            expected_session=session,
        )
    for field, value in (
        ("worker_mapping_warning_count", -1),
        ("worker_mapping_warning_count", True),
        ("worker_mapping_warning_count", 1_000_001),
        ("worker_physical_span_count", 0),
        ("worker_physical_span_count", True),
        ("worker_physical_span_count", 1_000_001),
    ):
        invalid_canary = json.loads(_prepared_response(session, nonce))
        invalid_canary["certificates"][0][field] = value
        with pytest.raises(ReviewPreparationWorkerError, match="invalid canary evidence"):
            _decode_response(
                canonical_json(invalid_canary).encode(),
                expected_nonce=nonce,
                expected_project=PROJECT,
                expected_session=session,
            )
    with pytest.raises(ReviewPreparationWorkerError, match="invalid protocol"):
        _decode_response(
            b'{"status":"prepared"',
            expected_nonce=nonce,
            expected_project=PROJECT,
            expected_session=session,
        )
    with pytest.raises(ReviewPreparationWorkerError, match="invalid protocol"):
        _decode_response(
            b'{"oversized_integer":' + (b"9" * 10_000) + b"}",
            expected_nonce=nonce,
            expected_project=PROJECT,
            expected_session=session,
        )


@pytest.mark.parametrize("error_code", ["preparation_timeout", "source_serialization"])
def test_worker_rejects_parent_owned_failure_as_child_authored_evidence(
    error_code: str,
) -> None:
    session = _session()
    nonce = "b" * 64
    payload = {
        "protocol": PREPARATION_WORKER_PROTOCOL,
        "importer_version": __version__,
        "nonce": nonce,
        "status": "rejected",
        "error_code": error_code,
    }
    with pytest.raises(ReviewPreparationWorkerError, match="unsupported rejection"):
        _decode_response(
            canonical_json(payload).encode(),
            expected_nonce=nonce,
            expected_project=PROJECT,
            expected_session=session,
        )


def test_supervisor_uses_private_protocol_pipe_and_secret_free_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WANDB_API_KEY", "must-not-cross")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("HTTPS_PROXY", "https://credential@example.invalid")
    environment = _worker_environment()
    assert "WANDB_API_KEY" not in environment
    assert "OPENAI_API_KEY" not in environment
    assert "HTTPS_PROXY" not in environment

    script = textwrap.dedent(
        """
        import json
        import os
        import sys

        request = json.load(sys.stdin)
        session = request["session"]
        response = {
            "protocol": request["protocol"],
            "importer_version": request["importer_version"],
            "nonce": request["nonce"],
            "status": "prepared",
            "project": request["project"],
            "session": {
                "id": session["id"],
                "started_at": session["started_at"],
                "last_activity_at": session["last_activity_at"],
                "is_subagent": False,
            },
            "certificates": [],
        }
        os.write(int(sys.argv[1]), json.dumps(response).encode())
        """
    )
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script, str(result_fd)),
    )
    result = supervisor.prepare(
        session=_session(),
        project=PROJECT,
        hivemind_binary="/usr/bin/true",
        timeout_seconds=5,
    )
    assert result.session_id == SESSION_ID
    assert result.certificate_payloads == ()


@pytest.mark.parametrize(
    "title",
    ["invalid-surrogate-\ud800", "x" * (2 * 1024 * 1024)],
    ids=["lone-surrogate", "oversized-metadata"],
)
def test_parent_source_serialization_failures_are_structured_and_do_not_spawn(
    title: str,
) -> None:
    session = replace(_session(), title=title)
    spawned = False

    def command_factory(_result_fd: int) -> tuple[str, ...]:
        nonlocal spawned
        spawned = True
        return (sys.executable, "-c", "raise SystemExit(99)")

    supervisor = ReviewPreparationSupervisor(command_factory=command_factory)
    with pytest.raises(ReviewPreparationSourceSerialization):
        supervisor.prepare(
            session=session,
            project=PROJECT,
            hivemind_binary="/usr/bin/true",
            timeout_seconds=5,
        )
    assert spawned is False


def test_default_worker_end_to_end_rejection_is_content_free(
    tmp_path: Path,
    session_payload: Callable[..., dict[str, Any]],
    atif_wrapper: Callable[..., dict[str, Any]],
) -> None:
    session_json = session_payload(
        id=SESSION_ID,
        title="E2E_PRIVATE_TITLE",
        started_at="2026-07-20T12:00:00Z",
        last_activity_at="2026-07-20T12:30:00Z",
        git_repo="",
        git_branch="",
        username="",
    )
    atif_json = atif_wrapper(
        version="ATIF-v2.0",
        wrapper_session_id=SESSION_ID,
        session_id=f"atif-{SESSION_ID}",
        steps=[
            {
                "step_id": 1,
                "timestamp": "2026-07-20T12:00:00Z",
                "source": "user",
                "message": "E2E_PRIVATE_PROMPT",
            },
            {
                "step_id": 2,
                "timestamp": "2026-07-20T12:00:01Z",
                "source": "agent",
                "message": "E2E_PRIVATE_RESPONSE",
            },
        ],
    )
    fake_cli = tmp_path / "fake-hivemind"
    fake_cli.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import sys

            session = json.loads({canonical_json(session_json)!r})
            atif = json.loads({canonical_json(atif_json)!r})
            path = sys.argv[2]
            if path == "/auth/me":
                payload = {{"user_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}
            elif path == "/sessions":
                payload = {{"sessions": []}}
            elif path.endswith("/llm"):
                payload = atif
            else:
                payload = session
            sys.stdout.write(json.dumps(payload))
            """
        ),
        encoding="utf-8",
    )
    fake_cli.chmod(0o700)

    result = ReviewPreparationSupervisor().prepare(
        session=Session.from_api(session_json),
        project=PROJECT,
        hivemind_binary=str(fake_cli.resolve()),
        timeout_seconds=60,
    )

    assert result.session_id == SESSION_ID
    assert result.is_subagent is False
    assert result.rejection_code == "atif_schema"
    assert result.certificate_payloads == ()
    assert result.canary_turn_facts == ()
    evidence = repr(result)
    assert "E2E_PRIVATE_TITLE" not in evidence
    assert "E2E_PRIVATE_PROMPT" not in evidence
    assert "E2E_PRIVATE_RESPONSE" not in evidence


def test_nominal_worker_response_is_rejected_if_descendant_survives(tmp_path: Path) -> None:
    pid_path = tmp_path / "child.pid"
    script = textwrap.dedent(
        f"""
        import json
        import os
        import subprocess
        import sys

        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
            ],
            close_fds=True,
        )
        with open({str(pid_path)!r}, "w", encoding="ascii") as stream:
            stream.write(str(child.pid))
        request = json.load(sys.stdin)
        session = request["session"]
        response = {{
            "protocol": request["protocol"],
            "importer_version": request["importer_version"],
            "nonce": request["nonce"],
            "status": "prepared",
            "project": request["project"],
            "session": {{
                "id": session["id"],
                "started_at": session["started_at"],
                "last_activity_at": session["last_activity_at"],
                "is_subagent": False,
            }},
            "certificates": [],
        }}
        os.write(int(sys.argv[1]), json.dumps(response).encode())
        """
    )
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script, str(result_fd)),
        termination_grace_seconds=0.05,
    )
    with pytest.raises(ReviewPreparationWorkerError, match="unexpected descendant"):
        supervisor.prepare(
            session=_session(),
            project=PROJECT,
            hivemind_binary="/usr/bin/true",
            timeout_seconds=5,
        )
    child_pid = int(pid_path.read_text())
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_inherited_result_pipe_is_generic_orphan_failure_not_timeout() -> None:
    script = textwrap.dedent(
        """
        import subprocess
        import sys

        result_fd = int(sys.argv[1])
        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            close_fds=True,
            pass_fds=(result_fd,),
        )
        """
    )
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script, str(result_fd)),
        termination_grace_seconds=0.05,
    )
    started = time.monotonic()
    with pytest.raises(ReviewPreparationWorkerError, match="result pipe") as captured:
        supervisor.prepare(
            session=_session(),
            project=PROJECT,
            hivemind_binary="/usr/bin/true",
            timeout_seconds=5,
        )
    assert not isinstance(captured.value, ReviewPreparationTimeout)
    assert time.monotonic() - started < 2


def test_supervisor_hard_timeout_reaps_worker() -> None:
    script = textwrap.dedent(
        """
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        """
    )
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script),
        termination_grace_seconds=0.05,
    )
    started = time.monotonic()
    with pytest.raises(ReviewPreparationTimeout, match="configured deadline"):
        supervisor.prepare(
            session=_session(),
            project=PROJECT,
            hivemind_binary="/usr/bin/true",
            timeout_seconds=0.1,
        )
    assert time.monotonic() - started < 2


def test_supervisor_rejects_oversized_private_response() -> None:
    script = "import os, sys; os.write(int(sys.argv[1]), b'x' * 1024)"
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script, str(result_fd)),
        max_response_bytes=32,
        termination_grace_seconds=0.05,
    )
    with pytest.raises(ReviewPreparationWorkerError, match="protocol bound"):
        supervisor.prepare(
            session=_session(),
            project=PROJECT,
            hivemind_binary="/usr/bin/true",
            timeout_seconds=5,
        )


def test_supervisor_keyboard_interrupt_cleans_up_and_reraises() -> None:
    script = textwrap.dedent(
        """
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        """
    )
    supervisor = ReviewPreparationSupervisor(
        command_factory=lambda result_fd: (sys.executable, "-c", script),
        termination_grace_seconds=0.05,
    )
    interrupt = threading.Timer(0.1, os.kill, args=(os.getpid(), signal.SIGINT))
    interrupt.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            supervisor.prepare(
                session=_session(),
                project=PROJECT,
                hivemind_binary="/usr/bin/true",
                timeout_seconds=5,
            )
    finally:
        interrupt.cancel()
        interrupt.join(timeout=1)


def test_cleanup_kills_group_when_leader_exited_with_live_child() -> None:
    grandchild = textwrap.dedent(
        """
        import os
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print(os.getpid(), flush=True)
        time.sleep(60)
        """
    )
    leader = textwrap.dedent(
        """
        import subprocess
        import sys

        child = subprocess.Popen(
            [sys.executable, "-c", sys.argv[1]],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert child.stdout is not None
        print(child.stdout.readline().strip(), flush=True)
        """
    )
    process = subprocess.Popen(
        [sys.executable, "-c", leader, grandchild],
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    child_pid = int(process.stdout.readline())
    process.wait(timeout=2)
    assert _process_group_exists(process.pid)

    _terminate_process_group(process, grace_seconds=0.05)

    deadline = time.monotonic() + 1
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _process_group_exists(process.pid)
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_cleanup_fails_closed_when_process_group_persists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 9_999_999

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    monkeypatch.setattr(worker_module.os, "killpg", lambda _pid, _signal: None)
    monkeypatch.setattr(worker_module, "_process_group_exists", lambda _pid: True)

    with pytest.raises(ReviewPreparationWorkerError, match="did not terminate cleanly"):
        _terminate_process_group(FakeProcess(), grace_seconds=0.01)  # type: ignore[arg-type]
