"""Hard process boundary for content-free review preparation certificates."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .errors import ReviewMirrorError
from .models import Session
from .review_manifest import (
    MAX_REVIEW_CHUNK_BYTES,
    MAX_REVIEW_CHUNKS,
    REVIEW_INDEX_SCHEMA,
    REVIEW_MANIFEST_SCHEMA,
    _chunk_name,
    _manifest_name,
)
from .review_state import REVIEW_PRESEAL_FAILURE_CODES, review_logical_key
from .source_identity import is_opaque_source_coordinate
from .utils import canonical_json, isoformat_z, parse_datetime

PREPARATION_WORKER_PROTOCOL = "hivemind-review-prepare-v1"
DEFAULT_SESSION_TIMEOUT_MINUTES = 15
MIN_SESSION_TIMEOUT_MINUTES = 1
MAX_SESSION_TIMEOUT_MINUTES = 60

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_IO_CHUNK_BYTES = 64 * 1024
_DEFAULT_TERMINATION_GRACE_SECONDS = 1.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ATIF_V1 = re.compile(r"^ATIF-v1\.\d+$")
_SAFE_LOCALE_ENV = frozenset({"LANG", "LC_ALL", "LC_CTYPE", "TZ"})
_CERTIFICATE_FIELDS = frozenset(
    {
        "session_id",
        "ordinal",
        "turn_key",
        "source_payload_sha256",
        "manifest_sha256",
        "index_sha256",
        "logical_key",
        "preview_signature",
        "started_at",
        "ended_at",
        "manifest_bytes",
        "chunk_count",
        "max_chunk_bytes",
        "index_bytes",
        "atif_schema_version",
    }
)
_WORKER_CERTIFICATE_FIELDS = _CERTIFICATE_FIELDS | {
    "worker_index_json",
    "worker_physical_span_count",
    "worker_mapping_warning_count",
}
_SESSION_FIELDS = frozenset(
    {
        "id",
        "agent_session_id",
        "title",
        "agent_type",
        "model",
        "started_at",
        "last_activity_at",
        "last_activity_known",
        "repository",
        "branch",
        "parent_session_id",
        "user",
    }
)
_SESSION_COORDINATE_FIELDS = frozenset({"id", "started_at", "last_activity_at", "is_subagent"})
# These two codes can only be established by the parent supervisor: the child
# does not own the wall clock or the bounded request serialization step.
_WORKER_REJECTION_CODES = REVIEW_PRESEAL_FAILURE_CODES - {
    "preparation_timeout",
    "source_serialization",
}


class ReviewPreparationWorkerError(ReviewMirrorError):
    """The isolated certificate worker returned no trustworthy evidence."""


class ReviewPreparationTimeout(ReviewPreparationWorkerError):
    """The isolated certificate worker exceeded its hard wall-clock budget."""


class ReviewPreparationSourceSerialization(ReviewPreparationWorkerError):
    """Parent-side source metadata could not cross the bounded private pipe."""


@dataclass(frozen=True)
class ReviewCanaryTurnFacts:
    """Content-free facts needed to enforce the canary turn constraints."""

    physical_span_count: int
    mapping_warning_count: int


@dataclass(frozen=True)
class ReviewPreparationResult:
    """Validated content-free output from one isolated preparation attempt."""

    session_id: str
    started_at: datetime
    last_activity_at: datetime
    certificate_payloads: tuple[dict[str, Any], ...] = ()
    canary_turn_facts: tuple[ReviewCanaryTurnFacts, ...] = ()
    is_subagent: bool = False
    rejection_code: str = ""


class ReviewPreparationSupervisor:
    """Spawn and supervise a fresh read-only worker for each source revision."""

    def __init__(
        self,
        *,
        command_factory: Callable[[int], Sequence[str]] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        termination_grace_seconds: float = _DEFAULT_TERMINATION_GRACE_SECONDS,
    ) -> None:
        self.command_factory = command_factory or _default_worker_command
        self.monotonic = monotonic
        self.max_response_bytes = max_response_bytes
        self.termination_grace_seconds = termination_grace_seconds
        if (
            type(self.max_response_bytes) is not int
            or not 1 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
            or self.termination_grace_seconds <= 0
        ):
            raise ValueError("review preparation worker bounds must be positive")

    def prepare(
        self,
        *,
        session: Session,
        project: str,
        hivemind_binary: str,
        timeout_seconds: float,
    ) -> ReviewPreparationResult:
        if timeout_seconds <= 0:
            raise ValueError("review session timeout must be positive")
        nonce = secrets.token_hex(32)
        request = _encode_request(
            nonce=nonce,
            project=project,
            hivemind_binary=hivemind_binary,
            session=session,
        )
        if len(request) > _MAX_REQUEST_BYTES:
            raise ReviewPreparationSourceSerialization(
                "review source metadata exceeded its private preparation bound"
            )
        try:
            response = self._exchange(request, timeout_seconds=timeout_seconds)
        except OSError as error:
            raise ReviewPreparationWorkerError(
                "review preparation worker could not start or exchange evidence"
            ) from error
        return _decode_response(
            response,
            expected_nonce=nonce,
            expected_project=project,
            expected_session=session,
        )

    def _exchange(self, request: bytes, *, timeout_seconds: float) -> bytes:
        if len(request) > _MAX_REQUEST_BYTES:
            raise ReviewPreparationWorkerError(
                "review preparation request exceeded its private protocol bound"
            )
        result_read_fd, result_write_fd = os.pipe()
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        request_offset = 0
        response = bytearray()
        result_open = True
        input_open = True
        try:
            process = subprocess.Popen(
                list(self.command_factory(result_write_fd)),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(result_write_fd,),
                start_new_session=True,
                env=_worker_environment(),
                bufsize=0,
            )
            os.close(result_write_fd)
            result_write_fd = -1
            if process.stdin is None:  # pragma: no cover - Popen contract.
                raise ReviewPreparationWorkerError(
                    "review preparation worker did not expose a private request pipe"
                )
            input_fd = process.stdin.fileno()
            os.set_blocking(input_fd, False)
            os.set_blocking(result_read_fd, False)
            selector.register(input_fd, selectors.EVENT_WRITE, "request")
            selector.register(result_read_fd, selectors.EVENT_READ, "result")
            deadline = self.monotonic() + timeout_seconds

            while True:
                if process.poll() is not None:
                    if not result_open:
                        break
                    # Every byte written by an exited leader is already
                    # readable. An open-but-empty pipe is therefore held by
                    # an untrusted descendant and is a generic worker failure,
                    # never durable timeout evidence.
                    try:
                        trailing = os.read(result_read_fd, _IO_CHUNK_BYTES)
                    except BlockingIOError as error:
                        raise ReviewPreparationWorkerError(
                            "review preparation worker left its result pipe open"
                        ) from error
                    if trailing:
                        response.extend(trailing)
                        if len(response) > self.max_response_bytes:
                            raise ReviewPreparationWorkerError(
                                "review preparation worker response exceeded its protocol bound"
                            )
                        continue
                    selector.unregister(result_read_fd)
                    os.close(result_read_fd)
                    result_read_fd = -1
                    result_open = False
                    break

                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    # Close the deadline race: only a leader observed alive at
                    # the deadline can author a timeout classification.
                    if process.poll() is not None:
                        continue
                    raise ReviewPreparationTimeout(
                        "review session preparation exceeded its configured deadline"
                    )
                for key, _events in selector.select(timeout=min(remaining, 0.1)):
                    if key.data == "request":
                        try:
                            written = os.write(input_fd, request[request_offset:])
                        except BrokenPipeError:
                            written = 0
                        except BlockingIOError:
                            continue
                        request_offset += written
                        if written == 0 or request_offset == len(request):
                            selector.unregister(input_fd)
                            process.stdin.close()
                            input_open = False
                    else:
                        try:
                            chunk = os.read(result_read_fd, _IO_CHUNK_BYTES)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(result_read_fd)
                            os.close(result_read_fd)
                            result_read_fd = -1
                            result_open = False
                            continue
                        response.extend(chunk)
                        if len(response) > self.max_response_bytes:
                            raise ReviewPreparationWorkerError(
                                "review preparation worker response exceeded its protocol bound"
                            )

            return_code = process.wait(timeout=0)
            if return_code != 0:
                raise ReviewPreparationWorkerError(
                    "review preparation worker exited without trustworthy evidence"
                )
            if _process_group_exists(process.pid):
                _terminate_process_group(
                    process,
                    grace_seconds=self.termination_grace_seconds,
                )
                raise ReviewPreparationWorkerError(
                    "review preparation worker left an unexpected descendant process"
                )
            return bytes(response)
        except BaseException:
            if process is not None:
                _terminate_process_group(
                    process,
                    grace_seconds=self.termination_grace_seconds,
                )
            raise
        finally:
            selector.close()
            if process is not None and input_open and process.stdin is not None:
                process.stdin.close()
            if result_read_fd >= 0:
                os.close(result_read_fd)
            if result_write_fd >= 0:
                os.close(result_write_fd)


def _default_worker_command(result_fd: int) -> Sequence[str]:
    return (
        sys.executable,
        "-m",
        "hivemind_weave._review_prepare_worker",
        "--result-fd",
        str(result_fd),
    )


def _worker_environment() -> dict[str, str]:
    """Construct a minimal environment with no destination or model credential."""
    account = pwd.getpwuid(os.geteuid())
    environment = {key: os.environ[key] for key in _SAFE_LOCALE_ENV if key in os.environ}
    environment.update(
        {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "PATH": ":".join(
                dict.fromkeys(
                    [
                        str(Path(sys.executable).resolve().parent),
                        "/usr/local/bin",
                        "/usr/bin",
                        "/bin",
                        "/usr/sbin",
                        "/sbin",
                    ]
                )
            ),
        }
    )
    return environment


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float,
) -> None:
    """Terminate all worker descendants and reap the worker before returning."""
    process_group_id = process.pid
    with suppress(ProcessLookupError):
        os.killpg(process_group_id, signal.SIGTERM)
    grace_deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process_group_id) and time.monotonic() < grace_deadline:
        process.poll()
        time.sleep(0.01)
    if _process_group_exists(process_group_id):
        with suppress(ProcessLookupError):
            os.killpg(process_group_id, signal.SIGKILL)
    # Reap the direct child even when its descendants held the private result
    # pipe open after the leader exited. Grandchildren are killed by group.
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as error:
        raise ReviewPreparationWorkerError(
            "review preparation worker could not be reaped after forced termination"
        ) from error
    disappearance_deadline = time.monotonic() + grace_seconds
    while _process_group_exists(process_group_id) and time.monotonic() < disappearance_deadline:
        time.sleep(0.01)
    if _process_group_exists(process_group_id):
        raise ReviewPreparationWorkerError(
            "review preparation worker process group did not terminate cleanly"
        )


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - the group is still live.
        return True
    return True


def _session_payload(session: Session) -> dict[str, Any]:
    return {
        "id": session.id,
        "agent_session_id": session.agent_session_id,
        "title": session.title,
        "agent_type": session.agent_type,
        "model": session.model,
        "started_at": isoformat_z(session.started_at),
        "last_activity_at": isoformat_z(session.last_activity_at),
        "last_activity_known": session.last_activity_known,
        "repository": session.repository,
        "branch": session.branch,
        "parent_session_id": session.parent_session_id,
        "user": session.user,
    }


def _decode_session(value: Any) -> Session:
    if not isinstance(value, Mapping) or set(value) != _SESSION_FIELDS:
        raise ReviewPreparationWorkerError(
            "review preparation worker session coordinate was malformed"
        )
    text_fields = _SESSION_FIELDS - {
        "started_at",
        "last_activity_at",
        "last_activity_known",
    }
    if any(not isinstance(value[field], str) for field in text_fields):
        raise ReviewPreparationWorkerError(
            "review preparation worker session coordinate was malformed"
        )
    started_at = parse_datetime(value["started_at"])
    last_activity_at = parse_datetime(value["last_activity_at"])
    if (
        started_at is None
        or last_activity_at is None
        or type(value["last_activity_known"]) is not bool
        or not is_opaque_source_coordinate(value["id"])
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker session coordinate was malformed"
        )
    return Session(
        id=value["id"],
        agent_session_id=value["agent_session_id"],
        title=value["title"],
        agent_type=value["agent_type"],
        model=value["model"],
        started_at=started_at,
        last_activity_at=last_activity_at,
        last_activity_known=value["last_activity_known"],
        repository=value["repository"],
        branch=value["branch"],
        parent_session_id=value["parent_session_id"],
        user=value["user"],
    )


def _encode_request(
    *,
    nonce: str,
    project: str,
    hivemind_binary: str,
    session: Session,
) -> bytes:
    if not _SHA256.fullmatch(nonce):
        raise ReviewPreparationWorkerError("review preparation request nonce was malformed")
    if not os.path.isabs(hivemind_binary) or "\x00" in hivemind_binary:
        raise ReviewPreparationWorkerError(
            "review preparation requires the resolved HiveMind executable"
        )
    try:
        encoded = canonical_json(
            {
                "protocol": PREPARATION_WORKER_PROTOCOL,
                "importer_version": __version__,
                "nonce": nonce,
                "project": project,
                "hivemind_binary": hivemind_binary,
                "session": _session_payload(session),
            }
        ).encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ReviewPreparationSourceSerialization(
            "review source metadata contained invalid Unicode"
        ) from error
    except (TypeError, ValueError) as error:
        raise ReviewPreparationWorkerError(
            "review preparation request could not be encoded safely"
        ) from error
    return encoded


def decode_worker_request(data: bytes) -> tuple[str, str, str, Session]:
    """Decode a private worker request without returning any transcript content."""
    if len(data) > _MAX_REQUEST_BYTES:
        raise ReviewPreparationWorkerError(
            "review preparation request exceeded its private protocol bound"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as error:
        raise ReviewPreparationWorkerError(
            "review preparation request was not canonical JSON"
        ) from error
    expected = {
        "protocol",
        "importer_version",
        "nonce",
        "project",
        "hivemind_binary",
        "session",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ReviewPreparationWorkerError("review preparation request shape was malformed")
    nonce = payload["nonce"]
    project = payload["project"]
    binary = payload["hivemind_binary"]
    if (
        payload["protocol"] != PREPARATION_WORKER_PROTOCOL
        or payload["importer_version"] != __version__
        or not isinstance(nonce, str)
        or not _SHA256.fullmatch(nonce)
        or not isinstance(project, str)
        or not project
        or not isinstance(binary, str)
        or not os.path.isabs(binary)
        or "\x00" in binary
    ):
        raise ReviewPreparationWorkerError("review preparation request identity was malformed")
    return nonce, project, binary, _decode_session(payload["session"])


def encode_worker_response(payload: Mapping[str, Any]) -> bytes:
    try:
        encoded = canonical_json(dict(payload)).encode("utf-8")
    except (UnicodeEncodeError, TypeError, ValueError) as error:
        raise ReviewPreparationWorkerError(
            "review preparation worker produced invalid Unicode"
        ) from error
    if len(encoded) > _MAX_RESPONSE_BYTES:
        raise ReviewPreparationWorkerError(
            "review preparation worker response exceeded its protocol bound"
        )
    return encoded


def _decode_response(
    data: bytes,
    *,
    expected_nonce: str,
    expected_project: str,
    expected_session: Session,
) -> ReviewPreparationResult:
    if len(data) > _MAX_RESPONSE_BYTES:
        raise ReviewPreparationWorkerError(
            "review preparation worker response exceeded its protocol bound"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError) as error:
        raise ReviewPreparationWorkerError(
            "review preparation worker returned invalid protocol evidence"
        ) from error
    common = {"protocol", "importer_version", "nonce", "status"}
    if not isinstance(payload, dict) or not common.issubset(payload):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed protocol evidence"
        )
    if (
        payload["protocol"] != PREPARATION_WORKER_PROTOCOL
        or payload["importer_version"] != __version__
        or payload["nonce"] != expected_nonce
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned mismatched protocol evidence"
        )
    if payload["status"] == "rejected":
        if set(payload) != common | {"error_code"} or payload["error_code"] not in (
            _WORKER_REJECTION_CODES
        ):
            raise ReviewPreparationWorkerError(
                "review preparation worker returned an unsupported rejection"
            )
        return ReviewPreparationResult(
            session_id=expected_session.id,
            started_at=expected_session.started_at,
            last_activity_at=expected_session.last_activity_at,
            rejection_code=payload["error_code"],
        )
    if payload["status"] != "prepared" or set(payload) != common | {
        "project",
        "session",
        "certificates",
    }:
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed protocol evidence"
        )
    if payload["project"] != expected_project:
        raise ReviewPreparationWorkerError(
            "review preparation worker returned mismatched project evidence"
        )
    coordinate = payload["session"]
    if not isinstance(coordinate, dict) or set(coordinate) != _SESSION_COORDINATE_FIELDS:
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed source coordinates"
        )
    observed_started_at = parse_datetime(coordinate["started_at"])
    observed_last_activity_at = parse_datetime(coordinate["last_activity_at"])
    if (
        coordinate["id"] != expected_session.id
        or observed_started_at != expected_session.started_at
        or observed_last_activity_at != expected_session.last_activity_at
        or type(coordinate["is_subagent"]) is not bool
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned mismatched source coordinates"
        )
    raw_certificates = payload["certificates"]
    if not isinstance(raw_certificates, list):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed certificate evidence"
        )
    certificates: list[dict[str, Any]] = []
    canary_turn_facts: list[ReviewCanaryTurnFacts] = []
    for ordinal, raw in enumerate(raw_certificates):
        if not isinstance(raw, dict) or set(raw) != _WORKER_CERTIFICATE_FIELDS:
            raise ReviewPreparationWorkerError(
                "review preparation worker returned malformed certificate evidence"
            )
        started_at = parse_datetime(raw["started_at"])
        ended_at = parse_datetime(raw["ended_at"])
        integer_fields = (
            "ordinal",
            "manifest_bytes",
            "chunk_count",
            "max_chunk_bytes",
            "index_bytes",
        )
        digest_fields = (
            "source_payload_sha256",
            "manifest_sha256",
            "index_sha256",
            "logical_key",
            "preview_signature",
        )
        if (
            raw["session_id"] != expected_session.id
            or raw["ordinal"] != ordinal
            or any(type(raw[field]) is not int for field in integer_fields)
            or any(
                not isinstance(raw[field], str) or not _SHA256.fullmatch(raw[field])
                for field in digest_fields
            )
            or not isinstance(raw["turn_key"], str)
            or not raw["turn_key"]
            or len(raw["turn_key"]) > 4_096
            or "\x00" in raw["turn_key"]
            or raw["logical_key"]
            != review_logical_key(
                expected_project,
                f"hivemind:{expected_session.id}",
                raw["turn_key"],
            )
            or started_at is None
            or ended_at is None
            or ended_at < started_at
            or raw["manifest_bytes"] <= 0
            or not 1 <= raw["chunk_count"] <= 64
            or not 1 <= raw["max_chunk_bytes"] <= 8 * 1024 * 1024
            or raw["index_bytes"] <= 0
            or not isinstance(raw["atif_schema_version"], str)
            or not _ATIF_V1.fullmatch(raw["atif_schema_version"])
        ):
            raise ReviewPreparationWorkerError(
                "review preparation worker returned invalid certificate evidence"
            )
        _validate_worker_index_evidence(raw)
        physical_span_count = raw["worker_physical_span_count"]
        mapping_warning_count = raw["worker_mapping_warning_count"]
        if (
            type(physical_span_count) is not int
            or not 1 <= physical_span_count <= 1_000_000
            or type(mapping_warning_count) is not int
            or not 0 <= mapping_warning_count <= 1_000_000
        ):
            raise ReviewPreparationWorkerError(
                "review preparation worker returned invalid canary evidence"
            )
        canary_turn_facts.append(
            ReviewCanaryTurnFacts(
                physical_span_count=physical_span_count,
                mapping_warning_count=mapping_warning_count,
            )
        )
        certificates.append(
            {
                **{key: raw[key] for key in _CERTIFICATE_FIELDS},
                "started_at": started_at,
                "ended_at": ended_at,
            }
        )
    return ReviewPreparationResult(
        session_id=expected_session.id,
        started_at=expected_session.started_at,
        last_activity_at=expected_session.last_activity_at,
        certificate_payloads=tuple(certificates),
        canary_turn_facts=tuple(canary_turn_facts),
        is_subagent=coordinate["is_subagent"],
    )


def _validate_worker_index_evidence(certificate: Mapping[str, Any]) -> None:
    index_json = certificate["worker_index_json"]
    if not isinstance(index_json, str):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed index evidence"
        )
    try:
        index_bytes = index_json.encode("utf-8", errors="strict")
        payload = json.loads(index_json)
        canonical_index = canonical_json(payload)
    except (UnicodeEncodeError, TypeError, ValueError) as error:
        raise ReviewPreparationWorkerError(
            "review preparation worker returned malformed index evidence"
        ) from error
    if (
        canonical_index != index_json
        or len(index_bytes) != certificate["index_bytes"]
        or hashlib.sha256(index_bytes).hexdigest() != certificate["index_sha256"]
        or not isinstance(payload, dict)
        or set(payload) != {"schema", "manifest", "chunking", "chunks"}
        or payload["schema"] != REVIEW_INDEX_SCHEMA
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned inconsistent index evidence"
        )
    manifest = payload["manifest"]
    chunking = payload["chunking"]
    chunks = payload["chunks"]
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema",
            "name",
            "sha256",
            "source_payload_sha256",
            "preview_signature",
            "byte_count",
            "media_type",
        }
        or manifest["schema"] != REVIEW_MANIFEST_SCHEMA
        or manifest["name"] != _manifest_name(certificate["manifest_sha256"])
        or manifest["sha256"] != certificate["manifest_sha256"]
        or manifest["source_payload_sha256"] != certificate["source_payload_sha256"]
        or manifest["preview_signature"] != certificate["preview_signature"]
        or manifest["byte_count"] != certificate["manifest_bytes"]
        or manifest["media_type"] != "application/json; charset=utf-8"
        or not isinstance(chunking, dict)
        or chunking
        != {
            "encoding": "utf-8",
            "max_chunk_bytes": MAX_REVIEW_CHUNK_BYTES,
            "max_chunks": MAX_REVIEW_CHUNKS,
            "chunk_count": certificate["chunk_count"],
        }
        or not isinstance(chunks, list)
        or len(chunks) != certificate["chunk_count"]
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned inconsistent index evidence"
        )
    chunk_sizes: list[int] = []
    for ordinal, chunk in enumerate(chunks):
        if (
            not isinstance(chunk, dict)
            or set(chunk) != {"index", "name", "sha256", "byte_count", "media_type"}
            or chunk["index"] != ordinal
            or not isinstance(chunk["sha256"], str)
            or not _SHA256.fullmatch(chunk["sha256"])
            or type(chunk["byte_count"]) is not int
            or not 1 <= chunk["byte_count"] <= MAX_REVIEW_CHUNK_BYTES
            or chunk["media_type"] != "text/plain; charset=utf-8"
        ):
            raise ReviewPreparationWorkerError(
                "review preparation worker returned inconsistent chunk evidence"
            )
        try:
            expected_name = _chunk_name(
                manifest_sha256=certificate["manifest_sha256"],
                chunk_sha256=chunk["sha256"],
                index=ordinal,
                chunk_count=len(chunks),
            )
        except ValueError as error:  # pragma: no cover - guarded by fixed digests/counts.
            raise ReviewPreparationWorkerError(
                "review preparation worker returned inconsistent chunk evidence"
            ) from error
        if chunk["name"] != expected_name:
            raise ReviewPreparationWorkerError(
                "review preparation worker returned inconsistent chunk evidence"
            )
        chunk_sizes.append(chunk["byte_count"])
    if (
        sum(chunk_sizes) != certificate["manifest_bytes"]
        or max(chunk_sizes) != certificate["max_chunk_bytes"]
        or any(size < MAX_REVIEW_CHUNK_BYTES - 3 for size in chunk_sizes[:-1])
    ):
        raise ReviewPreparationWorkerError(
            "review preparation worker returned inconsistent manifest-size evidence"
        )
