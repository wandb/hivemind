"""Read-only source-to-journal coverage audit for the review mirror."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import ATIFSchemaError, ReviewMirrorError
from .hivemind import HiveMindClient
from .models import Session
from .review import REVIEW_PROJECT, REVIEW_SETTLE_MINUTES, _validate_review_bound
from .review_state import (
    _valid_review_reference,
    review_logical_key,
    valid_review_span_id,
    valid_review_trace_id,
)
from .source_identity import is_opaque_source_coordinate
from .state import (
    _EXPECTED_SCHEMA_SQL,
    DB_APPLICATION_ID,
    DB_SCHEMA_VERSION,
    _normalize_sql,
)
from .utils import canonical_json, isoformat_z, parse_datetime

try:
    import fcntl
except ImportError:  # pragma: no cover - the importer targets macOS/Linux.
    fcntl = None  # type: ignore[assignment]

_ONE_YEAR = timedelta(days=365)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ATIF_V1 = re.compile(r"^ATIF-v1\.\d+$")
_SQLITE_HEADER = b"SQLite format 3\x00"
_MAX_JOURNAL_BYTES = 256 * 1024 * 1024
_READ_BLOCK_BYTES = 1024 * 1024


@dataclass(frozen=True, order=True)
class _Revision:
    session_id: str
    started_at: datetime
    last_activity_at: datetime


@dataclass(frozen=True)
class _SourceRevision:
    revision: _Revision
    is_subagent: bool


@dataclass(frozen=True)
class _Sweep:
    eligible: tuple[_SourceRevision, ...]
    deferred: tuple[_SourceRevision, ...]
    invalid_fingerprints: tuple[str, ...]

    @property
    def stable_certificate(self) -> tuple[object, ...]:
        return (self.eligible, self.deferred, self.invalid_fingerprints)


@dataclass(frozen=True)
class _JournalEvidence:
    completed: frozenset[_Revision]
    attempted: frozenset[_Revision]

    @classmethod
    def empty(cls) -> _JournalEvidence:
        return cls(completed=frozenset(), attempted=frozenset())

    @property
    def known_ids(self) -> frozenset[str]:
        return frozenset(item.session_id for item in self.attempted)

    def revisions_for(self, session_id: str) -> tuple[_Revision, ...]:
        return tuple(item for item in self.attempted if item.session_id == session_id)


@dataclass(frozen=True)
class AuditCounts:
    roots: int = 0
    subagents: int = 0
    unclassifiable: int = 0

    @property
    def total(self) -> int:
        return self.roots + self.subagents + self.unclassifiable


@dataclass(frozen=True)
class ReviewAuditConfig:
    since: str
    project: str
    state_path: Path
    until: str | None = None
    exclude_subagents: bool = False
    now: datetime | None = None


@dataclass(frozen=True)
class ReviewAuditReport:
    project: str
    since_utc: datetime
    until_utc: datetime
    settled_before: datetime
    completed_exact: AuditCounts
    planned_retry_exact: AuditCounts
    advanced_known_id: AuditCounts
    never_planned: AuditCounts
    deferred: AuditCounts
    invalid_unclassifiable: AuditCounts
    include_subagents: bool = True

    @property
    def eligible(self) -> int:
        return (
            self.completed_exact.total
            + self.planned_retry_exact.total
            + self.advanced_known_id.total
            + self.never_planned.total
        )

    @property
    def window_final(self) -> bool:
        return self.until_utc <= self.settled_before

    @property
    def ok(self) -> bool:
        return not (
            not self.window_final
            or self.deferred.total
            or self.planned_retry_exact.total
            or self.advanced_known_id.total
            or self.never_planned.total
            or self.invalid_unclassifiable.total
        )

    def render(self) -> str:
        rows = (
            ("completed exact", self.completed_exact),
            ("planned/retry exact", self.planned_retry_exact),
            ("advanced known ID", self.advanced_known_id),
            ("never planned", self.never_planned),
            ("deferred", self.deferred),
            ("invalid/unclassifiable", self.invalid_unclassifiable),
        )
        lines = [
            "Review coverage audit:",
            f"  project:              {self.project}",
            "  UTC window:           "
            f"[{isoformat_z(self.since_utc)}, {isoformat_z(self.until_utc)})",
            f"  settled through:      {isoformat_z(self.settled_before)}",
            f"  closed window final:  {'yes' if self.window_final else 'no'}",
            "  source scope:         supported 365-day feed",
            "  upstream limitation:  days predicate semantics undocumented",
            f"  subagents in scope:   {'yes' if self.include_subagents else 'no'}",
            "  source feed scans:    2 complete paginations, matching",
            "  category                 roots  subagents  unclassified  total",
        ]
        for label, counts in rows:
            lines.append(
                f"  {label:<24} {counts.roots:>6}  {counts.subagents:>9}  "
                f"{counts.unclassifiable:>12}  {counts.total:>5}"
            )
        lines.extend(
            [
                f"  eligible revisions:   {self.eligible}",
                f"  365-day feed coverage: {'COMPLETE' if self.ok else 'INCOMPLETE'}",
                "  unbounded source completeness: UNPROVEN",
            ]
        )
        return "\n".join(lines)


def _utc_bound(value: str, *, label: str) -> datetime:
    _validate_review_bound(value, label=label)
    parsed = parse_datetime(value)
    if parsed is None:  # pragma: no cover - guarded by _validate_review_bound.
        raise ValueError(f"{label} must be a valid RFC3339 timestamp")
    return parsed.astimezone(UTC)


def _resolve_window(config: ReviewAuditConfig) -> tuple[datetime, datetime, datetime]:
    if config.project != REVIEW_PROJECT:
        raise ValueError(f"review audit requires the fixed private project {REVIEW_PROJECT}")
    captured = (config.now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    since = _utc_bound(config.since, label="--since")
    until = captured if config.until is None else _utc_bound(config.until, label="--until")
    if until > captured:
        raise ValueError("--until cannot be in the future")
    if since >= until:
        raise ValueError("review audit requires --since earlier than --until")
    if until - since > _ONE_YEAR or since < captured - _ONE_YEAR:
        raise ValueError("review audit window must fit HiveMind's 365-day lookback")
    return since, until, captured


def _invalid_fingerprint(raw: dict[str, Any]) -> str:
    # This transient digest exists only to prove that two invalid source rows
    # are the same. It is never persisted or rendered.
    return hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()


def _source_revision(session: Session) -> _SourceRevision:
    if (
        not session.last_activity_known
        or session.started_at > session.last_activity_at
        or not is_opaque_source_coordinate(session.id)
        or (
            bool(session.parent_session_id)
            and not is_opaque_source_coordinate(session.parent_session_id)
        )
    ):
        raise ATIFSchemaError("source revision cannot be classified safely")
    return _SourceRevision(
        revision=_Revision(
            session_id=session.id,
            started_at=session.started_at.astimezone(UTC),
            last_activity_at=session.last_activity_at.astimezone(UTC),
        ),
        is_subagent=bool(session.parent_session_id),
    )


def _classify_sweep(
    raw_sessions: list[dict[str, Any]],
    *,
    since: datetime,
    until: datetime,
    settled_before: datetime,
    exclude_subagents: bool,
) -> _Sweep:
    parsed_by_id: dict[str, _SourceRevision] = {}
    invalid: list[str] = []
    for raw in raw_sessions:
        raw_activity = parse_datetime(raw.get("last_activity_at"))
        if raw_activity is not None and not (since <= raw_activity < until):
            continue
        try:
            source = _source_revision(Session.from_api(raw))
        except (ATIFSchemaError, TypeError, ValueError):
            invalid.append(_invalid_fingerprint(raw))
            continue
        if not (since <= source.revision.last_activity_at < until):
            continue
        if exclude_subagents and source.is_subagent:
            continue
        previous = parsed_by_id.get(source.revision.session_id)
        if previous is not None and previous != source:
            raise ReviewMirrorError(
                "review audit found inconsistent duplicate source summaries; "
                "no coverage verdict was produced"
            )
        parsed_by_id[source.revision.session_id] = source

    eligible: list[_SourceRevision] = []
    deferred: list[_SourceRevision] = []
    for source in parsed_by_id.values():
        if source.revision.last_activity_at > settled_before:
            deferred.append(source)
        else:
            eligible.append(source)

    def sort_key(item: _SourceRevision) -> tuple[datetime, str]:
        return item.revision.last_activity_at, item.revision.session_id

    return _Sweep(
        eligible=tuple(sorted(eligible, key=sort_key)),
        deferred=tuple(sorted(deferred, key=sort_key)),
        invalid_fingerprints=tuple(sorted(invalid)),
    )


def _count(items: list[_SourceRevision], *, unclassifiable: int = 0) -> AuditCounts:
    return AuditCounts(
        roots=sum(not item.is_subagent for item in items),
        subagents=sum(item.is_subagent for item in items),
        unclassifiable=unclassifiable,
    )


def _saved_revision(session_id: object, started: object, activity: object) -> _Revision:
    if not is_opaque_source_coordinate(session_id):
        raise ReviewMirrorError("review audit journal contains unsafe revision evidence")
    parsed_started = parse_datetime(started)
    parsed_activity = parse_datetime(activity)
    if (
        not isinstance(started, str)
        or not isinstance(activity, str)
        or parsed_started is None
        or parsed_activity is None
        or isoformat_z(parsed_started) != started
        or isoformat_z(parsed_activity) != activity
        or parsed_started > parsed_activity
    ):
        raise ReviewMirrorError("review audit journal contains malformed revision evidence")
    return _Revision(
        session_id=str(session_id),
        started_at=parsed_started,
        last_activity_at=parsed_activity,
    )


def _canonical_saved_time(value: object) -> datetime:
    parsed = parse_datetime(value)
    if not isinstance(value, str) or parsed is None or isoformat_z(parsed) != value:
        raise ReviewMirrorError("review audit journal has inconsistent completed-session evidence")
    return parsed


def _canonical_json_list(value: object) -> list[Any]:
    if not isinstance(value, str):
        raise ReviewMirrorError("review audit journal has inconsistent completed-session evidence")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ReviewMirrorError(
            "review audit journal has inconsistent completed-session evidence"
        ) from error
    if not isinstance(parsed, list) or canonical_json(parsed) != value:
        raise ReviewMirrorError("review audit journal has inconsistent completed-session evidence")
    return parsed


def _reference_name_contains_digest(reference: object, digest: object) -> bool:
    """Bind raw content hashes to deterministic object names, not ref versions.

    Weave object-version digests are independent from the SHA-256 of the raw
    object bytes. The publisher instead certifies that raw digest in the
    immutable object name before the reference is persisted.
    """
    if (
        not isinstance(reference, str)
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or not _valid_review_reference(reference)
    ):
        return False
    name = reference.rsplit("/", 1)[-1].rsplit(":", 1)[0]
    return digest in name


def _valid_turn_key(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 4_096 and "\x00" not in value


def _validate_completed_turn(row: sqlite3.Row) -> None:
    """Validate one current certificate and its reusable immutable visible row.

    A later appended-session plan may legitimately reuse an older visible row
    when the source turn hash is unchanged even if session-wide metadata made
    the current manifest, preview, or size certificate differ. Mirror the
    runtime's ``same_source_visible`` rule: both records must be internally
    complete, while their shared identity is project/session/turn, source hash,
    and deterministic logical key.
    """
    failure = "review audit journal has inconsistent completed-session evidence"
    session_id = row["session_id"]
    turn_key = row["turn_key"]
    planned_hashes = (
        row["source_payload_sha256"],
        row["manifest_sha256"],
        row["index_sha256"],
        row["logical_key"],
        row["preview_signature"],
    )
    if (
        not is_opaque_source_coordinate(session_id)
        or not _valid_turn_key(turn_key)
        or any(
            not isinstance(value, str) or not _SHA256.fullmatch(value) for value in planned_hashes
        )
    ):
        raise ReviewMirrorError(failure)
    expected_logical_key = review_logical_key(
        REVIEW_PROJECT,
        f"hivemind:{session_id}",
        turn_key,
    )
    planned_started = _canonical_saved_time(row["started_at"])
    planned_ended = _canonical_saved_time(row["ended_at"])
    if (
        row["logical_key"] != expected_logical_key
        or planned_started > planned_ended
        or type(row["manifest_bytes"]) is not int
        or int(row["manifest_bytes"]) <= 0
        or type(row["chunk_count"]) is not int
        or not 1 <= int(row["chunk_count"]) <= 64
        or type(row["max_chunk_bytes"]) is not int
        or not 1 <= int(row["max_chunk_bytes"]) <= 8 * 1024 * 1024
        or int(row["max_chunk_bytes"]) > int(row["manifest_bytes"])
        or type(row["index_bytes"]) is not int
        or int(row["index_bytes"]) <= 0
        or not isinstance(row["atif_schema_version"], str)
        or not _ATIF_V1.fullmatch(row["atif_schema_version"])
    ):
        raise ReviewMirrorError(failure)

    if (
        row["ledger_project"] != REVIEW_PROJECT
        or row["ledger_session_id"] != session_id
        or row["ledger_turn_key"] != turn_key
        or row["ledger_source_payload_sha256"] != row["source_payload_sha256"]
        or row["ledger_logical_key"] != expected_logical_key
        or row["ledger_status"] != "visible"
    ):
        raise ReviewMirrorError(failure)
    ledger_hashes = (
        row["ledger_source_payload_sha256"],
        row["ledger_manifest_sha256"],
        row["ledger_logical_key"],
        row["ledger_preview_signature"],
        row["ledger_index_sha256"],
    )
    if any(not isinstance(value, str) or not _SHA256.fullmatch(value) for value in ledger_hashes):
        raise ReviewMirrorError(failure)

    refs = _canonical_json_list(row["chunk_refs_json"])
    hashes = _canonical_json_list(row["chunk_hashes_json"])
    sizes = _canonical_json_list(row["chunk_sizes_json"])
    ledger_chunk_count = row["ledger_chunk_count"]
    ledger_manifest_bytes = row["ledger_manifest_bytes"]
    if (
        type(ledger_chunk_count) is not int
        or not 1 <= int(ledger_chunk_count) <= 64
        or type(ledger_manifest_bytes) is not int
        or int(ledger_manifest_bytes) <= 0
        or len(refs) != int(ledger_chunk_count)
        or len(hashes) != int(ledger_chunk_count)
        or len(sizes) != int(ledger_chunk_count)
        or not all(isinstance(ref, str) and _valid_review_reference(ref) for ref in refs)
        or not all(isinstance(digest, str) and _SHA256.fullmatch(digest) for digest in hashes)
        or not all(
            _reference_name_contains_digest(ref, digest)
            for ref, digest in zip(refs, hashes, strict=True)
        )
        or not all(type(size) is int and 0 < size <= 8 * 1024 * 1024 for size in sizes)
        or sum(sizes) != int(ledger_manifest_bytes)
    ):
        raise ReviewMirrorError(failure)

    index_ref = row["index_ref"]
    index_sha256 = row["ledger_index_sha256"]
    if (
        not isinstance(index_ref, str)
        or not _valid_review_reference(index_ref)
        or not isinstance(index_sha256, str)
        or not _SHA256.fullmatch(index_sha256)
        or not _reference_name_contains_digest(index_ref, index_sha256)
        or type(row["index_size"]) is not int
        or not 1 <= int(row["index_size"]) <= 8 * 1024 * 1024
        or not valid_review_trace_id(row["trace_id"])
        or not valid_review_span_id(row["root_span_id"])
        or row["error_code"] != ""
        or type(row["ledger_revision"]) is not int
        or int(row["ledger_revision"]) < 4
    ):
        raise ReviewMirrorError(failure)
    created_at = _canonical_saved_time(row["ledger_created_at"])
    updated_at = _canonical_saved_time(row["ledger_updated_at"])
    visible_at = _canonical_saved_time(row["visible_at"])
    if created_at > visible_at or visible_at > updated_at:
        raise ReviewMirrorError(failure)


class _ReadOnlyJournal:
    """Identity-pinned, lock-coordinated SQLite reader that cannot create files."""

    def __init__(self, path: Path) -> None:
        if fcntl is None:  # pragma: no cover - only unsupported platforms.
            raise ReviewMirrorError("review audit state locking is unavailable")
        expanded = path.expanduser()
        if ".." in expanded.parts:
            raise ReviewMirrorError("review audit state path is unsafe")
        self.path = Path(os.path.abspath(expanded))
        self._resources = ExitStack()
        self._directory_fd = -1
        self._lock_fd = -1
        self._database_fd = -1
        self._database_signature: tuple[int, ...] | None = None
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> _ReadOnlyJournal:
        try:
            self._open_parent()
            self._open_lock()
            self._database_fd = self._open_private_file(self.path.name, label="database")
            self._reject_uncheckpointed_sidecars()
            self._connection = self._connect()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        self._resources.close()

    def _open_parent(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(os.path.sep, flags)
        except OSError as error:
            raise ReviewMirrorError("review audit state ancestry is unsafe") from error
        self._resources.callback(os.close, directory_fd)
        allowed_owners = {0, os.geteuid()}
        for component in self.path.parent.parts[1:]:
            try:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
            except OSError as error:
                raise ReviewMirrorError("review audit state ancestry is unsafe") from error
            self._resources.callback(os.close, child_fd)
            try:
                parent_stat = os.fstat(directory_fd)
                child_stat = os.fstat(child_fd)
                path_stat = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise ReviewMirrorError("review audit state ancestry is unsafe") from error
            parent_writable = stat.S_IMODE(parent_stat.st_mode) & 0o022
            trusted_sticky = parent_stat.st_uid == 0 and bool(parent_stat.st_mode & stat.S_ISVTX)
            if (
                not stat.S_ISDIR(child_stat.st_mode)
                or parent_stat.st_uid not in allowed_owners
                or child_stat.st_uid not in allowed_owners
                or (parent_writable and not trusted_sticky)
                or (child_stat.st_dev, child_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
            ):
                raise ReviewMirrorError("review audit state ancestry is unsafe")
            directory_fd = child_fd
        try:
            final_stat = os.fstat(directory_fd)
        except OSError as error:
            raise ReviewMirrorError("review audit state ancestry is unsafe") from error
        if final_stat.st_uid != os.geteuid() or stat.S_IMODE(final_stat.st_mode) != 0o700:
            raise ReviewMirrorError("review audit state directory is not private")
        self._directory_fd = directory_fd

    def _open_private_file(self, name: str, *, label: str) -> int:
        # O_NONBLOCK must be present on the first open. Type validation happens
        # only after an fd exists, and opening an attacker-supplied FIFO for
        # reading without this flag can block before fstat gets a chance to
        # reject it.
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=self._directory_fd)
        except OSError as error:
            raise ReviewMirrorError(f"review audit state {label} is unavailable") from error
        self._resources.callback(os.close, descriptor)
        try:
            details = os.fstat(descriptor)
            path_details = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        except OSError as error:
            raise ReviewMirrorError(f"review audit state {label} is unavailable") from error
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
            or (details.st_dev, details.st_ino) != (path_details.st_dev, path_details.st_ino)
        ):
            raise ReviewMirrorError(f"review audit state {label} is unsafe")
        return descriptor

    def _open_lock(self) -> None:
        lock_fd = self._open_private_file(f"{self.path.name}.lock", label="lock")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReviewMirrorError(
                "review audit state is in use; retry after the importer exits"
            ) from error
        except OSError as error:
            raise ReviewMirrorError("review audit state lock is unavailable") from error
        self._lock_fd = lock_fd

    def _validate_lock_identity(self) -> None:
        try:
            details = os.fstat(self._lock_fd)
            path_details = os.stat(
                f"{self.path.name}.lock",
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ReviewMirrorError("review audit state lock changed during inspection") from error
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_nlink != 1
            or (details.st_dev, details.st_ino) != (path_details.st_dev, path_details.st_ino)
        ):
            raise ReviewMirrorError("review audit state lock changed during inspection")

    def _reject_uncheckpointed_sidecars(self) -> None:
        for suffix in ("-wal", "-journal"):
            name = f"{self.path.name}{suffix}"
            try:
                descriptor = self._open_private_file(name, label="sidecar")
            except ReviewMirrorError as error:
                try:
                    os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as probe_error:
                    raise ReviewMirrorError(
                        "review audit state sidecar is unavailable"
                    ) from probe_error
                raise error
            try:
                sidecar_size = os.fstat(descriptor).st_size
            except OSError as error:
                raise ReviewMirrorError("review audit state sidecar is unavailable") from error
            if sidecar_size:
                raise ReviewMirrorError(
                    "review audit state has uncheckpointed changes; retry after the importer exits"
                )
        shm_name = f"{self.path.name}-shm"
        try:
            self._open_private_file(shm_name, label="sidecar")
        except ReviewMirrorError as error:
            try:
                os.stat(shm_name, dir_fd=self._directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError as probe_error:
                raise ReviewMirrorError(
                    "review audit state sidecar is unavailable"
                ) from probe_error
            raise error

    def _validate_database_identity(self) -> None:
        try:
            details = os.fstat(self._database_fd)
            path_details = os.stat(
                self.path.name,
                dir_fd=self._directory_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ReviewMirrorError(
                "review audit state database changed during inspection"
            ) from error
        if (details.st_dev, details.st_ino) != (path_details.st_dev, path_details.st_ino):
            raise ReviewMirrorError("review audit state database changed during inspection")

    @staticmethod
    def _file_signature(details: os.stat_result) -> tuple[int, ...]:
        return (
            details.st_dev,
            details.st_ino,
            details.st_mode,
            details.st_uid,
            details.st_nlink,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )

    def _read_database_snapshot(self) -> bytearray:
        """Read exactly one bounded database image through the pinned fd."""
        self._validate_lock_identity()
        self._validate_database_identity()
        try:
            before = os.fstat(self._database_fd)
        except OSError as error:
            raise ReviewMirrorError(
                "review audit state database changed during inspection"
            ) from error
        if before.st_size <= 0 or before.st_size > _MAX_JOURNAL_BYTES:
            raise ReviewMirrorError("review audit state database size is unsafe")
        expected_signature = self._file_signature(before)
        snapshot = bytearray()
        offset = 0
        try:
            while offset < before.st_size:
                block = os.pread(
                    self._database_fd,
                    min(_READ_BLOCK_BYTES, before.st_size - offset),
                    offset,
                )
                if not block:
                    raise ReviewMirrorError("review audit state database changed during inspection")
                snapshot.extend(block)
                offset += len(block)
            after = os.fstat(self._database_fd)
        except ReviewMirrorError:
            raise
        except OSError as error:
            raise ReviewMirrorError(
                "review audit state database changed during inspection"
            ) from error
        self._validate_database_identity()
        if len(snapshot) != before.st_size or self._file_signature(after) != expected_signature:
            raise ReviewMirrorError("review audit state database changed during inspection")
        if (
            snapshot[: len(_SQLITE_HEADER)] != _SQLITE_HEADER
            or len(snapshot) < 20
            or snapshot[18] not in {1, 2}
            or snapshot[19] not in {1, 2}
        ):
            raise ReviewMirrorError("review audit state database could not be read safely")

        # The importer keeps its clean main file in WAL format even after a
        # successful checkpoint. Deserializing that header makes SQLite look
        # for a WAL path, so normalize only this private in-memory copy to the
        # equivalent rollback-mode header. The pinned source file is untouched.
        snapshot[18] = 1
        snapshot[19] = 1
        self._database_signature = expected_signature
        return snapshot

    @staticmethod
    def _zero_snapshot(snapshot: bytearray) -> None:
        zeros = b"\x00" * min(_READ_BLOCK_BYTES, len(snapshot))
        for offset in range(0, len(snapshot), _READ_BLOCK_BYTES):
            width = min(_READ_BLOCK_BYTES, len(snapshot) - offset)
            snapshot[offset : offset + width] = zeros[:width]
        snapshot.clear()

    def _validate_database_unchanged(self) -> None:
        self._validate_database_identity()
        if self._database_signature is None:
            raise ReviewMirrorError("review audit state database changed during inspection")
        try:
            current = os.fstat(self._database_fd)
        except OSError as error:
            raise ReviewMirrorError(
                "review audit state database changed during inspection"
            ) from error
        if self._file_signature(current) != self._database_signature:
            raise ReviewMirrorError("review audit state database changed during inspection")

    def _connect(self) -> sqlite3.Connection:
        snapshot = self._read_database_snapshot()
        try:
            connection = sqlite3.connect(":memory:")
            connection.deserialize(snapshot)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        except sqlite3.Error as error:
            if "connection" in locals():
                connection.close()
            raise ReviewMirrorError(
                "review audit state database could not be read safely"
            ) from error
        finally:
            self._zero_snapshot(snapshot)
        try:
            self._validate_database_unchanged()
            if application_id != DB_APPLICATION_ID or user_version != DB_SCHEMA_VERSION:
                raise ReviewMirrorError(
                    "review audit state schema is incompatible; audit never migrates state"
                )
            objects = {
                str(row["name"]): row
                for row in connection.execute(
                    """
                    SELECT type, name, tbl_name, sql
                    FROM sqlite_schema
                    WHERE name NOT LIKE 'sqlite_autoindex_%'
                      AND name NOT LIKE 'sqlite_%'
                    ORDER BY name
                    """
                ).fetchall()
            }
            if set(objects) != set(_EXPECTED_SCHEMA_SQL):
                raise ReviewMirrorError("review audit state schema contract is invalid")
            for name, expected_sql in _EXPECTED_SCHEMA_SQL.items():
                stored_sql = objects[name]["sql"]
                if not isinstance(stored_sql, str) or _normalize_sql(stored_sql) != _normalize_sql(
                    expected_sql
                ):
                    raise ReviewMirrorError("review audit state schema contract is invalid")
            if [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()] != [
                "ok"
            ]:
                raise ReviewMirrorError("review audit state integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ReviewMirrorError("review audit state integrity check failed")
        except ReviewMirrorError:
            connection.close()
            raise
        except sqlite3.Error as error:
            connection.close()
            raise ReviewMirrorError("review audit state integrity could not be verified") from error
        return connection

    def evidence(self) -> _JournalEvidence:
        if self._connection is None:  # pragma: no cover - guarded by __enter__.
            raise ReviewMirrorError("review audit state database is not open")
        try:
            session_rows = self._connection.execute(
                """
                SELECT session.session_id, session.started_at, session.last_activity_at,
                       session.status
                FROM review_plan_sessions AS session
                JOIN review_plans AS plan ON plan.plan_id = session.plan_id
                WHERE plan.project = ?
                """,
                (REVIEW_PROJECT,),
            ).fetchall()
            completed_rows = self._connection.execute(
                """
                SELECT session.plan_id, session.session_id, session.started_at,
                       session.last_activity_at
                FROM review_plan_sessions AS session
                JOIN review_plans AS plan ON plan.plan_id = session.plan_id
                WHERE plan.project = ? AND session.status = 'completed'
                  AND NOT EXISTS (
                      SELECT 1 FROM review_plan_retirements AS retired
                      WHERE retired.plan_id = plan.plan_id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM review_plan_revalidations AS revalidated
                      WHERE revalidated.plan_id = plan.plan_id
                  )
                """,
                (REVIEW_PROJECT,),
            ).fetchall()
            completed_turn_rows = self._connection.execute(
                """
                SELECT planned.plan_id, planned.session_id, planned.ordinal,
                       planned.turn_key, planned.source_payload_sha256,
                       planned.manifest_sha256, planned.index_sha256,
                       planned.logical_key, planned.preview_signature,
                       planned.started_at, planned.ended_at, planned.manifest_bytes,
                       planned.chunk_count, planned.max_chunk_bytes, planned.index_bytes,
                       planned.atif_schema_version,
                       ledger.project AS ledger_project,
                       ledger.session_id AS ledger_session_id,
                       ledger.turn_key AS ledger_turn_key,
                       ledger.source_payload_sha256 AS ledger_source_payload_sha256,
                       ledger.manifest_sha256 AS ledger_manifest_sha256,
                       ledger.logical_key AS ledger_logical_key,
                       ledger.preview_signature AS ledger_preview_signature,
                       ledger.manifest_bytes AS ledger_manifest_bytes,
                       ledger.chunk_count AS ledger_chunk_count,
                       ledger.status AS ledger_status,
                       ledger.chunk_refs_json, ledger.chunk_hashes_json,
                       ledger.chunk_sizes_json, ledger.index_ref,
                       ledger.index_sha256 AS ledger_index_sha256,
                       ledger.index_size, ledger.trace_id, ledger.root_span_id,
                       ledger.error_code, ledger.created_at AS ledger_created_at,
                       ledger.updated_at AS ledger_updated_at,
                       ledger.visible_at, ledger.revision AS ledger_revision
                FROM review_plan_sessions AS session
                JOIN review_plans AS plan ON plan.plan_id = session.plan_id
                JOIN review_plan_turns AS planned
                  ON planned.plan_id = session.plan_id
                 AND planned.session_id = session.session_id
                LEFT JOIN review_turn_ledger AS ledger
                  ON ledger.project = plan.project
                 AND ledger.session_id = planned.session_id
                 AND ledger.turn_key = planned.turn_key
                WHERE plan.project = ? AND session.status = 'completed'
                  AND NOT EXISTS (
                      SELECT 1 FROM review_plan_retirements AS retired
                      WHERE retired.plan_id = plan.plan_id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM review_plan_revalidations AS revalidated
                      WHERE revalidated.plan_id = plan.plan_id
                  )
                ORDER BY planned.plan_id, planned.session_id, planned.ordinal
                """,
                (REVIEW_PROJECT,),
            ).fetchall()
            retry_rows = self._connection.execute(
                """
                SELECT session_id, started_at, last_activity_at
                FROM review_preseal_failures
                WHERE project = ?
                """,
                (REVIEW_PROJECT,),
            ).fetchall()
        except sqlite3.Error as error:
            raise ReviewMirrorError("review audit journal evidence is unavailable") from error

        completed: set[_Revision] = set()
        attempted: set[_Revision] = set()
        for row in session_rows:
            revision = _saved_revision(
                row["session_id"], row["started_at"], row["last_activity_at"]
            )
            attempted.add(revision)
            status = str(row["status"])
            if status not in {"pending", "completed", "blocked"}:
                raise ReviewMirrorError("review audit journal contains malformed status evidence")
        turns_by_session: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in completed_turn_rows:
            key = (str(row["plan_id"]), str(row["session_id"]))
            turns_by_session.setdefault(key, []).append(row)
        for row in completed_rows:
            revision = _saved_revision(
                row["session_id"], row["started_at"], row["last_activity_at"]
            )
            plan_id = str(row["plan_id"])
            if not _SHA256.fullmatch(plan_id):
                raise ReviewMirrorError(
                    "review audit journal has inconsistent completed-session evidence"
                )
            turns = turns_by_session.get((plan_id, revision.session_id), [])
            for ordinal, turn in enumerate(turns):
                if type(turn["ordinal"]) is not int or turn["ordinal"] != ordinal:
                    raise ReviewMirrorError(
                        "review audit journal has inconsistent completed-session evidence"
                    )
                _validate_completed_turn(turn)
            completed.add(revision)
        for row in retry_rows:
            attempted.add(
                _saved_revision(row["session_id"], row["started_at"], row["last_activity_at"])
            )
        self._validate_lock_identity()
        self._validate_database_unchanged()
        self._reject_uncheckpointed_sidecars()
        self._validate_lock_identity()
        self._validate_database_unchanged()
        return _JournalEvidence(frozenset(completed), frozenset(attempted))


def _read_journal(path: Path) -> _JournalEvidence:
    expanded = path.expanduser()
    if ".." in expanded.parts or not expanded.name or expanded.name in {".", ".."}:
        raise ReviewMirrorError("review audit state path is unsafe")
    absolute = Path(os.path.abspath(expanded))
    try:
        absolute.lstat()
    except FileNotFoundError:
        return _JournalEvidence.empty()
    except OSError as error:
        raise ReviewMirrorError("review audit state path is unavailable") from error
    with _ReadOnlyJournal(absolute) as journal:
        return journal.evidence()


def audit_review(
    config: ReviewAuditConfig,
    *,
    hivemind: HiveMindClient | None = None,
) -> ReviewAuditReport:
    """Compare two stable source snapshots with exact local journal revisions."""
    since, until, captured = _resolve_window(config)
    settled_before = captured - timedelta(minutes=REVIEW_SETTLE_MINUTES)
    client = hivemind or HiveMindClient()
    client.preflight()
    sweeps = [
        _classify_sweep(
            client.list_sessions(days=365, include_subagents=True),
            since=since,
            until=until,
            settled_before=settled_before,
            exclude_subagents=config.exclude_subagents,
        )
        for _ in range(2)
    ]
    if sweeps[0].stable_certificate != sweeps[1].stable_certificate:
        raise ReviewMirrorError(
            "review audit source scans did not agree; no coverage verdict was produced"
        )
    sweep = sweeps[1]
    journal = _read_journal(config.state_path)

    completed: list[_SourceRevision] = []
    attempted: list[_SourceRevision] = []
    advanced: list[_SourceRevision] = []
    never: list[_SourceRevision] = []
    inconclusive = 0
    for source in sweep.eligible:
        revision = source.revision
        known_revisions = journal.revisions_for(revision.session_id)
        unsafe_known_revision = any(
            item.started_at != revision.started_at
            or item.last_activity_at > revision.last_activity_at
            for item in known_revisions
        )
        if unsafe_known_revision:
            # Never let an older exact record mask source regression or ID
            # reuse evidenced by another durable revision of the same ID.
            inconclusive += 1
        elif revision in journal.completed:
            completed.append(source)
        elif revision in journal.attempted:
            attempted.append(source)
        elif known_revisions:
            if all(revision.last_activity_at > item.last_activity_at for item in known_revisions):
                advanced.append(source)
            else:
                # An equal revision would have matched attempted above. Any
                # remaining non-increasing coordinate is not a safe append.
                inconclusive += 1
        else:
            never.append(source)

    return ReviewAuditReport(
        project=config.project,
        since_utc=since,
        until_utc=until,
        settled_before=settled_before,
        completed_exact=_count(completed),
        planned_retry_exact=_count(attempted),
        advanced_known_id=_count(advanced),
        never_planned=_count(never),
        deferred=_count(list(sweep.deferred)),
        invalid_unclassifiable=AuditCounts(
            unclassifiable=len(sweep.invalid_fingerprints) + inconclusive
        ),
        include_subagents=not config.exclude_subagents,
    )
