"""Secure, durable SQLite state for fixed-worklist imports and turn recovery."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from . import __version__
from .errors import StateConflictError, StateStoreError
from .utils import canonical_json, isoformat_z, parse_datetime, sha256_json

try:
    import fcntl
except ImportError:  # pragma: no cover - the importer targets macOS/Linux.
    fcntl = None  # type: ignore[assignment]


DB_APPLICATION_ID = 0x484D5756
DB_SCHEMA_VERSION = 2
RUN_SCHEMA_VERSION = "2"
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_SUCCESS_STATUSES = frozenset({"empty", "imported", "skipped"})
_SESSION_PROCESSABLE_STATUSES = frozenset({"certified", "failed", "conflict"})


@dataclass(frozen=True)
class StateRow:
    project: str
    session_id: str
    turn_key: str
    payload_sha256: str
    source_payload_sha256: str
    verification_signature: str
    status: str
    source_last_activity_at: str
    atif_schema_version: str
    trace_ids: list[str]
    root_span_ids: list[str]
    span_count: int
    last_error: str
    revision: int


@dataclass(frozen=True)
class ImportRun:
    run_id: str
    project: str
    cutoff: datetime
    days: int
    idle_minutes: int
    config: dict[str, Any]
    config_sha256: str
    importer_version: str
    schema_version: str
    status: str
    phase: str
    session_count: int
    discovered_count: int
    deferred_count: int
    total_turn_count: int
    turn_manifest_sha256: str
    revision: int


@dataclass(frozen=True)
class ImportRunSession:
    run_id: str
    ordinal: int
    session_id: str
    summary_last_activity_at: datetime
    status: str
    turn_count: int
    turn_set_sha256: str
    last_error: str
    revision: int


@dataclass(frozen=True)
class ImportRunTurn:
    run_id: str
    session_id: str
    ordinal: int
    turn_key: str
    source_payload_sha256: str


_IMPORTED_TURNS_SQL = """
CREATE TABLE imported_turns (
    project TEXT NOT NULL,
    session_id TEXT NOT NULL,
    turn_key TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL DEFAULT '',
    verification_signature TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'committed', 'conflict')),
    source_last_activity_at TEXT NOT NULL,
    atif_schema_version TEXT NOT NULL,
    trace_ids_json TEXT NOT NULL DEFAULT '[]',
    root_span_ids_json TEXT NOT NULL DEFAULT '[]',
    span_count INTEGER NOT NULL DEFAULT 0 CHECK(span_count >= 0),
    importer_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    imported_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (project, session_id, turn_key)
)
"""

_IMPORT_RUNS_SQL = """
CREATE TABLE import_runs (
    run_id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    cutoff TEXT NOT NULL,
    days INTEGER NOT NULL CHECK(days BETWEEN 1 AND 365),
    idle_minutes INTEGER NOT NULL CHECK(idle_minutes >= 0),
    config_json TEXT NOT NULL,
    config_sha256 TEXT NOT NULL,
    importer_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'completed')),
    phase TEXT NOT NULL CHECK(phase IN ('certifying', 'ready', 'completed')),
    session_count INTEGER NOT NULL CHECK(session_count > 0),
    discovered_count INTEGER NOT NULL CHECK(discovered_count >= session_count),
    deferred_count INTEGER NOT NULL CHECK(deferred_count >= 0),
    manifest_sha256 TEXT NOT NULL,
    total_turn_count INTEGER NOT NULL DEFAULT 0 CHECK(total_turn_count >= 0),
    turn_manifest_sha256 TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    certified_at TEXT,
    completed_at TEXT,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    CHECK(
        (status = 'active' AND phase IN ('certifying', 'ready') AND completed_at IS NULL)
        OR (status = 'completed' AND phase = 'completed' AND completed_at IS NOT NULL)
    )
)
"""

_IMPORT_RUN_SESSIONS_SQL = """
CREATE TABLE import_run_sessions (
    run_id TEXT NOT NULL REFERENCES import_runs(run_id),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    session_id TEXT NOT NULL,
    summary_last_activity_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(
        status IN (
            'uncertified', 'certified', 'empty', 'imported', 'skipped', 'failed', 'conflict'
        )
    ),
    turn_count INTEGER NOT NULL DEFAULT -1 CHECK(turn_count >= -1),
    turn_set_sha256 TEXT NOT NULL DEFAULT '',
    certified_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
    PRIMARY KEY (run_id, session_id),
    UNIQUE (run_id, ordinal),
    CHECK(
        (turn_count = -1 AND turn_set_sha256 = '' AND certified_at IS NULL)
        OR (turn_count >= 0 AND length(turn_set_sha256) = 64 AND certified_at IS NOT NULL)
    )
)
"""

_IMPORT_RUN_TURNS_SQL = """
CREATE TABLE import_run_turns (
    run_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    turn_key TEXT NOT NULL,
    source_payload_sha256 TEXT NOT NULL CHECK(length(source_payload_sha256) = 64),
    PRIMARY KEY (run_id, session_id, turn_key),
    UNIQUE (run_id, session_id, ordinal),
    FOREIGN KEY (run_id, session_id)
        REFERENCES import_run_sessions(run_id, session_id)
)
"""

_RUN_INDEX_SQL = """
CREATE INDEX import_runs_project_status ON import_runs(project, status)
"""

_ACTIVE_RUN_INDEX_SQL = """
CREATE UNIQUE INDEX import_runs_one_active_project
ON import_runs(project) WHERE status = 'active'
"""

_RUN_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_runs_immutable
BEFORE UPDATE OF
    run_id, project, cutoff, days, idle_minutes, config_json, config_sha256,
    importer_version, schema_version, session_count, discovered_count,
    deferred_count, manifest_sha256
ON import_runs
BEGIN
    SELECT RAISE(ABORT, 'import run manifest is immutable');
END
"""

_RUN_REVISION_TRIGGER_SQL = """
CREATE TRIGGER import_runs_revision_guard
BEFORE UPDATE ON import_runs
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'import run revision was not advanced');
END
"""

_SESSION_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_immutable
BEFORE UPDATE OF run_id, ordinal, session_id, summary_last_activity_at
ON import_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'import run session manifest is immutable');
END
"""

_SESSION_CERTIFICATE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_certificate_immutable
BEFORE UPDATE OF turn_count, turn_set_sha256, certified_at
ON import_run_sessions
WHEN OLD.certified_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'import run session certificate is immutable');
END
"""

_SESSION_REVISION_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_revision_guard
BEFORE UPDATE ON import_run_sessions
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'import run session revision was not advanced');
END
"""

_SESSION_SUCCESS_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_success_guard
BEFORE UPDATE OF status ON import_run_sessions
WHEN NEW.status IN ('empty', 'imported', 'skipped') AND (
    NEW.certified_at IS NULL
    OR NEW.turn_count < 0
    OR (NEW.status = 'empty' AND NEW.turn_count != 0)
    OR (
        NEW.status IN ('imported', 'skipped') AND (
            NEW.turn_count = 0
            OR (
                SELECT COUNT(*)
                FROM import_run_turns AS certified_turn
                WHERE certified_turn.run_id = NEW.run_id
                  AND certified_turn.session_id = NEW.session_id
            ) != NEW.turn_count
            OR EXISTS (
                SELECT 1
                FROM import_run_turns AS run_turn
                JOIN import_runs AS run ON run.run_id = run_turn.run_id
                LEFT JOIN imported_turns AS turn
                  ON turn.project = run.project
                 AND turn.session_id = run_turn.session_id
                 AND turn.turn_key = run_turn.turn_key
                 AND turn.source_payload_sha256 = run_turn.source_payload_sha256
                 AND turn.status = 'committed'
                WHERE run_turn.run_id = NEW.run_id
                  AND run_turn.session_id = NEW.session_id
                  AND turn.turn_key IS NULL
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'successful session status lacks certified turn evidence');
END
"""

_SESSION_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER import_run_sessions_no_delete
BEFORE DELETE ON import_run_sessions
BEGIN
    SELECT RAISE(ABORT, 'import run session manifest is immutable');
END
"""

_RUN_TURNS_IMMUTABLE_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_immutable
BEFORE UPDATE ON import_run_turns
BEGIN
    SELECT RAISE(ABORT, 'import run turn certificate is immutable');
END
"""

_RUN_TURNS_INSERT_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_insert_guard
BEFORE INSERT ON import_run_turns
WHEN NOT EXISTS (
    SELECT 1
    FROM import_run_sessions AS session
    JOIN import_runs AS run ON run.run_id = session.run_id
    WHERE session.run_id = NEW.run_id
      AND session.session_id = NEW.session_id
      AND session.status IN ('uncertified', 'failed')
      AND session.turn_count = -1
      AND run.status = 'active'
      AND run.phase = 'certifying'
)
BEGIN
    SELECT RAISE(ABORT, 'run turns can only be added during session certification');
END
"""

_RUN_TURNS_NO_DELETE_TRIGGER_SQL = """
CREATE TRIGGER import_run_turns_no_delete
BEFORE DELETE ON import_run_turns
BEGIN
    SELECT RAISE(ABORT, 'import run turn certificate is immutable');
END
"""

_TURN_REVISION_TRIGGER_SQL = """
CREATE TRIGGER imported_turns_revision_guard
BEFORE UPDATE ON imported_turns
WHEN NEW.revision != OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'imported turn revision was not advanced');
END
"""

_SCHEMA_SQL = (
    _IMPORTED_TURNS_SQL,
    _IMPORT_RUNS_SQL,
    _IMPORT_RUN_SESSIONS_SQL,
    _IMPORT_RUN_TURNS_SQL,
    _RUN_INDEX_SQL,
    _ACTIVE_RUN_INDEX_SQL,
    _RUN_IMMUTABLE_TRIGGER_SQL,
    _RUN_REVISION_TRIGGER_SQL,
    _SESSION_IMMUTABLE_TRIGGER_SQL,
    _SESSION_CERTIFICATE_TRIGGER_SQL,
    _SESSION_REVISION_TRIGGER_SQL,
    _SESSION_SUCCESS_TRIGGER_SQL,
    _SESSION_NO_DELETE_TRIGGER_SQL,
    _RUN_TURNS_IMMUTABLE_TRIGGER_SQL,
    _RUN_TURNS_INSERT_TRIGGER_SQL,
    _RUN_TURNS_NO_DELETE_TRIGGER_SQL,
    _TURN_REVISION_TRIGGER_SQL,
)

_EXPECTED_SCHEMA_SQL = {
    "imported_turns": _IMPORTED_TURNS_SQL,
    "import_runs": _IMPORT_RUNS_SQL,
    "import_run_sessions": _IMPORT_RUN_SESSIONS_SQL,
    "import_run_turns": _IMPORT_RUN_TURNS_SQL,
    "import_runs_project_status": _RUN_INDEX_SQL,
    "import_runs_one_active_project": _ACTIVE_RUN_INDEX_SQL,
    "import_runs_immutable": _RUN_IMMUTABLE_TRIGGER_SQL,
    "import_runs_revision_guard": _RUN_REVISION_TRIGGER_SQL,
    "import_run_sessions_immutable": _SESSION_IMMUTABLE_TRIGGER_SQL,
    "import_run_sessions_certificate_immutable": _SESSION_CERTIFICATE_TRIGGER_SQL,
    "import_run_sessions_revision_guard": _SESSION_REVISION_TRIGGER_SQL,
    "import_run_sessions_success_guard": _SESSION_SUCCESS_TRIGGER_SQL,
    "import_run_sessions_no_delete": _SESSION_NO_DELETE_TRIGGER_SQL,
    "import_run_turns_immutable": _RUN_TURNS_IMMUTABLE_TRIGGER_SQL,
    "import_run_turns_insert_guard": _RUN_TURNS_INSERT_TRIGGER_SQL,
    "import_run_turns_no_delete": _RUN_TURNS_NO_DELETE_TRIGGER_SQL,
    "imported_turns_revision_guard": _TURN_REVISION_TRIGGER_SQL,
}


def _normalize_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split()).lower()


def _canonical_config(config: dict[str, Any]) -> tuple[str, str]:
    config_json = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return config_json, sha256_json(config)


def _session_certificate(turns: list[tuple[str, str]]) -> str:
    return sha256_json(
        [
            {"ordinal": ordinal, "turn_key": turn_key, "source_payload_sha256": source_hash}
            for ordinal, (turn_key, source_hash) in enumerate(turns)
        ]
    )


def _manifest_payload(
    *,
    run_id: str,
    project: str,
    cutoff: datetime,
    days: int,
    idle_minutes: int,
    config_sha256: str,
    importer_version: str,
    schema_version: str,
    discovered_count: int,
    deferred_count: int,
    sessions: list[tuple[str, datetime]],
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "project": project,
        "cutoff": isoformat_z(cutoff),
        "days": days,
        "idle_minutes": idle_minutes,
        "config_sha256": config_sha256,
        "importer_version": importer_version,
        "schema_version": schema_version,
        "discovered_count": discovered_count,
        "deferred_count": deferred_count,
        "sessions": [
            {
                "ordinal": ordinal,
                "session_id": session_id,
                "summary_last_activity_at": isoformat_z(activity),
            }
            for ordinal, (session_id, activity) in enumerate(sessions)
        ],
    }


class StateStore:
    """One-process state store with a private, immutable recovery manifest."""

    def __init__(self, path: Path) -> None:
        if fcntl is None:  # pragma: no cover - only unsupported platforms.
            raise StateStoreError("local state locking is unavailable on this platform")
        expanded = path.expanduser()
        if ".." in expanded.parts:
            raise StateConflictError("state path cannot contain parent-directory traversal")
        self.path = Path(os.path.abspath(expanded))
        if not self.path.name or self.path.name in {".", ".."}:
            raise StateConflictError("state path must name a database file")
        self.resource_stack = ExitStack()
        self.connection: sqlite3.Connection | None = None
        self._closed = False
        previous_umask = os.umask(0o077)
        try:
            self._open_private_parent()
            self._open_and_lock()
            self._secure_database_files(create_database=True)
            self.connection = self._connect_database()
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            journal_mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise StateStoreError("local state database did not enable WAL journaling")
            self._migrate_and_validate()
            self._secure_database_files(create_database=False)
        except Exception:
            if self.connection is not None:
                self.connection.close()
            self.resource_stack.close()
            raise
        finally:
            os.umask(previous_umask)

    @property
    def _db(self) -> sqlite3.Connection:
        if self.connection is None:
            raise StateStoreError("local state database is not open")
        return self.connection

    def _open_private_parent(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(os.path.sep, flags)
        except OSError as error:
            raise StateConflictError("state directory could not be opened safely") from error
        directory_fds = [directory_fd]
        directory_chain: list[tuple[int, str, int]] = []
        try:
            for component in self.path.parent.parts[1:]:
                while True:
                    try:
                        next_fd = os.open(component, flags, dir_fd=directory_fd)
                    except FileNotFoundError:
                        try:
                            os.mkdir(component, 0o700, dir_fd=directory_fd)
                        except FileExistsError:
                            continue
                        except OSError as error:
                            raise StateConflictError(
                                "state directory could not be created safely"
                            ) from error
                        continue
                    except OSError as error:
                        raise StateConflictError(
                            "state directory could not be opened safely"
                        ) from error
                    directory_chain.append((directory_fd, component, next_fd))
                    directory_fds.append(next_fd)
                    directory_fd = next_fd
                    break
        except Exception:
            for opened_fd in reversed(directory_fds):
                os.close(opened_fd)
            raise
        for opened_fd in directory_fds:
            self.resource_stack.callback(os.close, opened_fd)
        self._directory_chain = tuple(directory_chain)
        self.directory_fd = directory_fd
        self._secure_fd(directory_fd, directory=True, mode=0o700, label="state directory")
        self._validate_directory_chain()

    def _validate_directory_chain(self) -> None:
        """Prove the absolute state path still resolves through every pinned directory."""
        allowed_owners = {0, os.geteuid()}
        for parent_fd, component, child_fd in self._directory_chain:
            try:
                parent_details = os.fstat(parent_fd)
                child_details = os.fstat(child_fd)
                path_details = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise StateConflictError(
                    "state directory ancestry identity could not be validated"
                ) from error
            if not stat.S_ISDIR(parent_details.st_mode) or not stat.S_ISDIR(
                child_details.st_mode
            ):
                raise StateConflictError("state directory ancestry has an unsafe file type")
            if (
                parent_details.st_uid not in allowed_owners
                or child_details.st_uid not in allowed_owners
            ):
                raise StateConflictError("state directory ancestry has an unsafe owner")
            parent_writable = stat.S_IMODE(parent_details.st_mode) & 0o022
            trusted_sticky_parent = parent_details.st_uid == 0 and bool(
                parent_details.st_mode & stat.S_ISVTX
            )
            if parent_writable and not trusted_sticky_parent:
                raise StateConflictError("state directory ancestry has unsafe permissions")
            if (child_details.st_dev, child_details.st_ino) != (
                path_details.st_dev,
                path_details.st_ino,
            ):
                raise StateConflictError("state directory changed while it was opened")

    def _connect_database(self) -> sqlite3.Connection:
        """Connect only while holding an identity-pinned database descriptor."""
        self._validate_directory_chain()
        database_fd = self._open_regular_at(
            self.path.name,
            create=False,
            label="state database file",
        )
        try:
            self._secure_fd(
                database_fd,
                directory=False,
                mode=0o600,
                label="state database file",
            )
            self._validate_fd_path_identity(
                database_fd,
                self.path.name,
                label="state database file",
            )
            self._validate_directory_chain()
            connection = sqlite3.connect(self.path)
            self._validate_directory_chain()
            self._validate_fd_path_identity(
                database_fd,
                self.path.name,
                label="state database file",
            )
            return connection
        except Exception:
            if "connection" in locals():
                connection.close()
            raise
        finally:
            os.close(database_fd)

    def _secure_fd(self, fd: int, *, directory: bool, mode: int, label: str) -> os.stat_result:
        try:
            details = os.fstat(fd)
            expected_type = (
                stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode)
            )
            if not expected_type or details.st_uid != os.geteuid():
                raise StateConflictError(f"{label} has an unsafe owner or file type")
            if not directory and details.st_nlink != 1:
                raise StateConflictError(f"{label} must not be hard-linked")
            os.fchmod(fd, mode)
            secured = os.fstat(fd)
        except OSError as error:
            raise StateConflictError(f"{label} permissions could not be secured") from error
        if stat.S_IMODE(secured.st_mode) != mode:
            raise StateConflictError(f"{label} permissions are not private")
        return secured

    def _open_regular_at(self, name: str, *, create: bool, label: str) -> int:
        base_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        while True:
            self._validate_directory_chain()
            try:
                fd = os.open(name, base_flags, dir_fd=self.directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    fd = os.open(
                        name,
                        base_flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=self.directory_fd,
                    )
                except FileExistsError:
                    continue
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise StateConflictError(f"{label} must not be a symlink") from error
                raise StateConflictError(f"{label} could not be opened safely") from error
            try:
                self._validate_directory_chain()
            except Exception:
                os.close(fd)
                raise
            return fd

    def _validate_fd_path_identity(self, fd: int, name: str, *, label: str) -> None:
        self._validate_directory_chain()
        try:
            fd_stat = os.fstat(fd)
            path_stat = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
        except OSError as error:
            raise StateConflictError(f"{label} identity could not be validated") from error
        if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise StateConflictError(f"{label} changed while it was opened")
        self._validate_directory_chain()

    def _open_and_lock(self) -> None:
        lock_name = f"{self.path.name}.lock"
        lock_fd = self._open_regular_at(lock_name, create=True, label="state lock file")
        try:
            self._secure_fd(lock_fd, directory=False, mode=0o600, label="state lock file")
            self._validate_fd_path_identity(lock_fd, lock_name, label="state lock file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(lock_fd)
            raise StateConflictError(
                f"another importer is using state database {self.path}"
            ) from error
        except Exception:
            os.close(lock_fd)
            raise
        self.lock_file: IO[str] = os.fdopen(lock_fd, "a+", encoding="utf-8")
        self.resource_stack.enter_context(self.lock_file)

    def _secure_database_files(self, *, create_database: bool) -> None:
        self._validate_directory_chain()
        names = [
            self.path.name,
            f"{self.path.name}-wal",
            f"{self.path.name}-shm",
            f"{self.path.name}-journal",
        ]
        for index, name in enumerate(names):
            try:
                fd = self._open_regular_at(
                    name,
                    create=create_database and index == 0,
                    label="state database file" if index == 0 else "state database sidecar",
                )
            except FileNotFoundError:
                continue
            try:
                label = "state database file" if index == 0 else "state database sidecar"
                self._secure_fd(fd, directory=False, mode=0o600, label=label)
                self._validate_fd_path_identity(fd, name, label=label)
            finally:
                os.close(fd)
        self._validate_directory_chain()

    def _schema_objects(self) -> dict[str, sqlite3.Row]:
        rows = self._db.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_autoindex_%'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        return {str(row["name"]): row for row in rows}

    def _migrate_and_validate(self) -> None:
        user_version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(self._db.execute("PRAGMA application_id").fetchone()[0])
        if user_version > DB_SCHEMA_VERSION:
            raise StateConflictError("state database schema is newer than this importer")
        if application_id not in {0, DB_APPLICATION_ID}:
            raise StateConflictError("state database belongs to a different application")
        try:
            self._db.execute("BEGIN IMMEDIATE")
            if user_version == DB_SCHEMA_VERSION:
                if application_id != DB_APPLICATION_ID:
                    raise StateConflictError("state database application identity is missing")
            elif user_version == 0 and application_id == 0:
                self._migrate_unversioned()
                self._db.execute(f"PRAGMA application_id={DB_APPLICATION_ID}")
                self._db.execute(f"PRAGMA user_version={DB_SCHEMA_VERSION}")
            else:
                raise StateConflictError("state database schema version is incompatible")
            self._validate_schema_contract()
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _migrate_unversioned(self) -> None:
        objects = self._schema_objects()
        if not objects:
            for statement in _SCHEMA_SQL:
                self._db.execute(statement)
            return
        if "imported_turns" not in objects or objects["imported_turns"]["type"] != "table":
            raise StateConflictError("unversioned state database has an unknown schema")
        allowed_old_names = {
            "imported_turns",
            "import_runs",
            "import_run_sessions",
            "import_runs_project_status",
            "import_runs_immutable",
            "import_run_sessions_immutable",
            "import_run_sessions_no_delete",
        }
        if not set(objects).issubset(allowed_old_names):
            raise StateConflictError("unversioned state database has unexpected schema objects")
        imported_columns = [
            str(row["name"])
            for row in self._db.execute("PRAGMA table_info(imported_turns)").fetchall()
        ]
        required = [
            "project",
            "session_id",
            "turn_key",
            "payload_sha256",
            "verification_signature",
            "status",
            "source_last_activity_at",
            "atif_schema_version",
            "trace_ids_json",
            "root_span_ids_json",
            "span_count",
            "importer_version",
            "created_at",
            "updated_at",
            "imported_at",
            "last_error",
        ]
        if any(column not in imported_columns for column in required):
            raise StateConflictError("legacy imported-turn journal has an unknown schema")
        if set(objects) != {"imported_turns"}:
            if "import_runs" not in objects or "import_run_sessions" not in objects:
                raise StateConflictError("unversioned run-manifest migration was incomplete")
            active = int(
                self._db.execute(
                    "SELECT COUNT(*) FROM import_runs WHERE status = 'active'"
                ).fetchone()[0]
            )
            if active:
                raise StateConflictError(
                    "unfinished legacy run lacks certified turns and cannot be resumed safely"
                )
            for trigger in (
                "import_run_sessions_no_delete",
                "import_run_sessions_immutable",
                "import_runs_immutable",
            ):
                if trigger in objects:
                    self._db.execute(f"DROP TRIGGER {trigger}")
            if "import_runs_project_status" in objects:
                self._db.execute("DROP INDEX import_runs_project_status")
            self._db.execute("DROP TABLE import_run_sessions")
            self._db.execute("DROP TABLE import_runs")

        self._db.execute("ALTER TABLE imported_turns RENAME TO imported_turns_legacy")
        self._db.execute(_IMPORTED_TURNS_SQL)
        source_expression = (
            "source_payload_sha256" if "source_payload_sha256" in imported_columns else "''"
        )
        revision_expression = "revision" if "revision" in imported_columns else "0"
        self._db.execute(
            f"""
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at, atif_schema_version,
                trace_ids_json, root_span_ids_json, span_count, importer_version, created_at,
                updated_at, imported_at, last_error, revision
            )
            SELECT
                project, session_id, turn_key, payload_sha256, {source_expression},
                verification_signature, status, source_last_activity_at, atif_schema_version,
                trace_ids_json, root_span_ids_json, span_count, importer_version, created_at,
                updated_at, imported_at, last_error, {revision_expression}
            FROM imported_turns_legacy
            """
        )
        self._db.execute("DROP TABLE imported_turns_legacy")
        for statement in _SCHEMA_SQL[1:]:
            self._db.execute(statement)

    def _validate_schema_contract(self) -> None:
        objects = self._schema_objects()
        if set(objects) != set(_EXPECTED_SCHEMA_SQL):
            raise StateConflictError("state database schema objects do not match the importer")
        for name, expected_sql in _EXPECTED_SCHEMA_SQL.items():
            stored_sql = objects[name]["sql"]
            if not isinstance(stored_sql, str) or _normalize_sql(stored_sql) != _normalize_sql(
                expected_sql
            ):
                raise StateConflictError(f"state database object {name} has an invalid contract")
        index_columns = [
            str(row["name"])
            for row in self._db.execute("PRAGMA index_info(import_runs_project_status)").fetchall()
        ]
        if index_columns != ["project", "status"]:
            raise StateConflictError("state database run index has an invalid contract")
        foreign_keys = self._db.execute("PRAGMA foreign_key_list(import_run_turns)").fetchall()
        if len(foreign_keys) != 2 or {
            (str(row["from"]), str(row["to"])) for row in foreign_keys
        } != {("run_id", "run_id"), ("session_id", "session_id")}:
            raise StateConflictError("state database run-turn foreign key is invalid")
        quick_check = self._db.execute("PRAGMA quick_check").fetchall()
        if [str(row[0]) for row in quick_check] != ["ok"]:
            raise StateConflictError("state database integrity check failed")
        if self._db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StateConflictError("state database foreign-key check failed")

    def _after_write(self) -> None:
        self._db.commit()
        self._secure_database_files(create_database=False)

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        try:
            self._secure_database_files(create_database=False)
        except Exception as error:
            failure = error
        try:
            self._db.close()
        finally:
            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                self.resource_stack.close()
                self._closed = True
        if failure is not None:
            raise failure

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _state_row(self, row: sqlite3.Row) -> StateRow:
        try:
            trace_ids = json.loads(row["trace_ids_json"])
            root_span_ids = json.loads(row["root_span_ids_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise StateConflictError("saved turn evidence is malformed") from error
        if not isinstance(trace_ids, list) or not all(isinstance(item, str) for item in trace_ids):
            raise StateConflictError("saved turn trace IDs are malformed")
        if not isinstance(root_span_ids, list) or not all(
            isinstance(item, str) for item in root_span_ids
        ):
            raise StateConflictError("saved turn root-span IDs are malformed")
        return StateRow(
            project=str(row["project"]),
            session_id=str(row["session_id"]),
            turn_key=str(row["turn_key"]),
            payload_sha256=str(row["payload_sha256"]),
            source_payload_sha256=str(row["source_payload_sha256"]),
            verification_signature=str(row["verification_signature"]),
            status=str(row["status"]),
            source_last_activity_at=str(row["source_last_activity_at"]),
            atif_schema_version=str(row["atif_schema_version"]),
            trace_ids=trace_ids,
            root_span_ids=root_span_ids,
            span_count=int(row["span_count"]),
            last_error=str(row["last_error"]),
            revision=int(row["revision"]),
        )

    def get(self, project: str, session_id: str, turn_key: str) -> StateRow | None:
        row = self._db.execute(
            """
            SELECT * FROM imported_turns
            WHERE project = ? AND session_id = ? AND turn_key = ?
            """,
            (project, session_id, turn_key),
        ).fetchone()
        return None if row is None else self._state_row(row)

    def _validated_run(self, row: sqlite3.Row) -> ImportRun:
        try:
            parsed_config = json.loads(row["config_json"])
            cutoff = parse_datetime(row["cutoff"])
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise StateConflictError("saved import run metadata is malformed") from error
        if not isinstance(parsed_config, dict) or cutoff is None:
            raise StateConflictError("saved import run metadata is malformed")
        config_json, config_sha256 = _canonical_config(parsed_config)
        if config_json != row["config_json"] or config_sha256 != row["config_sha256"]:
            raise StateConflictError("saved import run configuration failed its integrity check")
        if row["schema_version"] != RUN_SCHEMA_VERSION:
            raise StateConflictError(
                "unfinished import run uses an incompatible state schema version"
            )
        if row["importer_version"] != __version__:
            raise StateConflictError("unfinished import run uses an incompatible importer version")
        session_rows = self._db.execute(
            """
            SELECT *
            FROM import_run_sessions WHERE run_id = ? ORDER BY ordinal ASC
            """,
            (row["run_id"],),
        ).fetchall()
        if len(session_rows) != int(row["session_count"]):
            raise StateConflictError("saved import run session manifest is incomplete")
        sessions: list[tuple[str, datetime]] = []
        for expected_ordinal, session_row in enumerate(session_rows):
            activity = parse_datetime(session_row["summary_last_activity_at"])
            if int(session_row["ordinal"]) != expected_ordinal or activity is None:
                raise StateConflictError("saved import run session manifest is malformed")
            sessions.append((str(session_row["session_id"]), activity))
        manifest = _manifest_payload(
            run_id=str(row["run_id"]),
            project=str(row["project"]),
            cutoff=cutoff,
            days=int(row["days"]),
            idle_minutes=int(row["idle_minutes"]),
            config_sha256=config_sha256,
            importer_version=str(row["importer_version"]),
            schema_version=str(row["schema_version"]),
            discovered_count=int(row["discovered_count"]),
            deferred_count=int(row["deferred_count"]),
            sessions=sessions,
        )
        if sha256_json(manifest) != row["manifest_sha256"]:
            raise StateConflictError("saved import run manifest failed its integrity check")
        phase = str(row["phase"])
        if phase == "certifying":
            if (
                int(row["total_turn_count"]) != 0
                or str(row["turn_manifest_sha256"])
                or row["certified_at"] is not None
            ):
                raise StateConflictError("unsealed import run has unexpected turn evidence")
        else:
            turn_count, turn_manifest_sha256 = self._calculate_turn_manifest(
                str(row["run_id"]),
                session_rows,
            )
            if (
                turn_count != int(row["total_turn_count"])
                or turn_manifest_sha256 != str(row["turn_manifest_sha256"])
                or row["certified_at"] is None
            ):
                raise StateConflictError(
                    "saved import run turn certificate failed its integrity check"
                )
        return ImportRun(
            run_id=str(row["run_id"]),
            project=str(row["project"]),
            cutoff=cutoff,
            days=int(row["days"]),
            idle_minutes=int(row["idle_minutes"]),
            config=parsed_config,
            config_sha256=config_sha256,
            importer_version=str(row["importer_version"]),
            schema_version=str(row["schema_version"]),
            status=str(row["status"]),
            phase=phase,
            session_count=int(row["session_count"]),
            discovered_count=int(row["discovered_count"]),
            deferred_count=int(row["deferred_count"]),
            total_turn_count=int(row["total_turn_count"]),
            turn_manifest_sha256=str(row["turn_manifest_sha256"]),
            revision=int(row["revision"]),
        )

    def find_resumable_run(self, *, project: str, config: dict[str, Any]) -> ImportRun | None:
        rows = self._db.execute(
            """
            SELECT * FROM import_runs
            WHERE project = ? AND status = 'active' ORDER BY created_at ASC
            """,
            (project,),
        ).fetchall()
        if len(rows) > 1:
            raise StateConflictError(
                "multiple unfinished import runs exist for this project in the state database"
            )
        if not rows:
            return None
        run = self._validated_run(rows[0])
        _config_json, expected_hash = _canonical_config(config)
        if run.config_sha256 != expected_hash:
            raise StateConflictError(
                "unfinished import run configuration does not match this invocation"
            )
        return run

    def create_run(
        self,
        *,
        project: str,
        cutoff: datetime,
        days: int,
        idle_minutes: int,
        config: dict[str, Any],
        sessions: list[tuple[str, datetime]],
        discovered_count: int,
        deferred_count: int,
    ) -> ImportRun:
        if not sessions or len({session_id for session_id, _ in sessions}) != len(sessions):
            raise StateConflictError("import run requires unique eligible session IDs")
        run_id = uuid.uuid4().hex
        config_json, config_sha256 = _canonical_config(config)
        manifest = _manifest_payload(
            run_id=run_id,
            project=project,
            cutoff=cutoff,
            days=days,
            idle_minutes=idle_minutes,
            config_sha256=config_sha256,
            importer_version=__version__,
            schema_version=RUN_SCHEMA_VERSION,
            discovered_count=discovered_count,
            deferred_count=deferred_count,
            sessions=sessions,
        )
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            if self._db.execute(
                "SELECT 1 FROM import_runs WHERE project = ? AND status = 'active' LIMIT 1",
                (project,),
            ).fetchone():
                raise StateConflictError("an unfinished import run appeared during discovery")
            self._db.execute(
                """
                INSERT INTO import_runs (
                    run_id, project, cutoff, days, idle_minutes, config_json, config_sha256,
                    importer_version, schema_version, status, phase, session_count,
                    discovered_count, deferred_count, manifest_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'certifying', ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    project,
                    isoformat_z(cutoff),
                    days,
                    idle_minutes,
                    config_json,
                    config_sha256,
                    __version__,
                    RUN_SCHEMA_VERSION,
                    len(sessions),
                    discovered_count,
                    deferred_count,
                    sha256_json(manifest),
                    now,
                    now,
                ),
            )
            self._db.executemany(
                """
                INSERT INTO import_run_sessions (
                    run_id, ordinal, session_id, summary_last_activity_at,
                    status, updated_at
                ) VALUES (?, ?, ?, ?, 'uncertified', ?)
                """,
                [
                    (run_id, ordinal, session_id, isoformat_z(activity), now)
                    for ordinal, (session_id, activity) in enumerate(sessions)
                ],
            )
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute("SELECT * FROM import_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:  # pragma: no cover - guarded by committed insert.
            raise StateConflictError("created import run disappeared from local state")
        return self._validated_run(row)

    def _session_row(self, row: sqlite3.Row) -> ImportRunSession:
        activity = parse_datetime(row["summary_last_activity_at"])
        if activity is None:
            raise StateConflictError("saved import run activity timestamp is malformed")
        return ImportRunSession(
            run_id=str(row["run_id"]),
            ordinal=int(row["ordinal"]),
            session_id=str(row["session_id"]),
            summary_last_activity_at=activity,
            status=str(row["status"]),
            turn_count=int(row["turn_count"]),
            turn_set_sha256=str(row["turn_set_sha256"]),
            last_error=str(row["last_error"]),
            revision=int(row["revision"]),
        )

    def get_run_sessions(self, run_id: str) -> list[ImportRunSession]:
        run_row = self._db.execute(
            "SELECT * FROM import_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run_row is None:
            raise StateConflictError("saved import run no longer exists")
        self._validated_run(run_row)
        return [
            self._session_row(row)
            for row in self._db.execute(
                "SELECT * FROM import_run_sessions WHERE run_id = ? ORDER BY ordinal ASC",
                (run_id,),
            ).fetchall()
        ]

    def get_run_turns(self, run_id: str, session_id: str) -> list[ImportRunTurn]:
        return [
            ImportRunTurn(
                run_id=str(row["run_id"]),
                session_id=str(row["session_id"]),
                ordinal=int(row["ordinal"]),
                turn_key=str(row["turn_key"]),
                source_payload_sha256=str(row["source_payload_sha256"]),
            )
            for row in self._db.execute(
                """
                SELECT * FROM import_run_turns
                WHERE run_id = ? AND session_id = ? ORDER BY ordinal ASC
                """,
                (run_id, session_id),
            ).fetchall()
        ]

    @staticmethod
    def turn_set_certificate(turns: list[tuple[str, str]]) -> str:
        return _session_certificate(turns)

    def certify_run_session(
        self,
        *,
        run_id: str,
        session_id: str,
        expected_revision: int,
        turns: list[tuple[str, str]],
    ) -> ImportRunSession:
        if len({turn_key for turn_key, _ in turns}) != len(turns) or any(
            not turn_key or not _HEX_SHA256.fullmatch(source_hash)
            for turn_key, source_hash in turns
        ):
            raise StateConflictError("session turn certificate is malformed")
        certificate = _session_certificate(turns)
        now = isoformat_z(datetime.now(UTC))
        try:
            self._db.execute("BEGIN IMMEDIATE")
            current = self._db.execute(
                """
                SELECT session.*
                FROM import_run_sessions AS session
                JOIN import_runs AS run ON run.run_id = session.run_id
                WHERE session.run_id = ? AND session.session_id = ?
                  AND session.revision = ?
                  AND session.status IN ('uncertified', 'failed')
                  AND session.turn_count = -1
                  AND run.status = 'active' AND run.phase = 'certifying'
                """,
                (run_id, session_id, expected_revision),
            ).fetchone()
            if current is None:
                raise StateConflictError("session certification state changed unexpectedly")
            self._db.executemany(
                """
                INSERT INTO import_run_turns (
                    run_id, session_id, ordinal, turn_key, source_payload_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (run_id, session_id, ordinal, turn_key, source_hash)
                    for ordinal, (turn_key, source_hash) in enumerate(turns)
                ],
            )
            cursor = self._db.execute(
                """
                UPDATE import_run_sessions
                SET status = 'certified', turn_count = ?, turn_set_sha256 = ?,
                    certified_at = ?, attempts = attempts + 1, last_error = '',
                    updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND session_id = ? AND revision = ?
                  AND status IN ('uncertified', 'failed') AND turn_count = -1
                """,
                (
                    len(turns),
                    certificate,
                    now,
                    now,
                    run_id,
                    session_id,
                    expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("session certification state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (run_id, session_id),
        ).fetchone()
        if row is None:  # pragma: no cover
            raise StateConflictError("certified session disappeared from local state")
        return self._session_row(row)

    def record_uncertified_error(
        self,
        *,
        run_id: str,
        session_id: str,
        expected_revision: int,
        error: str,
    ) -> ImportRunSession:
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = 'failed', attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ?
              AND status IN ('uncertified', 'failed') AND turn_count = -1
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active' AND phase = 'certifying'
              )
            """,
            (
                error[:500],
                isoformat_z(datetime.now(UTC)),
                run_id,
                session_id,
                expected_revision,
                run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("uncertified session state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (run_id, session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def certificate_matches(
        self,
        entry: ImportRunSession,
        turns: list[tuple[str, str]],
    ) -> bool:
        saved = self.get_run_turns(entry.run_id, entry.session_id)
        expected = [(item.turn_key, item.source_payload_sha256) for item in saved]
        return (
            entry.turn_count == len(turns)
            and entry.turn_set_sha256 == _session_certificate(turns)
            and expected == turns
        )

    def restore_certified_session(
        self,
        *,
        entry: ImportRunSession,
    ) -> ImportRunSession:
        if entry.turn_count < 0 or not entry.turn_set_sha256:
            raise StateConflictError("uncertified session cannot be restored")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = 'certified', attempts = attempts + 1, last_error = '',
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ?
              AND status IN ('failed', 'conflict')
              AND turn_set_sha256 = ? AND turn_count = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active'
              )
            """,
            (
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.turn_set_sha256,
                entry.turn_count,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session recovery state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def seal_run(self, run: ImportRun) -> ImportRun:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            sessions = self._db.execute(
                """
                SELECT * FROM import_run_sessions
                WHERE run_id = ? ORDER BY ordinal ASC
                """,
                (run.run_id,),
            ).fetchall()
            if len(sessions) != run.session_count or any(
                row["status"] != "certified" or int(row["turn_count"]) < 0 for row in sessions
            ):
                raise StateConflictError("run cannot be sealed before every session is certified")
            total, manifest_hash = self._calculate_turn_manifest(run.run_id, sessions)
            now = isoformat_z(datetime.now(UTC))
            cursor = self._db.execute(
                """
                UPDATE import_runs
                SET phase = 'ready', total_turn_count = ?, turn_manifest_sha256 = ?,
                    certified_at = ?, updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status = 'active' AND phase = 'certifying'
                  AND revision = ? AND turn_manifest_sha256 = ''
                """,
                (total, manifest_hash, now, now, run.run_id, run.revision),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("run sealing state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise
        row = self._db.execute(
            "SELECT * FROM import_runs WHERE run_id = ?", (run.run_id,)
        ).fetchone()
        assert row is not None
        return self._validated_run(row)

    def _calculate_turn_manifest(
        self,
        run_id: str,
        sessions: list[sqlite3.Row],
    ) -> tuple[int, str]:
        """Stream the exact certified turn manifest without retaining all turns."""
        session_contract = {
            str(row["session_id"]): (int(row["ordinal"]), int(row["turn_count"]))
            for row in sessions
        }
        expected_total = sum(turn_count for _ordinal, turn_count in session_contract.values())
        observed_counts = {session_id: 0 for session_id in session_contract}
        digest = hashlib.sha256()
        digest.update(b"[")
        observed_total = 0
        turn_rows = self._db.execute(
            """
            SELECT session.ordinal AS session_ordinal, turn.ordinal AS turn_ordinal,
                   turn.session_id, turn.turn_key, turn.source_payload_sha256
            FROM import_run_sessions AS session
            JOIN import_run_turns AS turn
              ON turn.run_id = session.run_id AND turn.session_id = session.session_id
            WHERE session.run_id = ?
            ORDER BY session.ordinal ASC, turn.ordinal ASC
            """,
            (run_id,),
        )
        for row in turn_rows:
            session_id = str(row["session_id"])
            contract = session_contract.get(session_id)
            turn_ordinal = int(row["turn_ordinal"])
            if (
                contract is None
                or int(row["session_ordinal"]) != contract[0]
                or turn_ordinal != observed_counts[session_id]
            ):
                raise StateConflictError("run turn certificate ordering is malformed")
            payload = {
                "session_ordinal": contract[0],
                "turn_ordinal": turn_ordinal,
                "session_id": session_id,
                "turn_key": str(row["turn_key"]),
                "source_payload_sha256": str(row["source_payload_sha256"]),
            }
            if observed_total:
                digest.update(b",")
            digest.update(canonical_json(payload).encode("utf-8"))
            observed_counts[session_id] += 1
            observed_total += 1
        digest.update(b"]")
        if observed_total != expected_total or any(
            observed_counts[session_id] != turn_count
            for session_id, (_ordinal, turn_count) in session_contract.items()
        ):
            raise StateConflictError("run turn certificate is incomplete")
        return observed_total, digest.hexdigest()

    def mark_run_session_terminal(
        self,
        *,
        entry: ImportRunSession,
        status: str,
        error: str = "",
    ) -> ImportRunSession:
        if status not in {"empty", "imported", "skipped"}:
            raise ValueError(f"invalid terminal session status: {status}")
        if entry.status not in _SESSION_PROCESSABLE_STATUSES:
            raise StateConflictError("session terminal transition started from an invalid status")
        if entry.turn_count < 0 or not _HEX_SHA256.fullmatch(entry.turn_set_sha256):
            raise StateConflictError("session terminal transition lacks a turn certificate")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = ?, attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ? AND status = ?
              AND turn_count = ? AND turn_set_sha256 = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active' AND phase = 'ready'
              )
            """,
            (
                status,
                error[:500],
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.status,
                entry.turn_count,
                entry.turn_set_sha256,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session terminal state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def mark_run_session_issue(
        self,
        *,
        entry: ImportRunSession,
        status: str,
        error: str,
    ) -> ImportRunSession:
        if status not in {"failed", "conflict"}:
            raise ValueError(f"invalid session issue status: {status}")
        if entry.status not in _SESSION_PROCESSABLE_STATUSES:
            raise StateConflictError("session issue transition started from an invalid status")
        if entry.turn_count < 0 or not _HEX_SHA256.fullmatch(entry.turn_set_sha256):
            raise StateConflictError("session issue transition lacks a turn certificate")
        cursor = self._db.execute(
            """
            UPDATE import_run_sessions
            SET status = ?, attempts = attempts + 1, last_error = ?,
                updated_at = ?, revision = revision + 1
            WHERE run_id = ? AND session_id = ? AND revision = ? AND status = ?
              AND turn_count = ? AND turn_set_sha256 = ?
              AND EXISTS (
                  SELECT 1 FROM import_runs
                  WHERE run_id = ? AND status = 'active'
              )
            """,
            (
                status,
                error[:500],
                isoformat_z(datetime.now(UTC)),
                entry.run_id,
                entry.session_id,
                entry.revision,
                entry.status,
                entry.turn_count,
                entry.turn_set_sha256,
                entry.run_id,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("session issue state changed unexpectedly")
        self._after_write()
        row = self._db.execute(
            "SELECT * FROM import_run_sessions WHERE run_id = ? AND session_id = ?",
            (entry.run_id, entry.session_id),
        ).fetchone()
        assert row is not None
        return self._session_row(row)

    def complete_run(self, run: ImportRun) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
            status_rows = self._db.execute(
                """
                SELECT status, COUNT(*) AS count FROM import_run_sessions
                WHERE run_id = ? GROUP BY status
                """,
                (run.run_id,),
            ).fetchall()
            status_counts = {str(row["status"]): int(row["count"]) for row in status_rows}
            if sum(status_counts.values()) != run.session_count or any(
                status not in _RUN_SUCCESS_STATUSES for status in status_counts
            ):
                raise StateConflictError(
                    "import run cannot complete while session work is pending or unsuccessful"
                )
            session_rows = self._db.execute(
                """
                SELECT * FROM import_run_sessions
                WHERE run_id = ? ORDER BY ordinal ASC
                """,
                (run.run_id,),
            ).fetchall()
            total_turn_count, turn_manifest_sha256 = self._calculate_turn_manifest(
                run.run_id,
                session_rows,
            )
            if (
                total_turn_count != run.total_turn_count
                or turn_manifest_sha256 != run.turn_manifest_sha256
            ):
                raise StateConflictError("certified run turn manifest changed before completion")
            unresolved = int(
                self._db.execute(
                    """
                    SELECT COUNT(*)
                    FROM import_run_turns AS run_turn
                    LEFT JOIN imported_turns AS turn
                      ON turn.project = ?
                     AND turn.session_id = run_turn.session_id
                     AND turn.turn_key = run_turn.turn_key
                     AND turn.source_payload_sha256 = run_turn.source_payload_sha256
                     AND turn.status = 'committed'
                    WHERE run_turn.run_id = ? AND turn.turn_key IS NULL
                    """,
                    (run.project, run.run_id),
                ).fetchone()[0]
            )
            if unresolved:
                raise StateConflictError(
                    "import run cannot complete while certified turns are unresolved"
                )
            now = isoformat_z(datetime.now(UTC))
            cursor = self._db.execute(
                """
                UPDATE import_runs
                SET status = 'completed', phase = 'completed', completed_at = ?,
                    updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status = 'active' AND phase = 'ready'
                  AND revision = ? AND turn_manifest_sha256 != ''
                """,
                (now, now, run.run_id, run.revision),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("saved import run completion state changed unexpectedly")
            self._after_write()
        except Exception:
            self._db.rollback()
            raise

    def begin_pending(
        self,
        *,
        run_id: str,
        project: str,
        session_id: str,
        turn_key: str,
        payload_sha256: str,
        verification_signature: str,
        source_last_activity_at: datetime,
        atif_schema_version: str,
    ) -> StateRow:
        now = isoformat_z(datetime.now(UTC))
        cursor = self._db.execute(
            """
            INSERT INTO imported_turns (
                project, session_id, turn_key, payload_sha256, source_payload_sha256,
                verification_signature, status, source_last_activity_at,
                atif_schema_version, importer_version, created_at, updated_at
            )
            SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?
            FROM import_run_turns AS run_turn
            JOIN import_runs AS run ON run.run_id = run_turn.run_id
            JOIN import_run_sessions AS session
              ON session.run_id = run_turn.run_id AND session.session_id = run_turn.session_id
            WHERE run_turn.run_id = ? AND run_turn.session_id = ? AND run_turn.turn_key = ?
              AND run_turn.source_payload_sha256 = ?
              AND run.project = ? AND run.status = 'active' AND run.phase = 'ready'
              AND session.status IN ('certified', 'failed', 'conflict')
            """,
            (
                project,
                session_id,
                turn_key,
                payload_sha256,
                payload_sha256,
                verification_signature,
                isoformat_z(source_last_activity_at),
                atif_schema_version,
                __version__,
                now,
                now,
                run_id,
                session_id,
                turn_key,
                payload_sha256,
                project,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn was not bound to the certified run manifest")
        self._after_write()
        row = self.get(project, session_id, turn_key)
        assert row is not None
        return row

    def record_emitted(
        self,
        *,
        row: StateRow,
        trace_ids: list[str],
        root_span_ids: list[str],
        span_count: int,
    ) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET trace_ids_json = ?, root_span_ids_json = ?, span_count = ?,
                updated_at = ?, last_error = '', revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending'
              AND payload_sha256 = ? AND verification_signature = ?
            """,
            (
                json.dumps(trace_ids),
                json.dumps(root_span_ids),
                span_count,
                isoformat_z(datetime.now(UTC)),
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before emission evidence was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_committed(
        self,
        *,
        row: StateRow,
        trace_ids: list[str] | None = None,
        root_span_ids: list[str] | None = None,
        span_count: int | None = None,
    ) -> StateRow:
        now = isoformat_z(datetime.now(UTC))
        assignments = [
            "status = 'committed'",
            "updated_at = ?",
            "imported_at = ?",
            "last_error = ''",
            "revision = revision + 1",
        ]
        values: list[object] = [now, now]
        if trace_ids is not None:
            assignments.append("trace_ids_json = ?")
            values.append(json.dumps(trace_ids))
        if root_span_ids is not None:
            assignments.append("root_span_ids_json = ?")
            values.append(json.dumps(root_span_ids))
        if span_count is not None:
            assignments.append("span_count = ?")
            values.append(span_count)
        values.extend(
            [
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ]
        )
        cursor = self._db.execute(
            f"""
            UPDATE imported_turns SET {", ".join(assignments)}
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending'
              AND payload_sha256 = ? AND verification_signature = ?
            """,
            values,
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before it was committed")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_conflict(
        self,
        *,
        row: StateRow,
        new_payload_sha256: str,
        error: str | None = None,
    ) -> StateRow:
        message = error or f"source payload changed to {new_payload_sha256}"
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET status = 'conflict', updated_at = ?, last_error = ?, revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = ? AND payload_sha256 = ?
              AND source_payload_sha256 = ? AND verification_signature = ?
            """,
            (
                isoformat_z(datetime.now(UTC)),
                message[:500],
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.status,
                row.payload_sha256,
                row.source_payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("turn changed before its conflict was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def replace_unemitted_pending_payload(
        self,
        *,
        row: StateRow,
        payload_sha256: str,
        verification_signature: str,
        source_last_activity_at: datetime,
        atif_schema_version: str,
    ) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET payload_sha256 = ?, source_payload_sha256 = ?, verification_signature = ?,
                status = 'pending', source_last_activity_at = ?, atif_schema_version = ?,
                importer_version = ?, updated_at = ?, last_error = '', revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND payload_sha256 = ?
              AND status IN ('pending', 'conflict')
              AND span_count = 0 AND trace_ids_json = '[]' AND root_span_ids_json = '[]'
            """,
            (
                payload_sha256,
                payload_sha256,
                verification_signature,
                isoformat_z(source_last_activity_at),
                atif_schema_version,
                __version__,
                isoformat_z(datetime.now(UTC)),
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError(
                "could not replace pending payload because emission evidence or state changed"
            )
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def record_error(self, *, row: StateRow, error: str) -> StateRow:
        cursor = self._db.execute(
            """
            UPDATE imported_turns
            SET updated_at = ?, last_error = ?, revision = revision + 1
            WHERE project = ? AND session_id = ? AND turn_key = ?
              AND revision = ? AND status = 'pending' AND payload_sha256 = ?
              AND verification_signature = ?
            """,
            (
                isoformat_z(datetime.now(UTC)),
                error[:500],
                row.project,
                row.session_id,
                row.turn_key,
                row.revision,
                row.payload_sha256,
                row.verification_signature,
            ),
        )
        if cursor.rowcount != 1:
            self._db.rollback()
            raise StateConflictError("pending turn changed before its error was recorded")
        self._after_write()
        refreshed = self.get(row.project, row.session_id, row.turn_key)
        assert refreshed is not None
        return refreshed

    def mark_remote_conflict(self, *, row: StateRow, error: str) -> StateRow:
        if row.status != "pending":
            raise StateConflictError("only a pending turn can receive a remote conflict")
        return self.mark_conflict(row=row, new_payload_sha256=row.payload_sha256, error=error)
