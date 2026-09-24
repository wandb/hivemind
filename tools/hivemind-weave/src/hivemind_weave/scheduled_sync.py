"""Content-free configuration and fail-closed orchestration for local sync."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .backfill import (
    BackfillApplyConfig,
    BackfillPreviewConfig,
    apply_backfill,
    preview_backfill,
)
from .errors import ATIFSchemaError, ImporterError
from .hivemind import HiveMindClient
from .macos_keychain import KeychainError, KeychainReference, MacOSKeychain
from .macos_launchagent import MacOSLaunchAgent
from .models import Session
from .private_io import (
    PrivatePathError,
    atomic_write_private,
    ensure_private_directory,
    read_private_bytes,
    validate_private_file,
)
from .redaction import redact_string
from .state import StateStore, SyncDiscoveryRecord
from .utils import isoformat_z, sha256_json

SYNC_CONFIG_SCHEMA_VERSION = 1
SYNC_STATUS_SCHEMA_VERSION = 1

_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TIME_ZONE = re.compile(r"^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_STATUS_STATES = frozenset({"never_run", "running", "succeeded", "failed", "paused"})
_STATUS_ERRORS = frozenset(
    {
        "",
        "import_failed",
        "keychain_unavailable",
        "prior_run_incomplete",
        "discovery_failed",
        "unexpected_error",
        "upload_blocked",
        "upload_uncertain",
        "reconcile_unavailable",
    }
)

ImportRunner = Callable[["SyncConfig"], Any]
Clock = Callable[[], datetime]
PreviewRunner = Callable[..., Any]
ApplyRunner = Callable[..., Any]


class ScheduledSyncError(ImporterError):
    """A scheduled sync operation could not proceed safely."""


class SyncAlreadyRunning(ScheduledSyncError):
    """Another manual or scheduled process owns the scheduler lock."""


def _now_utc(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validate_utc(value: str, *, field_name: str) -> datetime:
    if not _UTC_TIMESTAMP.fullmatch(value):
        raise ScheduledSyncError(f"{field_name} must be a resolved UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ScheduledSyncError(f"{field_name} is not a valid UTC timestamp") from error
    return parsed


def _validated_values(
    values: Sequence[str],
    *,
    field_name: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > maximum:
        raise ScheduledSyncError(f"{field_name} has an invalid number of values")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if (
            not isinstance(value, str)
            or not pattern.fullmatch(value)
            or value.startswith("-")
            or redact_string(value) != value
        ):
            raise ScheduledSyncError(f"{field_name} must use bounded visible ASCII values")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(sorted(result))


@dataclass(frozen=True)
class SyncConfig:
    """Strict, transcript-free configuration saved for a LaunchAgent."""

    project: str
    since: str
    timezone: str
    state_path: Path
    interval_seconds: int = 900
    settle_minutes: int = 60
    until: str | None = None
    agents: tuple[str, ...] = ()
    repositories: tuple[str, ...] = ()
    session_ids: tuple[str, ...] = ()
    include_subagents: bool = True
    schema_version: int = SYNC_CONFIG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SYNC_CONFIG_SCHEMA_VERSION
        ):
            raise ScheduledSyncError("unsupported scheduled sync config schema")
        if not _PROJECT.fullmatch(self.project):
            raise ScheduledSyncError("scheduled project must use a bounded entity/project slug")
        since = _validate_utc(self.since, field_name="since")
        if self.until is not None:
            until = _validate_utc(self.until, field_name="until")
            if until <= since:
                raise ScheduledSyncError("until must be later than since")
        if (
            not isinstance(self.timezone, str)
            or not _TIME_ZONE.fullmatch(self.timezone)
            or len(self.timezone) > 128
        ):
            raise ScheduledSyncError("timezone must be a bounded IANA timezone name")
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ScheduledSyncError(
                "timezone is not available in the local timezone database"
            ) from error
        if type(self.interval_seconds) is not int or not 300 <= self.interval_seconds <= 86_400:
            raise ScheduledSyncError("interval_seconds must be between 300 and 86400")
        if type(self.settle_minutes) is not int or not 1 <= self.settle_minutes <= 10_080:
            raise ScheduledSyncError("settle_minutes must be between 1 and 10080")
        if type(self.include_subagents) is not bool:
            raise ScheduledSyncError("include_subagents must be a boolean")
        state_path = self.state_path.expanduser()
        if not state_path.is_absolute() or ".." in state_path.parts:
            raise ScheduledSyncError("scheduled state_path must be absolute without traversal")
        if any(ord(character) < 0x20 for character in str(state_path)):
            raise ScheduledSyncError("scheduled state_path contains control characters")
        object.__setattr__(self, "state_path", state_path)
        object.__setattr__(
            self,
            "agents",
            _validated_values(
                self.agents,
                field_name="agents",
                pattern=_AGENT,
                maximum=64,
            ),
        )
        object.__setattr__(
            self,
            "repositories",
            _validated_values(
                self.repositories,
                field_name="repositories",
                pattern=_REPOSITORY,
                maximum=512,
            ),
        )
        object.__setattr__(
            self,
            "session_ids",
            _validated_values(
                self.session_ids,
                field_name="session_ids",
                pattern=_SESSION_ID,
                maximum=10_000,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "project": self.project,
            "since": self.since,
            "timezone": self.timezone,
            "state_path": str(self.state_path),
            "interval_seconds": self.interval_seconds,
            "settle_minutes": self.settle_minutes,
            "agents": list(self.agents),
            "repositories": list(self.repositories),
            "session_ids": list(self.session_ids),
            "include_subagents": self.include_subagents,
        }
        if self.until is not None:
            payload["until"] = self.until
        return payload

    def discovery_sha256(self) -> str:
        return sha256_json(
            {
                "schema": "hivemind-weave-sync-discovery-v1",
                "project": self.project,
                "since": self.since,
                "until": self.until,
                "timezone": self.timezone,
                "settle_minutes": self.settle_minutes,
                "agents": list(self.agents),
                "repositories": list(self.repositories),
                "session_ids": list(self.session_ids),
                "include_subagents": self.include_subagents,
            }
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SyncConfig:
        required = {
            "schema_version",
            "project",
            "since",
            "timezone",
            "state_path",
            "interval_seconds",
            "settle_minutes",
            "agents",
            "repositories",
            "session_ids",
            "include_subagents",
        }
        allowed = required | {"until"}
        if set(payload) - allowed or required - set(payload):
            raise ScheduledSyncError("scheduled config has missing or unsupported fields")
        try:
            return cls(
                schema_version=payload["schema_version"],
                project=payload["project"],
                since=payload["since"],
                until=payload.get("until"),
                timezone=payload["timezone"],
                state_path=Path(payload["state_path"]),
                interval_seconds=payload["interval_seconds"],
                settle_minutes=payload["settle_minutes"],
                agents=tuple(payload["agents"]),
                repositories=tuple(payload["repositories"]),
                session_ids=tuple(payload["session_ids"]),
                include_subagents=payload["include_subagents"],
            )
        except (TypeError, ValueError) as error:
            raise ScheduledSyncError("scheduled config has invalid field types") from error


@dataclass(frozen=True)
class SyncPaths:
    """All scheduler-owned paths, with the LaunchAgent intentionally separate."""

    directory: Path
    config_path: Path
    status_path: Path
    lock_path: Path
    plist_path: Path

    @classmethod
    def defaults(cls, *, home: Path | None = None) -> SyncPaths:
        base_home = (home or Path.home()).expanduser()
        if not base_home.is_absolute():
            raise ScheduledSyncError("scheduler home must be absolute")
        directory = base_home / "Library" / "Application Support" / "hivemind-weave"
        return cls(
            directory=directory,
            config_path=directory / "sync.json",
            status_path=directory / "status.json",
            lock_path=directory / "sync.lock",
            plist_path=(
                base_home / "Library" / "LaunchAgents" / "com.wandb.hivemind-weave.sync.plist"
            ),
        )


@dataclass(frozen=True)
class SyncStatus:
    """Content-free status; correlation IDs and error bodies stay in SQLite."""

    state: str = "never_run"
    requires_attention: bool = False
    started_at: str = ""
    finished_at: str = ""
    last_success_at: str = ""
    error_code: str = ""
    discovered: int = 0
    eligible: int = 0
    deferred: int = 0
    planned: int = 0
    imported: int = 0
    skipped: int = 0
    conflicted: int = 0
    failed: int = 0
    emitted_spans: int = 0
    schema_version: int = SYNC_STATUS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SYNC_STATUS_SCHEMA_VERSION
        ):
            raise ScheduledSyncError("unsupported scheduled sync status schema")
        if self.state not in _STATUS_STATES or self.error_code not in _STATUS_ERRORS:
            raise ScheduledSyncError("scheduled sync status has an invalid state")
        if type(self.requires_attention) is not bool:
            raise ScheduledSyncError("scheduled sync attention flag must be boolean")
        for value in (self.started_at, self.finished_at, self.last_success_at):
            if value:
                _validate_utc(value, field_name="status timestamp")
        for name in (
            "discovered",
            "eligible",
            "deferred",
            "planned",
            "imported",
            "skipped",
            "conflicted",
            "failed",
            "emitted_spans",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ScheduledSyncError("scheduled sync status counters must be nonnegative")

    def to_dict(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SyncStatus:
        fields = set(cls.__dataclass_fields__)
        if set(payload) != fields:
            raise ScheduledSyncError("scheduled status has missing or unsupported fields")
        try:
            return cls(**payload)
        except TypeError as error:
            raise ScheduledSyncError("scheduled status has invalid field types") from error


@dataclass(frozen=True)
class SyncOnceOutcome:
    state: str
    exit_code: int
    status: SyncStatus | None = None


@dataclass(frozen=True)
class SyncInspection:
    configured: bool
    installed: bool
    loaded: bool
    keychain_available: bool
    status: SyncStatus = field(default_factory=SyncStatus)
    queued_sessions: int = 0
    deferred_sessions: int = 0
    unresolved_attempts: bool = False
    successful_scan_watermark: str = ""
    preflighted_turns: int = 0
    committed_turns: int = 0
    blocked_items: int = 0
    uncertain_turns: int = 0
    conflicted_turns: int = 0
    next_scheduled_at: str = ""


@dataclass(frozen=True)
class SyncDiscovery:
    cutoff: datetime
    scan_start: datetime
    discovered: int
    queued: int
    deferred: int


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_sync_config(path: Path, config: SyncConfig) -> None:
    atomic_write_private(path, _json_bytes(config.to_dict()))


def load_sync_config(path: Path) -> SyncConfig:
    try:
        payload = json.loads(read_private_bytes(path, limit=1024 * 1024))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ScheduledSyncError("scheduled config is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ScheduledSyncError("scheduled config must contain one JSON object")
    return SyncConfig.from_dict(payload)


def write_sync_status(path: Path, status: SyncStatus) -> None:
    atomic_write_private(path, _json_bytes(status.to_dict()))


def load_sync_status(path: Path) -> SyncStatus:
    if not path.exists() and not path.is_symlink():
        return SyncStatus()
    try:
        payload = json.loads(read_private_bytes(path, limit=64 * 1024))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ScheduledSyncError("scheduled status is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ScheduledSyncError("scheduled status must contain one JSON object")
    return SyncStatus.from_dict(payload)


class SyncRunLock:
    """A process lock acquired before Keychain, HiveMind, SQLite, or Weave access."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor = -1

    def __enter__(self) -> SyncRunLock:
        ensure_private_directory(self.path.parent)
        existed = self.path.exists() or self.path.is_symlink()
        if existed:
            validate_private_file(self.path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.descriptor = os.open(self.path, flags, 0o600)
            details = os.fstat(self.descriptor)
            if not existed:
                os.fchmod(self.descriptor, 0o600)
                details = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise PrivatePathError("scheduled sync lock has unsafe ownership or permissions")
            current = self.path.lstat()
            if (details.st_dev, details.st_ino) != (current.st_dev, current.st_ino):
                raise PrivatePathError("scheduled sync lock changed while it was opened")
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SyncAlreadyRunning(
                    "another scheduled or manual sync is already running"
                ) from error
            return self
        except Exception:
            if self.descriptor >= 0:
                os.close(self.descriptor)
                self.descriptor = -1
            raise

    def __exit__(self, *_args: Any) -> None:
        if self.descriptor >= 0:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = -1


@contextmanager
def _temporary_wandb_api_key(secret: str) -> Iterator[None]:
    variable = "WANDB_API_KEY"
    present = variable in os.environ
    original = os.environ.get(variable)
    os.environ[variable] = secret
    try:
        yield
    finally:
        if present:
            assert original is not None
            os.environ[variable] = original
        else:
            os.environ.pop(variable, None)


def _report_status(report: Any, *, started_at: str, finished_at: str) -> SyncStatus:
    aliases = {
        "discovered": ("discovered",),
        "eligible": ("eligible",),
        "deferred": ("deferred",),
        "planned": ("planned", "cohort_sessions", "selected"),
        "imported": ("imported", "imported_turns"),
        "skipped": ("skipped", "skipped_turns"),
        "conflicted": ("conflicted", "conflicted_turns"),
        "failed": ("failed", "failed_items"),
        "emitted_spans": ("emitted_spans",),
    }
    counters: dict[str, int] = {}
    for destination, candidates in aliases.items():
        value = next(
            (getattr(report, name) for name in candidates if hasattr(report, name)),
            0,
        )
        counters[destination] = int(value or 0)
    ok = bool(getattr(report, "ok", False))
    return SyncStatus(
        state="succeeded" if ok else "failed",
        requires_attention=not ok,
        started_at=started_at,
        finished_at=finished_at,
        last_success_at=finished_at if ok else "",
        error_code="" if ok else "import_failed",
        **counters,
    )


def _failed_status(
    *,
    started_at: str,
    finished_at: str,
    last_success_at: str,
    error_code: str,
) -> SyncStatus:
    return SyncStatus(
        state="failed",
        requires_attention=True,
        started_at=started_at,
        finished_at=finished_at,
        last_success_at=last_success_at,
        error_code=error_code,
        failed=1,
    )


def _clock_utc(clock: Clock) -> datetime:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0)


def _discover_incremental_sessions(
    config: SyncConfig,
    *,
    client: HiveMindClient,
    cutoff: datetime,
) -> SyncDiscovery:
    since = _validate_utc(config.since, field_name="since")
    configured_until = (
        _validate_utc(config.until, field_name="until") if config.until is not None else None
    )
    effective_cutoff = min(cutoff, configured_until) if configured_until is not None else cutoff
    config_hash = config.discovery_sha256()
    with StateStore(config.state_path) as state:
        feed = state.ensure_sync_feed(
            project=config.project,
            config_sha256=config_hash,
            since_utc=since,
        )
        tracked_deferred = state.get_deferred_sync_sessions(config.project)
    overlap_start = (
        feed.successful_scan_watermark - timedelta(hours=24)
        if feed.successful_scan_watermark is not None
        else since
    )
    scan_start = max(since, overlap_start)
    if effective_cutoff < scan_start:
        effective_cutoff = scan_start
    lookback = effective_cutoff - scan_start
    if lookback > timedelta(days=365):
        raise ScheduledSyncError(
            "sync discovery exceeds HiveMind's 365-day lookback; choose a newer --since"
        )
    days = min(365, max(1, math.ceil(lookback.total_seconds() / 86_400) + 1))

    client.preflight()
    raw_sessions = client.list_sessions(days=days, include_subagents=True)
    parsed: dict[str, Session] = {}
    for raw in raw_sessions:
        try:
            session = Session.from_api(raw)
        except ATIFSchemaError as error:
            raise ScheduledSyncError(
                "HiveMind returned an invalid session summary; the scan watermark was not advanced"
            ) from error
        previous = parsed.get(session.id)
        if previous is not None and previous != session:
            raise ScheduledSyncError(
                "HiveMind returned inconsistent duplicate summaries; "
                "the scan watermark was not advanced"
            )
        parsed[session.id] = session

    # A long settling window or an unknown activity timestamp can outlive the
    # 24-hour overlap. Re-read every outstanding deferred ID directly so a
    # chat cannot disappear merely because its old summary aged out of the
    # server-side list window.
    tracked_deferred_ids = {item.session_id for item in tracked_deferred}
    for item in tracked_deferred:
        if item.session_id in parsed:
            continue
        try:
            refreshed = Session.from_api(client.get_session(item.session_id))
        except Exception as error:
            raise ScheduledSyncError(
                "a deferred HiveMind session could not be rechecked; "
                "the scan watermark was not advanced"
            ) from error
        if refreshed.id != item.session_id:
            raise ScheduledSyncError(
                "a deferred HiveMind session changed identity; the scan watermark was not advanced"
            )
        parsed[refreshed.id] = refreshed

    records: list[SyncDiscoveryRecord] = []
    settle = timedelta(minutes=config.settle_minutes)
    for session in parsed.values():
        forced_deferred = session.id in tracked_deferred_ids
        if config.agents and session.agent_type not in config.agents:
            if forced_deferred:
                raise ScheduledSyncError("a deferred session no longer matches its agent filter")
            continue
        if config.repositories and session.repository not in config.repositories:
            if forced_deferred:
                raise ScheduledSyncError(
                    "a deferred session no longer matches its repository filter"
                )
            continue
        if config.session_ids and session.id not in config.session_ids:
            if forced_deferred:
                raise ScheduledSyncError("a deferred session no longer matches its exact filter")
            continue
        if not config.include_subagents and session.parent_session_id:
            if forced_deferred:
                raise ScheduledSyncError("a deferred session changed its subagent relationship")
            continue
        activity = session.last_activity_at
        if session.last_activity_known:
            if (activity < scan_start and not forced_deferred) or activity > effective_cutoff:
                continue
        elif (
            session.started_at < scan_start and not forced_deferred
        ) or session.started_at > effective_cutoff:
            continue
        eligible_after = activity + settle
        status = (
            "queued"
            if session.last_activity_known and eligible_after <= effective_cutoff
            else "deferred"
        )
        records.append(
            SyncDiscoveryRecord(
                session_id=session.id,
                started_at=session.started_at,
                last_activity_at=activity,
                activity_known=session.last_activity_known,
                eligible_after=eligible_after,
                status=status,
            )
        )
    records.sort(key=lambda item: (item.last_activity_at, item.session_id))
    with StateStore(config.state_path) as state:
        state.record_sync_scan(
            project=config.project,
            config_sha256=config_hash,
            since_utc=since,
            scan_started_at=cutoff,
            cutoff=effective_cutoff,
            records=records,
        )
        queued, deferred = state.sync_backlog_counts(config.project)
    return SyncDiscovery(
        cutoff=effective_cutoff,
        scan_start=scan_start,
        discovered=len(records),
        queued=queued,
        deferred=deferred,
    )


def _paused_after_discovery(
    previous: SyncStatus,
    discovery: SyncDiscovery,
) -> SyncStatus:
    return SyncStatus(
        state="paused",
        requires_attention=True,
        started_at=previous.started_at,
        finished_at=previous.finished_at,
        last_success_at=previous.last_success_at,
        error_code=("prior_run_incomplete" if previous.state == "running" else previous.error_code),
        discovered=discovery.discovered,
        eligible=discovery.queued,
        deferred=discovery.deferred,
        planned=previous.planned,
        imported=previous.imported,
        skipped=previous.skipped,
        conflicted=previous.conflicted,
        failed=previous.failed,
        emitted_spans=previous.emitted_spans,
    )


def _run_legacy_sync_once(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    import_runner: ImportRunner,
    keychain: MacOSKeychain | None = None,
    clock: Clock = lambda: datetime.now(UTC),
    acknowledge_attention: bool = False,
) -> SyncOnceOutcome:
    """Run one locked sync and persist only a content-free result summary."""
    ensure_private_directory(paths.directory)
    try:
        lock = SyncRunLock(paths.lock_path)
        lock.__enter__()
    except SyncAlreadyRunning:
        return SyncOnceOutcome(state="already_running", exit_code=0)
    try:
        previous = load_sync_status(paths.status_path)
        if not acknowledge_attention and (
            previous.requires_attention or previous.state == "running"
        ):
            paused = SyncStatus(
                state="paused",
                requires_attention=True,
                started_at=previous.started_at,
                finished_at=previous.finished_at,
                last_success_at=previous.last_success_at,
                error_code=(
                    "prior_run_incomplete" if previous.state == "running" else previous.error_code
                ),
                discovered=previous.discovered,
                eligible=previous.eligible,
                deferred=previous.deferred,
                planned=previous.planned,
                imported=previous.imported,
                skipped=previous.skipped,
                conflicted=previous.conflicted,
                failed=previous.failed,
                emitted_spans=previous.emitted_spans,
            )
            write_sync_status(paths.status_path, paused)
            return SyncOnceOutcome(state="paused", exit_code=1, status=paused)

        started_at = _now_utc(clock)
        running = SyncStatus(
            state="running",
            started_at=started_at,
            last_success_at=previous.last_success_at,
        )
        write_sync_status(paths.status_path, running)
        active_keychain = keychain or MacOSKeychain(KeychainReference(account=config.project))
        try:
            secret = active_keychain.read_secret()
        except KeychainError:
            failed = _failed_status(
                started_at=started_at,
                finished_at=_now_utc(clock),
                last_success_at=previous.last_success_at,
                error_code="keychain_unavailable",
            )
            write_sync_status(paths.status_path, failed)
            return SyncOnceOutcome(state="failed", exit_code=1, status=failed)
        try:
            with _temporary_wandb_api_key(secret):
                report = import_runner(config)
        except Exception as error:
            code = "import_failed" if isinstance(error, ImporterError) else "unexpected_error"
            failed = _failed_status(
                started_at=started_at,
                finished_at=_now_utc(clock),
                last_success_at=previous.last_success_at,
                error_code=code,
            )
            write_sync_status(paths.status_path, failed)
            return SyncOnceOutcome(state="failed", exit_code=1, status=failed)
        finally:
            secret = ""
        status = _report_status(
            report,
            started_at=started_at,
            finished_at=_now_utc(clock),
        )
        if not status.last_success_at:
            status = SyncStatus(
                **{
                    **status.to_dict(),
                    "last_success_at": previous.last_success_at,
                }
            )
        write_sync_status(paths.status_path, status)
        return SyncOnceOutcome(
            state=status.state,
            exit_code=0 if status.state == "succeeded" else 1,
            status=status,
        )
    finally:
        lock.__exit__(None, None, None)


def _functional_sync_once(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    keychain: MacOSKeychain | None,
    clock: Clock,
    hivemind: HiveMindClient | None,
    preview_runner: PreviewRunner,
    apply_runner: ApplyRunner,
) -> SyncOnceOutcome:
    ensure_private_directory(paths.directory)
    try:
        lock = SyncRunLock(paths.lock_path)
        lock.__enter__()
    except SyncAlreadyRunning:
        return SyncOnceOutcome(state="already_running", exit_code=0)
    try:
        previous = load_sync_status(paths.status_path)
        cutoff = _clock_utc(clock)
        client = hivemind or HiveMindClient()
        try:
            discovery = _discover_incremental_sessions(
                config,
                client=client,
                cutoff=cutoff,
            )
        except Exception:
            failed = SyncStatus(
                state="failed",
                requires_attention=previous.requires_attention,
                started_at=isoformat_z(cutoff),
                finished_at=_now_utc(clock),
                last_success_at=previous.last_success_at,
                error_code=(
                    previous.error_code if previous.requires_attention else "discovery_failed"
                ),
                failed=1,
            )
            write_sync_status(paths.status_path, failed)
            return SyncOnceOutcome(state="failed", exit_code=1, status=failed)

        with StateStore(config.state_path) as state:
            unresolved_attempt = state.has_unresolved_sync_attempts(config.project)
            next_session = state.get_next_sync_session(config.project)
            completed_after_status_start = bool(
                previous.started_at
                and state.has_completed_sync_attempt_since(
                    config.project,
                    _validate_utc(previous.started_at, field_name="status started_at"),
                )
            )
        stale_running_status = previous.state == "running" or (
            previous.state == "paused" and previous.error_code == "prior_run_incomplete"
        )
        if stale_running_status and not unresolved_attempt and completed_after_status_start:
            finished_at = _now_utc(clock)
            recovered = SyncStatus(
                state="succeeded",
                started_at=previous.started_at,
                finished_at=finished_at,
                last_success_at=finished_at,
                discovered=discovery.discovered,
                eligible=discovery.queued,
                deferred=discovery.deferred,
            )
            write_sync_status(paths.status_path, recovered)
            return SyncOnceOutcome(state="succeeded", exit_code=0, status=recovered)
        if previous.requires_attention or previous.state == "running" or unresolved_attempt:
            if not previous.requires_attention and previous.state != "running":
                previous = SyncStatus(
                    state="failed",
                    requires_attention=True,
                    started_at=isoformat_z(cutoff),
                    finished_at=isoformat_z(cutoff),
                    last_success_at=previous.last_success_at,
                    error_code="upload_uncertain",
                    failed=1,
                )
            paused = _paused_after_discovery(previous, discovery)
            write_sync_status(paths.status_path, paused)
            return SyncOnceOutcome(state="paused", exit_code=1, status=paused)

        if next_session is None:
            finished_at = _now_utc(clock)
            succeeded = SyncStatus(
                state="succeeded",
                started_at=isoformat_z(cutoff),
                finished_at=finished_at,
                last_success_at=finished_at,
                discovered=discovery.discovered,
                eligible=discovery.queued,
                deferred=discovery.deferred,
            )
            write_sync_status(paths.status_path, succeeded)
            return SyncOnceOutcome(state="succeeded", exit_code=0, status=succeeded)

        active_keychain = keychain or MacOSKeychain(KeychainReference(account=config.project))
        try:
            secret = active_keychain.read_secret()
        except KeychainError:
            failed = SyncStatus(
                state="failed",
                started_at=isoformat_z(cutoff),
                finished_at=_now_utc(clock),
                last_success_at=previous.last_success_at,
                error_code="keychain_unavailable",
                discovered=discovery.discovered,
                eligible=discovery.queued,
                deferred=discovery.deferred,
                failed=1,
            )
            write_sync_status(paths.status_path, failed)
            return SyncOnceOutcome(state="failed", exit_code=1, status=failed)

        plan_id = ""
        try:
            lower = max(
                _validate_utc(config.since, field_name="since"),
                next_session.last_activity_at - timedelta(seconds=1),
            )
            with _temporary_wandb_api_key(secret):
                preview = preview_runner(
                    BackfillPreviewConfig(
                        project=config.project,
                        state_path=config.state_path,
                        since=isoformat_z(lower),
                        until=isoformat_z(discovery.cutoff),
                        timezone_name=config.timezone,
                        agents=config.agents,
                        repositories=config.repositories,
                        session_ids=(next_session.session_id,),
                        exclude_subagents=not config.include_subagents,
                        now=cutoff,
                    ),
                    hivemind=client,
                )
                plan_id = str(preview.plan_id)
                with StateStore(config.state_path) as state:
                    state.begin_sync_attempt(session=next_session, plan_id=plan_id)
                running = SyncStatus(
                    state="running",
                    started_at=isoformat_z(cutoff),
                    last_success_at=previous.last_success_at,
                    discovered=discovery.discovered,
                    eligible=discovery.queued,
                    deferred=discovery.deferred,
                    planned=1,
                )
                write_sync_status(paths.status_path, running)
                applied = apply_runner(
                    BackfillApplyConfig(
                        project=config.project,
                        confirm_project=config.project,
                        plan_id=plan_id,
                        state_path=config.state_path,
                        max_sessions=1,
                    ),
                    hivemind=client,
                )
            success = (
                bool(getattr(applied, "ok", False))
                and int(getattr(applied, "remaining_sessions", 0) or 0) == 0
            )
            with StateStore(config.state_path) as state:
                state.finish_sync_attempt(
                    project=config.project,
                    session_id=next_session.session_id,
                    plan_id=plan_id,
                    success=success,
                    error_code="" if success else "upload_blocked",
                )
        except Exception:
            if plan_id:
                try:
                    with StateStore(config.state_path) as state:
                        state.finish_sync_attempt(
                            project=config.project,
                            session_id=next_session.session_id,
                            plan_id=plan_id,
                            success=False,
                            error_code="upload_uncertain",
                        )
                except Exception:
                    pass
                failed = SyncStatus(
                    state="failed",
                    requires_attention=True,
                    started_at=isoformat_z(cutoff),
                    finished_at=_now_utc(clock),
                    last_success_at=previous.last_success_at,
                    error_code="upload_uncertain",
                    discovered=discovery.discovered,
                    eligible=discovery.queued,
                    deferred=discovery.deferred,
                    planned=1,
                    failed=1,
                )
            else:
                failed = SyncStatus(
                    state="failed",
                    started_at=isoformat_z(cutoff),
                    finished_at=_now_utc(clock),
                    last_success_at=previous.last_success_at,
                    error_code="import_failed",
                    discovered=discovery.discovered,
                    eligible=discovery.queued,
                    deferred=discovery.deferred,
                    failed=1,
                )
            write_sync_status(paths.status_path, failed)
            return SyncOnceOutcome(state="failed", exit_code=1, status=failed)
        finally:
            secret = ""

        finished_at = _now_utc(clock)
        status = SyncStatus(
            state="succeeded" if success else "failed",
            requires_attention=not success,
            started_at=isoformat_z(cutoff),
            finished_at=finished_at,
            last_success_at=finished_at if success else previous.last_success_at,
            error_code="" if success else "upload_blocked",
            discovered=discovery.discovered,
            eligible=discovery.queued,
            deferred=discovery.deferred,
            planned=1,
            imported=int(getattr(applied, "imported_turns", 0) or 0),
            skipped=int(getattr(applied, "skipped_turns", 0) or 0),
            conflicted=int(getattr(applied, "conflicted_turns", 0) or 0),
            failed=int(getattr(applied, "failed_items", 0) or 0),
            emitted_spans=int(getattr(applied, "emitted_spans", 0) or 0),
        )
        write_sync_status(paths.status_path, status)
        return SyncOnceOutcome(
            state=status.state,
            exit_code=0 if success else 1,
            status=status,
        )
    finally:
        lock.__exit__(None, None, None)


def run_sync_once(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    import_runner: ImportRunner | None = None,
    keychain: MacOSKeychain | None = None,
    clock: Clock = lambda: datetime.now(UTC),
    acknowledge_attention: bool = False,
    hivemind: HiveMindClient | None = None,
    preview_runner: PreviewRunner = preview_backfill,
    apply_runner: ApplyRunner = apply_backfill,
) -> SyncOnceOutcome:
    if acknowledge_attention:
        raise ScheduledSyncError(
            "attention can only be cleared by evidence-backed 'hivemind-weave reconcile'"
        )
    if import_runner is not None:
        return _run_legacy_sync_once(
            config,
            paths=paths,
            import_runner=import_runner,
            keychain=keychain,
            clock=clock,
            acknowledge_attention=acknowledge_attention,
        )
    return _functional_sync_once(
        config,
        paths=paths,
        keychain=keychain,
        clock=clock,
        hivemind=hivemind,
        preview_runner=preview_runner,
        apply_runner=apply_runner,
    )


def run_sync_once_from_file(
    config_path: Path,
    *,
    paths: SyncPaths,
    import_runner: ImportRunner | None = None,
    keychain: MacOSKeychain | None = None,
    clock: Clock = lambda: datetime.now(UTC),
    acknowledge_attention: bool = False,
    hivemind: HiveMindClient | None = None,
    preview_runner: PreviewRunner = preview_backfill,
    apply_runner: ApplyRunner = apply_backfill,
) -> SyncOnceOutcome:
    config = load_sync_config(config_path)
    return run_sync_once(
        config,
        paths=paths,
        import_runner=import_runner,
        keychain=keychain,
        clock=clock,
        acknowledge_attention=acknowledge_attention,
        hivemind=hivemind,
        preview_runner=preview_runner,
        apply_runner=apply_runner,
    )


def reconcile_scheduled_sync(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    clock: Clock = lambda: datetime.now(UTC),
    keychain: MacOSKeychain | None = None,
    hivemind: HiveMindClient | None = None,
    apply_runner: ApplyRunner = apply_backfill,
) -> SyncStatus:
    """Resolve exact atomic status, then clear attention from committed evidence."""
    ensure_private_directory(paths.directory)
    with SyncRunLock(paths.lock_path):
        previous = load_sync_status(paths.status_path)
        if not config.state_path.exists() and not config.state_path.is_symlink():
            raise ScheduledSyncError(
                "private atomic turn evidence is not available; attention was not cleared"
            )
        with StateStore(config.state_path) as state:
            result = state.reconcile_sync_attempts(config.project)
            unresolved_plan_ids = state.get_unresolved_sync_plan_ids(config.project)
            queued, deferred = state.sync_backlog_counts(config.project)
            completed_after_status_start = bool(
                previous.started_at
                and state.has_completed_sync_attempt_since(
                    config.project,
                    _validate_utc(previous.started_at, field_name="status started_at"),
                )
            )
        if result.unresolved_attempts and unresolved_plan_ids:
            active_keychain = keychain or MacOSKeychain(KeychainReference(account=config.project))
            secret = ""
            try:
                secret = active_keychain.read_secret()
                client = hivemind or HiveMindClient()
                with _temporary_wandb_api_key(secret):
                    for plan_id in unresolved_plan_ids:
                        report = apply_runner(
                            BackfillApplyConfig(
                                project=config.project,
                                confirm_project=config.project,
                                plan_id=plan_id,
                                state_path=config.state_path,
                                max_sessions=1,
                            ),
                            hivemind=client,
                        )
                        if not bool(getattr(report, "ok", False)):
                            break
            except Exception:
                failed = SyncStatus(
                    state="failed",
                    requires_attention=True,
                    started_at=previous.started_at,
                    finished_at=_now_utc(clock),
                    last_success_at=previous.last_success_at,
                    error_code="reconcile_unavailable",
                    eligible=queued,
                    deferred=deferred,
                    failed=max(1, previous.failed),
                )
                write_sync_status(paths.status_path, failed)
                raise ScheduledSyncError(
                    "exact atomic reconciliation could not complete; attention remains set"
                ) from None
            finally:
                secret = ""
            with StateStore(config.state_path) as state:
                result = state.reconcile_sync_attempts(config.project)
                queued, deferred = state.sync_backlog_counts(config.project)
        if result.unresolved_attempts:
            code = "reconcile_unavailable" if not result.evidence_available else "upload_blocked"
            failed = SyncStatus(
                state="failed",
                requires_attention=True,
                started_at=previous.started_at,
                finished_at=_now_utc(clock),
                last_success_at=previous.last_success_at,
                error_code=code,
                eligible=queued,
                deferred=deferred,
                failed=max(1, previous.failed),
            )
            write_sync_status(paths.status_path, failed)
            raise ScheduledSyncError(
                "private atomic turn evidence is unresolved or incomplete; attention remains set"
            )
        if result.resolved_attempts == 0:
            if completed_after_status_start and (
                previous.state == "running"
                or (previous.state == "paused" and previous.error_code == "prior_run_incomplete")
            ):
                finished_at = _now_utc(clock)
                recovered = SyncStatus(
                    state="succeeded",
                    started_at=previous.started_at,
                    finished_at=finished_at,
                    last_success_at=finished_at,
                    eligible=queued,
                    deferred=deferred,
                )
                write_sync_status(paths.status_path, recovered)
                return recovered
            if previous.requires_attention or previous.state == "running":
                raise ScheduledSyncError(
                    "private atomic turn evidence is not available; attention was not cleared"
                )
            return previous
        finished_at = _now_utc(clock)
        reconciled = SyncStatus(
            state="succeeded",
            started_at=previous.started_at,
            finished_at=finished_at,
            last_success_at=previous.last_success_at,
            eligible=queued,
            deferred=deferred,
        )
        write_sync_status(paths.status_path, reconciled)
        return reconciled


def configure_scheduled_sync(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    launch_agent: MacOSLaunchAgent | None = None,
) -> None:
    """Persist one immutable, secret-free sync policy without installing a job."""
    ensure_private_directory(paths.directory)
    with SyncRunLock(paths.lock_path):
        configured = paths.config_path.exists() or paths.config_path.is_symlink()
        existing = load_sync_config(paths.config_path) if configured else None
        active_agent = launch_agent or MacOSLaunchAgent(paths.plist_path)
        installed = active_agent.is_installed()
        if existing is not None:
            same_policy = (
                existing.discovery_sha256() == config.discovery_sha256()
                and existing.state_path == config.state_path
            )
            if not same_policy:
                if installed and active_agent.is_loaded():
                    raise ScheduledSyncError(
                        "scheduled sync is loaded; unload it before changing its policy"
                    )
                raise ScheduledSyncError(
                    "an incompatible sync policy already exists; use a separate private "
                    "config/state path instead of mutating its identity"
                )
            if not paths.status_path.exists() and not paths.status_path.is_symlink():
                write_sync_status(paths.status_path, SyncStatus())
            return
        if installed and active_agent.is_loaded():
            raise ScheduledSyncError(
                "a loaded scheduled sync has no matching private config; configuration was refused"
            )
        write_sync_config(paths.config_path, config)
        if not paths.status_path.exists() and not paths.status_path.is_symlink():
            write_sync_status(paths.status_path, SyncStatus())


def set_project_keychain_secret(
    project: str,
    *,
    keychain: MacOSKeychain | None = None,
    replace: bool = True,
) -> None:
    """Prompt through macOS Keychain for one project-scoped W&B credential."""
    if not _PROJECT.fullmatch(project):
        raise ScheduledSyncError("scheduled project must use a bounded entity/project slug")
    active_keychain = keychain or MacOSKeychain(KeychainReference(account=project))
    active_keychain.install_interactive(replace=replace)


def install_scheduled_sync(
    config: SyncConfig,
    *,
    paths: SyncPaths,
    keychain: MacOSKeychain | None = None,
    launch_agent: MacOSLaunchAgent | None = None,
    python_executable: Path = Path(sys.executable),
) -> SyncInspection:
    """Install a non-RunAtLoad job for an already configured/keyed project."""
    ensure_private_directory(paths.directory)
    if not paths.plist_path.parent.exists():
        ensure_private_directory(paths.plist_path.parent)
    with SyncRunLock(paths.lock_path):
        if not paths.config_path.exists() and not paths.config_path.is_symlink():
            raise ScheduledSyncError("scheduled sync must be configured before installation")
        existing_config = load_sync_config(paths.config_path)
        if (
            existing_config.discovery_sha256() != config.discovery_sha256()
            or existing_config.state_path != config.state_path
        ):
            raise ScheduledSyncError(
                "installation cannot change the configured sync policy identity"
            )
        active_keychain = keychain or MacOSKeychain(KeychainReference(account=config.project))
        key_exists = active_keychain.has_secret()
        if not key_exists:
            raise ScheduledSyncError(
                "project Keychain credential is missing; run 'hivemind-weave auth "
                "keychain set --project ENTITY/PROJECT' first"
            )
        active_agent = launch_agent or MacOSLaunchAgent(paths.plist_path)
        # Stop an existing job before changing the config path it reads.  If a
        # later write or bootstrap fails, the result is a visibly stopped job,
        # never an old process silently consuming a new configuration.
        active_agent.unload()
        write_sync_config(paths.config_path, config)
        if not paths.status_path.exists() and not paths.status_path.is_symlink():
            write_sync_status(paths.status_path, SyncStatus())
        active_agent.write(
            config_path=paths.config_path,
            interval_seconds=config.interval_seconds,
            python_executable=python_executable,
        )
        active_agent.reload()
    return inspect_scheduled_sync(
        paths=paths,
        keychain=active_keychain,
        launch_agent=active_agent,
    )


def inspect_scheduled_sync(
    *,
    paths: SyncPaths,
    keychain: MacOSKeychain | None = None,
    launch_agent: MacOSLaunchAgent | None = None,
    clock: Clock = lambda: datetime.now(UTC),
) -> SyncInspection:
    configured = paths.config_path.exists() or paths.config_path.is_symlink()
    config = load_sync_config(paths.config_path) if configured else None
    active_agent = launch_agent or MacOSLaunchAgent(paths.plist_path)
    installed = active_agent.is_installed()
    loaded = active_agent.is_loaded()
    keychain_available = False
    if config is not None:
        active_keychain = keychain or MacOSKeychain(KeychainReference(account=config.project))
        keychain_available = active_keychain.has_secret()
    status = load_sync_status(paths.status_path)
    queued_sessions = 0
    deferred_sessions = 0
    unresolved_attempts = False
    watermark = ""
    diagnostics = {
        "preflighted": 0,
        "committed": 0,
        "blocked": 0,
        "uncertain": 0,
        "conflicted": 0,
    }
    if config is not None and (config.state_path.exists() or config.state_path.is_symlink()):
        with StateStore(config.state_path) as state:
            queued_sessions, deferred_sessions = state.sync_backlog_counts(config.project)
            unresolved_attempts = state.has_unresolved_sync_attempts(config.project)
            diagnostics = state.sync_diagnostic_counts(config.project)
            feed = state.get_sync_feed(config.project)
        if feed is not None and feed.successful_scan_watermark is not None:
            watermark = isoformat_z(feed.successful_scan_watermark)
    next_scheduled_at = ""
    if loaded and config is not None:
        now = _clock_utc(clock)
        last_finished = (
            _validate_utc(status.finished_at, field_name="status finished_at")
            if status.finished_at
            else now
        )
        interval = timedelta(seconds=config.interval_seconds)
        next_run = last_finished + interval
        if next_run <= now:
            elapsed_seconds = (now - last_finished).total_seconds()
            periods = math.floor(elapsed_seconds / config.interval_seconds) + 1
            next_run = last_finished + periods * interval
        next_scheduled_at = isoformat_z(next_run)
    return SyncInspection(
        configured=configured,
        installed=installed,
        loaded=loaded,
        keychain_available=keychain_available,
        status=status,
        queued_sessions=queued_sessions,
        deferred_sessions=deferred_sessions,
        unresolved_attempts=unresolved_attempts,
        successful_scan_watermark=watermark,
        preflighted_turns=diagnostics["preflighted"],
        committed_turns=diagnostics["committed"],
        blocked_items=diagnostics["blocked"],
        uncertain_turns=diagnostics["uncertain"],
        conflicted_turns=diagnostics["conflicted"],
        next_scheduled_at=next_scheduled_at,
    )
