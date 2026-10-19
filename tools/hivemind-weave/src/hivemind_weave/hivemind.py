"""Read-only HiveMind API access through the authenticated local CLI."""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .errors import AuthenticationError, HiveMindAPIError
from .utils import parse_datetime

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]

_SESSION_SNAPSHOT_ATTEMPTS = 5
_SESSION_SNAPSHOT_RETRY_DELAY_SECONDS = 2.0
_SESSION_PAGE_LIMIT = 100_000
_ATIF_FETCH_ATTEMPTS = 3
_ATIF_FETCH_RETRY_DELAY_SECONDS = 2.0
_CLI_TIMEOUT_SECONDS = 600
_SESSION_TOTAL_DRIFT_ERROR = "HiveMind session total_count changed during pagination"
_SESSION_COMPLETENESS_ERROR = "HiveMind pagination ended before every unique session was returned"
_SESSION_PRIMARY_SWEEP = (100, "asc")
_SESSION_RECOVERY_SWEEPS = (
    (100, "desc"),
    (97, "asc"),
    (97, "desc"),
    (89, "asc"),
    (89, "desc"),
)

_CHILD_ENV_ALLOWLIST = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    }
)


@dataclass(frozen=True)
class _SessionSweep:
    sessions_by_id: dict[str, dict[str, Any]]
    total_count: int


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    # HiveMind owns its authentication through `hivemind login`. Do not leak
    # unrelated destination/model credentials into the child process or allow
    # WANDB_API_KEY to override the CLI's stored authenticated identity.
    child_env = {key: os.environ[key] for key in _CHILD_ENV_ALLOWLIST if key in os.environ}
    account = pwd.getpwuid(os.geteuid())
    binary_directory = os.path.dirname(os.path.abspath(command[0]))
    child_env.update(
        {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "PATH": ":".join(
                dict.fromkeys(
                    [binary_directory, "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                )
            ),
        }
    )
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        env=child_env,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=_CLI_TIMEOUT_SECONDS,
    )


class HiveMindClient:
    """Small adapter that never reads or stores HiveMind credentials itself."""

    def __init__(
        self,
        *,
        binary: str = "hivemind",
        runner: CommandRunner = _default_runner,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self.binary = binary
        self.runner = runner
        self.sleeper = sleeper
        self.user_id: str | None = None

    def _run(self, arguments: list[str], *, purpose: str) -> dict[str, Any]:
        try:
            result = self.runner([self.binary, *arguments])
        except FileNotFoundError as error:
            raise AuthenticationError(
                "hivemind executable was not found; install HiveMind and run 'hivemind login'"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise HiveMindAPIError(f"HiveMind timed out while {purpose}") from error
        except OSError as error:
            raise HiveMindAPIError(
                f"HiveMind could not start while {purpose} ({error.__class__.__name__})"
            ) from error

        if result.returncode != 0:
            # CLI stderr is untrusted and can contain transcript fragments or
            # server diagnostics with secrets. Report only the status code.
            raise HiveMindAPIError(
                f"HiveMind failed while {purpose} (exit status {result.returncode})"
            )
        try:
            payload = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as error:
            # Never include stdout here: transcript responses can contain full private chats.
            raise HiveMindAPIError(f"HiveMind returned invalid JSON while {purpose}") from error
        if not isinstance(payload, dict):
            raise HiveMindAPIError(f"HiveMind returned an unexpected JSON shape while {purpose}")
        return payload

    def preflight(self) -> None:
        if self.runner is _default_runner:
            resolved_binary = shutil.which(self.binary)
            if resolved_binary is None:
                raise AuthenticationError(
                    "hivemind executable was not found; install HiveMind and run 'hivemind login'"
                )
            self.binary = os.path.realpath(resolved_binary)
        try:
            payload = self._run(
                ["api", "/auth/me", "--raw"],
                purpose="checking authentication",
            )
        except HiveMindAPIError as error:
            raise AuthenticationError(
                "HiveMind is not authenticated; run 'hivemind login' and retry"
            ) from error
        user_id = payload.get("user_id")
        if not isinstance(user_id, str) or not user_id.strip():
            raise AuthenticationError(
                "HiveMind authentication response did not include a stable user ID; "
                "run 'hivemind login'"
            )
        self.user_id = user_id.strip()
        try:
            read_check = self._run(
                [
                    "api",
                    "/sessions",
                    "--raw",
                    "-q",
                    "page=1",
                    "-q",
                    "page_size=10",
                    "-q",
                    f"user_id={self.user_id}",
                ],
                purpose="checking session read access",
            )
        except HiveMindAPIError as error:
            raise AuthenticationError(
                "HiveMind credentials cannot read sessions; log in with read access and retry"
            ) from error
        if not isinstance(read_check.get("sessions"), list):
            raise AuthenticationError(
                "HiveMind read-access check returned an invalid session response"
            )

    def list_sessions(self, *, days: int, include_subagents: bool = True) -> list[dict[str, Any]]:
        if self.user_id is None:
            raise AuthenticationError(
                "HiveMind user scope is unknown; authenticate with 'hivemind login' and retry"
            )
        for attempt in range(1, _SESSION_SNAPSHOT_ATTEMPTS + 1):
            try:
                primary = self._list_sessions_sweep(
                    days=days,
                    include_subagents=include_subagents,
                    page_size=_SESSION_PRIMARY_SWEEP[0],
                    sort_direction=_SESSION_PRIMARY_SWEEP[1],
                )
            except HiveMindAPIError as error:
                if str(error) != _SESSION_TOTAL_DRIFT_ERROR:
                    raise
            else:
                # Preserve the ordinary path: one internally stable ASC/100 sweep whose
                # unique-ID cardinality equals total_count is already a complete snapshot.
                if len(primary.sessions_by_id) == primary.total_count:
                    return self._ordered_sessions(primary.sessions_by_id)
                recovered = self._recover_sessions(
                    days=days,
                    include_subagents=include_subagents,
                    primary=primary,
                )
                if recovered is not None:
                    return recovered
            if attempt < _SESSION_SNAPSHOT_ATTEMPTS:
                self.sleeper(_SESSION_SNAPSHOT_RETRY_DELAY_SECONDS)
        raise HiveMindAPIError(_SESSION_COMPLETENESS_ERROR)

    def _recover_sessions(
        self,
        *,
        days: int,
        include_subagents: bool,
        primary: _SessionSweep,
    ) -> list[dict[str, Any]] | None:
        """Repair a deficient primary sweep without ever accepting a partial result."""
        epoch_total = primary.total_count
        sessions_by_id = dict(primary.sessions_by_id)
        for page_size, sort_direction in _SESSION_RECOVERY_SWEEPS:
            try:
                sweep = self._list_sessions_sweep(
                    days=days,
                    include_subagents=include_subagents,
                    page_size=page_size,
                    sort_direction=sort_direction,
                )
            except HiveMindAPIError as error:
                if str(error) == _SESSION_TOTAL_DRIFT_ERROR:
                    # A sweep that straddles a changing live set cannot seed or confirm an
                    # epoch. Start again from the primary ordering after the retry delay.
                    return None
                raise

            # Any one exact sweep carries the same proof as the primary sweep and does not
            # need to rely on IDs accumulated under another page boundary.
            if len(sweep.sessions_by_id) == sweep.total_count:
                return self._ordered_sessions(sweep.sessions_by_id)

            if sweep.total_count != epoch_total:
                epoch_total = sweep.total_count
                sessions_by_id = dict(sweep.sessions_by_id)
                continue

            merged = dict(sessions_by_id)
            merged.update(sweep.sessions_by_id)
            if len(merged) > epoch_total:
                # Same-count membership churn means the previous epoch is stale. The current
                # internally stable sweep is the only safe seed for a new proof attempt.
                sessions_by_id = dict(sweep.sessions_by_id)
                continue
            sessions_by_id = merged
            if len(sessions_by_id) != epoch_total:
                continue

            # Completeness assembled from multiple deficient sweeps needs one independent,
            # exact sweep with the same total and membership. A deficient subset cannot
            # distinguish a stable candidate from same-count membership churn.
            try:
                confirmation = self._list_sessions_sweep(
                    days=days,
                    include_subagents=include_subagents,
                    page_size=_SESSION_PRIMARY_SWEEP[0],
                    sort_direction=_SESSION_PRIMARY_SWEEP[1],
                )
            except HiveMindAPIError as error:
                if str(error) == _SESSION_TOTAL_DRIFT_ERROR:
                    return None
                raise
            confirmation_ids = set(confirmation.sessions_by_id)
            if confirmation.total_count != epoch_total:
                return None
            candidate_ids = set(sessions_by_id)
            if len(confirmation_ids) != epoch_total:
                return None
            if confirmation_ids != candidate_ids:
                return None
            sessions_by_id.update(confirmation.sessions_by_id)
            return self._ordered_sessions(sessions_by_id)
        return None

    @staticmethod
    def _ordered_sessions(
        sessions_by_id: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        far_future = datetime.max.replace(tzinfo=UTC)
        return sorted(
            sessions_by_id.values(),
            key=lambda item: (
                parse_datetime(item.get("started_at")) or far_future,
                str(item.get("id", "")),
            ),
        )

    def _list_sessions_sweep(
        self,
        *,
        days: int,
        include_subagents: bool,
        page_size: int,
        sort_direction: str,
    ) -> _SessionSweep:
        """Read one bounded page-number sweep and retain every unique session ID."""
        page = 1
        sessions_by_id: dict[str, dict[str, Any]] = {}
        expected_total: int | None = None
        previous_new_started_at: datetime | None = None
        while True:
            payload = self._run(
                [
                    "api",
                    "/sessions",
                    "--raw",
                    "-q",
                    f"days={days}",
                    "-q",
                    f"page={page}",
                    "-q",
                    f"page_size={page_size}",
                    "-q",
                    "sort_by=started_at",
                    "-q",
                    f"sort_direction={sort_direction}",
                    "-q",
                    f"include_subagents={'true' if include_subagents else 'false'}",
                    "-q",
                    f"user_id={self.user_id}",
                ],
                purpose=f"listing sessions page {page}",
            )
            items = payload.get("sessions")
            if not isinstance(items, list):
                raise HiveMindAPIError("HiveMind session response is missing a sessions list")
            total_count = payload.get("total_count")
            if isinstance(total_count, bool) or not isinstance(total_count, int) or total_count < 0:
                raise HiveMindAPIError("HiveMind session response is missing valid total_count")
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise HiveMindAPIError("HiveMind session total_count changed during pagination")
            returned_page = payload.get("page")
            returned_page_size = payload.get("page_size")
            if type(returned_page) is not int or returned_page != page:
                raise HiveMindAPIError("HiveMind returned an unexpected page number")
            if type(returned_page_size) is not int or returned_page_size != page_size:
                raise HiveMindAPIError("HiveMind returned an unexpected page_size")
            if (
                payload.get("sort_by") != "started_at"
                or payload.get("sort_direction") != sort_direction
            ):
                raise HiveMindAPIError("HiveMind returned an unexpected session sort order")
            if len(items) > page_size:
                raise HiveMindAPIError(
                    "HiveMind returned more sessions than the requested page_size"
                )
            page_previous_started_at: datetime | None = None
            for item in items:
                if not isinstance(item, dict):
                    raise HiveMindAPIError("HiveMind returned a non-object session summary")
                session_id = item.get("id")
                if not isinstance(session_id, str) or not session_id:
                    raise HiveMindAPIError("HiveMind returned a session without an id")
                started_at = parse_datetime(item.get("started_at"))
                if started_at is None:
                    raise HiveMindAPIError("HiveMind returned a session with invalid started_at")
                if page_previous_started_at is not None and (
                    (sort_direction == "asc" and started_at < page_previous_started_at)
                    or (sort_direction == "desc" and started_at > page_previous_started_at)
                ):
                    raise HiveMindAPIError("HiveMind returned sessions outside the requested order")
                page_previous_started_at = started_at
                if session_id not in sessions_by_id:
                    if previous_new_started_at is not None and (
                        (sort_direction == "asc" and started_at < previous_new_started_at)
                        or (sort_direction == "desc" and started_at > previous_new_started_at)
                    ):
                        raise HiveMindAPIError(
                            "HiveMind returned sessions outside the requested order"
                        )
                    previous_new_started_at = started_at
                sessions_by_id[session_id] = item

            has_more = payload.get("has_more")
            if not isinstance(has_more, bool):
                raise HiveMindAPIError("HiveMind session response is missing boolean has_more")
            if not has_more:
                break
            if not items:
                raise HiveMindAPIError("HiveMind returned an empty session page with has_more=true")
            page += 1
            if page > _SESSION_PAGE_LIMIT:
                raise HiveMindAPIError("HiveMind pagination exceeded its safety limit")
        assert expected_total is not None  # The API always returns at least page one.
        return _SessionSweep(sessions_by_id=sessions_by_id, total_count=expected_total)

    def get_session(self, session_id: str) -> dict[str, Any]:
        """Fetch one already-known session without scanning a moving time window."""
        safe_id = quote(session_id, safe="")
        payload = self._run(
            ["api", f"/sessions/{safe_id}", "--raw"],
            purpose="fetching the selected session summary",
        )
        returned_id = payload.get("id")
        if not isinstance(returned_id, str) or returned_id != session_id:
            raise HiveMindAPIError("HiveMind selected-session summary identity does not match")
        return payload

    def get_atif(self, session_id: str) -> dict[str, Any]:
        safe_id = quote(session_id, safe="")
        arguments = [
            "api",
            f"/sessions/{safe_id}/llm",
            "--raw",
            "-q",
            "format=atif",
            "-q",
            "event_types=user,assistant,reasoning,tools,files,errors",
        ]
        payload: dict[str, Any] | None = None
        for attempt in range(1, _ATIF_FETCH_ATTEMPTS + 1):
            try:
                payload = self._run(
                    arguments,
                    purpose="fetching ATIF for the selected session",
                )
                break
            except HiveMindAPIError as error:
                transient = str(error).startswith(
                    (
                        "HiveMind timed out while fetching ATIF for the selected session",
                        "HiveMind failed while fetching ATIF for the selected session",
                        "HiveMind returned invalid JSON while fetching ATIF "
                        "for the selected session",
                    )
                )
                if not transient or attempt == _ATIF_FETCH_ATTEMPTS:
                    raise
                self.sleeper(_ATIF_FETCH_RETRY_DELAY_SECONDS)
        if payload is None:  # pragma: no cover - loop must return or raise.
            raise AssertionError("ATIF fetch retry loop ended unexpectedly")
        trajectory = payload.get("trajectory")
        if not isinstance(trajectory, dict):
            raise HiveMindAPIError("HiveMind selected-session ATIF response is missing trajectory")
        wrapper_session_id = payload.get("session_id")
        if not isinstance(wrapper_session_id, str) or wrapper_session_id != session_id:
            raise HiveMindAPIError(
                "HiveMind selected-session ATIF response identity does not match"
            )
        step_count = payload.get("step_count")
        if isinstance(step_count, bool) or not isinstance(step_count, int) or step_count < 0:
            raise HiveMindAPIError("HiveMind selected-session ATIF response has invalid step_count")
        if not isinstance(payload.get("metadata"), dict):
            raise HiveMindAPIError("HiveMind selected-session ATIF response has invalid metadata")
        return payload
