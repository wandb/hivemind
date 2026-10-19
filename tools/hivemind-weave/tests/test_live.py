from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from hivemind_weave.review import (
    REVIEW_PROJECT,
    ReviewApplyConfig,
    ReviewPreviewConfig,
    apply_review,
    preview_review,
)

pytestmark = pytest.mark.live

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FIXTURE_NOW = datetime(2026, 8, 3, tzinfo=UTC)
_FIXTURE_SINCE = "2026-08-01T00:00:00Z"
_FIXTURE_UNTIL = "2026-08-02T00:00:00Z"
_LARGE_BLOCK_BYTES = 64 * 1024
_LARGE_BLOCK_COUNT = 144


class SyntheticHiveMind:
    """In-memory source for the opt-in smoke; it never invokes HiveMind."""

    def __init__(self, *, run_id: str) -> None:
        session_id = str(
            UUID(
                bytes=hashlib.sha256(f"hivemind-weave-review-smoke:{run_id}".encode()).digest()[
                    :16
                ],
                version=4,
            )
        )
        # Keep the transport fixture large without turning the smoke into a
        # pathological NER benchmark over thousands of repeated declarations.
        # The content is intentionally inert and already contains no PII.
        block = "x" * _LARGE_BLOCK_BYTES
        large_result = {
            "fixture": "hivemind-review-large-v1",
            "chunks": [block] * _LARGE_BLOCK_COUNT,
        }
        self.user_id: str | None = "22222222-2222-4222-8222-222222222222"
        self.session = {
            "id": session_id,
            "agent_session_id": f"run-{session_id}",
            "title": "Deterministic synthetic large review smoke",
            "agent_type": "codex",
            "model": "gpt-5.6-codex",
            "started_at": "2026-08-01T12:00:00Z",
            "last_activity_at": "2026-08-01T12:05:00Z",
            "git_repo": "wandb/hivemind",
            "git_branch": "synthetic/review-smoke",
            "parent_session_id": "",
            "username": "synthetic-review-user",
        }
        steps: list[dict[str, Any]] = [
            {
                "step_id": 1,
                "timestamp": "2026-08-01T12:00:00Z",
                "source": "system",
                "message": "Validate only the deterministic synthetic review fixture.",
            },
            {
                "step_id": 2,
                "timestamp": "2026-08-01T12:00:01Z",
                "source": "user",
                "message": "Inspect the generated synthetic archive and summarize its shape.",
            },
            {
                "step_id": 3,
                "timestamp": "2026-08-01T12:00:02Z",
                "source": "agent",
                "model_name": "gpt-5.6-codex",
                "message": "I will inspect the deterministic archive.",
                "reasoning_content": "Check the declared chunk count and preserve the full result.",
                "tool_calls": [
                    {
                        "tool_call_id": "call-synthetic-1",
                        "function_name": "inspect_synthetic_archive",
                        "arguments": {
                            "fixture": "hivemind-review-large-v1",
                            "expected_chunks": _LARGE_BLOCK_COUNT,
                        },
                    }
                ],
                "observation": {
                    "results": [
                        {
                            "source_call_id": "call-synthetic-1",
                            "content": large_result,
                        }
                    ]
                },
                "metrics": {
                    "prompt_tokens": 32,
                    "completion_tokens": 16,
                    "cached_tokens": 0,
                    "reasoning_tokens": 8,
                },
                "finish_reason": "tool_call",
            },
            {
                "step_id": 4,
                "timestamp": "2026-08-01T12:05:00Z",
                "source": "agent",
                "model_name": "gpt-5.6-codex",
                "message": (
                    "The deterministic synthetic archive is complete and internally consistent."
                ),
                "finish_reason": "stop",
            },
        ]
        self.transcript = {
            "session_id": session_id,
            "trajectory": {
                "schema_version": "ATIF-v1.7",
                "session_id": f"atif-{session_id}",
                "agent": {
                    "name": "codex",
                    "version": "synthetic-review-v1",
                    "model_name": "gpt-5.6-codex",
                },
                "steps": steps,
            },
            "step_count": len(steps),
            "metadata": {"fixture": "hivemind-review-large-v1"},
        }

    def preflight(self) -> None:
        return None

    def list_sessions(self, *, days: int, include_subagents: bool) -> list[dict[str, Any]]:
        assert 1 <= days <= 365
        assert include_subagents is True
        return [dict(self.session)]

    def get_session(self, session_id: str) -> dict[str, Any]:
        assert session_id == self.session["id"]
        return dict(self.session)

    def get_atif(self, session_id: str) -> dict[str, Any]:
        assert session_id == self.session["id"]
        return self.transcript


def _required_live_state_path() -> Path:
    raw = os.environ.get("HIVEMIND_WEAVE_LIVE_STATE_PATH", "").strip()
    if not raw:
        pytest.fail(
            "live synthetic review requires HIVEMIND_WEAVE_LIVE_STATE_PATH pointing to a "
            "caller-owned persistent private SQLite path"
        )
    path = Path(raw).expanduser()
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        pytest.fail("HIVEMIND_WEAVE_LIVE_STATE_PATH must be an absolute database-file path")
    resolved = Path(os.path.abspath(path))
    volatile_roots = {
        Path("/tmp"),
        Path("/private/tmp"),
        Path(tempfile.gettempdir()).resolve(),
    }
    if any(resolved == root or root in resolved.parents for root in volatile_roots):
        pytest.fail("HIVEMIND_WEAVE_LIVE_STATE_PATH must not use a temporary directory")
    parent = resolved.parent
    if not parent.is_dir():
        pytest.fail("create the dedicated persistent state directory before running the live smoke")
    details = parent.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        pytest.fail("the live-smoke state directory must be caller-owned with mode 0700")
    return resolved


def test_fixed_project_synthetic_review_is_idempotent() -> None:
    if os.environ.get("HIVEMIND_WEAVE_LIVE") != "1":
        pytest.skip("set HIVEMIND_WEAVE_LIVE=1 to enable the live synthetic review smoke")
    if os.environ.get("HIVEMIND_WEAVE_LIVE_CONFIRM_PROJECT") != REVIEW_PROJECT:
        pytest.fail(
            "HIVEMIND_WEAVE_LIVE_CONFIRM_PROJECT must exactly equal wandb/hivemind-chats-review"
        )
    if not os.environ.get("WANDB_API_KEY"):
        pytest.fail("live synthetic review requires WANDB_API_KEY in the process environment")
    run_id = os.environ.get("HIVEMIND_WEAVE_LIVE_RUN_ID", "").strip()
    if not _RUN_ID.fullmatch(run_id):
        pytest.fail(
            "HIVEMIND_WEAVE_LIVE_RUN_ID must be a new bounded ASCII identifier for this smoke"
        )

    state_path = _required_live_state_path()
    client = SyntheticHiveMind(run_id=run_id)
    preview = preview_review(
        ReviewPreviewConfig(
            since=_FIXTURE_SINCE,
            until=_FIXTURE_UNTIL,
            project=REVIEW_PROJECT,
            state_path=state_path,
            session_ids=(client.session["id"],),
            now=_FIXTURE_NOW,
        ),
        hivemind=client,  # type: ignore[arg-type]
    )
    assert preview.ok, preview.render()
    assert preview.selected_sessions == 1
    assert preview.turns == 1
    assert preview.manifest_bytes > 8 * 1024 * 1024
    assert preview.max_chunks_per_turn >= 2

    apply_config = ReviewApplyConfig(
        plan_id=preview.plan_id,
        confirm_project=REVIEW_PROJECT,
        state_path=state_path,
        max_sessions=1,
    )
    first = apply_review(apply_config, hivemind=client)  # type: ignore[arg-type]
    assert first.ok, first.render()
    assert first.visible_turns == 1, (
        "the run ID must be new for the persistent state journal; preserve this state path "
        "after any uncertain result"
    )
    assert first.remaining_sessions == 0

    second = apply_review(apply_config, hivemind=client)  # type: ignore[arg-type]
    assert second.ok, second.render()
    assert second.visible_turns == 0
    assert second.uncertain_turns == 0
    assert second.conflicted_turns == 0
    assert second.remaining_sessions == 0
