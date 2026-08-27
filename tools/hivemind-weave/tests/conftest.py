from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def session_payload() -> Callable[..., dict[str, Any]]:
    def build(**overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": "11111111-1111-4111-8111-111111111111",
            "agent_session_id": "agent-session-1",
            "title": "Implement the importer",
            "agent_type": "codex",
            "model": "gpt-5.6-codex",
            "started_at": "2026-08-01T12:00:00Z",
            "last_activity_at": "2026-08-01T12:20:00Z",
            "git_repo": "wandb/hivemind",
            "git_branch": "codex/importer",
            "parent_session_id": "",
            "username": "developer",
        }
        payload.update(overrides)
        return payload

    return build


@pytest.fixture
def atif_wrapper() -> Callable[..., dict[str, Any]]:
    def build(
        *,
        version: str = "ATIF-v1.7",
        steps: list[dict[str, Any]] | None = None,
        agent: dict[str, Any] | None = None,
        wrapper_session_id: str = "11111111-1111-4111-8111-111111111111",
        **trajectory_overrides: Any,
    ) -> dict[str, Any]:
        if steps is None:
            steps = [
                {
                    "step_id": 1,
                    "timestamp": "2026-08-01T12:00:00Z",
                    "source": "system",
                    "message": "You are a coding agent.",
                },
                {
                    "step_id": 2,
                    "timestamp": "2026-08-01T12:00:01Z",
                    "source": "user",
                    "message": "Create hello.txt",
                },
                {
                    "step_id": 3,
                    "timestamp": "2026-08-01T12:00:02Z",
                    "source": "agent",
                    "model_name": "gpt-5.6-codex",
                    "message": "I will create it.",
                    "reasoning_content": "Use the write tool.",
                    "tool_calls": [
                        {
                            "tool_call_id": "call-1",
                            "function_name": "write_file",
                            "arguments": {"path": "hello.txt", "content": "hello"},
                        }
                    ],
                    "observation": {
                        "results": [
                            {
                                "source_call_id": "call-1",
                                "content": {"ok": True},
                            }
                        ]
                    },
                    "metrics": {
                        "prompt_tokens": 10,
                        "completion_tokens": 4,
                        "cached_tokens": 2,
                        "reasoning_tokens": 1,
                    },
                    "finish_reason": "tool_call",
                },
                {
                    "step_id": 4,
                    "timestamp": "2026-08-01T12:00:04Z",
                    "source": "agent",
                    "message": "Created hello.txt.",
                },
            ]
        trajectory: dict[str, Any] = {
            "schema_version": version,
            "session_id": "atif-session",
            "agent": agent or {"name": "codex", "version": "1.2.3", "model_name": "gpt-5.6-codex"},
            "steps": steps,
        }
        trajectory.update(trajectory_overrides)
        return {
            "session_id": wrapper_session_id,
            "trajectory": trajectory,
            "step_count": len(steps),
            "metadata": {},
        }

    return build
