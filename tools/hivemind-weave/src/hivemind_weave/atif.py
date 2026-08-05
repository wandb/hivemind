"""Tolerant ATIF 1.x to Weave-conversation normalization."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import __version__
from .errors import ATIFSchemaError
from .models import (
    ChatMessage,
    MappedConversation,
    MappedLLM,
    MappedSubAgent,
    MappedTool,
    MappedTurn,
    Session,
)
from .redaction import redact_data, redact_string
from .utils import (
    canonical_json,
    coerce_int,
    coerce_string,
    first_present,
    parse_datetime,
    sha256_json,
)

_VERSION = re.compile(r"^(?:ATIF-)?v?(\d+)(?:\.(\d+))?$", re.IGNORECASE)
_AGENT_SOURCES = {"agent", "assistant"}
_OBSERVATION_SOURCES = {"tool", "observation", "environment"}


@dataclass
class _Step:
    raw: dict[str, Any]
    index: int
    step_id: str
    source: str
    timestamp: datetime
    timestamp_inferred: bool = False


@dataclass
class _Group:
    steps: list[_Step] = field(default_factory=list)
    copied_context: list[_Step] = field(default_factory=list)
    trailing_copied: list[_Step] = field(default_factory=list)
    synthetic: bool = False


@dataclass
class _Observation:
    uid: str
    step_index: int
    call_id: str
    content: Any
    timestamp: datetime
    subagent_refs: list[Any] = field(default_factory=list)
    consumed: bool = False
    context_added: bool = False


def _subagent_reference_key(reference: Any) -> str:
    if isinstance(reference, dict):
        return coerce_string(
            first_present(
                reference,
                "trajectory_id",
                "trajectory_path",
                "id",
                default="",
            )
        )
    return coerce_string(reference)


def content_to_text(value: Any) -> str:
    """Preserve ATIF string or multimodal content in a displayable text field."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for part in value:
            if isinstance(part, dict) and str(part.get("type", "")).lower() == "text":
                text = first_present(part, "text", "content", default="")
                parts.append(coerce_string(text))
            else:
                # Keep image/file/source details rather than dropping non-text content.
                parts.append(canonical_json(part))
        return "\n".join(item for item in parts if item)
    return canonical_json(value)


def verification_signature(
    started_at: datetime,
    messages: list[ChatMessage],
    output_messages: list[ChatMessage],
) -> str:
    first_user = next((item.content for item in messages if item.role == "user"), "")
    last_assistant = next(
        (item.content for item in reversed(output_messages) if item.role == "assistant"),
        "",
    )
    return sha256_json(
        {
            "started_at_ms": int(started_at.timestamp() * 1000),
            "first_user": first_user,
            "last_assistant": last_assistant,
        }
    )


def _turn_key_component(step: _Step) -> str:
    stripped = step.step_id.strip()
    if re.fullmatch(r"\d{1,20}", stripped) and redact_string(stripped) == stripped:
        return stripped
    # ATIF step IDs are source-controlled and may contain paths, credentials,
    # or low-entropy PII. Hashing those values would create a durable guessing
    # oracle, so non-technical IDs use their stable transcript position instead.
    return f"index:{step.index}"


def _validate_schema_version(value: Any) -> str:
    version = coerce_string(value).strip()
    match = _VERSION.fullmatch(version)
    if not match:
        raise ATIFSchemaError("unsupported or missing ATIF schema_version")
    if int(match.group(1)) != 1:
        raise ATIFSchemaError(f"unsupported ATIF major version {int(match.group(1))}")
    minor = int(match.group(2) or 0)
    return f"ATIF-v1.{minor}"


def _normalize_steps(raw_steps: Any, session: Session) -> list[_Step]:
    if not isinstance(raw_steps, list):
        raise ATIFSchemaError("ATIF trajectory is missing a steps list")
    steps: list[_Step] = []
    previous: datetime | None = None
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise ATIFSchemaError(f"ATIF step {index + 1} is not an object")
        source = coerce_string(raw.get("source")).strip().lower()
        if not source:
            raise ATIFSchemaError(f"ATIF step {index + 1} is missing source")
        timestamp = parse_datetime(raw.get("timestamp"))
        inferred = timestamp is None
        if timestamp is None:
            timestamp = (
                session.started_at if previous is None else previous + timedelta(microseconds=1)
            )
        if previous is not None and timestamp < previous:
            timestamp = previous
            inferred = True
        previous = timestamp
        step_id = coerce_string(raw.get("step_id"), str(index + 1))
        steps.append(
            _Step(
                raw=raw,
                index=index,
                step_id=step_id,
                source=source,
                timestamp=timestamp,
                timestamp_inferred=inferred,
            )
        )
    return steps


def _split_groups(steps: list[_Step]) -> list[_Group]:
    groups: list[_Group] = []
    current: _Group | None = None
    pending_system: list[_Step] = []
    pending_copied: list[_Step] = []
    for step in steps:
        if step.raw.get("is_copied_context") is True:
            pending_copied.append(step)
            continue
        if step.source == "user":
            if current is not None:
                groups.append(current)
            current = _Group(
                steps=[*pending_system, step],
                copied_context=pending_copied,
                synthetic=False,
            )
            pending_system = []
            pending_copied = []
        elif step.source == "system" and current is None:
            pending_system.append(step)
        else:
            if current is None:
                current = _Group(
                    steps=[*pending_system],
                    copied_context=pending_copied,
                    synthetic=True,
                )
                pending_system = []
                pending_copied = []
            elif pending_copied:
                # A copied-context suffix is not yet known to belong to a
                # future user turn. Preserve it on the current turn without
                # making it part of that turn's typed LLM input or payload
                # hash. If a user turn later appears, the same steps become
                # its leading context without rehashing imported history.
                current.trailing_copied.extend(pending_copied)
                pending_copied = []
            current.steps.append(step)
    if current is not None:
        # Keep an unresolved EOF suffix in a non-hashed archival attribute.
        # A later append can then move it into the next turn's LLM input while
        # the already-imported turn remains identical for journal purposes.
        current.trailing_copied.extend(pending_copied)
        groups.append(current)
    # Leading system/copy-only prefixes are not complete turns. Waiting for a
    # non-copied user or output step prevents a temporary synthetic turn from
    # becoming stale when the live transcript is later appended.
    return groups


def _observation_results(
    step: _Step,
    embedded_subagents: dict[str, dict[str, Any]],
) -> list[_Observation]:
    containers: list[Any] = []
    if "observation" in step.raw:
        containers.append(step.raw.get("observation"))
    if "observations" in step.raw:
        containers.append(step.raw.get("observations"))
    if step.source in _OBSERVATION_SOURCES and not containers:
        containers.append(step.raw)

    raw_results: list[Any] = []
    for container in containers:
        if isinstance(container, dict) and isinstance(container.get("results"), list):
            raw_results.extend(container["results"])
        elif isinstance(container, list):
            raw_results.extend(container)
        elif isinstance(container, dict):
            raw_results.append(container)

    results: list[_Observation] = []
    for offset, result in enumerate(raw_results):
        if not isinstance(result, dict):
            result = {"content": result}
        call_id = coerce_string(
            first_present(
                result,
                "source_call_id",
                "tool_call_id",
                "call_id",
                "id",
                default="",
            )
        )
        content = first_present(result, "content", "result", "output", "message", default=None)
        reference = first_present(
            result,
            "subagent_trajectory_ref",
            "trajectory_path",
            default=None,
        )
        correlation_keys = {
            "source_call_id",
            "tool_call_id",
            "call_id",
            "id",
            "step_id",
            "timestamp",
            "ended_at",
            "end_time",
            "source",
        }
        content_keys = {"content", "result", "output", "message"}
        reference_keys = {"subagent_trajectory_ref", "trajectory_path"}
        remaining = {
            key: value
            for key, value in result.items()
            if key not in correlation_keys | content_keys | reference_keys
        }
        references = (
            reference
            if isinstance(reference, list)
            else ([reference] if reference is not None else [])
        )
        if reference is None and not remaining:
            preserved_content: Any = content if content is not None else ""
        else:
            preserved: dict[str, Any] = dict(remaining)
            if content is not None:
                preserved["content"] = content
            if reference is not None:
                preserved["subagent_trajectory_ref"] = reference
                matched_trajectories: list[dict[str, Any]] = []
                for item in references:
                    reference_id = _subagent_reference_key(item)
                    if reference_id in embedded_subagents:
                        matched_trajectories.append(embedded_subagents[reference_id])
                if len(matched_trajectories) == 1:
                    preserved["trajectory"] = matched_trajectories[0]
                elif matched_trajectories:
                    preserved["trajectories"] = matched_trajectories
            preserved_content = preserved
        results.append(
            _Observation(
                uid=f"{step.index}:{offset}",
                step_index=step.index,
                call_id=call_id,
                content=preserved_content,
                timestamp=step.timestamp,
                subagent_refs=references,
            )
        )
    return results


def _tool_calls(step: _Step) -> list[dict[str, Any]]:
    calls = step.raw.get("tool_calls")
    if calls is None:
        return []
    if not isinstance(calls, list):
        return [{"function_name": "invalid_tool_calls", "arguments": calls}]
    return [call if isinstance(call, dict) else {"arguments": call} for call in calls]


def _map_subagent(
    reference: Any,
    embedded_subagents: dict[str, dict[str, Any]],
    fallback_timestamp: datetime,
) -> MappedSubAgent:
    reference_data = reference if isinstance(reference, dict) else {}
    reference_id = _subagent_reference_key(reference)
    trajectory = embedded_subagents.get(reference_id, {})
    agent = trajectory.get("agent") if isinstance(trajectory.get("agent"), dict) else {}
    raw_steps = trajectory.get("steps") if isinstance(trajectory.get("steps"), list) else []
    timestamps = [
        parsed
        for raw_step in raw_steps
        if isinstance(raw_step, dict)
        and (parsed := parse_datetime(raw_step.get("timestamp"))) is not None
    ]
    system_instructions: list[str] = []
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        source = coerce_string(raw_step.get("source")).lower()
        if source == "system":
            text = content_to_text(raw_step.get("message"))
            if text:
                system_instructions.append(text)
        elif source == "user":
            break
    reference_extra = (
        reference_data.get("extra") if isinstance(reference_data.get("extra"), dict) else {}
    )
    started_at = min(timestamps) if timestamps else fallback_timestamp
    ended_at = max(timestamps) if timestamps else fallback_timestamp
    return MappedSubAgent(
        name=coerce_string(
            first_present(
                agent,
                "name",
                default=first_present(reference_extra, "agent_name", default="subagent"),
            )
        ),
        model=coerce_string(
            first_present(
                agent,
                "model_name",
                "model",
                default=first_present(reference_extra, "model", default=""),
            )
        ),
        # ATIF v1.7 resolves siblings by trajectory ID/path. session_id is
        # informational and can collide, so use it only for legacy refs.
        agent_id=(
            coerce_string(first_present(reference_data, "trajectory_id", "id", default=""))
            or (
                "trajectory-path:"
                + sha256_json(
                    {"trajectory_path": coerce_string(reference_data.get("trajectory_path"))}
                )[:24]
                if coerce_string(reference_data.get("trajectory_path"))
                else ""
            )
            or coerce_string(reference_data.get("session_id"))
            or reference_id
            or "subagent"
        ),
        description="Explicit delegation recorded by the ATIF transcript",
        version=coerce_string(agent.get("version")),
        system_instructions=system_instructions,
        started_at=started_at,
        ended_at=max(started_at, ended_at),
        # ATIF steps have point timestamps rather than explicit child-span ends.
        timestamp_inferred=True,
    )


def _provider(model: str, agent_type: str, explicit: str) -> str:
    if explicit:
        return explicit.lower()
    probe = f"{model} {agent_type}".lower()
    if "claude" in probe or "anthropic" in probe:
        return "anthropic"
    if "gemini" in probe or "google" in probe:
        return "google"
    if any(item in probe for item in ("codex", "openai", "gpt-")) or re.search(
        r"\bo[134](?:\b|[-.])", probe
    ):
        return "openai"
    return "unknown"


def _usage(metrics: Any) -> dict[str, int]:
    if not isinstance(metrics, dict):
        metrics = {}
    extra = metrics.get("extra") if isinstance(metrics.get("extra"), dict) else {}
    return {
        "input_tokens": coerce_int(
            first_present(metrics, "input_tokens", "prompt_tokens", default=0)
        ),
        "output_tokens": coerce_int(
            first_present(metrics, "output_tokens", "completion_tokens", default=0)
        ),
        "reasoning_tokens": coerce_int(
            first_present(metrics, "reasoning_tokens", default=extra.get("reasoning_tokens", 0))
        ),
        "cache_creation_input_tokens": coerce_int(
            first_present(
                metrics,
                "cache_creation_input_tokens",
                default=extra.get("cache_creation_input_tokens", 0),
            )
        ),
        "cache_read_input_tokens": coerce_int(
            first_present(
                metrics,
                "cache_read_input_tokens",
                "cached_tokens",
                default=first_present(extra, "cache_read_input_tokens", "cached_tokens", default=0),
            )
        ),
    }


def _finish_reasons(raw: dict[str, Any]) -> list[str]:
    value = first_present(raw, "finish_reasons", "finish_reason", "stop_reason", default=[])
    if isinstance(value, list):
        return [coerce_string(item) for item in value if coerce_string(item)]
    reason = coerce_string(value)
    return [reason] if reason else []


def _preserved_step_data(step: _Step) -> dict[str, Any]:
    """Keep the exact redacted ATIF step alongside its typed Weave fields.

    Typed fields power the Agents UI, while this canonical copy guarantees
    tolerant 1.x parsing never silently loses a vendor field or source shape.
    """
    return {
        "step_id": step.step_id,
        "source": step.source,
        "raw_step": step.raw,
    }


def _step_end(step: _Step, group: _Group) -> tuple[datetime, bool]:
    explicit = parse_datetime(first_present(step.raw, "ended_at", "end_time", default=None))
    if explicit is not None and explicit >= step.timestamp:
        return (explicit, False)
    metrics = step.raw.get("metrics")
    duration_ms = metrics.get("duration_ms") if isinstance(metrics, dict) else None
    if (
        not isinstance(duration_ms, bool)
        and isinstance(duration_ms, (int, float))
        and math.isfinite(float(duration_ms))
        and duration_ms >= 0
    ):
        return (step.timestamp + timedelta(milliseconds=float(duration_ms)), False)
    later = next(
        (candidate.timestamp for candidate in group.steps if candidate.index > step.index),
        step.timestamp,
    )
    return (max(step.timestamp, later), True)


def _clean_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in attributes.items() if value not in (None, "", [])}


def _embedded_start(value: Any) -> datetime | None:
    if not isinstance(value, dict) or not isinstance(value.get("steps"), list):
        return None
    timestamps = [
        parsed
        for step in value["steps"]
        if isinstance(step, dict) and (parsed := parse_datetime(step.get("timestamp"))) is not None
    ]
    return min(timestamps) if timestamps else None


def _attach_unreferenced_subagents(
    turns: list[MappedTurn],
    payloads: list[Any],
    *,
    session: Session,
) -> None:
    """Keep orphan embedded trajectories without inventing SubAgent spans.

    Each timestamped payload is attached to the closest chronological parent
    turn. Timestamp-less payloads stay on the first turn, preventing an append
    from moving already-imported content and changing a historical hash.
    """
    if not payloads:
        return
    if not turns:
        raise ATIFSchemaError(
            f"session {session.id} has unreferenced embedded trajectories but no turn"
        )
    buckets: list[list[Any]] = [[] for _ in turns]
    for payload in payloads:
        timestamp = _embedded_start(payload)
        if timestamp is None:
            target = 0
        else:
            preceding = [index for index, turn in enumerate(turns) if turn.started_at <= timestamp]
            target = preceding[-1] if preceding else 0
        buckets[target].append(payload)
    for turn, values in zip(turns, buckets, strict=True):
        if not values:
            continue
        turn.attributes["hivemind.unreferenced_subagent_trajectories"] = canonical_json(values)
        warnings = list(turn.attributes.get("hivemind.mapping_warnings", []))
        warnings.append(f"unreferenced_subagent_trajectories:{len(values)}")
        turn.attributes["hivemind.mapping_warnings"] = sorted(set(warnings))
        turn.finalize_hash()


def _map_group(
    group: _Group,
    *,
    session: Session,
    schema_version: str,
    default_model: str,
    default_provider: str,
    embedded_subagents: dict[str, dict[str, Any]],
    embedded_subagent_count: int,
    global_attributes: dict[str, Any],
    hash_context: dict[str, Any],
) -> MappedTurn:
    if not group.steps:
        raise ATIFSchemaError(f"session {session.id} contains an empty turn group")
    warnings: list[str] = []

    root_system_instructions: list[str] = []
    current_system_instructions: list[str] = []
    messages: list[ChatMessage] = []
    context_messages: list[ChatMessage] = []
    llms: list[MappedLLM] = []
    tools: list[MappedTool] = []
    terminal_output: ChatMessage | None = None
    observations = [
        result for step in group.steps for result in _observation_results(step, embedded_subagents)
    ]
    subagents = [
        _map_subagent(reference, embedded_subagents, observation.timestamp)
        for observation in observations
        for reference in observation.subagent_refs
    ]
    child_timestamp_inferred = False

    # Copied context remains LLM input but must not become new root turns/spans.
    for copied in group.copied_context:
        text = content_to_text(copied.raw.get("message"))
        if copied.source == "system":
            if text:
                current_system_instructions.append(text)
                root_system_instructions.append(text)
                context_messages.append(ChatMessage(role="system", content=text))
        elif copied.source == "user" and text:
            context_messages.append(ChatMessage(role="user", content=text))
        elif copied.source in _AGENT_SOURCES and text:
            context_messages.append(ChatMessage(role="assistant", content=text))
        elif copied.source in _OBSERVATION_SOURCES:
            for observation in _observation_results(copied, embedded_subagents):
                context_messages.append(
                    ChatMessage(role="tool", content=content_to_text(observation.content))
                )

    for step in group.steps:
        for observation in observations:
            if observation.step_index < step.index and not observation.context_added:
                context_messages.append(
                    ChatMessage(
                        role="tool",
                        content=content_to_text(observation.content),
                    )
                )
                observation.context_added = True
        if step.source == "system":
            text = content_to_text(step.raw.get("message"))
            if text:
                current_system_instructions.append(text)
                context_messages.append(ChatMessage(role="system", content=text))
                if not llms:
                    root_system_instructions.append(text)
                else:
                    warnings.append(f"system_update_after_llm:{step.step_id}")
            continue
        if step.source == "user":
            message = ChatMessage(role="user", content=content_to_text(step.raw.get("message")))
            messages.append(message)
            context_messages.append(message)
            continue
        if step.source in _AGENT_SOURCES:
            step_extra = step.raw.get("extra")
            if not isinstance(step_extra, dict):
                step_extra = {}
            model = coerce_string(
                first_present(
                    step.raw,
                    "model_name",
                    "model",
                    default=first_present(
                        step_extra,
                        "model_name",
                        "model",
                        default=default_model,
                    ),
                )
            )
            explicit_provider = coerce_string(
                first_present(
                    step.raw,
                    "provider_name",
                    "provider",
                    default=first_present(
                        step_extra,
                        "provider_name",
                        "provider",
                        default=default_provider,
                    ),
                )
            )
            message_text = content_to_text(step.raw.get("message"))
            reasoning = content_to_text(
                first_present(step.raw, "reasoning_content", "reasoning", default="")
            )
            output_messages = (
                [ChatMessage(role="assistant", content=message_text)] if message_text else []
            )
            llm_count = step.raw.get("llm_call_count")
            if isinstance(llm_count, int) and llm_count != 1:
                warnings.append(f"agent_step_{step.step_id}_llm_call_count_{llm_count}")
            llm_ended_at, llm_end_inferred = _step_end(step, group)
            child_timestamp_inferred = child_timestamp_inferred or llm_end_inferred
            llms.append(
                MappedLLM(
                    model=model,
                    provider=_provider(model, session.agent_type, explicit_provider),
                    system_instructions=list(current_system_instructions),
                    input_messages=list(context_messages),
                    output_messages=output_messages,
                    reasoning=reasoning,
                    usage=_usage(step.raw.get("metrics")),
                    finish_reasons=_finish_reasons(step.raw),
                    started_at=step.timestamp,
                    ended_at=llm_ended_at,
                )
            )
            if message_text:
                terminal_output = ChatMessage(role="assistant", content=message_text)
                context_messages.append(terminal_output)

            for call_offset, call in enumerate(_tool_calls(step)):
                function = call.get("function") if isinstance(call.get("function"), dict) else {}
                call_id = (
                    coerce_string(first_present(call, "tool_call_id", "id", "call_id", default=""))
                    or f"unidentified-{step.step_id}-{call_offset + 1}"
                )
                name = coerce_string(
                    first_present(
                        call,
                        "function_name",
                        "name",
                        "tool_name",
                        default=function.get("name", "unknown_tool"),
                    )
                )
                arguments = first_present(
                    call,
                    "arguments",
                    "args",
                    "input",
                    default=function.get("arguments", {}),
                )
                matched = [
                    observation
                    for observation in observations
                    if not observation.consumed and observation.call_id == call_id
                ]
                for observation in matched:
                    observation.consumed = True
                if not matched:
                    warnings.append(f"unmatched_tool_call:{call_id}")
                    result: Any = None
                    tool_end, tool_end_inferred = _step_end(step, group)
                    child_timestamp_inferred = child_timestamp_inferred or tool_end_inferred
                else:
                    result = (
                        matched[0].content
                        if len(matched) == 1
                        else [observation.content for observation in matched]
                    )
                    tool_end = max(observation.timestamp for observation in matched)
                    for observation in matched:
                        if observation.step_index != step.index:
                            continue
                        context_messages.append(
                            ChatMessage(
                                role="tool",
                                content=content_to_text(observation.content),
                            )
                        )
                        observation.context_added = True
                tools.append(
                    MappedTool(
                        name=name or "unknown_tool",
                        arguments=arguments,
                        result=result,
                        tool_call_id=call_id,
                        tool_type=coerce_string(call.get("type")),
                        description=coerce_string(
                            first_present(
                                call,
                                "description",
                                "tool_description",
                                default=function.get("description", ""),
                            )
                        ),
                        started_at=step.timestamp,
                        ended_at=max(step.timestamp, tool_end),
                    )
                )
        elif step.source not in _OBSERVATION_SOURCES:
            text = content_to_text(step.raw.get("message"))
            if text:
                context_messages.append(
                    ChatMessage(role="system", content=f"[{step.source}] {text}")
                )
            warnings.append(f"unknown_step_source:{step.source}")

    for observation in observations:
        if observation.consumed:
            continue
        observation.consumed = True
        call_id = observation.call_id or f"unmatched-{observation.uid}"
        warnings.append(f"unmatched_observation:{call_id}")
        tools.append(
            MappedTool(
                name="unmatched_observation",
                arguments={},
                result=observation.content,
                tool_call_id=call_id,
                tool_type="observation",
                description="ATIF observation without a matching tool call",
                started_at=observation.timestamp,
                ended_at=observation.timestamp,
            )
        )

    first_non_system = next(
        (step for step in group.steps if step.source != "system"), group.steps[0]
    )
    key_prefix = "synthetic" if group.synthetic else "step"
    turn_key = f"atif:{key_prefix}:{_turn_key_component(first_non_system)}"
    turn_started_at = min(step.timestamp for step in group.steps)
    end_candidates = [step.timestamp for step in group.steps]
    end_candidates.extend(
        parsed
        for step in group.steps
        if (parsed := parse_datetime(first_present(step.raw, "ended_at", "end_time"))) is not None
    )
    end_candidates.extend(item.ended_at for item in llms)
    end_candidates.extend(item.ended_at for item in tools)
    end_candidates.extend(item.ended_at for item in subagents)
    turn_ended_at = max(end_candidates)
    inferred = (
        any(step.timestamp_inferred for step in [*group.copied_context, *group.steps])
        or child_timestamp_inferred
        or any(item.timestamp_inferred for item in subagents)
    )
    output_messages = [terminal_output] if terminal_output is not None else []
    preserved_steps = [
        preserved
        for step in [*group.copied_context, *group.steps]
        if (preserved := _preserved_step_data(step))
    ]
    trailing_preserved_steps = [
        preserved for step in group.trailing_copied if (preserved := _preserved_step_data(step))
    ]

    attributes = _clean_attributes(
        {
            **global_attributes,
            "hivemind.session_id": session.id,
            "hivemind.agent_session_id": session.agent_session_id,
            "hivemind.turn_key": turn_key,
            "hivemind.repository": redact_string(session.repository),
            "hivemind.branch": redact_string(session.branch),
            "hivemind.parent_session_id": session.parent_session_id,
            "hivemind.is_subagent": bool(session.parent_session_id),
            "hivemind.atif_schema_version": schema_version,
            "hivemind.importer_version": __version__,
            "hivemind.timestamp_inferred": inferred,
            "hivemind.synthetic_turn": group.synthetic,
            "hivemind.llm_spans_inferred": True,
            "hivemind.copied_context_steps": len(group.copied_context),
            "hivemind.embedded_subagent_count": embedded_subagent_count,
            "hivemind.mapping_warnings": sorted(set(warnings)),
            "hivemind.preserved_step_data": (
                canonical_json(preserved_steps) if preserved_steps else ""
            ),
            # This suffix is deliberately outside payload_for_hash. It is
            # complete source archival, but its ownership cannot be known
            # until the next non-copied user step arrives.
            "hivemind.trailing_copied_context_steps": len(group.trailing_copied),
            "hivemind.trailing_copied_step_data": (
                canonical_json(trailing_preserved_steps) if trailing_preserved_steps else ""
            ),
        }
    )
    turn = MappedTurn(
        key=turn_key,
        messages=messages,
        output_messages=output_messages,
        system_instructions=root_system_instructions,
        llms=llms,
        tools=tools,
        subagents=subagents,
        started_at=turn_started_at,
        ended_at=max(turn_started_at, turn_ended_at),
        hash_context=hash_context,
        attributes=attributes,
    )
    turn.verification_signature = verification_signature(
        turn.started_at, turn.messages, turn.output_messages
    )
    turn.finalize_hash()
    return turn


def map_atif(session: Session, wrapper: dict[str, Any]) -> MappedConversation:
    """Map a HiveMind ATIF wrapper without mutating or retaining raw secrets."""
    wrapper_session_id = wrapper.get("session_id")
    if not isinstance(wrapper_session_id, str) or wrapper_session_id != session.id:
        raise ATIFSchemaError(f"session {session.id} ATIF wrapper has a mismatched session_id")
    wrapper_step_count = wrapper.get("step_count")
    if (
        isinstance(wrapper_step_count, bool)
        or not isinstance(wrapper_step_count, int)
        or wrapper_step_count < 0
    ):
        raise ATIFSchemaError(f"session {session.id} ATIF wrapper has invalid step_count")
    raw_wrapper_metadata = wrapper.get("metadata")
    if not isinstance(raw_wrapper_metadata, dict):
        raise ATIFSchemaError(f"session {session.id} ATIF wrapper has invalid metadata")
    raw_trajectory = wrapper.get("trajectory")
    if not isinstance(raw_trajectory, dict):
        raise ATIFSchemaError(f"session {session.id} is missing ATIF trajectory")
    trajectory = redact_data(raw_trajectory)
    if not isinstance(trajectory, dict):
        raise ATIFSchemaError(f"session {session.id} has invalid ATIF trajectory")
    wrapper_metadata = redact_data(raw_wrapper_metadata)
    if not isinstance(wrapper_metadata, dict):
        raise ATIFSchemaError(f"session {session.id} ATIF wrapper has invalid metadata")
    wrapper_extra = redact_data(
        {
            key: value
            for key, value in wrapper.items()
            if key not in {"session_id", "trajectory", "step_count", "metadata"}
        }
    )
    if not isinstance(wrapper_extra, dict):  # pragma: no cover - dict input above.
        raise ATIFSchemaError(f"session {session.id} ATIF wrapper has invalid extra fields")
    schema_version = _validate_schema_version(trajectory.get("schema_version"))
    agent = trajectory.get("agent")
    if not isinstance(agent, dict):
        raise ATIFSchemaError(f"session {session.id} ATIF trajectory is missing agent")
    steps = _normalize_steps(trajectory.get("steps"), session)
    groups = _split_groups(steps)

    if wrapper_step_count != len(steps):
        raise ATIFSchemaError(
            f"session {session.id} ATIF wrapper step_count {wrapper_step_count} "
            f"does not match trajectory length {len(steps)}"
        )
    embedded_raw = trajectory.get("subagent_trajectories", [])
    if embedded_raw is None:
        embedded_items: list[Any] = []
    elif isinstance(embedded_raw, list):
        embedded_items = embedded_raw
    else:
        # Preserve an unexpected but parseable 1.x variant instead of silently
        # dropping it. It will be attached as unreferenced trajectory data.
        embedded_items = [embedded_raw]
    embedded_subagents: dict[str, dict[str, Any]] = {}
    for embedded in embedded_items:
        if not isinstance(embedded, dict):
            continue
        resolution_keys = {
            coerce_string(embedded.get("trajectory_id")),
            coerce_string(embedded.get("trajectory_path")),
        } - {""}
        for resolution_key in resolution_keys:
            if (
                resolution_key in embedded_subagents
                and embedded_subagents[resolution_key] != embedded
            ):
                raise ATIFSchemaError(
                    f"session {session.id} has duplicate embedded subagent resolution keys"
                )
            embedded_subagents[resolution_key] = embedded
    referenced_subagent_keys = {
        reference_key
        for step in steps
        for observation in _observation_results(step, embedded_subagents)
        for reference in observation.subagent_refs
        if (reference_key := _subagent_reference_key(reference))
    }
    unreferenced_subagents = [
        embedded
        for embedded in embedded_items
        if not isinstance(embedded, dict)
        or not (
            {
                coerce_string(embedded.get("trajectory_id")),
                coerce_string(embedded.get("trajectory_path")),
            }
            - {""}
        ).intersection(referenced_subagent_keys)
    ]
    agent_extra = agent.get("extra") if isinstance(agent.get("extra"), dict) else {}
    model = coerce_string(
        first_present(
            agent,
            "model_name",
            "model",
            default=first_present(
                agent_extra,
                "model_name",
                "model",
                default=first_present(
                    wrapper_metadata,
                    "model_name",
                    "model",
                    default=session.model,
                ),
            ),
        )
    )
    default_provider = coerce_string(
        first_present(
            agent,
            "provider_name",
            "provider",
            default=first_present(
                agent_extra,
                "provider_name",
                "provider",
                default=first_present(
                    wrapper_metadata,
                    "provider_name",
                    "provider",
                    default="",
                ),
            ),
        )
    )
    agent_name = session.agent_type or coerce_string(agent.get("name"), "unknown")
    global_attributes = _clean_attributes(
        {
            "hivemind.atif_trajectory_id": coerce_string(
                first_present(trajectory, "trajectory_id", "session_id", default="")
            ),
            "hivemind.atif_trajectory_extra": (
                canonical_json(trajectory["extra"]) if "extra" in trajectory else ""
            ),
            "hivemind.atif_agent_extra": (
                canonical_json(agent["extra"]) if "extra" in agent else ""
            ),
            "hivemind.atif_tool_definitions": (
                canonical_json(agent["tool_definitions"]) if "tool_definitions" in agent else ""
            ),
            "hivemind.atif_final_metrics": (
                canonical_json(trajectory["final_metrics"]) if "final_metrics" in trajectory else ""
            ),
            "hivemind.atif_wrapper_metadata": (
                canonical_json(wrapper_metadata) if wrapper_metadata else ""
            ),
            "hivemind.atif_wrapper_extra": (canonical_json(wrapper_extra) if wrapper_extra else ""),
            "hivemind.atif_trajectory_metadata": canonical_json(
                {
                    key: value
                    for key, value in trajectory.items()
                    if key not in {"steps", "subagent_trajectories"}
                }
            ),
        }
    )
    conversation_name = redact_string(session.title)
    agent_id = session.agent_session_id or session.id
    agent_version = coerce_string(agent.get("version"))
    hash_context = {
        "conversation_id": f"hivemind:{session.id}",
        "conversation_name": conversation_name,
        "agent_name": agent_name,
        "model": model,
        "agent_id": agent_id,
        "agent_version": agent_version,
        "agent_extra": agent.get("extra", {}),
        "agent_tool_definitions": agent.get("tool_definitions", []),
        "trajectory_extra": trajectory.get("extra", {}),
        "wrapper_metadata": wrapper_metadata,
        "wrapper_extra": wrapper_extra,
        # Final metrics are session aggregates and normally change when a new
        # turn is appended. Hash every other trajectory-level source field so
        # historical metadata edits conflict without making normal appends do so.
        "trajectory_metadata": {
            key: value
            for key, value in trajectory.items()
            if key not in {"steps", "subagent_trajectories", "final_metrics"}
        },
    }
    turns = [
        _map_group(
            group,
            session=session,
            schema_version=schema_version,
            default_model=model,
            default_provider=default_provider,
            embedded_subagents=embedded_subagents,
            embedded_subagent_count=len(embedded_items),
            global_attributes=global_attributes,
            hash_context=hash_context,
        )
        for group in groups
    ]
    turn_keys = [turn.key for turn in turns]
    if len(set(turn_keys)) != len(turn_keys):
        raise ATIFSchemaError(f"session {session.id} contains duplicate deterministic turn keys")
    _attach_unreferenced_subagents(turns, unreferenced_subagents, session=session)
    return MappedConversation(
        conversation_id=f"hivemind:{session.id}",
        conversation_name=conversation_name,
        agent_name=agent_name,
        model=model,
        agent_id=agent_id,
        agent_version=agent_version,
        schema_version=schema_version,
        source_last_activity_at=session.last_activity_at,
        turns=turns,
    )
