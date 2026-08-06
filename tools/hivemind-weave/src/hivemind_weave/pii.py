"""Configure Weave Presidio redaction without runtime model downloads."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from copy import copy
from dataclasses import replace
from functools import lru_cache
from typing import Any

from .models import (
    ChatMessage,
    MappedConversation,
    MappedTurn,
)
from .redaction import redact_data, redact_string
from .source_identity import is_opaque_source_coordinate
from .utils import canonical_json, sha256_json

_PII_ENGINE_REDACTOR: Any | None = None
_REDACTION_CACHE: OrderedDict[tuple[int, str], str] = OrderedDict()
_REDACTION_CACHE_BYTES = 0
# ATIF-derived LLM contexts repeat the same already-redacted message and tool
# fields across later inferred calls. Retaining bounded redacted values (never
# raw cache keys) prevents Presidio work from growing quadratically on large
# sessions while capping UTF-8 redacted-value storage at 128 MiB. Values are
# transient process memory and are cleared whenever the PII engine is reset.
_MAX_REDACTION_CACHE_ENTRY_BYTES = 8 * 1024 * 1024
_MAX_REDACTION_CACHE_BYTES = 128 * 1024 * 1024
_MAX_REDACTION_FIXED_POINT_PASSES = 8
_CORRELATION_ATTRIBUTES = {
    "hivemind.session_id",
    "hivemind.parent_session_id",
    "hivemind.turn_key",
    "hivemind.payload_sha256",
    "hivemind.source_payload_sha256",
    "hivemind.atif_schema_version",
    "hivemind.importer_version",
}

# The mapper preserves these ATIF structures as canonical JSON strings so they
# remain searchable attributes without losing source fields. Parse them before
# applying any text regexes: credential syntax embedded in a JSON string (for
# example, a quoted ``OPENAI_API_KEY=...`` snippet) can legitimately span JSON
# escape characters and make a text-level replacement syntactically invalid.
# Structured redaction followed by canonical serialization is both lossless and
# substantially cheaper than asking Presidio to analyze one large JSON blob.
_CANONICAL_JSON_ATTRIBUTE_KEYS = frozenset(
    {
        "hivemind.atif_agent_extra",
        "hivemind.atif_final_metrics",
        "hivemind.atif_tool_definitions",
        "hivemind.atif_trajectory_extra",
        "hivemind.atif_trajectory_metadata",
        "hivemind.atif_wrapper_extra",
        "hivemind.atif_wrapper_metadata",
        "hivemind.preserved_step_data",
        "hivemind.trailing_copied_step_data",
        "hivemind.unreferenced_subagent_trajectories",
    }
)

_HASH_CORRELATORS = {"conversation_id"}
_SOURCE_COORDINATE_KEYS = {
    "agent_id",
    "agent_session_id",
    "atif_trajectory_id",
    "parent_session_id",
    "session_id",
    "trajectory_id",
}
_REDACTED_SOURCE_COORDINATE = "[REDACTED_SOURCE_COORDINATE]"

_KNOWN_AGENT_TYPES = {
    "claude",
    "claude-code",
    "codex",
    "copilot",
    "cursor",
    "gemini",
    "gemini-cli",
    "github-copilot",
    "github-copilot-cli",
    "opencode",
    "pi",
    "unknown",
}
_KNOWN_PROVIDERS = {"anthropic", "google", "openai", "unknown"}
_KNOWN_SHORT_MODELS = {"o1", "o3", "o4"}
_KNOWN_MODEL = re.compile(
    r"^(?:"
    r"gpt-(?=[a-z0-9._:/-]*[0-9])"
    r"(?:(?:[0-9]+[a-z]?)|codex|mini|nano|turbo|preview|latest|chat|audio|realtime|oss)"
    r"(?:[._:/-](?:(?:[0-9]+[a-z]?)|codex|mini|nano|turbo|preview|latest|chat|audio|realtime|oss))*|"
    r"claude-(?:(?:haiku|sonnet|opus|instant|latest|preview)|[0-9]+)"
    r"(?:[._:/-](?:(?:haiku|sonnet|opus|instant|latest|preview)|[0-9]+))*|"
    r"gemini-(?:[0-9]+|flash|pro|ultra|nano|exp|experimental|preview|latest|thinking|live|image)"
    r"(?:[._:/-](?:[0-9]+|flash|pro|ultra|nano|exp|experimental|preview|latest|thinking|live|image))*|"
    r"codex(?:$|-(?:[0-9]+|mini|max|latest|cli)"
    r"(?:[._:/-](?:[0-9]+|mini|max|latest|cli))*)"
    r")$"
)
_CODE_DECLARATION = re.compile(
    r"(?P<prefix>^[ \t]*(?:(?:export|default|public|private|protected|internal|static|"
    r"abstract|final|sealed|async|pub)\s+)*(?:class|def|function|const|let|var|struct|"
    r"enum|interface|"
    r"type|func|fn|module|namespace)\s+)(?P<identifier>[A-Za-z_$][A-Za-z0-9_$]*)",
    re.MULTILINE,
)
_NEW_EXPRESSION = re.compile(
    r"(?P<prefix>\bnew\s+)(?P<identifier>[A-Za-z_$][A-Za-z0-9_$]*)(?=\s*\()"
)
_SCOPED_CODE_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$][A-Za-z0-9_$]*(?:::[A-Za-z_$][A-Za-z0-9_$]*)+"
    r"(?=(?:\s*\(|\b))"
)
_CODE_IDENTIFIER_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_$])[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:::[A-Za-z_$][A-Za-z0-9_$]*)*(?![A-Za-z0-9_$])"
)
_LIKELY_FULL_NAME_OR_LOCATION = re.compile(
    r"\b[A-Z][a-z]{1,}(?:[-'][A-Z]?[a-z]+)?\s+"
    r"[A-Z][a-z]{1,}(?:[-'][A-Z]?[a-z]+)?\b"
)
_LIKELY_CAMEL_CASE_NAME = re.compile(r"\b[A-Z][a-z]{1,}[A-Z][a-z]{1,}\b")
_COORDINATE_LIKE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_COORDINATE_WORD = re.compile(r"[A-Za-z]{3,}")
_SAFE_COORDINATE_WORDS = {
    "agent",
    "atif",
    "call",
    "child",
    "content",
    "conversation",
    "description",
    "digest",
    "ended",
    "finish",
    "hash",
    "hivemind",
    "id",
    "index",
    "input",
    "manifest",
    "message",
    "metadata",
    "metrics",
    "model",
    "name",
    "output",
    "parent",
    "payload",
    "preview",
    "provider",
    "reasoning",
    "repository",
    "result",
    "schema",
    "session",
    "source",
    "span",
    "started",
    "step",
    "timestamp",
    "tokens",
    "tool",
    "trace",
    "turn",
    "usage",
    "user",
    "version",
    "warning",
}
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NAME_BASED_UUID = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])",
    re.IGNORECASE,
)
_ATIF_VERSION = re.compile(r"^ATIF-v\d+\.\d+$", re.IGNORECASE)
_REDACTION_MARKER_PATTERN = r"(?:\[REDACTED(?:_[A-Z0-9]{1,32})*\]|<[A-Z][A-Z0-9_]{1,63}>)"
_REDACTION_PLACEHOLDER = re.compile(rf"^{_REDACTION_MARKER_PATTERN}$")
_EMBEDDED_REDACTION_PLACEHOLDER = re.compile(_REDACTION_MARKER_PATTERN)
_INTERNAL_MARKER_NAMESPACE = 0xE010
_INTERNAL_CODE_NAMESPACE = 0xE011
_INTERNAL_PROTECTION_TOKEN = re.compile("\ue000[\ue010\ue011][\ue100-\ue1ff]{8}\ue001")
_PERSON_PLACEHOLDER = re.compile(r"<PERSON>", re.IGNORECASE)
_CONTEXTUAL_ENTITY_TYPES = frozenset({"LOCATION", "NRP", "ORGANIZATION", "PERSON"})
_REPEATABLE_CONTEXT_ENTITY = re.compile(
    r"[^\W\d_]+(?:[ '\N{RIGHT SINGLE QUOTATION MARK}-][^\W\d_]+)*",
    re.UNICODE,
)


class _FullTextAnalyzer:
    """Raise spaCy's safety ceiling monotonically before full-text analysis.

    Presidio and its anonymizer continue to receive the original complete
    string, so entity context and offsets are never divided, truncated, or
    bypassed. The cached pipeline is process-local; the lock makes concurrent
    calls in one process safe, and the monotonic update can never reduce a
    limit needed by an analysis already starting on another thread.
    """

    def __init__(self, analyzer: Any, nlp_engine: Any) -> None:
        self._analyzer = analyzer
        self._nlp_engine = nlp_engine
        self._max_length_lock = threading.Lock()

    def analyze(self, text: str, language: str, **kwargs: Any) -> list[Any]:
        pipeline = self._nlp_engine.nlp.get(language)
        if pipeline is not None:
            with self._max_length_lock:
                pipeline.max_length = max(int(pipeline.max_length), len(text))
        return list(self._analyzer.analyze(text=text, language=language, **kwargs))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._analyzer, name)


def _internal_protection_token(namespace: int, number: int) -> str:
    """Return a fixed-width, linguistically inert private-use token."""
    ordinal = number.to_bytes(8, byteorder="big", signed=False)
    return "\ue000" + chr(namespace) + "".join(chr(0xE100 + byte) for byte in ordinal) + "\ue001"


def _expand_contextual_entity_repetitions(value: str, results: list[Any]) -> list[Any]:
    """Apply a recognized name/location phrase to its exact repeated tokens.

    Statistical NER can recognize only the boundary instances of a long list
    of the same entity. Re-running NER after anonymization then makes the typed
    marker itself a context feature, producing slow one-at-a-time closure. For
    contextual alphabetic entities only, copy an already-supported result to
    every exact whole-token occurrence before the anonymizer runs. Punctuation-
    bearing code and filenames are deliberately excluded; generated markers
    are separately shielded from feedback below.
    """
    expanded = list(results)
    seen = {(int(result.start), int(result.end), str(result.entity_type)) for result in results}
    templates: dict[tuple[str, str], Any] = {}
    for result in results:
        start = int(result.start)
        end = int(result.end)
        entity_type = str(result.entity_type)
        if not (0 <= start < end <= len(value)) or entity_type not in _CONTEXTUAL_ENTITY_TYPES:
            continue
        phrase = value[start:end]
        if len(phrase) < 2 or _REPEATABLE_CONTEXT_ENTITY.fullmatch(phrase) is None:
            continue
        templates.setdefault((entity_type, phrase), result)

    for (entity_type, phrase), template in templates.items():
        offset = 0
        while True:
            start = value.find(phrase, offset)
            if start < 0:
                break
            end = start + len(phrase)
            offset = end
            left_is_word = start > 0 and (value[start - 1].isalnum() or value[start - 1] == "_")
            right_is_word = end < len(value) and (value[end].isalnum() or value[end] == "_")
            identity = (start, end, entity_type)
            if not left_is_word and not right_is_word and identity not in seen:
                repeated = copy(template)
                repeated.start = start
                repeated.end = end
                expanded.append(repeated)
                seen.add(identity)
    return expanded


def _exclude_internal_protection_tokens(value: str, results: list[Any]) -> list[Any]:
    """Discard analyzer spans touching temporary private-use shields."""
    protected_spans = [match.span() for match in _INTERNAL_PROTECTION_TOKEN.finditer(value)]
    if not protected_spans:
        return results
    return [
        result
        for result in results
        if not any(
            int(result.start) < protected_end and protected_start < int(result.end)
            for protected_start, protected_end in protected_spans
        )
    ]


def _looks_like_technical_identifier(value: str) -> bool:
    stripped = value.strip()
    return bool(
        _UUID.fullmatch(stripped)
        or _ATIF_VERSION.fullmatch(stripped)
        or _REDACTION_PLACEHOLDER.fullmatch(stripped)
    )


def _scrub_coordinate_like_pii(value: str, engine_redactor: Any) -> str:
    """Catch names hidden behind identifier punctuation or camel casing.

    Small NER models often miss ``session-AliceJohnson`` as a whole token. A
    generic technical-ID exemption made that miss absolute. Coordinate-like
    content now receives a conservative component pass after credential
    scrubbing. The pass is bounded to short standalone identifier strings, so
    it does not multiply work across large prose or code bodies.
    """
    if not _COORDINATE_LIKE_TEXT.fullmatch(value):
        return value
    if _UUID.fullmatch(value) or _ATIF_VERSION.fullmatch(value):
        return value
    matches = list(_COORDINATE_WORD.finditer(value))
    pii_indexes: set[int] = set()
    for index, match in enumerate(matches):
        token = match.group(0)
        if token.lower() in _SAFE_COORDINATE_WORDS:
            continue
        elif _LIKELY_CAMEL_CASE_NAME.fullmatch(token):
            pii_indexes.add(index)
        else:
            probe = token.title() if token.islower() else token
            if engine_redactor(probe) != probe:
                pii_indexes.add(index)
    if not pii_indexes:
        return value

    # NER commonly recognizes only one half of a delimiter-separated personal
    # name (for example ``john`` but not ``smith``). Once any component is PII,
    # remove every non-protocol alphabetic component in that same coordinate.
    result = value
    for match in reversed(matches):
        if match.group(0).lower() not in _SAFE_COORDINATE_WORDS:
            result = f"{result[: match.start()]}[REDACTED]{result[match.end() :]}"
    return result


def _code_positions(value: str) -> list[bool]:
    """Mark positions outside comments and string/regex literals."""
    positions = [True] * len(value)
    quote = ""
    line_comment = False
    block_comment = False
    escaped = False
    index = 0
    previous_significant = ""
    while index < len(value):
        if line_comment:
            positions[index] = False
            if value[index] == "\n":
                line_comment = False
                previous_significant = ""
            index += 1
            continue
        if block_comment:
            positions[index] = False
            if value.startswith("*/", index):
                if index + 1 < len(value):
                    positions[index + 1] = False
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            positions[index] = False
            char = value[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if value.startswith("```", index):
            positions[index : index + 3] = [False] * min(3, len(value) - index)
            index += 3
            continue
        if value.startswith("//", index) or value.startswith("--", index):
            line_comment = True
            continue
        if value.startswith("/*", index):
            block_comment = True
            continue
        char = value[index]
        if char == "#":
            line_comment = True
            continue
        if char in {"'", '"', "`"}:
            quote = char
            positions[index] = False
            index += 1
            continue
        if char == "/" and previous_significant in {
            "",
            "=",
            "(",
            ":",
            ",",
            "[",
            "!",
            "&",
            "|",
            "?",
            "{",
            ";",
        }:
            quote = "/"
            positions[index] = False
            index += 1
            continue
        if char == "\n":
            previous_significant = ""
        elif not char.isspace():
            previous_significant = char
        index += 1
    return positions


def _identifier_is_person_name(identifier: str, engine_redactor: Any) -> bool:
    """Probe a code identifier as words without treating locations as people."""
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", identifier)
    words = [word for word in re.split(r"[\s_$:]+", expanded) if word]
    if len(words) < 2:
        return False
    probe = " ".join(word.title() if word.islower() or word.isupper() else word for word in words)
    return bool(_PERSON_PLACEHOLDER.search(engine_redactor(probe)))


def _redact_person_code_identifiers(value: str, engine_redactor: Any) -> str:
    """Actively remove name-shaped identifiers before shielding code syntax."""
    result = value
    decisions: dict[str, bool] = {}
    matches: list[re.Match[str]] = []
    for match in _CODE_IDENTIFIER_TOKEN.finditer(value):
        identifier = match.group(0)
        is_person = decisions.get(identifier)
        if is_person is None:
            is_person = _identifier_is_person_name(identifier, engine_redactor)
            decisions[identifier] = is_person
        if is_person:
            matches.append(match)
    for match in reversed(matches):
        result = f"{result[: match.start()]}[REDACTED]{result[match.end() :]}"
    return result


def _protect_declared_code_identifiers(
    value: str,
    engine_redactor: Any,
) -> tuple[str, dict[str, str]]:
    positions = _code_positions(value)
    spans: list[tuple[int, int]] = []
    declared_identifiers: set[str] = set()
    for pattern in (_CODE_DECLARATION, _NEW_EXPRESSION):
        for match in pattern.finditer(value):
            start, end = match.span("identifier")
            identifier = match.group("identifier")
            if (
                start < len(positions)
                and positions[start]
                and not _identifier_is_person_name(identifier, engine_redactor)
            ):
                spans.append((start, end))
                if pattern is _CODE_DECLARATION:
                    declared_identifiers.add(identifier)

    # A declaration is only useful if later references survive too. Protect
    # exact identifier tokens outside comments and literals; those regions stay
    # unprotected so real names and locations there are still removed.
    for identifier in declared_identifiers:
        reference = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(identifier)}(?![A-Za-z0-9_$])")
        for match in reference.finditer(value):
            start, end = match.span()
            if start < len(positions) and all(positions[start:end]):
                spans.append((start, end))
    for match in _SCOPED_CODE_IDENTIFIER.finditer(value):
        start, end = match.span()
        if (
            start < len(positions)
            and all(positions[start:end])
            and not _identifier_is_person_name(match.group(0), engine_redactor)
        ):
            spans.append((start, end))

    # Prefer the widest candidate when syntaxes overlap, then apply replacements
    # right-to-left so source offsets remain valid.
    selected: list[tuple[int, int]] = []
    for span in sorted(set(spans), key=lambda item: (-(item[1] - item[0]), item[0])):
        if not any(span[0] < other[1] and other[0] < span[1] for other in selected):
            selected.append(span)
    replacements: dict[str, str] = {}
    protected = value
    placeholder_offset = 0
    while any(
        _internal_protection_token(
            _INTERNAL_CODE_NAMESPACE,
            placeholder_offset + number,
        )
        in value
        for number in range(len(selected))
    ):
        placeholder_offset += max(1, len(selected))
    for number, (start, end) in enumerate(sorted(selected, reverse=True)):
        token = _internal_protection_token(
            _INTERNAL_CODE_NAMESPACE,
            placeholder_offset + number,
        )
        replacements[token] = value[start:end]
        protected = f"{protected[:start]}{token}{protected[end:]}"
    return (protected, replacements)


def _protect_redaction_placeholders(value: str) -> tuple[str, dict[str, str]]:
    """Hide semantic redaction markers from later Presidio passes.

    Presidio emits typed markers such as ``<LOCATION>``. Feeding those markers
    back into the NER model changes the linguistic context around neighboring
    text and can reveal one new false-positive entity per pass. Replace every
    already-redacted marker with a collision-safe opaque token while NER runs,
    then restore the marker byte-for-byte. Real surrounding text still receives
    complete analysis.
    """
    matches = list(_EMBEDDED_REDACTION_PLACEHOLDER.finditer(value))
    if not matches:
        return value, {}

    placeholder_offset = 0
    while any(
        _internal_protection_token(
            _INTERNAL_MARKER_NAMESPACE,
            placeholder_offset + number,
        )
        in value
        for number in range(len(matches))
    ):
        placeholder_offset += len(matches)

    protected = value
    replacements: dict[str, str] = {}
    for number, match in enumerate(reversed(matches)):
        placeholder = _internal_protection_token(
            _INTERNAL_MARKER_NAMESPACE,
            placeholder_offset + number,
        )
        replacements[placeholder] = match.group(0)
        protected = f"{protected[: match.start()]}{placeholder}{protected[match.end() :]}"
    return protected, replacements


def _source_aware_redact(value: str, engine_redactor: Any) -> str:
    """Redact all content while shielding declared code identifiers.

    Identifiers in syntactically explicit declarations and their code-position
    references are masked during NER and restored afterward. Comments, literals,
    regexes, template strings, fenced blocks, and inline backticks all remain
    subject to PII redaction.
    """
    scrubbed = redact_string(value)
    # UUIDv5 is name-derived and can be a durable equality oracle. Preserve it
    # only in independently validated source-coordinate fields, which bypass
    # this generic string path through ``redact_source_coordinate``.
    scrubbed = _NAME_BASED_UUID.sub(_REDACTED_SOURCE_COORDINATE, scrubbed)
    if _looks_like_technical_identifier(scrubbed):
        return scrubbed
    # Standalone identifiers and protocol coordinates are handled component by
    # component. This preserves finite protocol vocabulary such as
    # ``atif_trajectory_metadata`` while still removing ``alice_johnson``.
    if _COORDINATE_LIKE_TEXT.fullmatch(scrubbed):
        return _scrub_coordinate_like_pii(scrubbed, engine_redactor)
    scrubbed = _redact_person_code_identifiers(scrubbed, engine_redactor)
    protected, replacements = _protect_declared_code_identifiers(scrubbed, engine_redactor)
    # Small NER models occasionally tag only the surname of a two-token name.
    # Remove an obvious title-cased pair up front; declared/scoped identifiers
    # are already shielded above, so this remains conservative around code.
    protected = _LIKELY_FULL_NAME_OR_LOCATION.sub("[REDACTED]", protected)
    protected = _LIKELY_CAMEL_CASE_NAME.sub("[REDACTED]", protected)
    protected, redaction_markers = _protect_redaction_placeholders(protected)
    redacted = engine_redactor(protected)
    for placeholder, marker in redaction_markers.items():
        if redacted.count(placeholder) != 1:
            raise ValueError("PII engine altered an internal redaction-marker token")
        redacted = redacted.replace(placeholder, marker, 1)
    for placeholder, identifier in replacements.items():
        if redacted.count(placeholder) != 1:
            raise ValueError("PII engine altered an internal code-identifier token")
        redacted = redacted.replace(placeholder, identifier, 1)
    return redacted


@lru_cache(maxsize=1)
def configure_weave_pii() -> None:
    """Install a cached, offline Presidio engine into Weave's redaction hook.

    Presidio's default provider downloads a large language model on first use.
    Import jobs must not gain a hidden network dependency, so the package locks
    and installs a compact English NER model ahead of time. The importer's own
    credential/PII scrubber runs before this second layer.
    """
    import tldextract
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    from presidio_anonymizer import AnonymizerEngine
    from weave.utils import pii_redaction

    global _PII_ENGINE_REDACTOR, _REDACTION_CACHE_BYTES
    _REDACTION_CACHE.clear()
    _REDACTION_CACHE_BYTES = 0

    # Presidio's email recognizer uses tldextract, whose module-level default
    # fetches the public-suffix list on first use. The package ships a snapshot,
    # so force that deterministic offline path before creating the recognizers.
    tldextract.extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

    @lru_cache(maxsize=1)
    def offline_engines() -> tuple[Any, AnonymizerEngine]:
        nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
        nlp_engine.load()
        analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en"],
        )
        return (
            _FullTextAnalyzer(analyzer, nlp_engine),
            AnonymizerEngine(),
        )

    pii_redaction._get_engines = offline_engines
    supported = set(offline_engines()[0].get_supported_entities("en"))
    requested = tuple(pii_redaction._get_redaction_entities())

    def supported_redaction_entities() -> list[str]:
        return [entity for entity in requested if entity in supported]

    def engine_redactor(value: str) -> str:
        if not value:
            return value
        analyzer, anonymizer = offline_engines()
        results = analyzer.analyze(
            text=value,
            language="en",
            entities=supported_redaction_entities(),
        )
        results = _exclude_internal_protection_tokens(value, results)
        expanded = _expand_contextual_entity_repetitions(value, results)
        return str(anonymizer.anonymize(text=value, analyzer_results=expanded).text)

    _PII_ENGINE_REDACTOR = engine_redactor
    pii_redaction._hivemind_engine_redactor = engine_redactor

    # Weave's cross-country default contains a few recognizers Presidio does
    # not ship for English. Filtering those avoids a warning for every string;
    # all locally available Weave-requested entities remain enabled.
    pii_redaction._get_redaction_entities = supported_redaction_entities
    pii_redaction.redact_pii_string = lambda value: _source_aware_redact(
        value,
        engine_redactor,
    )
    probe = "Alice Johnson lives in New York and uses codex-pii-probe@example.com"
    redacted_probe = pii_redaction.redact_pii_string(probe)
    if any(value in redacted_probe for value in ("Alice Johnson", "New York", "probe@example")):
        raise RuntimeError("Presidio person/location/email redaction self-test failed")


def _redact_pii_string_uncached(value: str) -> str:
    # Call the captured engine directly. Importing the mutable Weave hook here
    # made cached/reconfigured test and long-running processes intermittently
    # bypass the source-aware wrapper.
    if _PII_ENGINE_REDACTOR is None:
        configure_weave_pii()
    if _PII_ENGINE_REDACTOR is None:  # pragma: no cover - guarded above.
        raise RuntimeError("Presidio redaction engine was not configured")
    return _source_aware_redact(value, _PII_ENGINE_REDACTOR)


def _redact_pii_string(value: str) -> str:
    """Cache by digest only; raw pre-redaction text is never retained as a key."""
    encoded_value = value.encode("utf-8")
    if len(encoded_value) > _MAX_REDACTION_CACHE_ENTRY_BYTES:
        return _redact_pii_string_uncached(value)

    global _REDACTION_CACHE_BYTES
    cache_key = (len(encoded_value), hashlib.sha256(encoded_value).hexdigest())
    cached = _REDACTION_CACHE.get(cache_key)
    if cached is not None:
        _REDACTION_CACHE.move_to_end(cache_key)
        return cached

    redacted = _redact_pii_string_uncached(value)
    redacted_bytes = len(redacted.encode("utf-8"))
    if redacted_bytes <= _MAX_REDACTION_CACHE_ENTRY_BYTES:
        _REDACTION_CACHE[cache_key] = redacted
        _REDACTION_CACHE_BYTES += redacted_bytes
        while _REDACTION_CACHE_BYTES > _MAX_REDACTION_CACHE_BYTES:
            _, evicted = _REDACTION_CACHE.popitem(last=False)
            _REDACTION_CACHE_BYTES -= len(evicted.encode("utf-8"))
    return redacted


def _pii_walk(value: Any, *, key: str = "") -> Any:
    if isinstance(value, str):
        if key in _CANONICAL_JSON_ATTRIBUTE_KEYS and value:
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError as error:
                raise ValueError("mapped ATIF JSON attribute is invalid") from error
            return canonical_json(_pii_walk(decoded))
        return _redact_pii_string(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        redacted_key_index = 0
        reserved_keys = {str(raw_key) for raw_key in value}
        for raw_key, raw_value in value.items():
            source_key = str(raw_key)
            coordinate_key = source_key.rsplit(".", 1)[-1].lower()
            scrubbed_key = _redact_pii_string(source_key)
            if scrubbed_key != source_key:
                while True:
                    redacted_key_index += 1
                    scrubbed_key = f"[REDACTED_PII_KEY_{redacted_key_index:04d}]"
                    if scrubbed_key not in reserved_keys and scrubbed_key not in result:
                        break
            if scrubbed_key in result:
                raise ValueError("mapping keys collide after PII redaction")
            if coordinate_key in _SOURCE_COORDINATE_KEYS:
                result[scrubbed_key] = redact_source_coordinate(raw_value)
            else:
                result[scrubbed_key] = _pii_walk(raw_value, key=source_key)
        return result
    if isinstance(value, list):
        return [_pii_walk(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_pii_walk(item) for item in value)
    return value


def redact_upload_data(value: Any) -> Any:
    """Apply credential patterns and offline Presidio before SDK construction.

    Weave 0.53 redacts its typed conversation fields, but custom attributes are
    merged afterward. Running the same engine locally closes that gap and also
    makes the guarantee testable against the exact payload handed to the SDK.
    """
    configure_weave_pii()

    def redact_once(candidate: Any) -> Any:
        return _pii_walk(
            redact_data(
                candidate,
                json_string_keys=_CANONICAL_JSON_ATTRIBUTE_KEYS,
            )
        )

    current = value
    for _ in range(_MAX_REDACTION_FIXED_POINT_PASSES):
        redacted = redact_once(current)
        if redacted == current:
            return redacted
        current = redacted
    raise ValueError("credential and PII redaction did not reach a fixed point")


def redact_agent_name(value: str) -> str:
    return value if value.strip().lower() in _KNOWN_AGENT_TYPES else str(redact_upload_data(value))


def redact_model_name(value: str) -> str:
    stripped = value.strip()
    return (
        value
        if stripped in _KNOWN_SHORT_MODELS or _KNOWN_MODEL.fullmatch(stripped)
        else str(redact_upload_data(value))
    )


def redact_provider_name(value: str) -> str:
    return value if value.strip().lower() in _KNOWN_PROVIDERS else str(redact_upload_data(value))


def redact_source_coordinate(value: object, *, allow_name_based: bool = False) -> str:
    """Preserve a contracted source ID, opting into UUIDv5 only at trusted boundaries."""
    if value == "":
        return ""
    if allow_name_based:
        valid = is_opaque_source_coordinate(value)
    else:
        valid = isinstance(value, str) and _UUID.fullmatch(value) is not None
    return str(value) if valid else _REDACTED_SOURCE_COORDINATE


def _message(item: ChatMessage) -> ChatMessage:
    return replace(item, content=str(redact_upload_data(item.content)))


def _destination_message_content(message: ChatMessage) -> str:
    """Return the exact text persisted by Weave for one typed message.

    ``sanitize_mapped_conversation`` has already applied the first local PII
    pass.  The sink applies ``redact_upload_data`` once more immediately before
    constructing Weave's ``Message`` object.  While building span attributes,
    Weave dumps that typed message to a dict, recursively redacts the dict, and
    validates it back into a ``Message``.  Reproduce that exact typed-message
    path here: its dict-leaf redaction can legitimately differ from Weave's
    top-level ``redact_pii_string`` hook.
    """
    sink_text = str(redact_upload_data(message.content))
    from weave.conversation import Message
    from weave.utils import pii_redaction

    redacted = pii_redaction.redact_messages([Message(role=message.role, content=sink_text)])
    return str(redacted[0].content)


def _verification_signature(turn: MappedTurn) -> str:
    first_user = next((item for item in turn.messages if item.role == "user"), None)
    last_assistant = next(
        (item for item in reversed(turn.output_messages) if item.role == "assistant"),
        None,
    )
    # Hash the exact destination representation: local sanitization (already
    # present on ``turn``), the sink pass, and Weave's final typed-message pass.
    # The signature is deliberately excluded from the semantic payload hash.
    uploaded_first_user = _destination_message_content(first_user) if first_user is not None else ""
    uploaded_last_assistant = (
        _destination_message_content(last_assistant) if last_assistant is not None else ""
    )
    return sha256_json(
        {
            "started_at_ms": int(turn.started_at.timestamp() * 1000),
            "first_user": uploaded_first_user,
            "last_assistant": uploaded_last_assistant,
        }
    )


def _sanitize_turn_attributes(source: dict[str, Any]) -> dict[str, Any]:
    """Redact preserved ATIF JSON as data, never as an opaque text blob."""
    ordinary = dict(source)
    structured: dict[str, str] = {}
    for key in _CANONICAL_JSON_ATTRIBUTE_KEYS:
        if key not in ordinary:
            continue
        raw = ordinary.pop(key)
        if raw == "":
            structured[key] = ""
            continue
        if not isinstance(raw, str):
            raise ValueError("mapped ATIF JSON attribute is not text")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError("mapped ATIF JSON attribute is invalid") from error
        # Prove both representations: first redact the decoded source shape,
        # then make its canonical JSON text a fixed point of the same final
        # defense pass that will later see the complete manifest.
        try:
            serialized = canonical_json(redact_upload_data(decoded))
            verified = redact_upload_data({key: serialized})
        except ValueError as error:
            raise ValueError(f"mapped ATIF JSON attribute {key} failed redaction") from error
        if not isinstance(verified, dict):  # pragma: no cover - dict invariant.
            raise ValueError("mapped ATIF JSON attribute wrapper changed type")
        final_text = verified.get(key)
        if not isinstance(final_text, str):  # pragma: no cover - string invariant.
            raise ValueError("mapped ATIF JSON attribute changed type during redaction")
        structured[key] = final_text

    redacted = redact_upload_data(ordinary)
    if not isinstance(redacted, dict):  # pragma: no cover - dict shape invariant.
        raise ValueError("mapped turn attributes changed shape during redaction")
    redacted.update(structured)
    return redacted


def _sanitize_turn(turn: MappedTurn) -> MappedTurn:
    # Build the complete destination-safe semantic payload before deriving any
    # durable content identity. Hashing raw names or locations would retain a
    # low-entropy equality oracle even though the transcript itself was later
    # redacted.
    attributes = _sanitize_turn_attributes(turn.attributes)
    hash_context = redact_upload_data(turn.hash_context)
    assert isinstance(hash_context, dict)
    for key in _CORRELATION_ATTRIBUTES:
        if key in turn.attributes:
            attributes[key] = (
                redact_source_coordinate(turn.attributes[key], allow_name_based=True)
                if key in {"hivemind.session_id", "hivemind.parent_session_id"}
                else turn.attributes[key]
            )
    for key in _HASH_CORRELATORS:
        if key in turn.hash_context:
            hash_context[key] = turn.hash_context[key]
    if "agent_name" in turn.hash_context:
        hash_context["agent_name"] = redact_agent_name(str(turn.hash_context["agent_name"]))
    if "model" in turn.hash_context:
        hash_context["model"] = redact_model_name(str(turn.hash_context["model"]))
    if "agent_id" in turn.hash_context:
        hash_context["agent_id"] = redact_source_coordinate(turn.hash_context["agent_id"])

    llms = [
        replace(
            item,
            model=redact_model_name(item.model),
            provider=redact_provider_name(item.provider),
            system_instructions=[
                str(redact_upload_data(value)) for value in item.system_instructions
            ],
            input_messages=[_message(message) for message in item.input_messages],
            output_messages=[_message(message) for message in item.output_messages],
            reasoning=str(redact_upload_data(item.reasoning)),
            finish_reasons=[str(redact_upload_data(value)) for value in item.finish_reasons],
        )
        for item in turn.llms
    ]
    tools = [
        replace(
            item,
            name=str(redact_upload_data(item.name)),
            arguments=redact_upload_data(item.arguments),
            result=redact_upload_data(item.result),
            tool_call_id=str(redact_upload_data(item.tool_call_id)),
            tool_type=str(redact_upload_data(item.tool_type)),
            description=str(redact_upload_data(item.description)),
        )
        for item in turn.tools
    ]
    subagents = [
        replace(
            item,
            name=str(redact_upload_data(item.name)),
            model=redact_model_name(item.model),
            agent_id=redact_source_coordinate(item.agent_id),
            description=str(redact_upload_data(item.description)),
            version=str(redact_upload_data(item.version)),
            system_instructions=[
                str(redact_upload_data(value)) for value in item.system_instructions
            ],
        )
        for item in turn.subagents
    ]
    sanitized = replace(
        turn,
        messages=[_message(message) for message in turn.messages],
        output_messages=[_message(message) for message in turn.output_messages],
        system_instructions=[str(redact_upload_data(value)) for value in turn.system_instructions],
        llms=llms,
        tools=tools,
        subagents=subagents,
        hash_context=hash_context,
        attributes=attributes,
        payload_sha256="",
        verification_signature="",
    )
    sanitized.verification_signature = _verification_signature(sanitized)
    source_payload_sha256 = sha256_json(sanitized.payload_for_hash())
    # The source hash covers the complete credential- and PII-redacted semantic
    # turn. The transport's independent wire hash additionally certifies exact
    # serialization and externalized-reference planning.
    sanitized.payload_sha256 = source_payload_sha256
    sanitized.attributes["hivemind.source_payload_sha256"] = source_payload_sha256
    sanitized.attributes["hivemind.payload_sha256"] = source_payload_sha256
    return sanitized


def sanitize_mapped_conversation(conversation: MappedConversation) -> MappedConversation:
    """Return a PII-scrubbed upload with no pre-redaction content identity."""
    return replace(
        conversation,
        conversation_name=str(redact_upload_data(conversation.conversation_name)),
        agent_name=redact_agent_name(conversation.agent_name),
        model=redact_model_name(conversation.model),
        agent_id=redact_source_coordinate(conversation.agent_id),
        agent_version=str(redact_upload_data(conversation.agent_version)),
        turns=[_sanitize_turn(turn) for turn in conversation.turns],
    )
