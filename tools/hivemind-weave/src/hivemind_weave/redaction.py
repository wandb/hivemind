"""Defense-in-depth local redaction before any Weave object is constructed."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_PART = re.compile(r"[A-Za-z0-9]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_BASIC_AUTH = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")
_SECRET_HEADER = re.compile(
    r"(?im)^(?P<prefix>\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|"
    r"X-API-Key|Api-Key)\s*[:=]\s*)(?P<value>[^\r\n]+)$"
)
_KNOWN_TOKEN = re.compile(
    r"(?i)\b(?:sk|rk|sa|gh[opusr]|github_pat|xox[a-z]?|hf|glpat|npm)[-_][A-Za-z0-9_-]{8,}"
)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_WANDB_KEY_CONTEXT = re.compile(
    r"(?i)(?P<prefix>\b(?:wandb|weights[ -]?and[ -]?biases)(?:[ _-]?api)?[ _-]?key\s*[:=]?\s*)"
    r"(?P<value>[a-f0-9]{40})\b"
)
_SECRET_KEY_NAME = (
    r"[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|"
    r"DATABASE_URL|CONNECTION_STRING|DSN)"
)
_SECRET_QUOTED_ASSIGNMENT = re.compile(
    # Start only at a key-token boundary. Without this guard the greedy key
    # prefix is retried at every character of a large ordinary string, which
    # makes redaction quadratic before attributes can be safely chunked.
    rf"(?i)(?P<prefix>(?<![A-Z0-9_])['\"]?{_SECRET_KEY_NAME}['\"]?\s*[:=]\s*)"
    # Consume escaped characters as units so a quote inside a JSON/string
    # literal does not terminate the credential value early.
    r"(?P<quote>['\"])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)"
)
_SECRET_BARE_ASSIGNMENT = re.compile(
    rf"(?i)(?P<prefix>(?<![A-Z0-9_])['\"]?{_SECRET_KEY_NAME}['\"]?\s*[:=]\s*)"
    # Quoted values are handled by _SECRET_QUOTED_ASSIGNMENT above. Excluding
    # quotes here prevents a second pass from consuming the opening quote of
    # an already-redacted value and corrupting JSON or source code.
    rf"(?P<value>{re.escape(REDACTED)}|[^\s\"';,}}\]]+)"
)
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(r"(?<!\w)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\w)")
_CANONICAL_UUID = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}(?![0-9a-f])"
)
_CARD_DIGIT_RUN = re.compile(r"(?<!\d)(?:\d[ -]?){12,}\d(?!\d)")
_URL_USERINFO = re.compile(
    r"(?i)(?P<scheme>\b[a-z][a-z0-9+.-]{1,31}://)"
    r"(?P<userinfo>[^\s/@:]+:[^\s/@]+)@"
)


def _redact_card_run(match: re.Match[str]) -> str:
    """Redact every non-overlapping Luhn-valid 13-19 digit window in a run."""
    value = match.group(0)
    digit_positions = [index for index, character in enumerate(value) if character.isdigit()]
    digits = [int(value[position]) for position in digit_positions]
    # A Luhn window doubles one of the two global index parities. Prefix sums
    # make every 13-19 digit check O(1), keeping large numeric fields linear.
    prefix_sums = [[0], [0]]
    for index, digit in enumerate(digits):
        doubled = digit * 2
        if doubled > 9:
            doubled -= 9
        for parity in (0, 1):
            contribution = doubled if index % 2 == parity else digit
            prefix_sums[parity].append(prefix_sums[parity][-1] + contribution)

    selected: list[tuple[int, int]] = []
    start = 0
    while start + 13 <= len(digits):
        selected_length = 0
        for length in range(min(19, len(digits) - start), 12, -1):
            end = start + length
            doubled_parity = (start + length % 2) % 2
            checksum = prefix_sums[doubled_parity][end] - prefix_sums[doubled_parity][start]
            if checksum % 10 == 0:
                selected.append((digit_positions[start], digit_positions[end - 1] + 1))
                selected_length = length
                break
        start += selected_length or 1

    redacted = value
    for start, end in sorted(selected, reverse=True):
        redacted = f"{redacted[:start]}{REDACTED}{redacted[end:]}"
    return redacted


def _redact_cards_preserving_uuids(value: str) -> str:
    """Keep canonical UUID tokens while scanning all surrounding numeric runs."""
    parts: list[str] = []
    offset = 0
    for match in _CANONICAL_UUID.finditer(value):
        parts.append(_CARD_DIGIT_RUN.sub(_redact_card_run, value[offset : match.start()]))
        parts.append(match.group(0))
        offset = match.end()
    parts.append(_CARD_DIGIT_RUN.sub(_redact_card_run, value[offset:]))
    return "".join(parts)


def _key_parts(key: str) -> list[str]:
    """Split snake, kebab, and camel-case field names into semantic parts."""
    expanded = _CAMEL_CASE_BOUNDARY.sub("_", key)
    return [part.lower() for part in _KEY_PART.findall(expanded)]


def _is_sensitive_key(key: str) -> bool:
    """Return whether a structured field is expected to carry a credential.

    Matching semantic key parts avoids both sides of substring matching: it
    catches common forms such as ``apiToken`` and ``id_token`` while leaving
    ordinary schema keys such as ``authorizer`` and ``cookiecutter_template``
    intact.
    """
    parts = _key_parts(key)
    if not parts:
        return False
    compact = "".join(parts)

    if compact in {
        "apikey",
        "accesstoken",
        "authtoken",
        "authorization",
        "bearertoken",
        "clientsecret",
        "clienttoken",
        "connectionstring",
        "credential",
        "credentials",
        "databaseurl",
        "dburl",
        "dsn",
        "idtoken",
        "jdbcurl",
        "passphrase",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessiontoken",
        "token",
    }:
        return True

    # Environment and provider prefixes are common (OPENAI_API_KEY,
    # GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY). A credential term at the end of a
    # compound key denotes the value itself, unlike token_count or
    # password_policy, which describe non-secret metadata.
    if len(parts) >= 2 and parts[-2:] in (
        ["api", "key"],
        ["private", "key"],
        ["secret", "key"],
    ):
        return True
    if parts[-1] in {"credential", "credentials", "password", "passwd", "secret", "token"}:
        return True
    if parts[-1] == "cookie" or parts == ["auth"]:
        return True
    # Secret-bearing access-key names conventionally include an explicit
    # secret marker; public access-key IDs remain available for debugging.
    return "secret" in parts and "key" in parts


def redact_string(value: str) -> str:
    redacted = _PRIVATE_KEY.sub(REDACTED, value)
    redacted = _BEARER.sub(f"Bearer {REDACTED}", redacted)
    redacted = _BASIC_AUTH.sub(f"Basic {REDACTED}", redacted)
    redacted = _SECRET_HEADER.sub(lambda match: f"{match.group('prefix')}{REDACTED}", redacted)
    redacted = _KNOWN_TOKEN.sub(REDACTED, redacted)
    redacted = _AWS_KEY.sub(REDACTED, redacted)
    redacted = _GOOGLE_API_KEY.sub(REDACTED, redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _WANDB_KEY_CONTEXT.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        redacted,
    )
    redacted = _SECRET_QUOTED_ASSIGNMENT.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('quote')}{REDACTED}{match.group('quote')}"
        ),
        redacted,
    )
    redacted = _SECRET_BARE_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}", redacted
    )
    redacted = _URL_USERINFO.sub(
        lambda match: f"{match.group('scheme')}{REDACTED}@",
        redacted,
    )
    redacted = _EMAIL.sub(REDACTED, redacted)
    redacted = _SSN.sub(REDACTED, redacted)
    redacted = _PHONE.sub(REDACTED, redacted)
    redacted = _redact_cards_preserving_uuids(redacted)
    return redacted


def redact_data(
    value: Any,
    *,
    key: str = "",
    json_string_keys: frozenset[str] = frozenset(),
) -> Any:
    """Return a shape-preserving copy with credentials and common PII removed."""
    if key and _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, str):
        if key in json_string_keys and value:
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError as error:
                raise ValueError("declared JSON string field is invalid") from error
            return json.dumps(
                redact_data(decoded, json_string_keys=json_string_keys),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        return redact_string(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        redacted_key_index = 0
        for item_key, item_value in value.items():
            raw_key = str(item_key)
            scrubbed_key = redact_string(raw_key)
            if scrubbed_key != raw_key:
                redacted_key_index += 1
                scrubbed_key = f"[REDACTED_KEY_{redacted_key_index:04d}]"
            if scrubbed_key in result:
                raise ValueError("mapping keys collide after credential redaction")
            result[scrubbed_key] = redact_data(
                item_value,
                key=raw_key,
                json_string_keys=json_string_keys,
            )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [redact_data(item, json_string_keys=json_string_keys) for item in value]
    return value
