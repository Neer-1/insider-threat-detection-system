# NEW — LM Studio HTTP client: async, graceful-failure, tolerant JSON parsing

"""
Talks to LM Studio's OpenAI-compatible local server (core/config.py's
LM_STUDIO_BASE_URL/REASONING_MODEL). Async via httpx, not synchronous
`requests` — a synchronous HTTP call made directly inside an `async def`
would block the entire event loop for the call's whole duration (the
~10s/pass this model was measured at), freezing the real-time scheduler
and every incoming FastAPI request along with it. This client always runs
from backend/reasoning/worker.py's own background task, never inline in
analyzer.py's hot path.

Every failure mode here — connection refused, timeout, malformed JSON,
missing/invalid fields, an unparseable response — returns None rather
than raising. The caller's contract (backend/reasoning/core.py) is: None
means "abort this judgment, log it, leave the deterministic alert as-is",
never a partial or best-guess result. This is a hardcoded assumption
about the exact shape LM Studio + this model returns (fenced JSON, a
"reasoning_content" preamble that gets discarded, specific required
keys) -- deliberately strict rather than lenient, so a shift in the
model's output format fails loudly (as a skipped judgment, logged) rather
than silently accepting garbage.
"""

import json
import re

import httpx

from backend.core.config import (
    LM_STUDIO_BASE_URL,
    REASONING_MAX_TOKENS,
    REASONING_MODEL,
    REASONING_RECOMMENDATIONS,
    REASONING_TEMPERATURE,
    REASONING_TIMEOUT_SECONDS,
)

# Matches a ```json ... ``` or bare ``` ... ``` fence LM Studio/Gemma
# commonly wraps JSON output in despite being told to return only JSON —
# confirmed directly during testing (see core/config.py's comment on
# REASONING_MAX_TOKENS for the exact test call this behaviour came from).
_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _strip_fence(text: str) -> str:
    match = _FENCE_PATTERN.search(text)
    return match.group(1) if match else text


def _extract_first_json_object(text: str) -> str | None:
    """Falls back to a balanced-brace scan for the first {...} block if
    the whole (fence-stripped) string isn't valid JSON on its own -- some
    models add a stray sentence before or after the JSON even when told
    not to. Not a regex (nested braces inside string values break a naive
    regex); a simple depth counter that respects quoted strings."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _parse_json_object(content: str) -> dict | None:
    """Shared tolerant-JSON-extraction step used by every parser below --
    fence-stripping, then a direct parse attempt, then the balanced-brace
    scan fallback. Returns the parsed dict, or None if nothing in the
    content parses as one. Callers layer their own schema validation on
    top of this; extraction itself doesn't know or care what the caller's
    required fields are."""
    if not content or not content.strip():
        return None

    stripped = _strip_fence(content).strip()
    for candidate in (stripped, _extract_first_json_object(stripped)):
        if candidate is None:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def parse_judgment(content: str, *, require_agreed_field: bool) -> dict | None:
    """Tolerant parse + strict validation. Returns a dict with
    "explanation" (str), "recommendation" (one of REASONING_RECOMMENDATIONS),
    "confidence" (float, clamped to [0, 1] if a real number was given but
    slightly out of range), and — for the critic pass only —
    "agreed_with_initial" (bool). Returns None on any failure: empty/
    missing content, unparseable JSON, missing required keys, or a
    recommendation outside the fixed vocabulary. Confidence being absent
    or non-numeric doesn't fail the whole judgment -- it's treated as
    None (not required for the recommendation to be actionable), matching
    the fixed-vocabulary "recommendation" being the load-bearing field."""
    parsed = _parse_json_object(content)
    if parsed is None:
        return None

    explanation = parsed.get("explanation")
    recommendation = parsed.get("recommendation")
    if not isinstance(explanation, str) or not explanation.strip():
        return None
    if recommendation not in REASONING_RECOMMENDATIONS:
        return None
    if require_agreed_field and not isinstance(parsed.get("agreed_with_initial"), bool):
        return None

    confidence = parsed.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        confidence = max(0.0, min(1.0, float(confidence)))
    else:
        confidence = None

    result = {"explanation": explanation.strip(), "recommendation": recommendation, "confidence": confidence}
    if require_agreed_field:
        result["agreed_with_initial"] = bool(parsed["agreed_with_initial"])
    return result


def _parse_single_text_field(content: str, field_name: str) -> dict | None:
    """Shared tolerant parse + validation for every single-string-field
    report section (event description, response guide, weekly per-
    employee paragraph) -- much smaller schema than a judgment (one
    required field, no fixed-vocabulary recommendation to validate
    against), reusing the exact same extraction step as parse_judgment
    above since all of these talk to the same model with the same
    real-world quirks (fenced output, a stray sentence around the JSON).
    Returns a dict with `field_name` (str), or None on any failure."""
    parsed = _parse_json_object(content)
    if parsed is None:
        return None

    value = parsed.get(field_name)
    if not isinstance(value, str) or not value.strip():
        return None

    return {field_name: value.strip()}


def parse_event_description(content: str) -> dict | None:
    return _parse_single_text_field(content, "narrative")


def parse_response_guide(content: str) -> dict | None:
    return _parse_single_text_field(content, "guidance")


def parse_weekly_paragraph(content: str) -> dict | None:
    return _parse_single_text_field(content, "paragraph")


async def chat(messages: list[dict], *, parser) -> dict | None:
    """One completion call against LM Studio, parsed and validated by
    `parser` (a callable taking the raw content string and returning a
    dict or None -- parse_judgment for the trigger-based two-pass
    judgment flow, parse_event_description/parse_response_guide/
    parse_weekly_paragraph for the report sections; generalized from a
    hardcoded parse_judgment call so this one client/retry/error-handling
    path serves all of them without duplicating
    it). None on any failure (network error, timeout, non-2xx response,
    unparseable or invalid output) -- never raises out of this function;
    callers treat None as "skip this" (an aborted judgment, or a failed
    report generation, depending on the caller)."""
    from backend.core.runtime import EXTERNAL_SERVICES
    if not EXTERNAL_SERVICES:
        return None
    try:
        async with httpx.AsyncClient(timeout=REASONING_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{LM_STUDIO_BASE_URL}/chat/completions",
                json={
                    "model": REASONING_MODEL,
                    "messages": messages,
                    "max_tokens": REASONING_MAX_TOKENS,
                    "temperature": REASONING_TEMPERATURE,
                },
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        print(f"[reasoning] LM Studio call failed ({type(e).__name__}: {e}) — skipping")
        return None

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        print("[reasoning] LM Studio response missing expected choices[0].message.content — skipping")
        return None

    result = parser(content)
    if result is None:
        print(f"[reasoning] could not parse a valid response from LM Studio — skipping. Raw content: {content[:300]!r}")
    return result
