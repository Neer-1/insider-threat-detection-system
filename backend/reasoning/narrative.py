# NEW — per-section report narrative generation. Replaces the old single
# generate_employee_narrative() (one combined summary) with three
# independent, single-pass calls: event description, response guide (both
# for the per-employee report), and one per-employee weekly paragraph.
# Separate from core.py's run_two_pass_judgment() on purpose, same as
# before: these produce descriptive report text for an admin-requested
# PDF, not an actionable judgment driving a Response row, so the two-pass
# analyst/critic cross-examination isn't proportionate here.

"""
Called from backend/reports/employee_report.py and backend/reports/
weekly_report.py, themselves only ever called from an admin explicitly
requesting a report -- never from the real-time detection scheduler, never
queued, never automatic. Same read-only discipline as everything else in
backend/reasoning/: every function here takes an already-assembled context
dict and returns a string or None, never touches the database itself, and
has no side effects of its own.

Each function is independent on purpose -- a report's sections must
degrade individually (backend/reports/pdf_builder.py's callers render an
"AI commentary unavailable" note for whichever one came back None), never
as an all-or-nothing block. Calling code must not assume that because one
of these returned text, the others will too.
"""

from backend.reasoning import client
from backend.reasoning.prompts import (
    EVENT_DESCRIPTION_SYSTEM_PROMPT,
    RESPONSE_GUIDE_SYSTEM_PROMPT,
    WEEKLY_EMPLOYEE_SYSTEM_PROMPT,
    build_event_description_message,
    build_response_guide_message,
    build_weekly_employee_message,
)


async def generate_event_description(context: dict, incident: dict) -> str | None:
    """The connecting narrative for one standing incident -- the incident's
    own facts (timestamps, filenames, etc.) are rendered directly into the
    PDF by backend/reports/employee_report.py, never by this function.
    Only ever called when a standing incident exists; a genuinely clean
    employee needs no LLM call for this section at all."""
    message = build_event_description_message(context, incident)
    result = await client.chat(
        [
            {"role": "system", "content": EVENT_DESCRIPTION_SYSTEM_PROMPT},
            {"role": "user", "content": message},
        ],
        parser=client.parse_event_description,
    )
    return result["narrative"] if result is not None else None


async def generate_response_guide(context: dict, incident: dict, policy_excerpt: str | None) -> str | None:
    """Suggested next steps for the same standing incident, optionally
    grounded in a relevant policy/bylaws excerpt (backend/reasoning/
    policy_document.py's select_relevant_excerpt, keyed on the incident's
    own anomaly_type + department -- same selection mechanism the trigger-
    based judgment flow already uses). Independent call from
    generate_event_description above -- one failing must not affect the
    other."""
    message = build_response_guide_message(context, incident, policy_excerpt)
    result = await client.chat(
        [
            {"role": "system", "content": RESPONSE_GUIDE_SYSTEM_PROMPT},
            {"role": "user", "content": message},
        ],
        parser=client.parse_response_guide,
    )
    return result["guidance"] if result is not None else None


async def generate_weekly_paragraph(entry: dict) -> str | None:
    """One employee's paragraph within the weekly company-wide report.
    Only called for employees with SOME activity to report on in the
    7-day window (an alert or a decision) -- a genuinely clean week's
    "nothing notable" line is a fixed deterministic sentence
    (backend/reports/weekly_report.py), not generated, since there is
    nothing for the model to comment on at all."""
    message = build_weekly_employee_message(entry)
    result = await client.chat(
        [
            {"role": "system", "content": WEEKLY_EMPLOYEE_SYSTEM_PROMPT},
            {"role": "user", "content": message},
        ],
        parser=client.parse_weekly_paragraph,
    )
    return result["paragraph"] if result is not None else None
