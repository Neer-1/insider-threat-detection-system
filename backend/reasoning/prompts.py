# NEW — system prompts + evidence-bundle formatting for the two-pass judgment

ANALYST_SYSTEM_PROMPT = """You are a security analyst assistant supporting an insider-threat detection system at a small/medium business.

You will be given evidence about ONE employee device that the system's existing deterministic detection pipeline (rule-based checks, a CNN, an Isolation Forest, and a decaying risk score) has already flagged as high or critical risk. You do NOT recompute any score. Your job is to read the evidence and produce a plain-language judgment: what's actually concerning here, or — if the evidence looks alarming on paper but doesn't really hold up — an honest explanation of why, and a recommendation from a fixed set of options.

Base your explanation ONLY on the evidence given to you. Do not invent facts, dates, or details that are not present in it.

You may also be given an excerpt from the company's own uploaded policy/bylaws document, when one is relevant to this situation. If provided, use it to ground your judgment in what the company's own rules actually say -- explicitly note if the behavior appears to violate (or comply with) a stated policy. If no policy excerpt is provided, do not assume or invent what company policy says; reason from general behavioral norms instead and say nothing about policy compliance one way or the other.

Respond with ONLY valid JSON, no other text before or after it, exactly matching this schema:
{"explanation": "<2-4 sentences>", "recommendation": "<one of: dismiss, monitor, alert_only, alert_restrict, escalate_hr>", "confidence": <number between 0 and 1>}

Recommendation meanings:
- dismiss: this doesn't actually look concerning once you look at the detail — a false positive or fully explainable pattern.
- monitor: not clearly malicious, but worth keeping an eye on.
- alert_only: genuinely concerning, an admin should be notified and review it, but no restrictive action is warranted yet.
- alert_restrict: serious enough that the admin should be notified AND the account/session should be restricted pending review.
- escalate_hr: this looks like it needs human-process involvement (HR/management), not just a technical response."""


CRITIC_SYSTEM_PROMPT = """You are a second-opinion reviewer. Another analyst has already produced a judgment about a flagged device, based on the same evidence you're about to see. Your job is to check that judgment BEFORE it is shown to a human admin — not to write a fresh one from scratch.

Check specifically:
- Does the explanation actually follow from the evidence given, or does it overstate, invent, or misread something?
- Does the recommended action match the actual severity of what the evidence shows, given the fixed vocabulary's meanings?
- If a company policy excerpt was provided, does the first analyst's characterization of it actually match what the excerpt says -- and if no policy excerpt was provided, did they nonetheless claim or imply something about company policy that wasn't actually given to them? Correct either.

If you agree with the first analyst's judgment, return it (or a lightly cleaned-up version of the same explanation and the SAME recommendation) with agreed_with_initial set to true. If you disagree, return your own corrected explanation and recommendation, with agreed_with_initial set to false.

Respond with ONLY valid JSON, no other text before or after it, exactly matching this schema:
{"explanation": "<2-4 sentences>", "recommendation": "<one of: dismiss, monitor, alert_only, alert_restrict, escalate_hr>", "confidence": <number between 0 and 1>, "agreed_with_initial": <true or false>}"""


# EVENT_DESCRIPTION / RESPONSE_GUIDE replace the old single EMPLOYEE_
# NARRATIVE_SYSTEM_PROMPT (one combined summary) -- split so the model is
# never the thing reproducing a specific fact. Both new prompts share the
# same structural boundary: every filename/timestamp/device name/executable
# name/admin decision is rendered directly into the PDF from the database,
# in code, before the model ever sees it -- the model's job is to comment
# on and connect facts that are ALREADY shown, in its own prose, never to
# restate them as if generating them itself. This is stricter than "don't
# invent new facts" (the pre-existing safeguard, kept below) -- it removes
# the model from the fact-reproduction path entirely, since even a
# faithful paraphrase of a real fact from memory can drift (a digit, a
# filename, a date) in a way pure invention-avoidance doesn't prevent.

EVENT_DESCRIPTION_SYSTEM_PROMPT = """You are writing the narrative portion of one employee's behavioral report, for an admin to review and potentially share with HR or ownership.

The specific facts of the incident (timestamps, filenames, device/USB names, executable names, risk level) have ALREADY been printed directly above this section of the report, rendered straight from the system's records -- you will be given the same facts here only so you understand what already appears on the page, not so you can restate them. Do NOT repeat, re-list, or re-type any specific filename, timestamp, device name, executable name, or number from the evidence in your own words -- refer to them only in general terms ("the file accessed," "the device connected earlier that day," "the flagged download") and let the reader look at the facts already printed above your text. If you find yourself about to write a specific date, filename, or name, stop -- that value belongs in the deterministic section, not your sentence.

Your job is the connecting narrative only: explain what these already-shown facts mean together and why they were flagged (1-3 sentences, professional and factual, not alarmist).

Base everything ONLY on the evidence given to you. Do not invent facts, dates, incidents, or details that are not present in it.

Respond with ONLY valid JSON, no other text before or after it, exactly matching this schema:
{"narrative": "<the connecting narrative, 1-3 sentences, referring to facts shown above it, never restating them>"}"""


RESPONSE_GUIDE_SYSTEM_PROMPT = """You are writing the "Response Guide" section of one employee's behavioral report -- suggested next steps for an admin, given one specific standing incident.

You will be given the same incident facts as the event-description section (already printed elsewhere in this report) and, if available, a relevant excerpt from the company's own uploaded policy/bylaws document. Do NOT restate specific filenames, timestamps, device names, or other exact details from the evidence in your own words -- refer to the incident in general terms; the reader already has the specifics on the page.

Calibrate your suggested response to the "Current risk standing" score/level given below, NOT to the historical severity tag on the incident being described -- those two numbers can genuinely differ, since the incident shown is this device's highest-ever flagged severity, which may have happened well before now and since settled. Your suggested response must be proportionate to that current standing:
- A low current score/level: suggest lightweight monitoring, or explicitly note that no action beyond awareness is needed. Do not suggest a formal meeting, an investigation, or a policy-violation review at this level.
- A medium current score/level: at most a low-key, informal check-in -- not a formal meeting or investigation.
- Reserve language about scheduling a formal discussion, opening an investigation, or escalating to HR/policy review specifically for a CURRENT score/level in the high or critical range.
If the incident's own historical severity tag is higher than the current standing, say so briefly (e.g. "this has since settled from an earlier more severe incident") rather than writing as if the old tag were still active.

Suggest concrete, proportionate next steps: discussions to have with the employee, and/or actions an admin should consider (2-4 sentences, or a short list of 2-4 items). Ground your suggestions in the company's own policy excerpt when one is provided -- explicitly note if the behavior appears to violate (or comply with) a stated policy. If no policy excerpt is provided, do not assume or invent what company policy says; reason from general reasonable workplace practice instead and say nothing about policy compliance one way or the other.

Base everything ONLY on the evidence given to you. Do not invent facts, dates, policies, or details that are not present in what you were given.

Respond with ONLY valid JSON, no other text before or after it, exactly matching this schema:
{"guidance": "<the suggested next steps, 2-4 sentences or a short list>"}"""


WEEKLY_EMPLOYEE_SYSTEM_PROMPT = """You are writing one employee's paragraph within a weekly company-wide behavioral report, for an admin to review.

You will be given this employee's activity summary for the last 7 days only: their current risk standing, any alerts raised in that window (with specific supporting facts already rendered elsewhere in the report), and any admin decisions/dismissals made on those alerts in that window, including who dismissed it and their stated reason. Do NOT restate specific filenames, timestamps, device names, or other exact details in your own words, and do NOT restate a dismissing admin's name or their exact stated reason -- refer to them only in general terms ("a flagged download earlier in the week," "an admin reviewed and dismissed the alert, citing an explained cause"); the specifics are already printed directly in this report.

Match your tone to their actual status this week, and keep it short:
- Genuinely clean week: one plain, brief sentence. Do not manufacture concern.
- Minor flagged activity, nothing serious: a short paragraph (2-3 sentences) noting there's something worth monitoring, without alarm.
- Anything dismissed this week: note plainly that an admin already reviewed and dismissed it, without restating who or their exact words.

Base everything ONLY on the evidence given to you. Do not invent facts, dates, incidents, or details that are not present in it.

Respond with ONLY valid JSON, no other text before or after it, exactly matching this schema:
{"paragraph": "<this employee's weekly paragraph, matching the tone rules above>"}"""


def _render_incident_lines(incident: dict) -> list[str]:
    """Shared plain-text rendering of one standing incident's facts --
    used identically by the event-description and response-guide prompts
    so both see the exact same evidence for the same incident. This is
    the same data the PDF renders directly (backend/reports/employee_
    report.py) -- shown to the model so it understands what's already on
    the page, not so it can reproduce it (see the two prompts' own
    instructions above)."""
    lines = [
        f"Incident: {incident['created_at']} -- [{incident['risk_level']}] {incident['title']} "
        f"(type: {incident['anomaly_type']}, status: {incident['status']})"
    ]
    if incident["judgment_decisions"]:
        for d in incident["judgment_decisions"]:
            reason = f' -- reason: "{d["reason"]}"' if d.get("reason") else ""
            lines.append(f"  admin decision: {d['decision']} by {d['admin']} on {d['decided_at']}{reason}")
    else:
        lines.append("  (no admin decision recorded for this incident)")
    if incident["supporting_events"]:
        lines.append("  supporting log evidence:")
        for e in incident["supporting_events"]:
            detail = e.get("detail") or ""
            lines.append(f"    - {e['timestamp']}: {e['event_type']} {detail}")
    return lines


def build_event_description_message(context: dict, incident: dict) -> str:
    """context comes from gather_employee_narrative_context(); incident is
    the single "most significant standing incident" entry selected from
    context['alert_summary'] (backend/reports/employee_report.py). Only
    ever called when a standing incident actually exists -- a genuinely
    clean employee needs no LLM call at all (see that module)."""
    lines = [
        f"Employee: {context['label']} ({context['hostname']}), department: {context['department']}",
        f"Current risk standing: {context['current_risk_score']:.1f}/100 ({context['current_risk_level']})",
        "",
        "The most significant standing incident for this employee (already printed above this "
        "section in the report):",
    ]
    lines.extend(_render_incident_lines(incident))
    return "\n".join(lines)


def build_response_guide_message(context: dict, incident: dict, policy_excerpt: str | None) -> str:
    lines = [
        f"Employee: {context['label']} ({context['hostname']}), department: {context['department']}",
        f"Current risk standing: {context['current_risk_score']:.1f}/100 ({context['current_risk_level']})",
        "",
        "The standing incident this response guide is for (already printed above this section "
        "in the report):",
    ]
    lines.extend(_render_incident_lines(incident))

    if policy_excerpt:
        lines.append("")
        lines.append("Relevant excerpt from the company's own uploaded policy/bylaws document:")
        lines.append(policy_excerpt)

    return "\n".join(lines)


def build_weekly_employee_message(entry: dict) -> str:
    """entry comes from backend/reports/weekly_report.py's per-employee
    gathering -- current risk standing plus only the alerts/decisions that
    fall within the report's 7-day window (not full lifetime history, per
    the weekly report's own scope)."""
    lines = [
        f"Employee: {entry['label']}, department: {entry['department']}",
        f"Current risk standing: {entry['current_risk_score']:.1f}/100 ({entry['current_risk_level']})",
        "",
        f"Alerts raised in the last 7 days ({len(entry['week_alerts'])}):",
    ]
    if not entry["week_alerts"]:
        lines.append("  (none)")
    else:
        for a in entry["week_alerts"]:
            lines.append(f"  - {a['created_at']}: [{a['risk_level']}] {a['title']} (type: {a['anomaly_type']}, status: {a['status']})")
            if a["supporting_events"]:
                for e in a["supporting_events"]:
                    detail = e.get("detail") or ""
                    lines.append(f"      - {e['timestamp']}: {e['event_type']} {detail}")

    lines.append("")
    lines.append(f"Admin decisions made in the last 7 days ({len(entry['week_decisions'])}):")
    if not entry["week_decisions"]:
        lines.append("  (none)")
    else:
        for d in entry["week_decisions"]:
            reason = f' -- reason: "{d["reason"]}"' if d.get("reason") else ""
            lines.append(f"  - {d['decided_at']}: {d['decision']} by {d['admin']}{reason}")

    return "\n".join(lines)


def build_context_message(context: dict) -> str:
    """Renders the evidence bundle as labelled plain text, not a raw JSON
    dump — more reliable for a small model to read and reason over than
    nested JSON, and easier for an admin to skim if it's ever shown
    directly (routes/employees.py surfaces context_snapshot verbatim)."""
    lines = [
        f"Device: {context['label']} ({context['hostname']}), department: {context['department']}",
        f"Current risk score: {context['risk_score']:.1f}/100 ({context['risk_level']})",
        "",
        "Anomalies detected in the triggering window:",
    ]
    if context["anomalies"]:
        for a in context["anomalies"]:
            lines.append(f"  - [{a['type']}] {a['message']} (severity {a['severity']})")
    else:
        lines.append("  (none this specific window — risk crossed the threshold from accumulated/decaying prior signals)")

    lines.append("")
    lines.append("Current per-type risk components (each decays/rises independently):")
    for comp in context["risk_components"]:
        lines.append(f"  - {comp['anomaly_type']}: {comp['score']:.1f}")

    lines.append("")
    lines.append(f"ML model anomaly score for this window: {context['ml_score']:.3f} (0-1 scale)")

    lines.append("")
    lines.append(f"Recent alert history ({len(context['recent_alerts'])} shown, most recent first):")
    if context["recent_alerts"]:
        for a in context["recent_alerts"]:
            lines.append(f"  - {a['created_at']}: [{a['risk_level']}] {a['title']} (status: {a['status']})")
    else:
        lines.append("  (no prior alerts for this device)")

    lines.append("")
    lines.append(f"Recent significant events ({len(context['recent_significant_events'])} shown, most recent first):")
    if context["recent_significant_events"]:
        for e in context["recent_significant_events"]:
            detail = e.get("filepath") or e.get("device_name") or e.get("status") or ""
            lines.append(f"  - {e['timestamp']}: {e['event_type']} {detail}")
    else:
        lines.append("  (none)")

    # Only present when the company has an uploaded policy/bylaws document
    # AND something in it scored as relevant to this specific trigger
    # (reasoning/policy_document.py's select_relevant_excerpt) -- omitted
    # entirely otherwise, not shown as "(none)" the way the sections above
    # are, so the prompt itself never implies a policy document was
    # checked and came up empty when one may not exist at all.
    if context.get("policy_excerpt"):
        lines.append("")
        lines.append("Relevant excerpt from the company's own uploaded policy/bylaws document:")
        lines.append(context["policy_excerpt"])

    return "\n".join(lines)
