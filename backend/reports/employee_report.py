# NEW — per-employee narrative PDF ("Generate Employee Report" button on
# the profile page). Reads from data that already exists (the learned
# baseline system, alert/judgment history, significant events) and asks
# the Reasoning Core for two independent, narrowly-scoped narrative
# sections (event description, response guide) -- no new detection logic.
#
# Structural anti-hallucination boundary: every specific fact (filename,
# timestamp, device/USB name, executable name, risk score, admin decision
# + reason, date) is rendered directly from gather_employee_narrative_
# context()'s data into the PDF, in code, by build_employee_report_pdf
# below -- never generated or retyped by the model. The model (backend/
# reasoning/narrative.py) is only ever given those same facts to
# understand what's already on the page; its prompts (reasoning/
# prompts.py) explicitly forbid restating them. See that module for the
# full reasoning.

from datetime import timedelta

from sqlalchemy.orm import Session

from backend.agent_logic.alert_history import build_alert_history
from backend.agent_logic.baseline_learning import get_effective_baseline
from backend.agent_logic.significant_events import significant_log_predicate
from backend.core.config import ANALYSIS_WINDOW_MINUTES, RISK_LEVEL_RANK, risk_level_for_score
from backend.models.company_policy_document import CompanyPolicyDocument
from backend.models.devices import Device, DeviceMetadata
from backend.models.logs import Log
from backend.reasoning.policy_document import select_relevant_excerpt
from backend.reports.pdf_builder import bold_line, bullet, empty_note, format_mauritius, label_value, new_report, paragraph, section_title, to_bytes

# How many significant log rows to include as supporting evidence per
# flagged incident -- "the specific ... entries relevant to that history,
# not their entire raw log history." A handful is enough to substantiate
# what the alert was actually about without turning the report into a log
# dump; an admin who wants more already has "View raw logs" on the
# profile page itself.
SUPPORTING_EVENTS_LIMIT = 8


def _supporting_events(db: Session, device: Device, around) -> list[dict]:
    """Significant Log rows from the SAME detection window that actually
    produced the alert (ANALYSIS_WINDOW_MINUTES before it), not a blanket
    scan of this device's whole history -- reuses the exact predicate
    GET /logs/significant already uses, so "relevant" means the same
    thing here as it does everywhere else in the app."""
    if around is None:
        return []
    window_start = around - timedelta(minutes=ANALYSIS_WINDOW_MINUTES)
    rows = (
        db.query(Log)
        .filter(Log.device_id == device.device_id, Log.timestamp >= window_start, Log.timestamp <= around)
        .filter(significant_log_predicate())
        .order_by(Log.timestamp.desc())
        .limit(SUPPORTING_EVENTS_LIMIT)
        .all()
    )
    return [
        {
            "timestamp": format_mauritius(log.timestamp),
            "event_type": log.event_type,
            "detail": log.filepath or log.device_name or log.action or "",
        }
        for log in rows
    ]


def gather_employee_narrative_context(db: Session, device: Device) -> dict:
    """Read-only evidence assembly for the employee report -- department,
    monitoring duration, current risk standing, the learned baseline
    (agent_logic/baseline_learning.py), and the full correlated alert/
    judgment history (agent_logic/alert_history.py) with supporting log
    evidence per flagged incident. Used both to build the LLM prompt
    (reasoning/prompts.py's build_narrative_context_message) and, again,
    to lay out the PDF itself -- one source of truth for both."""
    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    # Genuinely None when unset -- get_effective_baseline/select_relevant_
    # excerpt below already treat None exactly like an unrecognized
    # department. Guarded to "unassigned" only in the returned dict's own
    # "department" field further down, where it's rendered as text in the
    # PDF (build_employee_report_pdf's label_value call).
    department = metadata.department if metadata and metadata.department else None

    score = device.current_risk_score or 0.0
    baseline = get_effective_baseline(db, device.device_id, device.company_id, department)

    history_entries = build_alert_history(db, device)

    alert_summary = []
    for entry in history_entries:
        alert = entry["alert"]
        judgments = entry["judgments"]

        if alert is not None:
            created_at_raw = alert["created_at"]
            title = alert["title"]
            anomaly_type = alert["anomaly_type"]
            risk_level = alert["risk_level"]
            entry_status = alert["status"]
        else:
            # Orphan judgment (models/reasoning.py's alert_id docstring --
            # the aggregate score crossing a threshold doesn't always
            # correspond to one specific Alert row). Still real flagged
            # history, worth including, just described in its own terms
            # rather than an alert's.
            j0 = judgments[0]
            created_at_raw = j0["triggered_at"]
            title = "Aggregate risk threshold crossed (no single triggering alert)"
            anomaly_type = "aggregate"
            risk_level = j0["trigger_risk_level"]
            entry_status = "n/a"

        # One merged, already-chronological timeline per entry (accept/
        # override plus any legacy dismiss rows from before the dismiss/
        # undo consolidation, and every dismiss/undo toggle since) --
        # agent_logic/alert_history.py's build_alert_history builds this
        # the same way for every consumer, this report included.
        judgment_decisions = [
            {
                "decision": d["decision"],
                "admin": d["admin_username"] or "unknown admin",
                "decided_at": format_mauritius(d["decided_at"]),
                "reason": d["reason"],
            }
            for d in entry["decision_history"]
        ]

        alert_summary.append({
            "created_at": format_mauritius(created_at_raw),
            "risk_level": risk_level,
            "title": title,
            "anomaly_type": anomaly_type,
            "status": entry_status,
            "judgment_decisions": judgment_decisions,
            "supporting_events": _supporting_events(db, device, created_at_raw),
        })

    # "Most significant standing incident" for the Event Description /
    # Response Guide sections -- highest risk_level, most recent as
    # tiebreak. alert_summary is already newest-first (built in that order
    # from build_alert_history's own sort), so max() picking the FIRST
    # maximal element it encounters already gives "most recent among
    # highest severity" for free, no separate datetime tiebreak needed.
    # None for a genuinely clean employee -- callers must not invent one.
    standing_incident = (
        max(alert_summary, key=lambda e: RISK_LEVEL_RANK.get(e["risk_level"], -1))
        if alert_summary
        else None
    )

    policy_excerpt = None
    if standing_incident is not None:
        policy_doc = db.query(CompanyPolicyDocument).filter(CompanyPolicyDocument.company_id == device.company_id).first()
        if policy_doc is not None:
            # select_relevant_excerpt only ever reads a.get("type") off
            # each anomaly dict (backend/reasoning/policy_document.py) --
            # a single-item list carrying just the standing incident's own
            # anomaly_type is enough to reuse it unchanged, same selection
            # mechanism the trigger-based judgment flow already uses.
            policy_excerpt = select_relevant_excerpt(
                db, device.company_id, policy_doc.converted_markdown, [{"type": standing_incident["anomaly_type"]}], department
            )

    return {
        "label": device.label or device.hostname,
        "hostname": device.hostname,
        "username": device.username,
        "os_info": device.os_info,
        "ip_address": device.ip_address,
        "department": department or "unassigned",
        "enrolled_at": format_mauritius(device.enrolled_at) if device.enrolled_at else None,
        "current_risk_score": score,
        "current_risk_level": risk_level_for_score(score),
        "baseline": baseline,
        "total_alerts": len(alert_summary),
        "alert_summary": alert_summary,
        "standing_incident": standing_incident,
        "policy_excerpt": policy_excerpt,
    }


def _render_incident_facts(pdf, incident: dict) -> None:
    """Direct data render of one incident's facts -- timestamps, exact
    filenames/USB names/executable names, admin decisions -- shared by the
    Event Description and (indirectly, via the same context) Response
    Guide sections. Never touched by the model; see this module's
    docstring."""
    bold_line(pdf, f"{incident['created_at']} -- [{incident['risk_level']}] {incident['title']}", size=11)
    label_value(pdf, "Type", incident["anomaly_type"])
    label_value(pdf, "Status", incident["status"])

    if incident["judgment_decisions"]:
        for d in incident["judgment_decisions"]:
            line = f"Admin decision: {d['decision']} by {d['admin']} on {d['decided_at']}"
            if d["reason"]:
                line += f' -- reason: "{d["reason"]}"'
            bullet(pdf, line)
    else:
        bullet(pdf, "No admin decision recorded for this incident.")

    if incident["supporting_events"]:
        paragraph(pdf, "Supporting log evidence:", size=9.5, italic=True)
        for e in incident["supporting_events"]:
            detail = f" -- {e['detail']}" if e["detail"] else ""
            bullet(pdf, f"{e['timestamp']}: {e['event_type']}{detail}", indent="  ")


def build_employee_report_pdf(
    device: Device,
    company_name: str,
    context: dict,
    event_description: str | None,
    response_guide: str | None,
) -> bytes:
    """event_description/response_guide are the model's OWN connecting
    narrative for context['standing_incident'] (backend/reasoning/
    narrative.py) -- None means either there was no standing incident to
    begin with (nothing was ever asked of the model for that employee) or
    the call was attempted and failed/didn't validate; the two cases are
    rendered differently below (a plain "clean" statement vs. an explicit
    "AI commentary unavailable" note) so a reader can never confuse
    "nothing happened" with "something happened but the AI couldn't
    comment on it". Every specific fact in this PDF is rendered directly
    from `context` -- these two strings are the ONLY model-generated text
    in the whole document, and neither is permitted (per their prompts) to
    contain a specific fact of its own."""
    employee_label = device.label or device.hostname
    incident = context["standing_incident"]

    pdf = new_report(
        "LITDS Employee Behavioral Report",
        f"{company_name} -- {employee_label} ({device.hostname})",
    )

    section_title(pdf, "Overview")
    label_value(pdf, "Department", context["department"])
    label_value(pdf, "Monitored since", context["enrolled_at"] or "unknown")
    label_value(pdf, "Current risk standing", f"{context['current_risk_level']} ({round(context['current_risk_score'])}/100)")
    pdf.ln(2)

    baseline = context["baseline"]
    bold_line(pdf, "Typical activity baseline for this person:")
    bullet(pdf, f"Files accessed per day: expected ~{baseline['avg_files_per_day']:.1f}")
    bullet(pdf, f"Normal working hours: {baseline['normal_hours'][0]:02d}:00-{baseline['normal_hours'][1]:02d}:00")
    bullet(pdf, f"Expected failed logins: ~{baseline['avg_failed_logins']:.1f}")

    section_title(pdf, "Device Details")
    label_value(pdf, "Hostname", context["hostname"])
    label_value(pdf, "Device username", context["username"] or "unknown")
    label_value(pdf, "Operating system", context["os_info"] or "unknown")
    label_value(pdf, "IP address", context["ip_address"] or "unknown")

    section_title(pdf, "Event Description")
    if incident is None:
        empty_note(pdf, "No incidents on record for this employee -- behavior has remained within expected bounds for the entire monitored period.")
    else:
        _render_incident_facts(pdf, incident)
        pdf.ln(2)
        if event_description:
            paragraph(pdf, event_description)
        else:
            empty_note(pdf, "AI commentary unavailable for this section -- the AI reasoning service was unreachable or returned an unusable response. The incident facts above are unaffected and reflect the system's own records.")

    section_title(pdf, "Response Guide")
    if incident is None:
        empty_note(pdf, "No corrective or preventative action is currently indicated -- there is no flagged incident for this employee to respond to.")
    elif response_guide:
        paragraph(pdf, response_guide)
        if not context.get("policy_excerpt"):
            paragraph(pdf, "No company policy/bylaws document was available (or nothing in it matched this incident) -- this guidance reflects general reasoning only.", size=9, italic=True)
    else:
        empty_note(pdf, "AI commentary unavailable for this section -- the AI reasoning service was unreachable or returned an unusable response.")

    section_title(pdf, f"Flagged History ({context['total_alerts']} total)")
    if not context["alert_summary"]:
        empty_note(pdf, "No alerts have ever been raised for this employee -- activity has stayed within expected bounds for the entire monitored period.")
    else:
        for entry in context["alert_summary"]:
            _render_incident_facts(pdf, entry)
            pdf.ln(3)

    return to_bytes(pdf)
