# NEW — weekly company-wide behavioral PDF (one report, every approved
# employee). Same structural anti-hallucination boundary as
# backend/reports/employee_report.py: every specific fact (timestamps,
# filenames, admin names/reasons, risk scores) is rendered directly from
# the database into the PDF, in code -- the model only ever writes each
# employee's short connecting paragraph, and only when there's genuinely
# something in the window to comment on (see gather_weekly_context below).

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.agent_logic.alert_history import build_alert_history
from backend.core.config import risk_level_for_score
from backend.models.devices import Device, DeviceMetadata
from backend.reports.employee_report import _supporting_events
from backend.reports.pdf_builder import bold_line, bullet, empty_note, format_mauritius, label_value, new_report, paragraph, section_title, to_bytes

WEEKLY_WINDOW_DAYS = 7
# high/critical only -- matches RISK_LEVEL_RANK's own bands (core/config.py);
# "elevated" here means the same thing "elevated" means everywhere else in
# the app, not a separately-invented threshold.
ELEVATED_RISK_LEVELS = ("high", "critical")


def _surname_sort_key(label: str) -> tuple[str, str]:
    """Sorting convention, not a fact about the data: there is no
    structured first/last name field anywhere in this schema (Device.label
    is free-text, admin-typed at approval time) -- the last whitespace-
    separated word in the label is treated as the surname for sort
    purposes ("John Smith" sorts under "Smith"). A single-word label (no
    space -- e.g. a hostname-derived label) has no word to treat as a
    surname, so it falls back to sorting by the whole label unchanged.
    Documented here as the heuristic it is, not assumed to be reliable for
    every possible label an admin might type."""
    parts = label.strip().split()
    surname = parts[-1].lower() if parts else ""
    return (surname, label.lower())


def gather_weekly_context(db: Session, company_id: int) -> dict:
    """Read-only evidence assembly for every approved device in the
    company, windowed to the last WEEKLY_WINDOW_DAYS days. Returns
    employees pre-sorted (department alphabetical, then surname-heuristic
    alphabetical within department) and the deterministic elevated-
    employee summary -- both computed here, in code, once, so the PDF
    builder and the per-employee LLM-call decision both read the exact
    same grouping/order instead of two independent passes that could
    disagree."""
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(days=WEEKLY_WINDOW_DAYS)

    devices = db.query(Device).filter(Device.company_id == company_id, Device.approval_status == "approved").all()

    employees = []
    for device in devices:
        metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
        # Purely a display/grouping/sort label in this file (never fed into
        # a baseline/keyword lookup here) -- "unassigned", not the old
        # "engineering" fallback, and never raw None: current_department.
        # upper() below and the (department, surname) sort key both assume
        # a real string.
        department = (metadata.department if metadata and metadata.department else None) or "unassigned"
        score = device.current_risk_score or 0.0
        risk_level = risk_level_for_score(score)
        label = device.label or device.hostname

        history_entries = build_alert_history(db, device)

        week_alerts = []
        week_decisions = []
        for entry in history_entries:
            alert = entry["alert"]
            judgments = entry["judgments"]

            if alert is not None:
                created_at_raw = alert["created_at"]
                title = alert["title"]
                anomaly_type = alert["anomaly_type"]
                entry_risk_level = alert["risk_level"]
                entry_status = alert["status"]
            else:
                j0 = judgments[0]
                created_at_raw = j0["triggered_at"]
                title = "Aggregate risk threshold crossed (no single triggering alert)"
                anomaly_type = "aggregate"
                entry_risk_level = j0["trigger_risk_level"]
                entry_status = "n/a"

            if created_at_raw is not None and created_at_raw >= window_start:
                week_alerts.append({
                    "created_at": format_mauritius(created_at_raw),
                    "risk_level": entry_risk_level,
                    "title": title,
                    "anomaly_type": anomaly_type,
                    "status": entry_status,
                    "supporting_events": _supporting_events(db, device, created_at_raw),
                })

            for d in entry["decision_history"]:
                if d["decided_at"] is not None and d["decided_at"] >= window_start:
                    week_decisions.append({
                        "decision": d["decision"],
                        "admin": d["admin_username"] or "unknown admin",
                        "decided_at": format_mauritius(d["decided_at"]),
                        "reason": d["reason"],
                    })

        employees.append({
            "label": label,
            "hostname": device.hostname,
            "department": department,
            "current_risk_score": score,
            "current_risk_level": risk_level,
            "week_alerts": week_alerts,
            "week_decisions": week_decisions,
        })

    employees.sort(key=lambda e: (e["department"], _surname_sort_key(e["label"])))

    # Deterministic, not LLM-generated -- highest risk score first, so the
    # most urgent name reads first regardless of department/surname order
    # used for the main body above.
    elevated = sorted(
        (e for e in employees if e["current_risk_level"] in ELEVATED_RISK_LEVELS),
        key=lambda e: e["current_risk_score"],
        reverse=True,
    )

    return {
        "window_start": format_mauritius(window_start),
        "window_end": format_mauritius(window_end),
        "employees": employees,
        "elevated": [
            {"label": e["label"], "department": e["department"], "risk_score": e["current_risk_score"], "risk_level": e["current_risk_level"]}
            for e in elevated
        ],
    }


def build_weekly_report_pdf(company_name: str, context: dict, weekly_paragraphs: dict[str, str | None]) -> bytes:
    """weekly_paragraphs maps employee label -> AI paragraph text, or None
    if that employee had activity worth commenting on but the LLM call
    failed/didn't validate (never None just because there's nothing to
    say -- see gather_weekly_context/the route: a genuinely clean
    employee's line is a fixed deterministic sentence, generated with no
    LLM call at all, and never appears in this dict)."""
    pdf = new_report(
        "LITDS Weekly Company Report",
        f"{company_name} -- {context['window_start']} to {context['window_end']}",
    )

    # Quick-reference summary FIRST, immediately after the header -- who to
    # check first, nothing else (name/department/risk score/level only, no
    # alerts/decisions/narrative). The full department-by-department
    # breakdown below is where an admin actually goes to read about a
    # specific person; this is deliberately just a table of contents for
    # that, not a second copy of it. Same underlying `context["elevated"]`
    # list as before (deterministic, sorted highest-risk first) -- only its
    # position in the document moved.
    section_title(pdf, "Summary: Employees Requiring Attention")
    if not context["elevated"]:
        empty_note(pdf, "No employees are currently at high or critical risk.")
    else:
        paragraph(pdf, "Highest risk first. See that employee's own section below for the full detail.", size=9, italic=True)
        for e in context["elevated"]:
            bullet(pdf, f"{e['label']} ({e['department']}) -- {e['risk_level']} ({round(e['risk_score'])}/100)")

    current_department = None
    for employee in context["employees"]:
        if employee["department"] != current_department:
            current_department = employee["department"]
            section_title(pdf, current_department.upper())

        bold_line(pdf, f"{employee['label']} ({employee['hostname']})", size=11)
        label_value(pdf, "Current risk standing", f"{employee['current_risk_level']} ({round(employee['current_risk_score'])}/100)")

        has_activity = bool(employee["week_alerts"] or employee["week_decisions"])
        if not has_activity:
            paragraph(pdf, "Nothing notable this week -- activity has stayed within expected bounds.", size=10)
        else:
            for a in employee["week_alerts"]:
                bullet(pdf, f"{a['created_at']}: [{a['risk_level']}] {a['title']} (type: {a['anomaly_type']}, status: {a['status']})")
                for e in a["supporting_events"]:
                    detail = f" -- {e['detail']}" if e["detail"] else ""
                    bullet(pdf, f"{e['timestamp']}: {e['event_type']}{detail}", indent="  ")
            for d in employee["week_decisions"]:
                line = f"Admin decision: {d['decision']} by {d['admin']} on {d['decided_at']}"
                if d["reason"]:
                    line += f' -- reason: "{d["reason"]}"'
                bullet(pdf, line)

            ai_paragraph = weekly_paragraphs.get(employee["label"])
            if ai_paragraph:
                paragraph(pdf, ai_paragraph, size=10)
            else:
                empty_note(pdf, "AI commentary unavailable for this employee -- the facts above are unaffected and reflect the system's own records.")
        pdf.ln(3)

    return to_bytes(pdf)
