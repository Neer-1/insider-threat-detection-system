# FROM ai-agent-assignment: app/api/routes/analyze.py — copied, split: the /employees* endpoints go here, needs changes: scoped to the logged-in admin's company

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response as FastAPIResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.agent_logic.alert_history import build_alert_history
from backend.auth.dependencies import get_current_admin
from backend.core.config import risk_level_for_score
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.alerts import Alert
from backend.models.devices import Device, DeviceMetadata
from backend.models.employee_notification import EmployeeNotification
from backend.models.risk_snapshot import DeviceRiskSnapshot
from backend.reasoning.narrative import generate_event_description, generate_response_guide
from backend.reports.employee_report import build_employee_report_pdf, gather_employee_narrative_context

# Display window for the risk sparkline -- deliberately separate from
# core/config.py's RISK_SNAPSHOT_RETENTION_HOURS (25h): retention is "when
# rows get physically deleted" (agent_logic/risk_snapshots.py's
# prune_old_snapshots, which only actually runs roughly once an hour), this
# is "what's actually relevant to show right now" -- a real 24h window
# regardless of whether pruning has caught up to trim the table's tail yet.
RISK_HISTORY_DISPLAY_HOURS = 24

router = APIRouter(prefix="/employees", tags=["employees"])


class EmployeeOut(BaseModel):
    device_id: str
    label: str
    department: str | None
    hostname: str
    connection_status: str
    open_alert_count: int
    # Device.current_risk_score, read straight off the persisted/decaying
    # value agent_logic/analyzer.py maintains -- the grid and the profile
    # page (get_employee, below) now both read this exact same field
    # instead of each computing their own "risk" independently (the root
    # cause of the last "grid says low, profile says high" report).
    risk_score: float
    risk_level: str


@router.get("", response_model=list[EmployeeOut])
def list_employees(
    status_filter: str | None = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """"Employee" here means an approved, employee-associated device —
    employees never get their own login (onboarding_flow.md), so there is
    no separate Employee table; a Device with a label is the closest thing
    to one. Defaults to "approved" (the live/active roster the dashboard
    grid uses) -- pass status_filter="offboarded" to list the archive of
    former employees instead, same pattern as GET /alerts."""
    devices = (
        db.query(Device)
        .filter(Device.company_id == admin.company_id, Device.approval_status == (status_filter or "approved"))
        .all()
    )

    result = []
    for d in devices:
        open_alerts = db.query(Alert).filter(Alert.device_id == d.device_id, Alert.status == "open").count()
        metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == d.device_id).first()
        score, connection_status = float(d.current_risk_score or 0.0), d.connection_status
        result.append(
            EmployeeOut(
                device_id=d.public_id,
                label=d.label or d.hostname,
                department=metadata.department if metadata else None,
                hostname=d.hostname,
                connection_status=connection_status,
                open_alert_count=open_alerts,
                risk_score=score,
                risk_level=risk_level_for_score(score),
            )
        )
    return result


@router.get("/risk-history")
def get_risk_history(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Bulk fetch -- every approved device's DeviceRiskSnapshot rows within
    the last RISK_HISTORY_DISPLAY_HOURS, ONE request rather than one per
    monitoring card. Backs the Live Employee Monitoring card's 24h risk
    sparkline (dashboard/app.js's refreshRiskHistory), polled on its own
    slower cadence -- a 15-minute-granularity trend (core/config.py's
    RISK_SNAPSHOT_INTERVAL_MINUTES) gets nothing from 5s refresh, and
    fetching per-card would mean N requests every poll instead of one.

    Returns {device_public_id: [{"recorded_at", "risk_score"}, ...]}, every
    approved device present (possibly with an empty list, for one with no
    snapshots yet), each device's own list already chronological
    (oldest-first) -- exactly the order a sparkline draws left-to-right in,
    no client-side sort needed."""
    devices = (
        db.query(Device)
        .filter(Device.company_id == admin.company_id, Device.approval_status == "approved")
        .all()
    )
    result: dict[str, list[dict]] = {d.public_id: [] for d in devices}
    if not devices:
        return result

    id_to_public = {d.device_id: d.public_id for d in devices}
    window_start = datetime.now(timezone.utc) - timedelta(hours=RISK_HISTORY_DISPLAY_HOURS)

    rows = (
        db.query(DeviceRiskSnapshot)
        .filter(DeviceRiskSnapshot.device_id.in_(id_to_public.keys()), DeviceRiskSnapshot.recorded_at >= window_start)
        .order_by(DeviceRiskSnapshot.recorded_at.asc())
        .all()
    )
    for row in rows:
        result[id_to_public[row.device_id]].append({
            "recorded_at": row.recorded_at,
            "risk_score": row.risk_score,
        })
    return result


@router.get("/{device_public_id}")
def get_employee(device_public_id: str, admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    device = (
        db.query(Device)
        .filter(
            Device.public_id == device_public_id,
            Device.company_id == admin.company_id,
            # Offboarded devices stay viewable here (archive), just excluded
            # from list_employees()'s live roster above.
            Device.approval_status.in_(["approved", "offboarded"]),
        )
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()

    # Full history: every Alert ever raised for this device, correlated
    # with every ReasoningJudgment ever produced for it (not just the
    # still-pending ones above) — this is what the profile's "Recent
    # Alert History" card renders as a re-openable list. Factored out into
    # build_alert_history() (above) so the employee narrative report
    # (backend/reports/employee_report.py) builds the identical
    # correlation instead of a second copy that could disagree with it.
    history_entries = build_alert_history(db, device)

    # Notify Employee audit trail (models/employee_notification.py) --
    # separate list, not merged into alert_history above: these rows
    # aren't anchored to any alert/judgment (they're a standalone,
    # admin-initiated action, reachable regardless of risk level), so
    # they render as their own section on the same profile page instead
    # of being forced into alert_history's per-alert-or-judgment shape.
    notification_rows = (
        db.query(EmployeeNotification)
        .filter(EmployeeNotification.device_id == device.device_id)
        .order_by(EmployeeNotification.sent_at.desc())
        .all()
    )

    score, connection_status = float(device.current_risk_score or 0.0), device.connection_status
    return {
        "device_id": device.public_id,
        "label": device.label or device.hostname,
        "department": metadata.department if metadata else None,
        "email": metadata.email if metadata else None,
        "hostname": device.hostname,
        "username": device.username,
        "os_info": device.os_info,
        "ip_address": device.ip_address,
        "connection_status": connection_status,
        "approval_status": device.approval_status,
        "enrolled_at": device.enrolled_at,
        "last_seen": device.last_seen,
        "info_refresh_requested": device.info_refresh_requested,
        # Same field, same source as list_employees() above -- see
        # EmployeeOut.risk_score's comment.
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        # Every Alert ever raised for this device (up to ALERT_HISTORY_LIMIT),
        # each correlated with whatever ReasoningJudgment(s) it produced (if
        # any), newest first. Replaces the old recent_alerts list: every
        # entry is now re-openable regardless of decision status, and
        # standalone judgments with no linked Alert (alert_id is nullable —
        # see models/reasoning.py) are included as their own entries so
        # nothing that ever fired for this device is invisible here.
        "alert_history": history_entries,
        "employee_notifications": [
            {
                "sent_at": n.sent_at,
                "admin": n.admin.username if n.admin else "unknown admin",
                "message": n.message,
                "status": n.status,
                "error": n.error,
            }
            for n in notification_rows
        ],
    }


@router.get("/{device_public_id}/report.pdf")
async def get_employee_report(device_public_id: str, admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """"Generate Employee Report" button on the profile page. Works for a
    completely clean employee (no LLM call is even attempted -- see
    gather_employee_narrative_context's standing_incident, None for a
    clean employee) as well as one with real flagged history (up to two
    independent LLM calls: event description, response guide). Unlike the
    per-alert report, this can make fresh LLM calls -- everything else
    about it is a plain read+format over data that already exists.
    Per-section degradation, not a whole-report failure: if the AI section(s)
    fail, the PDF still generates in full with an explicit "AI commentary
    unavailable" note in their place -- a data-complete report with one
    honest, clearly-marked gap beats no report at all. This never raises
    503 for an AI-call failure any more; it only 404s for a missing
    device."""
    device = (
        db.query(Device)
        .filter(
            Device.public_id == device_public_id,
            Device.company_id == admin.company_id,
            Device.approval_status.in_(["approved", "offboarded"]),
        )
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

    context = gather_employee_narrative_context(db, device)

    event_description = None
    response_guide = None
    incident = context["standing_incident"]
    if incident is not None:
        # Independent calls on purpose -- one failing must not affect the
        # other (backend/reasoning/narrative.py's own module docstring).
        event_description = await generate_event_description(context, incident)
        response_guide = await generate_response_guide(context, incident, context.get("policy_excerpt"))

    pdf_bytes = build_employee_report_pdf(device, admin.company.company_name, context, event_description, response_guide)

    filename = f"litds-employee-report-{device.hostname}.pdf".replace(" ", "_")
    return FastAPIResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
