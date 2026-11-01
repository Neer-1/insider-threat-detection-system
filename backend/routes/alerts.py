# FROM ai-agent-assignment: app/api/routes/analyze.py — same file, split: the /alerts* endpoints go here, needs changes: scoped to company

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.agent_logic import dismissal
from backend.auth.dependencies import get_current_admin
from backend.core.config import ALERTS_TREND_WINDOW_DAYS
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.alerts import Alert
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    status_filter: str | None = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Joined so device_id in the response is Device.public_id (the UUID
    # string every other admin-facing route uses), not Alert.device_id's
    # raw internal FK int. Returning the int here was a real bug: the
    # dashboard compares this field against /employees' device_id (already
    # public_id), so the comparison silently never matched anything —
    # every employee card showed 0/low regardless of real alerts, and the
    # alert feed threw on a.device_id.slice(...) since it's a number, not
    # a string, which the feed's try/catch swallowed into a blank panel.
    query = (
        db.query(Alert, Device.public_id)
        .join(Device, Device.device_id == Alert.device_id)
        .filter(Alert.company_id == admin.company_id)
    )
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    rows = query.order_by(Alert.created_at.desc()).all()
    return [
        {
            "alert_id": a.id,
            "device_id": public_id,
            "risk_level": a.risk_level,
            "risk_score": a.risk_score,
            "anomalies": a.anomalies,
            # Stable rule identifier (e.g. "high_file_access") -- exposed
            # alongside the live-generated `title` so the dashboard's
            # employee-grid flags (dashboard/app.js) can show the compact,
            # non-drifting form instead of the longer sentence-style title.
            "anomaly_type": a.anomaly_type,
            "title": a.title,
            "description": a.description,
            "status": a.status,
            "created_at": a.created_at,
        }
        for a, public_id in rows
    ]


@router.get("/stats/daily")
def alerts_per_day(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Max Alert.risk_score per calendar day (UTC), oldest first, for the
    last ALERTS_TREND_WINDOW_DAYS days -- backs the Overview page's
    "Alerts Over Time" chart. Was a raw daily COUNT; changed to severity
    (max risk_score that day, 0 if none) because a count-based chart
    always peaks near the top of its own range on whichever day had the
    most alerts, regardless of how trivial they were -- a day with ten
    dismissed low-risk alerts looked identical to a day with one genuine
    critical incident. `count` is kept alongside as secondary context (the
    frontend surfaces it in the chart's hover tooltip), not dropped.

    Dismissed alerts still count toward their day's max: Alert.risk_score
    is a point-in-time snapshot set when the row is created/refreshed by
    the detection pipeline (agent_logic/analyzer.py) and is never rewritten
    by the dismiss/undo flow (agent_logic/dismissal.py only ever changes
    Alert.status, never risk_score) -- consistent with this system's
    append-only audit philosophy, dismissal doesn't erase that an alert
    happened. Every day in the window is present in the response (0 if
    genuinely quiet that day), not just days that had at least one alert,
    so the chart's x-axis is a real continuous week rather than silently
    compressing around gaps.

    Bucketed in Python rather than a SQL date()/DATE_TRUNC expression --
    this project supports both SQLite and Postgres (core/config.py's
    DATABASE_URL) and a single dialect-specific date function would only
    work correctly on one of them; a week of rows is small enough that
    this costs nothing to do in Python instead."""
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=ALERTS_TREND_WINDOW_DAYS - 1)
    window_start = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)

    rows = (
        db.query(Alert.created_at, Alert.risk_score)
        .filter(Alert.company_id == admin.company_id, Alert.created_at >= window_start)
        .all()
    )
    buckets = {
        (start_date + timedelta(days=i)).isoformat(): {"max_risk_score": 0.0, "count": 0}
        for i in range(ALERTS_TREND_WINDOW_DAYS)
    }
    for created_at, risk_score in rows:
        if created_at is None:
            continue
        key = created_at.date().isoformat()
        if key not in buckets:
            continue
        bucket = buckets[key]
        bucket["count"] += 1
        if risk_score > bucket["max_risk_score"]:
            bucket["max_risk_score"] = risk_score
    return [
        {"date": d, "max_risk_score": round(buckets[d]["max_risk_score"], 1), "count": buckets[d]["count"]}
        for d in sorted(buckets)
    ]


@router.get("/stats/by-type")
def alerts_by_type(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Alert.anomaly_type counts within the SAME ALERTS_TREND_WINDOW_DAYS
    window as alerts_per_day above (deliberately kept consistent so the
    Overview page's two trend charts describe the same period, not two
    independently-chosen ranges) -- backs "Top Trigger Categories",
    highest-count first. A real GROUP BY/COUNT aggregation, not a client-
    side count over the (potentially much larger, unbounded) full alert
    history dashboard/app.js already loads for the alert feed."""
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=ALERTS_TREND_WINDOW_DAYS - 1)
    window_start = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)

    rows = (
        db.query(Alert.anomaly_type, func.count(Alert.id))
        .filter(Alert.company_id == admin.company_id, Alert.created_at >= window_start)
        .group_by(Alert.anomaly_type)
        .order_by(func.count(Alert.id).desc())
        .all()
    )
    return [{"anomaly_type": anomaly_type, "count": count} for anomaly_type, count in rows]


class AlertToggleRequest(BaseModel):
    reason: str


def _reject_if_already_decided_by_judgment(db: Session, alert: Alert) -> None:
    """Option A, carried over from the pre-merge design: an alert whose
    linked ReasoningJudgment was accepted or overridden already had an
    admin act on it through that path -- dismiss isn't offered as a second,
    independent way to re-decide it. (A still-`awaiting_admin` judgment no
    longer blocks dismiss -- see dismiss_alert's own docstring for why that
    guard, from before the Reasoning Core card was merged into this same
    row, no longer applies.)"""
    decided_judgment = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.alert_id == alert.id, ReasoningJudgment.status.in_(["accepted", "overridden"]))
        .first()
    )
    if decided_judgment is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This alert's Reasoning Core judgment was already accepted or overridden — not offered here",
        )


@router.post("/{alert_id}/dismiss")
def dismiss_alert(
    alert_id: int,
    payload: AlertToggleRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Recent Alert History's per-row Dismiss action -- covers every alert,
    whether or not it has a linked ReasoningJudgment. Before the Reasoning
    Core card was merged into this same row, this endpoint refused to run
    if a linked judgment was still `awaiting_admin`, on the theory that the
    judgment's own separate card was the right place to dismiss from. That
    card no longer exists -- this row's one Dismiss button is now the ONLY
    way left to act on it, so that guard is gone; dismissing here proceeds
    regardless of judgment state, EXCEPT when a judgment was already
    accepted/overridden (see _reject_if_already_decided_by_judgment).
    Deliberately does not touch the judgment's own status either way (see
    agent_logic/dismissal.py's dismiss() docstring) -- Alert.status alone is
    what this row's dismissed/not-dismissed rendering reads."""
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.company_id == admin.company_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if alert.status == "dismissed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Alert is already dismissed")

    _reject_if_already_decided_by_judgment(db, alert)

    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="reason is required when dismissing an alert",
        )

    dismissal.dismiss(db, alert=alert, admin_id=admin.admin_id, reason=reason)
    db.commit()

    return {"alert_id": alert.id, "status": alert.status}


@router.post("/{alert_id}/undo")
def undo_alert_dismissal(
    alert_id: int,
    payload: AlertToggleRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Reverses dismiss_alert -- same required-reason validation, restores
    the risk-component score via agent_logic/dismissal.py's undo() (see its
    docstring for the max(current, snapshot) restoration rule), resets
    Alert.status to "open". Supports genuine back-and-forth: dismiss, undo,
    dismiss again -- each call here is its own permanent AlertDecision row,
    nothing is overwritten."""
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.company_id == admin.company_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if alert.status != "dismissed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Alert is not dismissed")

    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="reason is required when undoing a dismissal",
        )

    dismissal.undo(db, alert=alert, admin_id=admin.admin_id, reason=reason)
    db.commit()

    return {"alert_id": alert.id, "status": alert.status}
