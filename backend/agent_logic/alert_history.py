# NEW — shared "correlate every Alert with every ReasoningJudgment for one
# device" builder, used by GET /employees/{id} (dashboard profile) AND
# backend/reports/employee_report.py (employee narrative PDF).
#
# Lives in agent_logic/, not routes/employees.py where it originally lived
# -- moved here for the exact same reason significant_events.py's shared
# predicate did: backend/reports/ needs this too, and reports/ importing
# from routes/ (an API layer) while routes/employees.py also needs to call
# the report generator would create a circular import. agent_logic/ is
# core logic both layers can depend on without depending on each other.

from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.models.alert_decision import AlertDecision
from backend.models.alerts import Alert
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment
from backend.models.reasoning_decision import ReasoningDecision

# Cap on how many past flagged items this returns -- "every past flagged
# item" per device, but an unbounded query re-run on every 5s profile poll
# (dashboard/app.js's refreshAll) doesn't scale indefinitely. 50 is a
# generous page for an SME-scale deployment; if this ever needs to be more
# than that, it needs real pagination like GET /logs/raw already has, not
# a bigger cap.
ALERT_HISTORY_LIMIT = 50


def judgment_out(j: ReasoningJudgment) -> dict:
    """Shared shape for a ReasoningJudgment whether it's still awaiting a
    decision or has one already -- the AI Reasoning Core assessment shown
    inline within its alert's Recent Alert History row (there's no separate
    floating card anymore). No decisions/history here -- that's merged
    per-entry in build_alert_history's decision_history instead of being
    split across a per-judgment list and a per-alert list."""
    return {
        "judgment_id": j.id,
        "triggered_at": j.triggered_at,
        "trigger_risk_score": j.trigger_risk_score,
        "trigger_risk_level": j.trigger_risk_level,
        "explanation": j.final_explanation,
        "recommendation": j.final_recommendation,
        "confidence": j.final_confidence,
        "critic_changed_judgment": j.critic_changed_judgment,
        "initial_recommendation": j.initial_recommendation,
        "model_used": j.model_used,
        "context_snapshot": j.context_snapshot,
        "status": j.status,
        "admin_decision": j.admin_decision,
    }


def _merge_decision_timeline(
    judgments: list[ReasoningJudgment],
    reasoning_decisions_by_judgment: dict[int, list[ReasoningDecision]],
    alert_decisions: list[AlertDecision],
) -> list[dict]:
    """One combined, chronologically-sorted timeline of every decision ever
    made about one alert (or one orphan judgment) -- accept/override plus
    any LEGACY dismiss rows sitting in ReasoningDecision from before this
    round's dismiss/undo consolidation (real production data, e.g. two
    judgments dismissed in earlier rounds -- not migrated, just read
    alongside the new rows here), merged with every AlertDecision
    dismiss/undo toggle going forward. This is deliberately a read-time
    merge of two tables, not a rewrite of history into one -- see
    agent_logic/dismissal.py's module docstring for why dismiss/undo no
    longer write ReasoningDecision at all."""
    items = []
    for j in judgments:
        for d in reasoning_decisions_by_judgment.get(j.id, []):
            items.append({
                "decision": d.decision,
                "action_value": d.action_value,
                "reason": d.dismiss_reason,
                "score_snapshot": None,
                "admin_username": d.admin.username if d.admin else None,
                "decided_at": d.decided_at,
            })
    for d in alert_decisions:
        items.append({
            "decision": d.decision,
            "action_value": None,
            "reason": d.reason,
            "score_snapshot": d.score_snapshot,
            "admin_username": d.admin.username if d.admin else None,
            "decided_at": d.decided_at,
        })
    items.sort(key=lambda x: x["decided_at"] or datetime.min.replace(tzinfo=timezone.utc))
    return items


def build_alert_history(db: Session, device: Device) -> list[dict]:
    """Every Alert ever raised for this device, correlated with every
    ReasoningJudgment ever produced for it (not just still-pending ones),
    newest first -- the full re-openable history the profile page's
    "Recent Alert History" card renders (now the ONLY place an alert and
    its AI assessment are shown -- no separate floating Reasoning Core
    card), and what the employee narrative report's evidence gathering
    reads from too."""
    all_alerts = (
        db.query(Alert)
        .filter(Alert.device_id == device.device_id)
        .order_by(Alert.created_at.desc())
        .limit(ALERT_HISTORY_LIMIT)
        .all()
    )
    alert_ids = [a.id for a in all_alerts]

    all_judgments = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.device_id == device.device_id)
        .order_by(ReasoningJudgment.triggered_at.desc())
        .limit(ALERT_HISTORY_LIMIT)
        .all()
    )
    judgment_ids = [j.id for j in all_judgments]

    reasoning_decisions_by_judgment: dict[int, list[ReasoningDecision]] = {jid: [] for jid in judgment_ids}
    if judgment_ids:
        for d in db.query(ReasoningDecision).filter(ReasoningDecision.judgment_id.in_(judgment_ids)).all():
            reasoning_decisions_by_judgment[d.judgment_id].append(d)

    alert_decisions_by_alert: dict[int, list[AlertDecision]] = {aid: [] for aid in alert_ids}
    alert_decisions_by_judgment: dict[int, list[AlertDecision]] = {jid: [] for jid in judgment_ids}
    if alert_ids or judgment_ids:
        query = db.query(AlertDecision)
        conditions = []
        if alert_ids:
            conditions.append(AlertDecision.alert_id.in_(alert_ids))
        if judgment_ids:
            conditions.append(AlertDecision.judgment_id.in_(judgment_ids))
        for d in query.filter(or_(*conditions)).all():
            if d.alert_id is not None and d.alert_id in alert_decisions_by_alert:
                alert_decisions_by_alert[d.alert_id].append(d)
            elif d.judgment_id is not None and d.judgment_id in alert_decisions_by_judgment:
                alert_decisions_by_judgment[d.judgment_id].append(d)

    # A judgment's alert_id can be null (models/reasoning.py's docstring —
    # the aggregate trigger doesn't always correspond to one specific
    # Alert), so judgments group into "tied to an alert" vs "standalone",
    # and either can exist without the other for a given device.
    judgments_by_alert: dict[int, list[ReasoningJudgment]] = {}
    orphan_judgments: list[ReasoningJudgment] = []
    for j in all_judgments:
        if j.alert_id is not None:
            judgments_by_alert.setdefault(j.alert_id, []).append(j)
        else:
            orphan_judgments.append(j)

    history_entries = []
    for a in all_alerts:
        linked = judgments_by_alert.get(a.id, [])
        history_entries.append({
            "sort_key": a.created_at,
            "alert": {
                "alert_id": a.id,
                "risk_level": a.risk_level,
                "risk_score": a.risk_score,
                "anomalies": a.anomalies,
                "anomaly_type": a.anomaly_type,
                "title": a.title,
                "description": a.description,
                "status": a.status,
                "created_at": a.created_at,
            },
            "judgments": [judgment_out(j) for j in linked],
            "decision_history": _merge_decision_timeline(
                linked, reasoning_decisions_by_judgment, alert_decisions_by_alert.get(a.id, [])
            ),
        })
    for j in orphan_judgments:
        history_entries.append({
            "sort_key": j.triggered_at,
            "alert": None,
            "judgments": [judgment_out(j)],
            "decision_history": _merge_decision_timeline(
                [j], reasoning_decisions_by_judgment, alert_decisions_by_judgment.get(j.id, [])
            ),
        })
    history_entries.sort(key=lambda e: e["sort_key"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    for e in history_entries:
        del e["sort_key"]  # only needed for ordering, not part of the response shape
    return history_entries
