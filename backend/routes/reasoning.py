# NEW — AI Reasoning Core: the Human Oversight Gate. The ONLY path anything the
# Reasoning Core recommends can turn into a real Response row.

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response as FastAPIResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.agent_logic import dismissal
from backend.auth.dependencies import get_current_admin
from backend.core.config import REASONING_RECOMMENDATIONS
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.alerts import Alert
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment
from backend.models.reasoning_decision import ReasoningDecision
from backend.reasoning.actions import apply_decision
from backend.reports.alert_report import build_alert_report_pdf

router = APIRouter(prefix="/reasoning", tags=["reasoning"])

_STATUS_FOR_DECISION = {"accept": "accepted", "override": "overridden"}


class ReasoningDecisionRequest(BaseModel):
    decision: str  # "accept" | "override"
    # Required, and must be one of REASONING_RECOMMENDATIONS, only when
    # decision == "override" -- the admin picking a DIFFERENT one of the
    # same five fixed values, not a free-form action.
    override_recommendation: str | None = None


class JudgmentToggleRequest(BaseModel):
    reason: str


@router.post("/{judgment_id}/decide")
def decide_reasoning_judgment(
    judgment_id: int,
    payload: ReasoningDecisionRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """accept executes judgment.final_recommendation exactly as the
    Reasoning Core produced it; override lets the admin substitute a
    different one of the same five fixed values. Nothing the Reasoning
    Core recommends ever reaches a Response row without one of these two
    explicit choices landing here first.

    "dismiss" used to be a third decision value here, but is no longer
    accepted -- it moved entirely to POST /{judgment_id}/dismiss (this
    judgment has a linked Alert) or POST /alerts/{alert_id}/dismiss (it
    doesn't), so there is exactly one dismiss/undo implementation
    (agent_logic/dismissal.py) instead of two kept in sync by hand. Not
    kept as a deprecated alias here -- nothing calls it that way, keeping
    it would just be a second path to the same state with none of the
    undo/toggle machinery behind it.

    Re-deciding an already-decided judgment is allowed (dashboard's
    re-openable alert history lets an admin revisit and change a past
    call) — this used to be blocked with a 409, but that made a wrong or
    outdated decision permanent with no way to correct it. Every decision,
    past and present, is preserved: a ReasoningDecision row is appended
    here every time regardless of prior state, so nothing is ever
    overwritten or lost, only added to. judgment.status/admin_decision/
    decided_by/decided_at are updated to reflect the LATEST decision (for
    cheap reads elsewhere), but the full history lives in the decisions
    table and is what GET /employees/{id} exposes for the re-opened view.

    Changing a decision does NOT retroactively touch Response rows already
    created by a PRIOR decision on this judgment — Response is an
    append-only action log elsewhere in this app (e.g. an executed device
    lock can't be un-executed by deleting a row), and decisions here are
    held to the same standard. apply_decision below creates ITS OWN new
    Response rows same as any first-time decision would; it never
    inspects or removes what an earlier decision already did."""
    judgment = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.id == judgment_id, ReasoningJudgment.company_id == admin.company_id)
        .first()
    )
    if judgment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Judgment not found")

    if payload.decision == "accept":
        action_value = judgment.final_recommendation
    elif payload.decision == "override":
        if payload.override_recommendation not in REASONING_RECOMMENDATIONS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"override_recommendation must be one of {REASONING_RECOMMENDATIONS}",
            )
        action_value = payload.override_recommendation
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="decision must be accept or override")

    if action_value is not None:
        # Same Response-row mechanism the deterministic pipeline already
        # uses (agent_logic/response_engine.py's save_responses) — see
        # backend/reasoning/actions.py for why this is a separate mapping
        # rather than forced onto response_engine.py's own level-keyed one.
        apply_decision(db, judgment.alert_id, action_value, admin.admin_id)

    now = datetime.now(timezone.utc)
    db.add(ReasoningDecision(
        judgment_id=judgment.id,
        decision=payload.decision,
        action_value=action_value,
        dismiss_reason=None,
        admin_id=admin.admin_id,
        decided_at=now,
    ))

    judgment.status = _STATUS_FOR_DECISION[payload.decision]
    judgment.admin_decision = action_value
    judgment.decided_by_admin_id = admin.admin_id
    judgment.decided_at = now
    db.commit()

    return {"judgment_id": judgment.id, "status": judgment.status, "admin_decision": judgment.admin_decision}


def _reject_if_has_alert(judgment: ReasoningJudgment) -> None:
    if judgment.alert_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This judgment has a linked alert — use POST /alerts/{alert_id}/dismiss or /undo instead",
        )


@router.post("/{judgment_id}/dismiss")
def dismiss_judgment(
    judgment_id: int,
    payload: JudgmentToggleRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Dismiss for an ORPHAN judgment only -- one with no linked Alert at
    all (models/reasoning.py's alert_id is nullable: the aggregate-score
    trigger doesn't always correspond to one specific Alert row). A
    judgment WITH a linked alert is dismissed through that alert instead
    (routes/alerts.py) -- exactly one dismiss path per real-world entity,
    both sharing agent_logic/dismissal.py's dismiss() implementation.

    No risk-component rollback happens here: an orphan judgment has no
    anomaly_type to roll back (dismissal.py's dismiss() is a no-op on that
    front for this path) -- there's nothing to reset because nothing was
    ever attributed to one specific type in the first place."""
    judgment = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.id == judgment_id, ReasoningJudgment.company_id == admin.company_id)
        .first()
    )
    if judgment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Judgment not found")

    _reject_if_has_alert(judgment)

    if judgment.status == "dismissed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Judgment is already dismissed")
    if judgment.status in ("accepted", "overridden"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This judgment was already accepted or overridden — not offered here",
        )

    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="reason is required when dismissing a judgment",
        )

    dismissal.dismiss(db, judgment=judgment, admin_id=admin.admin_id, reason=reason)
    db.commit()

    return {"judgment_id": judgment.id, "status": judgment.status}


@router.post("/{judgment_id}/undo")
def undo_judgment_dismissal(
    judgment_id: int,
    payload: JudgmentToggleRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Reverses dismiss_judgment -- orphan judgments only, same restriction
    as above. Resets status back to "awaiting_admin"."""
    judgment = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.id == judgment_id, ReasoningJudgment.company_id == admin.company_id)
        .first()
    )
    if judgment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Judgment not found")

    _reject_if_has_alert(judgment)

    if judgment.status != "dismissed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Judgment is not dismissed")

    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="reason is required when undoing a dismissal",
        )

    dismissal.undo(db, judgment=judgment, admin_id=admin.admin_id, reason=reason)
    db.commit()

    return {"judgment_id": judgment.id, "status": judgment.status}


@router.get("/{judgment_id}/report.pdf")
def get_alert_report(judgment_id: int, admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """"Generate Report" button on an AI Reasoning Core card. Pure read +
    format over data already sitting on the judgment row -- no new LLM
    call, no write of any kind. Company-scoped like every other admin-
    facing route here."""
    judgment = (
        db.query(ReasoningJudgment)
        .filter(ReasoningJudgment.id == judgment_id, ReasoningJudgment.company_id == admin.company_id)
        .first()
    )
    if judgment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Judgment not found")

    device = db.query(Device).filter(Device.device_id == judgment.device_id).first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    alert = db.query(Alert).filter(Alert.id == judgment.alert_id).first() if judgment.alert_id else None
    decisions = db.query(ReasoningDecision).filter(ReasoningDecision.judgment_id == judgment.id).all()

    pdf_bytes = build_alert_report_pdf(judgment, alert, device, admin.company.company_name, decisions)

    filename = f"litds-alert-report-{device.hostname}-{judgment.id}.pdf".replace(" ", "_")
    return FastAPIResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
