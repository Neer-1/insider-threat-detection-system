# NEW — risk rollback/restore on a confirmed admin dismiss/undo toggle, and
# the one shared dismiss()/undo() implementation both routes/alerts.py and
# routes/reasoning.py call. The ONLY place anything ever resets or restores
# a DeviceRiskComponent outside of normal decay.

"""
Deliberately its own narrow module, in agent_logic/ (alongside analyzer.py,
response_engine.py) and NOT in backend/reasoning/ -- this is a human-gated
action a dismiss/undo decision triggers, not something the Reasoning Core
itself does or can reach. backend/reasoning/ (client.py, core.py,
worker.py, actions.py, prompts.py) never imports this module and never
will; the only callers are routes/alerts.py's dismiss/undo endpoints and
routes/reasoning.py's dismiss/undo endpoints (for an orphan judgment with
no linked Alert), both after a written reason has already been validated.

This is a deliberate, narrowly-scoped EXCEPTION to the read-only boundary
the Reasoning Core itself is held to (core/config.py's "AI Reasoning Core"
section, backend/reasoning/core.py's gather_context docstring): the LLM
layer never writes to risk scoring, full stop. What's different here is
that a human admin's own explicit, reason-required decision -- not the
model -- is what triggers this. That distinction is the whole point and is
kept airtight by this module only ever being reachable from these places.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models.alert_decision import AlertDecision
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment
from backend.models.risk_components import DeviceRiskComponent


def rollback_risk_component(db: Session, device_id: int, anomaly_type: str | None) -> float | None:
    """Resets the ONE DeviceRiskComponent row matching `anomaly_type` back
    to 0 -- not the whole aggregate current_risk_score, since other anomaly
    types may be legitimately contributing independently and shouldn't be
    wiped out by a dismissal that has nothing to do with them. Recomputes
    current_risk_score as the sum of every component for this device
    afterward, same cap-at-100 rule analyzer.py's _update_risk_components
    already uses.

    Returns the score the component held immediately BEFORE this reset (or
    None if there was nothing to roll back) -- dismiss() below persists
    this onto the AlertDecision row as score_snapshot, exactly what a later
    undo() restores toward. This is the only place that value is ever
    captured, so undo has no way to reconstruct it except from that row.

    No-op (returns None) if anomaly_type is None (a judgment with no linked
    alert -- models/reasoning.py's alert_id is nullable, the aggregate-score
    trigger doesn't always correspond to one specific Alert), or if no
    matching component exists to reset -- both are legitimate states, not
    failures.

    Interaction with dedup, decided deliberately rather than left implicit:
    if this same anomaly_type re-fires later, it starts completely fresh
    from 0 with the normal rise curve -- no suppression flag, no dampening.
    A dismissal is a statement about what already happened, not a standing
    exemption for this type going forward.

    Does NOT commit -- mutates the Session's objects in place and leaves
    the commit to the caller, so this rolls back atomically together with
    whichever decision row and status update triggered it, in one
    transaction."""
    if anomaly_type is None:
        return None

    components = (
        db.query(DeviceRiskComponent)
        .filter(DeviceRiskComponent.device_id == device_id)
        .all()
    )
    target = next((c for c in components if c.anomaly_type == anomaly_type), None)
    if target is None:
        return None

    old_score = target.score
    now = datetime.now(timezone.utc)
    target.score = 0.0
    target.updated_at = now

    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device is not None:
        # Summed from the already-loaded `components` list (target's score
        # already updated to 0.0 in that same list) rather than a fresh
        # SQL SUM() -- the session's autoflush is off (database/db.py's
        # SessionLocal), so a fresh aggregate query here could read the
        # pre-update value still sitting in the database.
        device.current_risk_score = min(100.0, sum(c.score for c in components))
        device.risk_score_updated_at = now

    return old_score


def restore_risk_component(db: Session, device_id: int, anomaly_type: str | None, snapshot: float | None) -> float | None:
    """Undo's counterpart to rollback_risk_component -- restores toward
    `snapshot` (the value rollback_risk_component captured at dismiss time),
    NOT by re-injecting the original severity through the normal scoring
    pipeline (that would produce a number nobody could reconstruct by hand
    afterward, and would misrepresent an admin's explicit correction as a
    fresh real detection). A precise, narrow reversal of the one specific
    reset dismiss made, mirroring how that reset was itself scoped.

    Sets the component to max(current_score, snapshot), not snapshot
    unconditionally: a dismissal never suppresses this anomaly_type from
    recurring for real, independent reasons while the alert sat dismissed
    (see rollback_risk_component's own docstring) -- so if it genuinely
    re-rose on its own in the meantime, undo must never silently erase
    that real, newer signal by dragging the score back down to the old
    snapshot. This is the same "never pulled down by a single reading,
    only decay does that" rule _decay_and_rise already applies everywhere
    else in this pipeline, not a new one invented for this path.

    updated_at is set to NOW, not the original dismiss-time timestamp --
    decay operates on wall-clock time since last touched (analyzer.py's
    _decay_and_rise), so restoring with a stale timestamp would expose the
    restored value to an immediate, enormous one-cycle decay computed
    against however long ago the ORIGINAL dismissal happened, erasing the
    restore almost as soon as it landed. Decay must resume counting from
    the moment of the undo, exactly like a fresh observation would.

    Returns the score actually left in place after the max() comparison
    (for the caller to persist onto the "undo" AlertDecision row, so that
    row's own audit trail is precise about what really happened, not just
    an echo of the snapshot) -- or None if there was nothing to restore
    (no anomaly_type, no snapshot, i.e. nothing was ever rolled back for
    this toggle in the first place).

    Does NOT commit -- same transactional contract as rollback_risk_component."""
    if anomaly_type is None or snapshot is None:
        return None

    components = (
        db.query(DeviceRiskComponent)
        .filter(DeviceRiskComponent.device_id == device_id)
        .all()
    )
    target = next((c for c in components if c.anomaly_type == anomaly_type), None)
    if target is None:
        # The component row itself no longer exists (unusual, but not
        # impossible over a long enough history) -- create it fresh at the
        # snapshotted value rather than silently doing nothing, since a
        # snapshot exists and an admin explicitly asked for a restore.
        target = DeviceRiskComponent(device_id=device_id, anomaly_type=anomaly_type, score=0.0, updated_at=None)
        db.add(target)
        components.append(target)

    now = datetime.now(timezone.utc)
    target.score = max(target.score, snapshot)
    target.updated_at = now

    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device is not None:
        device.current_risk_score = min(100.0, sum(c.score for c in components))
        device.risk_score_updated_at = now

    return target.score


def _latest_decision(db: Session, *, alert_id: int | None, judgment_id: int | None) -> AlertDecision | None:
    q = db.query(AlertDecision)
    q = q.filter(AlertDecision.alert_id == alert_id) if alert_id is not None else q.filter(AlertDecision.judgment_id == judgment_id)
    return q.order_by(AlertDecision.decided_at.desc(), AlertDecision.id.desc()).first()


def dismiss(db: Session, *, alert=None, judgment: ReasoningJudgment = None, admin_id: int, reason: str) -> AlertDecision:
    """The one shared dismiss implementation -- exactly one of `alert` /
    `judgment` is passed (the routes validate this and which entity actually
    exists/is in a dismissable state; this function just does the mutation).

    alert path (the common case, whether or not this alert has a linked
    ReasoningJudgment): rolls back its anomaly_type's risk component,
    flips Alert.status to "dismissed". Deliberately does NOT also touch a
    linked judgment's own status -- since the merged UI reads dismissed/
    not-dismissed off Alert.status alone (there's no separate judgment card
    left to keep in sync), a linked judgment's status is no longer
    load-bearing for anything the UI renders.

    judgment path (orphan judgments only, alert_id is None): nothing to
    roll back (no anomaly_type without a linked Alert), just flips
    ReasoningJudgment.status to "dismissed" -- the judgment IS the entity
    being dismissed here, there's nothing else to anchor to.

    Does NOT commit -- caller's transaction."""
    now = datetime.now(timezone.utc)
    if alert is not None:
        score_snapshot = rollback_risk_component(db, alert.device_id, alert.anomaly_type)
        alert.status = "dismissed"
        decision = AlertDecision(
            alert_id=alert.id, judgment_id=None, decision="dismiss",
            reason=reason, score_snapshot=score_snapshot, admin_id=admin_id, decided_at=now,
        )
    else:
        judgment.status = "dismissed"
        judgment.admin_decision = None
        judgment.decided_by_admin_id = admin_id
        judgment.decided_at = now
        decision = AlertDecision(
            alert_id=None, judgment_id=judgment.id, decision="dismiss",
            reason=reason, score_snapshot=None, admin_id=admin_id, decided_at=now,
        )
    db.add(decision)
    return decision


def undo(db: Session, *, alert=None, judgment: ReasoningJudgment = None, admin_id: int, reason: str) -> AlertDecision:
    """Reverses the most recent dismiss() on this alert/judgment -- reads
    that dismiss's own AlertDecision row (via _latest_decision; when the
    entity is currently dismissed, its latest decision IS that dismiss,
    since dismiss/undo always write their row in the same transaction as
    the status flip) for the score_snapshot to restore toward. See
    restore_risk_component for why this is max(current, snapshot), not an
    unconditional overwrite.

    Alert.status resets unconditionally to "open" (not whatever it was
    before dismissal -- open/acknowledged/resolved) -- ordinary bookkeeping
    (analyzer.py's auto-resolve) re-settles the exact status from there the
    same way it would for any other open alert; there is no acknowledged/
    resolved-specific behavior worth reconstructing here.

    Does NOT commit -- caller's transaction."""
    now = datetime.now(timezone.utc)
    if alert is not None:
        previous = _latest_decision(db, alert_id=alert.id, judgment_id=None)
        snapshot = previous.score_snapshot if previous else None
        restored = restore_risk_component(db, alert.device_id, alert.anomaly_type, snapshot)
        alert.status = "open"
        decision = AlertDecision(
            alert_id=alert.id, judgment_id=None, decision="undo",
            reason=reason, score_snapshot=restored, admin_id=admin_id, decided_at=now,
        )
    else:
        judgment.status = "awaiting_admin"
        judgment.admin_decision = None
        judgment.decided_by_admin_id = admin_id
        judgment.decided_at = now
        decision = AlertDecision(
            alert_id=None, judgment_id=judgment.id, decision="undo",
            reason=reason, score_snapshot=None, admin_id=admin_id, decided_at=now,
        )
    db.add(decision)
    return decision
