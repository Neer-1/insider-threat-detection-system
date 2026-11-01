# FROM ai-agent-assignment: app/agent/analyzer.py — copied, needs changes: orchestrator now carries company_id/device_id through the pipeline and persists results + Alert rows

"""
Risk-scoring redesign (post-build): risk used to be "the highest-severity
unresolved Alert for a device", with a separate _apply_historical_risk_
adjustments() bonus system that re-read a device's own alert history to
push the score up further on top of that. Both were removed. Neither
"unresolved" nor "history bonus" had any mechanism that ever pulled a
score back down — a device could only ever climb over its lifetime,
confirmed live: 39 -> 38 -> 48 -> 48 -> 47 across five cycles of
completely unchanged behaviour, purely from the history bonus reading the
device's own still-open alert back against itself.

Replaced with a persisted, continuously-decaying score derived from
Device.current_risk_score — originally one global decay/rise pair applied
to one aggregate number (see git history / docs/known_limitations.md for
that version). Refined again here into PER-ANOMALY-TYPE decay: a single
global rate was too blunt -- a failed-login streak should be forgiven
within minutes of a successful login, while sustained privilege
escalation shouldn't fade at the same speed just because a few clean
minutes passed. current_risk_score is now the sum (capped at 100) of a
set of DeviceRiskComponent rows (models/risk_components.py), one per
anomaly_type, each decaying/rising on its own core/config.py-tuned
schedule (_update_risk_components below). Device.current_risk_score/
risk_score_updated_at keep their exact same shape/meaning to every other
caller (routes/employees.py, the dashboard) -- they're just derived from
the per-type components now instead of computed directly.

Alerts still get created/updated for audit trail, the alert feed, and
response_engine containment actions -- they aren't the source of "current
risk" either way. Alert.risk_score/risk_level record that window's own
instantaneous severity (an honest point-in-time reading, for the record);
Device.current_risk_score is the separate, slower-moving number actually
shown as a device's risk on the grid/profile.
"""

from datetime import datetime, timedelta, timezone
from math import exp
from typing import Callable

from sqlalchemy.orm import Session

from backend.agent_logic.anomaly_detector import detect_anomalies
from backend.agent_logic.baseline_learning import get_expected_max_delta, update_pending_max_delta
from backend.agent_logic.behavioural_profiler import profile_behaviour
from backend.agent_logic.decision_engine import make_decision
from backend.agent_logic.feature_extractor import extract_feature_sequence, extract_features, save_feature
from backend.agent_logic.response_engine import recommend_actions, save_responses
from backend.agent_logic.risk_scorer import score_risk
from backend.core.config import (
    ANALYSIS_WINDOW_MINUTES,
    CNN_SEQUENCE_LENGTH,
    DECAY_FREEZE_THRESHOLD,
    ESCALATION_MIN_COOLDOWN_SECONDS,
    ESCALATION_MIN_SCORE_INCREASE,
    REASONING_TRIGGER_MIN_LEVEL,
    RISK_LEVEL_RANK,
    SHARP_DELTA_MIN_ABSOLUTE,
    SHARP_DELTA_ZSCORE_MULTIPLIER,
    risk_level_for_score,
    tau_for_anomaly_type,
)
from backend.models.alerts import Alert
from backend.models.devices import Device, DeviceMetadata
from backend.models.risk_components import DeviceRiskComponent
from backend.reasoning.core import gather_context
from backend.reasoning.worker import enqueue_reasoning_trigger

# (list of recent feature-window dicts, chronological, current window last)
# -> (anomaly_score 0..1, confidence 0..1). backend/ai/ plugs a real
# implementation in here (Isolation Forest, the CNN) — this module never
# imports from ai/ directly, so it has no idea which model is actually
# behind the score. Changed from a single dict to a sequence so a temporal
# model (the CNN) can see escalation across windows, not just the current
# one; Isolation Forest's score_fn just reads the last element and ignores
# the rest, since it has no temporal awareness — see
# predict_isolation_forest.py.
ScoreFn = Callable[[list[dict]], tuple[float, float]]


def _decay_and_rise(current: float, last_updated, raw_score: float, anomaly_type: str, now: datetime, freeze_basis: float) -> float:
    """The actual decay/rise math -- unchanged from the original single-
    aggregate version, just parameterized by anomaly_type's own tau pair
    instead of importing one global constant. Applies real-time decay,
    then (only if this type's fresh raw_score is higher than the decayed
    value) rises toward it. Never pulled down by a single low reading --
    only the passage of time without new anomalies of this type lowers
    it. Both constants are wall-clock time constants, not "per cycle", so
    this behaves the same whether the scheduler runs every 10 seconds or
    every 15 minutes.

    If the DEVICE'S aggregate score (freeze_basis) is at or above
    DECAY_FREEZE_THRESHOLD, decay is skipped entirely this cycle -- not
    slowed, literally zero change from the passage of time alone -- see
    config.py's "Decay-freeze near high/critical" section for the full
    reasoning (including why this replaced an earlier multiplicative
    slow-down, and why this is keyed on the device aggregate rather than
    this component's own score). rise_tau is never touched by the freeze
    either way: a genuine new anomaly of this type must still climb at its
    normal speed no matter whether the device is currently frozen."""
    if last_updated is not None and last_updated.tzinfo is None:
        # SQLite has no native datetime type -- DateTime(timezone=True)
        # columns can come back tz-naive on read-back even though every
        # write used datetime.now(timezone.utc), which breaks a direct
        # subtraction against a fresh tz-aware `now`. Every write in this
        # codebase is UTC, so a naive read-back is safely assumed UTC.
        last_updated = last_updated.replace(tzinfo=timezone.utc)
    current = current or 0.0
    dt = max((now - last_updated).total_seconds(), 0.0) if last_updated is not None else 0.0

    if dt <= 0:
        # First-ever update for this (device, type) pair -- no time basis
        # for decay or a rise curve, so just take the raw reading directly
        # rather than silently staying at 0.
        new_score = raw_score if raw_score > current else current
    else:
        _decay_tau, rise_tau = tau_for_anomaly_type(anomaly_type)
        if freeze_basis >= DECAY_FREEZE_THRESHOLD:
            decayed = current
        else:
            decayed = current * exp(-dt / _decay_tau)
        if raw_score > decayed:
            rise_factor = 1 - exp(-dt / rise_tau)
            new_score = decayed + rise_factor * (raw_score - decayed)
        else:
            new_score = decayed

    return max(0.0, min(100.0, new_score))


def _update_risk_components(db: Session, device: Device, anomalies: list[dict], ml_score: float, now: datetime) -> float:
    """Updates every anomaly type's DeviceRiskComponent for this device --
    the types detected this cycle (decay then rise toward this window's
    severity for that type) AND every OTHER previously-tracked type that
    found nothing this cycle (pure decay, so a type that stops recurring
    actually fades out of the aggregate instead of freezing at its last
    value forever). Returns the new aggregate (sum of every component,
    capped at 100) that becomes Device.current_risk_score. Mutates
    `device` and the DeviceRiskComponent rows in place; caller commits."""
    # Captured ONCE, before any component below is touched -- every
    # component's decay this cycle freezes (or doesn't) off the same
    # whole-device snapshot (config.py's DECAY_FREEZE_THRESHOLD), not its
    # own individual score. See config.py's top-of-section comment for
    # why: no single component can structurally reach the freeze zone
    # alone (each is capped by its own anomaly type's fixed severity
    # weight, all well under RISK_CRITICAL), so a device only ever becomes
    # high/critical by summing several moderate components -- and freezing
    # has to key off
    # that same sum to ever actually engage.
    freeze_basis = device.current_risk_score or 0.0

    raw_by_type: dict[str, float] = {}
    for a in anomalies:
        # detect_anomalies() emits at most one entry per type per window
        # today, but max() rather than sum() here is the correct rule
        # regardless -- "severity" already represents that whole
        # condition's weight, multiple hits of the same type in one
        # window shouldn't double it.
        raw_by_type[a["type"]] = max(raw_by_type.get(a["type"], 0.0), a["severity"])

    # ML model's own window score doesn't belong to any rule-based type --
    # its own pseudo-type bucket instead of being dropped from the decay
    # model or folded into an arbitrary existing type. Same 0..20-point
    # scale risk_scorer.py's ml_contribution uses.
    raw_by_type["ml_signal"] = round(ml_score * 20)

    existing = {
        c.anomaly_type: c
        for c in db.query(DeviceRiskComponent).filter(DeviceRiskComponent.device_id == device.device_id).all()
    }

    total = 0.0
    for anomaly_type, raw_score in raw_by_type.items():
        component = existing.get(anomaly_type)
        if component is None:
            component = DeviceRiskComponent(device_id=device.device_id, anomaly_type=anomaly_type, score=0.0, updated_at=None)
            db.add(component)
            existing[anomaly_type] = component
        component.score = _decay_and_rise(component.score, component.updated_at, raw_score, anomaly_type, now, freeze_basis)
        component.updated_at = now
        total += component.score

    for anomaly_type, component in existing.items():
        if anomaly_type in raw_by_type:
            continue  # already updated above
        component.score = _decay_and_rise(component.score, component.updated_at, 0.0, anomaly_type, now, freeze_basis)
        component.updated_at = now
        total += component.score

    new_aggregate = min(100.0, total)
    device.current_risk_score = new_aggregate
    device.risk_score_updated_at = now
    return new_aggregate


def _reasoning_trigger_fires(previous_level: str, new_level: str) -> bool:
    """AI Reasoning Core trigger (core/config.py's REASONING_TRIGGER_MIN_
    LEVEL / "AI Reasoning Core" section) -- an UPWARD transition into
    high/critical, not a level check re-evaluated every cycle. A device
    that simply stays at "high" for the next twenty cycles doesn't
    re-trigger; newly reaching high, or escalating high -> critical,
    does. Decreasing severity never triggers."""
    min_rank = RISK_LEVEL_RANK[REASONING_TRIGGER_MIN_LEVEL]
    new_rank = RISK_LEVEL_RANK.get(new_level, 0)
    previous_rank = RISK_LEVEL_RANK.get(previous_level, 0)
    return new_rank >= min_rank and new_rank > previous_rank


def _sharp_delta_trigger_fires(db: Session, device: Device, department: str, score_delta: float) -> bool:
    """A deliberate, NARROW exception to the medium-band exclusion above
    (REASONING_TRIGGER_MIN_LEVEL stays "high" -- this doesn't change that
    floor, it's a separate additional condition) -- only considered by the
    caller when persisted_level == "medium" and the ordinary edge-trigger
    didn't already fire. A rapid jump (e.g. 3->30, 20->50) can be a
    meaningful signal on its own, distinct from a slow gradual drift to
    the same destination -- but "sharp" is measured against what's
    actually normal for THIS device/department (agent_logic/baseline_
    learning.py's get_expected_max_delta, the same learned-baseline
    system feature_extractor.py already uses), not an arbitrary
    one-size-fits-all number.

    SHARP_DELTA_MIN_ABSOLUTE is an always-enforced floor regardless of how
    statistically unusual a tiny jump looks for a very quiet device --
    substantively large in absolute terms too, not just relatively
    surprising."""
    if score_delta <= 0:
        return False
    mean, std = get_expected_max_delta(db, device.device_id, device.company_id, department)
    threshold = max(SHARP_DELTA_MIN_ABSOLUTE, mean + SHARP_DELTA_ZSCORE_MULTIPLIER * std)
    return score_delta >= threshold


def _escalation_trigger_fires(device: Device, persisted_score: float, now: datetime) -> bool:
    """Sustained continued escalation AFTER the first trigger -- only
    considered by the caller when the device is already high/critical and
    neither the edge-trigger nor the sharp-delta trigger fired this cycle
    (so at most one of the three trigger types ever fires per cycle).

    Fires only on genuine further climb since the LAST trigger of ANY kind
    for this device (Device.last_reasoning_trigger_score/_at, updated
    whichever of the three conditions fires) -- not merely because time
    has passed at the same level. This is also what makes it compose
    correctly with dismiss/undo (agent_logic/dismissal.py) with no new
    dismiss-aware code: a dismissal rolls back the matching
    DeviceRiskComponent, which lowers persisted_score on the very next
    cycle -- a genuinely-settled device simply can't clear last_
    reasoning_trigger_score + ESCALATION_MIN_SCORE_INCREASE again without
    a real further climb, while a genuine later re-climb (the same type
    recurring completely fresh, or a different component growing) clears
    it exactly the same as it would have without any dismissal in
    between. The cooldown is a backstop against a pathological fast-
    oscillation edge case, not the primary gate -- the score-increase
    requirement is."""
    if device.last_reasoning_trigger_score is None or device.last_reasoning_trigger_at is None:
        return False
    last_at = device.last_reasoning_trigger_at
    if last_at.tzinfo is None:
        last_at = last_at.replace(tzinfo=timezone.utc)
    if persisted_score < device.last_reasoning_trigger_score + ESCALATION_MIN_SCORE_INCREASE:
        return False
    return (now - last_at) >= timedelta(seconds=ESCALATION_MIN_COOLDOWN_SECONDS)


def _generate_reasoning(features: dict, anomalies: list[dict], risk_level: str) -> str:
    reasons = []
    if anomalies:
        reasons.append(f"{len(anomalies)} anomalies detected during behavioural analysis")
    if features["after_hours"]:
        reasons.append("Activity occurred outside normal working hours")
    if features["sensitive_ratio"] >= 0.5:
        reasons.append("Large ratio of sensitive file access detected")
    reasons.append(f"Threat level assessed as {risk_level}")
    return ". ".join(reasons) + "."


def analyze_device_window(
    db: Session,
    company_id: int,
    device_id: int,
    window_start: datetime,
    window_end: datetime,
    score_fn: ScoreFn,
    time_window: str = "hourly",
) -> dict:
    """Runs the full detection pipeline for one device over one time window:
    extract features -> rule-based anomalies -> behavioural profile ->
    pluggable model score -> device risk update -> decision -> response.
    Always persists a Feature row (the audit/training record for this
    window, even if nothing anomalous happened). Persists/refreshes an
    Alert whenever a genuine rule-based anomaly is present — per
    dissertation section 4.7, low-severity events still get an alert, just
    no enforcement action. High/critical recommendations are recorded as
    pending Response rows. Always
    updates Device.current_risk_score, anomalies or not — decay only
    happens when this runs."""

    device = db.query(Device).filter(Device.device_id == device_id, Device.company_id == company_id).first()
    if device is None:
        raise ValueError(f"Device {device_id} not found for company {company_id}")

    features = extract_features(db, company_id, device_id, window_start, window_end)
    feature_row = save_feature(db, company_id, device_id, window_start, window_end, time_window, features)

    anomalies = detect_anomalies(features)  # type, message and severity per finding
    profile = profile_behaviour(features)

    # CNN_SEQUENCE_LENGTH consecutive windows ending at this one, current
    # window last — reuses the already-computed `features` dict for that
    # last slot instead of recomputing it a second time.
    feature_sequence = extract_feature_sequence(
        db, company_id, device_id, window_start, window_end, CNN_SEQUENCE_LENGTH, current_features=features
    )
    ml_score, ml_confidence = score_fn(feature_sequence)

    raw = score_risk(features, anomalies, profile, ml_score)
    raw_score = raw["risk_score"]
    raw_level = raw["risk_level"]

    now = datetime.now(timezone.utc)
    # Captured BEFORE _update_risk_components mutates device.current_risk_score
    # -- the AI Reasoning Core trigger (below) needs to compare against
    # what the level (and, for the sharp-delta/escalation triggers, the
    # actual numeric score) WAS, not what it's about to become.
    previous_score = device.current_risk_score or 0.0
    previous_level = risk_level_for_score(previous_score)
    persisted_score = _update_risk_components(db, device, anomalies, ml_score, now)
    persisted_level = risk_level_for_score(persisted_score)

    # Real-time delta accumulator (agent_logic/baseline_learning.py's
    # pending_max_delta_today) -- feeds the sharp-delta trigger's learned
    # baseline. Every cycle, not just ones that trigger anything; folded
    # into risk_delta_mean/var at the next daily rollup regardless of
    # whether this specific cycle's jump was itself trigger-worthy.
    update_pending_max_delta(db, device, persisted_score - previous_score)

    decision = make_decision(raw_score, raw_level, anomalies, features)
    response = recommend_actions(raw_level, features, anomalies)
    reasoning = _generate_reasoning(features, anomalies, raw_level)

    alert = None
    if anomalies:
        primary_type = anomalies[0]["type"]
        primary_message = anomalies[0]["message"]
        # Same ongoing episode still tripping the same rule -- refresh the
        # existing unresolved alert in place instead of stacking a new row
        # on top of an issue that never went away. Matches on anomaly_type
        # (stable), not title (drifts cycle to cycle — see anomaly_
        # detector.py's docstring for the confirmed live reproduction).
        # Excludes "dismissed" alongside "resolved" -- an admin dismissal is
        # a statement about what already happened (models/alerts.py's
        # Alert.status docstring), not a standing exemption for this type;
        # a recurrence must start a genuinely new alert, never silently
        # resurrect/overwrite the dismissed one in place.
        existing = (
            db.query(Alert)
            .filter(
                Alert.device_id == device_id,
                Alert.status.notin_(["resolved", "dismissed"]),
                Alert.anomaly_type == primary_type,
            )
            .order_by(Alert.created_at.desc())
            .first()
        )
        if existing is not None:
            existing.risk_level = raw_level
            existing.risk_score = raw_score
            existing.replace_anomalies(anomalies)
            existing.title = primary_message
            existing.description = reasoning
            existing.created_at = now
            alert = existing
        else:
            alert = Alert(
                company_id=company_id,
                device_id=device_id,
                risk_level=raw_level,
                risk_score=raw_score,
                anomaly_type=primary_type,
                title=primary_message,
                description=reasoning,
                status="open",
            )
            alert.replace_anomalies(anomalies)
            db.add(alert)
        db.commit()
        db.refresh(alert)

        if raw_level.lower() in ("high", "critical") and response["actions"]:
            save_responses(db, alert.id, response["actions"])

    # Auto-clear stale low/medium alerts whose type didn't recur this
    # window -- keeps the triage queue (open-alert count, alert feed) from
    # accumulating noise indefinitely. This no longer drives the device's
    # displayed risk (current_risk_score/decay does that now), just alert
    # bookkeeping. high/critical are deliberately never auto-resolved:
    # those still need a human to actually look at them (PATCH
    # /alerts/{id}). Threshold is 2x the analysis WINDOW size (minutes),
    # not the scheduler's cadence (seconds) -- staleness is about how long
    # the underlying activity has aged out of the rolling window being
    # analyzed, not how often that window gets re-checked.
    stale_cutoff = now - timedelta(minutes=2 * ANALYSIS_WINDOW_MINUTES)
    current_types = {a["type"] for a in anomalies}
    # Excludes "dismissed" alongside "resolved" -- an already-dismissed
    # alert must never get auto-resolved on top of that (a stronger,
    # admin-driven terminal state silently downgraded by bookkeeping).
    stale_candidates = (
        db.query(Alert)
        .filter(
            Alert.device_id == device_id,
            Alert.status.notin_(["resolved", "dismissed"]),
            Alert.risk_level.in_(["low", "medium"]),
            Alert.created_at <= stale_cutoff,
        )
        .all()
    )
    stale_alerts = [a for a in stale_candidates if a.anomaly_type not in current_types]
    for stale in stale_alerts:
        stale.status = "resolved"

    db.commit()  # covers device.current_risk_score/risk_score_updated_at and any stale-alert resolutions

    # AI Reasoning Core trigger -- see core/config.py's "AI Reasoning Core"
    # section and _reasoning_trigger_fires/_sharp_delta_trigger_fires/
    # _escalation_trigger_fires above. Everything from here down is cheap
    # (DB reads via gather_context, then a synchronous queue put) -- the
    # actual LLM calls never run on this thread; backend/reasoning/
    # worker.py's background task does that, fully decoupled from this
    # scheduler-driven function. If nothing crossed the threshold this
    # cycle, none of this runs at all.
    #
    # Exactly one of the three ever fires per cycle (elif, not three
    # independent ifs) -- the edge-trigger takes priority since it's
    # already the most fundamentally "new" event (a real level
    # transition); the sharp-delta trigger only applies to the medium
    # band the edge-trigger doesn't cover; the escalation re-trigger only
    # applies once already sustained at high/critical with neither of the
    # other two having fired.
    trigger_reason = None
    if _reasoning_trigger_fires(previous_level, persisted_level):
        trigger_reason = "new_crossing"
    elif persisted_level == "medium":
        metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device_id).first()
        # Genuinely None when unset -- get_expected_max_delta (called
        # inside _sharp_delta_trigger_fires) already treats None exactly
        # like an unrecognized department (the generic DEFAULT_EXPECTED_
        # MAX_DELTA floor, no department-specific learned data to blend).
        department = metadata.department if metadata and metadata.department else None
        if _sharp_delta_trigger_fires(db, device, department, persisted_score - previous_score):
            trigger_reason = "sharp_delta"
    elif persisted_level in ("high", "critical"):
        if _escalation_trigger_fires(device, persisted_score, now):
            trigger_reason = "continued_escalation"

    if trigger_reason is not None:
        trigger_alert_id = alert.id if alert else None
        if trigger_alert_id is None:
            # This cycle's own anomalies list was empty (or didn't create/
            # refresh an alert) but the AGGREGATE still crossed the
            # threshold -- e.g. ml_signal alone, on top of other already-
            # elevated components. Fall back to the device's most recent
            # still-open alert, if any, as the "most relevant" one for
            # context/accept-to-Response-row purposes. Excludes "dismissed"
            # alongside "resolved" -- a dismissed alert was explicitly
            # closed by an admin and must never be picked back up as the
            # attachment point for a brand-new judgment.
            fallback_alert = (
                db.query(Alert)
                .filter(Alert.device_id == device_id, Alert.status.notin_(["resolved", "dismissed"]))
                .order_by(Alert.created_at.desc())
                .first()
            )
            trigger_alert_id = fallback_alert.id if fallback_alert else None

        context = gather_context(db, device, anomalies, ml_score, persisted_score, persisted_level)
        enqueue_reasoning_trigger({
            "company_id": company_id,
            "device_id": device_id,
            "alert_id": trigger_alert_id,
            "trigger_risk_score": persisted_score,
            "trigger_risk_level": persisted_level,
            "trigger_reason": trigger_reason,
            "context": context,
        })

        # Shared high-water-mark for all three trigger types (models/
        # devices.py's Device.last_reasoning_trigger_score/_at docstring)
        # -- updated regardless of trigger_reason, and regardless of
        # whether the LLM call later succeeds (matches the email
        # notification itself already being decoupled from Reasoning Core
        # success -- "did we notify" is decided here, at enqueue time).
        device.last_reasoning_trigger_score = persisted_score
        device.last_reasoning_trigger_at = now
        db.commit()

    return {
        "feature_id": feature_row.feature_id,
        "alert_id": alert.id if alert else None,
        "anomalies": [a["message"] for a in anomalies],
        "risk_score": persisted_score,
        "risk_level": persisted_level,
        "raw_window_score": raw_score,
        "raw_window_level": raw_level,
        "decision": decision,
        "actions": response["actions"],
        "response_status": response["response_status"],
        "ai_reasoning": reasoning,
        "ml_anomaly_score": round(ml_score, 4),
        "ml_confidence": None if ml_confidence is None else round(ml_confidence, 4),
    }
