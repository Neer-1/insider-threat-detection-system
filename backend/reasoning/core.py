# NEW — evidence gathering + the bounded two-pass judgment

"""
gather_context() runs synchronously, inside agent_logic/analyzer.py's
analyze_device_window() at the moment a trigger fires — it's just DB
reads (cheap), not the LLM call itself, so it doesn't add meaningfully to
the real-time scheduler's per-cycle cost. The resulting dict is what gets
queued (backend/reasoning/worker.py); run_two_pass_judgment() is what
actually calls out to LM Studio, and only ever runs from the worker's own
background task, never inline in the scheduler.
"""

from sqlalchemy.orm import Session

from backend.agent_logic.significant_events import significant_log_predicate
from backend.models.alerts import Alert
from backend.models.company_policy_document import CompanyPolicyDocument
from backend.models.devices import Device, DeviceMetadata
from backend.models.logs import Log
from backend.models.risk_components import DeviceRiskComponent
from backend.reasoning import client
from backend.reasoning.policy_document import select_relevant_excerpt
from backend.reasoning.prompts import ANALYST_SYSTEM_PROMPT, CRITIC_SYSTEM_PROMPT, build_context_message

RECENT_ALERTS_LIMIT = 10
RECENT_SIGNIFICANT_EVENTS_LIMIT = 15


def gather_context(
    db: Session,
    device: Device,
    anomalies: list[dict],
    ml_score: float,
    risk_score: float,
    risk_level: str,
) -> dict:
    """Builds the evidence bundle the LLM reasons over. Treats the
    deterministic layer's own outputs (anomalies, ml_score, risk_score/
    level, DeviceRiskComponent rows) as given facts to read, not
    something recomputed here -- this function only adds READ-ONLY
    context around them (department, recent alert/event history)."""
    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    # Genuinely None when unset -- select_relevant_excerpt below already
    # treats None exactly like an unrecognized department (no extra policy-
    # keyword boost, still works via the anomaly-type keywords alone).
    # Guarded to "unassigned" only where this actually renders as text
    # for the model (the returned dict's own "department" field, below --
    # reasoning/prompts.py embeds it directly into the LLM prompt), not
    # here where it's still a real lookup key.
    department = metadata.department if metadata and metadata.department else None

    components = (
        db.query(DeviceRiskComponent)
        .filter(DeviceRiskComponent.device_id == device.device_id, DeviceRiskComponent.score > 0.5)
        .order_by(DeviceRiskComponent.score.desc())
        .all()
    )

    recent_alerts = (
        db.query(Alert)
        .filter(Alert.device_id == device.device_id)
        .order_by(Alert.created_at.desc())
        .limit(RECENT_ALERTS_LIMIT)
        .all()
    )

    recent_events = (
        db.query(Log)
        .filter(Log.device_id == device.device_id)
        .filter(significant_log_predicate())
        .order_by(Log.timestamp.desc())
        .limit(RECENT_SIGNIFICANT_EVENTS_LIMIT)
        .all()
    )

    # Company bylaws/policy, if uploaded (routes/company.py) -- read-only,
    # same as everything else this function assembles: never writes to
    # risk_score/DeviceRiskComponent, just one more input handed to the
    # LLM as prose (reasoning/prompts.py's build_context_message). Simple
    # keyword-based section selection (reasoning/policy_document.py), not
    # the whole document -- see that module's docstring for why. None if
    # no document is configured, or if the document exists but nothing in
    # it scored as relevant to this specific trigger.
    policy_doc = db.query(CompanyPolicyDocument).filter(CompanyPolicyDocument.company_id == device.company_id).first()
    policy_excerpt = (
        select_relevant_excerpt(db, device.company_id, policy_doc.converted_markdown, anomalies, department)
        if policy_doc is not None
        else None
    )

    return {
        "label": device.label or device.hostname,
        "hostname": device.hostname,
        "department": department or "unassigned",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "anomalies": [{"type": a["type"], "message": a["message"], "severity": a["severity"]} for a in anomalies],
        "risk_components": [{"anomaly_type": c.anomaly_type, "score": c.score} for c in components],
        "ml_score": ml_score,
        "recent_alerts": [
            {
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "risk_level": a.risk_level,
                "title": a.title,
                "status": a.status,
            }
            for a in recent_alerts
        ],
        "recent_significant_events": [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "event_type": e.event_type,
                "filepath": e.filepath,
                "device_name": e.device_name,
                "status": e.status,
            }
            for e in recent_events
        ],
        "policy_excerpt": policy_excerpt,
    }


async def run_two_pass_judgment(context: dict) -> dict | None:
    """The bounded EMAD-inspired critic pass (see core/config.py's "AI
    Reasoning Core" section for why this is two passes, not open-ended
    debate). Returns None if EITHER pass fails (LM Studio unreachable,
    or its output didn't parse/validate) -- a failed Pass 1 means Pass 2
    never runs at all (nothing sound to critique), matching "treat a
    parse failure as an aborted pass, not something Pass 2 tries to
    repair"."""
    evidence_text = build_context_message(context)

    initial = await client.chat(
        [
            {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
            {"role": "user", "content": evidence_text},
        ],
        parser=lambda content: client.parse_judgment(content, require_agreed_field=False),
    )
    if initial is None:
        return None

    critic_prompt = (
        evidence_text
        + "\n\n--- FIRST ANALYST'S JUDGMENT (to review, not to trust blindly) ---\n"
        + f"explanation: {initial['explanation']}\n"
        + f"recommendation: {initial['recommendation']}\n"
    )
    final = await client.chat(
        [
            {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
            {"role": "user", "content": critic_prompt},
        ],
        parser=lambda content: client.parse_judgment(content, require_agreed_field=True),
    )
    if final is None:
        return None

    changed = (not final["agreed_with_initial"]) or (final["recommendation"] != initial["recommendation"])

    return {
        "initial_explanation": initial["explanation"],
        "initial_recommendation": initial["recommendation"],
        "initial_confidence": initial["confidence"],
        "final_explanation": final["explanation"],
        "final_recommendation": final["recommendation"],
        "final_confidence": final["confidence"],
        "critic_changed_judgment": changed,
    }
