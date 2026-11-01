# FROM ai-agent-assignment: app/agent/response_engine.py — copied, needs changes: writes real Response rows tied to a device_id instead of print/simulate

from sqlalchemy.orm import Session

from backend.models.responses import Response


def recommend_actions(risk_level: str, features: dict, anomalies: list) -> dict:
    """Same rule table as the original assignment, copied direct — only
    risk_level casing changed (lowercase) to match the rest of the schema."""
    level = (risk_level or "").lower()
    actions = []

    if level == "critical":
        actions.append("Disable user account immediately")
        actions.append("Notify security administrator and SOC team")
        actions.append("Preserve full session audit log as evidence")
        actions.append("Flag account for forensic investigation")
        if features.get("usb_inserted"):
            actions.append("Block USB device and log device serial number")
        if features.get("ip_address") and features["ip_address"] != "unknown":
            actions.append(f"Block IP address: {features['ip_address']}")
        if features.get("privilege_escalation"):
            actions.append("Revoke all elevated privileges immediately")
    elif level == "high":
        actions.append("Lock active session")
        actions.append("Raise security alert to team lead")
        actions.append("Enable enhanced logging for this user")
        actions.append("Request manager review within 1 hour")
        if features.get("large_print_job"):
            actions.append("Cancel pending print jobs and notify print admin")
    elif level == "medium":
        actions.append("Flag session for manual review")
        actions.append("Log incident in security register")
        actions.append("Enable 24-hour enhanced monitoring")
        actions.append("Notify line manager via automated email")
    else:
        actions.append("Continue standard monitoring")
        actions.append("No immediate action required")

    return {"actions": actions, "response_status": "recommendation_only"}


def save_responses(db: Session, alert_id: int, actions: list[str], triggered_by_admin_id: int | None = None) -> list[Response]:
    """Persists each recommended action as its own Response row tied to the
    Alert that triggered it. status="pending" — these are recommendations;
    there's no real
    actuator (account lock, IP block, etc.) wired up yet to ever mark one
    "completed".

    triggered_by_admin_id (new, optional, defaults to None so every
    existing caller here — analyzer.py's automatic deterministic-pipeline
    responses — is unaffected) is what Response.triggered_by_admin_id was
    always meant for: distinguishing an automatic system response from
    one an admin explicitly chose. The AI Reasoning Core's accept/override
    flow (routes/reasoning.py) is the first caller to actually pass it."""
    responses = []
    for action_text in actions:
        response = Response(
            alert_id=alert_id,
            action_taken=action_text[:100],
            status="pending",
            triggered_by_admin_id=triggered_by_admin_id,
        )
        db.add(response)
        responses.append(response)
    db.commit()
    for response in responses:
        db.refresh(response)
    return responses
