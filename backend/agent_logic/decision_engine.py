# FROM ai-agent-assignment: app/agent/decision_engine.py — copied direct

def make_decision(risk_score: int, risk_level: str, anomalies: list, features: dict) -> str:
    """Maps the risk score and anomalies to a human-readable decision
    string. risk_level is compared lowercase (critical/high/medium/low) to
    match the rest of the schema, unlike the original's Capitalised
    strings — the branching logic itself is unchanged."""
    level = (risk_level or "").lower()

    if level == "critical":
        if features.get("usb_inserted") and features.get("privilege_escalation"):
            return "Confirmed insider threat — USB exfiltration with privilege escalation detected"
        if features.get("failed_logins", 0) >= 5 and features.get("after_hours"):
            return "Potential account compromise — brute force attempt during after-hours access"
        if features.get("department_mismatch") and features.get("files_accessed", 0) >= 20:
            return "Potential data exfiltration — unauthorised bulk access to sensitive files"
        return "Potential insider threat detected — multiple critical indicators present"

    if level == "high":
        if features.get("access_velocity", 0) >= 5:
            return "Suspicious bulk file access — possible data harvesting behaviour"
        if features.get("large_print_job") and features.get("sensitive_ratio", 0) >= 0.4:
            return "Possible physical data exfiltration via print job"
        return "Suspicious behaviour confirmed — multiple elevated risk indicators"

    if level == "medium":
        if features.get("after_hours"):
            return "Anomalous after-hours access — flagged for review"
        if features.get("baseline_deviation", 0) >= 2:
            return "Behavioural deviation from baseline — monitoring recommended"
        return "Anomalous pattern observed — below critical threshold"

    return "Normal user behaviour — no action required"
