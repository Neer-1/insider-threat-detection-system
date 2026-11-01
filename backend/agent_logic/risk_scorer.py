# FROM ai-agent-assignment: app/agent/risk_scorer.py — copied direct, reuses thresholds from config.py

from backend.core.config import (
    ACCESS_VELOCITY_CRITICAL,
    ACCESS_VELOCITY_HIGH,
    BASELINE_DEVIATION_HIGH,
    BASELINE_DEVIATION_WARN,
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WARN,
    FILES_ACCESSED_HIGH,
    FILES_ACCESSED_WARN,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    SENSITIVE_RATIO_HIGH,
    SENSITIVE_RATIO_WARN,
    SEVERITY_ACCESS_VELOCITY_CRITICAL,
    SEVERITY_ACCESS_VELOCITY_HIGH,
    SEVERITY_AFTER_HOURS,
    SEVERITY_BASELINE_DEVIATION_HIGH,
    SEVERITY_BASELINE_DEVIATION_WARN,
    SEVERITY_DEPARTMENT_MISMATCH,
    SEVERITY_FAILED_LOGINS_HIGH,
    SEVERITY_FAILED_LOGINS_WARN,
    SEVERITY_FILES_ACCESSED_HIGH,
    SEVERITY_FILES_ACCESSED_WARN,
    SEVERITY_LARGE_DOWNLOAD,
    SEVERITY_LARGE_PRINT_JOB,
    SEVERITY_PRIVILEGE_ESCALATION,
    SEVERITY_SENSITIVE_RATIO_HIGH,
    SEVERITY_SENSITIVE_RATIO_WARN,
    SEVERITY_UNVERIFIED_INSTALL,
    SEVERITY_USB_ACTIVITY,
)


def score_risk(features: dict, anomalies: list, profile: dict, ml_score: float) -> dict:
    """Combines rule-based anomaly count, behavioural profile flags, and the
    pluggable model's anomaly score into a final risk score (0-100).
    ml_score must be on a 0..1 scale — whatever analyzer.py's score_fn ends
    up wired to (Isolation Forest now, the CNN later) has to return that
    range for this weighting to stay meaningful.

    Point-values are the same SEVERITY_* constants anomaly_detector.py tags
    each detected anomaly with (core/config.py) — one shared number per
    condition instead of two copies that could drift apart. `anomalies`
    itself is accepted but not read here (kept for signature compatibility
    with callers) — this function derives its score straight from
    `features`, same as before this file existed."""
    score = 0

    # Streak (consecutive_failed_logins), not the raw per-window count --
    # same reasoning as anomaly_detector.py: a login success should stop
    # this contributing almost immediately, not linger for the rest of
    # whatever window happened to contain the earlier failures.
    fl = features.get("consecutive_failed_logins", features["failed_logins"])
    if fl >= FAILED_LOGIN_THRESHOLD:
        score += SEVERITY_FAILED_LOGINS_HIGH
    elif fl >= FAILED_LOGIN_WARN:
        score += SEVERITY_FAILED_LOGINS_WARN

    # USB: only scores when insertion was followed by a qualifying large
    # transfer or install/execution from the device (feature_extractor.py's
    # usb_followup_activity) -- a bare insertion no longer contributes.
    if features.get("usb_followup_activity"):
        score += SEVERITY_USB_ACTIVITY

    if features["privilege_escalation"]:
        score += SEVERITY_PRIVILEGE_ESCALATION
    if features["large_print_job"]:
        score += SEVERITY_LARGE_PRINT_JOB
    if features["after_hours"]:
        score += SEVERITY_AFTER_HOURS
    if features["department_mismatch"]:
        score += SEVERITY_DEPARTMENT_MISMATCH

    fa = features["files_accessed"]
    if fa >= FILES_ACCESSED_HIGH:
        score += SEVERITY_FILES_ACCESSED_HIGH
    elif fa >= FILES_ACCESSED_WARN:
        score += SEVERITY_FILES_ACCESSED_WARN

    av = features["access_velocity"]
    if av >= ACCESS_VELOCITY_CRITICAL:
        score += SEVERITY_ACCESS_VELOCITY_CRITICAL
    elif av >= ACCESS_VELOCITY_HIGH:
        score += SEVERITY_ACCESS_VELOCITY_HIGH

    sr = features["sensitive_ratio"]
    if sr >= SENSITIVE_RATIO_HIGH:
        score += SEVERITY_SENSITIVE_RATIO_HIGH
    elif sr >= SENSITIVE_RATIO_WARN:
        score += SEVERITY_SENSITIVE_RATIO_WARN

    bd = features["baseline_deviation"]
    if bd >= BASELINE_DEVIATION_HIGH:
        score += SEVERITY_BASELINE_DEVIATION_HIGH
    elif bd >= BASELINE_DEVIATION_WARN:
        score += SEVERITY_BASELINE_DEVIATION_WARN

    # New — same exfiltration/introduction category as USB (see
    # anomaly_detector.py / agent/collector.py for what's collectible).
    if features.get("large_downloads_count", 0) > 0:
        score += SEVERITY_LARGE_DOWNLOAD
    if features.get("unverified_installs_count", 0) > 0:
        score += SEVERITY_UNVERIFIED_INSTALL

    ml_contribution = round(ml_score * 20)
    score += ml_contribution

    score += len(profile["profile_flags"]) * 3

    score = max(0, min(100, score))

    if score >= RISK_CRITICAL:
        level = "critical"
    elif score >= RISK_HIGH:
        level = "high"
    elif score >= RISK_MEDIUM:
        level = "medium"
    else:
        level = "low"

    return {"risk_score": score, "risk_level": level}
