# FROM ai-agent-assignment: app/agent/anomaly_detector.py — copied direct, rule logic is reusable as-is

from backend.core.config import (
    ACCESS_VELOCITY_CRITICAL,
    ACCESS_VELOCITY_HIGH,
    BASELINE_DEVIATION_HIGH,
    BASELINE_DEVIATION_WARN,
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WARN,
    FILES_ACCESSED_HIGH,
    FILES_ACCESSED_WARN,
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
    SEVERITY_TIME_DEVIATION,
    SEVERITY_UNVERIFIED_INSTALL,
    SEVERITY_USB_ACTIVITY,
)


def detect_anomalies(features: dict) -> list[dict]:
    """Rule-based checks over one device's aggregated feature window.
    Thresholds and messages are ported near-verbatim from the original
    single-session version. Returns structured {"type", "message",
    "severity"} records — "type" is a fixed identifier per rule check
    (dedup key, per analyzer.py), "message" is the human-readable text,
    "severity" is the same 0-100-scale point-value risk_scorer.py assigns
    that condition (core/config.py's SEVERITY_* constants — shared, not a
    second copy), which is what feeds that type's DeviceRiskComponent
    decay/rise in analyzer.py.

    The "message" split from "type" exists because message embeds live-
    computed numbers (counts, percentages, sigma values) that drift
    slightly between analysis cycles even when the underlying behaviour
    hasn't actually changed — confirmed live: a single ongoing pattern
    produced "...(8.74 sigma)" on one cycle and "...(9.74 sigma)" on the
    very next, as the rolling analysis window shifted by a few seconds.
    "type" never changes for the same rule, so that's what dedup keys on."""
    anomalies = []

    # Consecutive-failure STREAK, not a raw per-window count (feature_
    # extractor.py's _consecutive_failed_logins) -- a success resets this
    # to zero immediately regardless of how many failures preceded it, so
    # "two fails then a success" barely registers while "ten in a row with
    # no success" flags hard. features["failed_logins"] (the raw window
    # count) still exists and is still persisted to Feature for audit/
    # training purposes -- it's just not what severity is judged on here
    # any more.
    streak = features.get("consecutive_failed_logins", features["failed_logins"])
    if streak >= FAILED_LOGIN_THRESHOLD:
        anomalies.append({
            "type": "failed_logins",
            "message": f"Multiple consecutive failed login attempts (x{streak}) — threshold exceeded",
            "severity": SEVERITY_FAILED_LOGINS_HIGH,
        })
    elif streak >= FAILED_LOGIN_WARN:
        anomalies.append({
            "type": "failed_logins",
            "message": f"Elevated consecutive failed logins (x{streak})",
            "severity": SEVERITY_FAILED_LOGINS_WARN,
        })

    # USB: insertion alone is routine, not scored. usb_followup_activity
    # (feature_extractor.py's _usb_followup_activity) is only True when an
    # insertion was followed by a large transfer or install/execution tied
    # to that same device within USB_ACTIVITY_WINDOW_MINUTES -- the raw
    # insertion event is still logged either way (agent/collector.py never
    # stops reporting it, and it still shows up in GET /logs/significant
    # as relevant context), it just doesn't independently fire this
    # anomaly type any more.
    if features.get("usb_followup_activity"):
        anomalies.append({
            "type": "usb_insertion",
            "message": "USB device insertion followed by large transfer or execution from the device",
            "severity": SEVERITY_USB_ACTIVITY,
        })

    if features["after_hours"]:
        login_hour = features.get("login_hour")
        if login_hour is not None:
            message = f"After-hours system access (login at {login_hour:02d}:00)"
        else:
            message = "After-hours system access detected"
        anomalies.append({"type": "after_hours", "message": message, "severity": SEVERITY_AFTER_HOURS})

    fa = features["files_accessed"]
    if fa >= FILES_ACCESSED_HIGH:
        anomalies.append({
            "type": "high_file_access",
            "message": f"High file access volume ({fa} files in window)",
            "severity": SEVERITY_FILES_ACCESSED_HIGH,
        })
    elif fa >= FILES_ACCESSED_WARN:
        anomalies.append({
            "type": "high_file_access",
            "message": f"Above-average file access ({fa} files in window)",
            "severity": SEVERITY_FILES_ACCESSED_WARN,
        })

    av = features["access_velocity"]
    if av >= ACCESS_VELOCITY_CRITICAL:
        anomalies.append({
            "type": "access_velocity",
            "message": f"Critical access velocity ({av} files/min) — possible bulk exfiltration",
            "severity": SEVERITY_ACCESS_VELOCITY_CRITICAL,
        })
    elif av >= ACCESS_VELOCITY_HIGH:
        anomalies.append({
            "type": "access_velocity",
            "message": f"High access velocity ({av} files/min)",
            "severity": SEVERITY_ACCESS_VELOCITY_HIGH,
        })

    sr = features["sensitive_ratio"]
    if sr >= SENSITIVE_RATIO_HIGH:
        anomalies.append({
            "type": "sensitive_ratio",
            "message": f"High sensitive file ratio ({int(sr * 100)}% of accessed files are sensitive)",
            "severity": SEVERITY_SENSITIVE_RATIO_HIGH,
        })
    elif sr >= SENSITIVE_RATIO_WARN:
        anomalies.append({
            "type": "sensitive_ratio",
            "message": f"Elevated sensitive file access ({int(sr * 100)}% of files)",
            "severity": SEVERITY_SENSITIVE_RATIO_WARN,
        })

    # department_mismatch now means "touched a sensitive file outside this
    # department's own allow-list" (core/config.py's DEPARTMENT_ALLOWED_
    # SENSITIVE_PATTERNS), not the old flat "this department can never
    # touch sensitive files" boolean -- see feature_extractor.py's
    # _out_of_scope_sensitive_count.
    if features["department_mismatch"]:
        anomalies.append({
            "type": "department_mismatch",
            "message": (
                f"Out-of-scope sensitive file access — {features['department'] or 'unassigned'} department "
                f"accessing content outside its normal scope"
            ),
            "severity": SEVERITY_DEPARTMENT_MISMATCH,
        })

    if features["privilege_escalation"]:
        anomalies.append({
            "type": "privilege_escalation",
            "message": "Privilege escalation attempt detected",
            "severity": SEVERITY_PRIVILEGE_ESCALATION,
        })

    if features["large_print_job"]:
        anomalies.append({
            "type": "large_print_job",
            "message": "Large print job submitted — possible data exfiltration via print",
            "severity": SEVERITY_LARGE_PRINT_JOB,
        })

    # New — same exfiltration/introduction category as USB, previously not
    # captured at all. See agent/collector.py for what's actually
    # observable here (Downloads-folder polling + Mark-of-the-Web).
    if features.get("large_downloads_count", 0) > 0:
        anomalies.append({
            "type": "large_download",
            "message": f"Large file downloaded ({features['large_downloads_count']} in window)",
            "severity": SEVERITY_LARGE_DOWNLOAD,
        })

    if features.get("unverified_installs_count", 0) > 0:
        anomalies.append({
            "type": "unverified_install",
            "message": (
                f"Software installed from an unverified source "
                f"({features['unverified_installs_count']} in window)"
            ),
            "severity": SEVERITY_UNVERIFIED_INSTALL,
        })

    bd = features["baseline_deviation"]
    if bd >= BASELINE_DEVIATION_HIGH:
        anomalies.append({
            "type": "baseline_deviation",
            "message": f"Significant deviation from behavioural baseline ({bd} sigma)",
            "severity": SEVERITY_BASELINE_DEVIATION_HIGH,
        })
    elif bd >= BASELINE_DEVIATION_WARN:
        anomalies.append({
            "type": "baseline_deviation",
            "message": f"Moderate deviation from behavioural baseline ({bd} sigma)",
            "severity": SEVERITY_BASELINE_DEVIATION_WARN,
        })

    td = features["time_deviation"]
    if td >= 3:
        anomalies.append({
            "type": "time_deviation",
            "message": f"Login {td}h outside normal working hours for this department",
            "severity": SEVERITY_TIME_DEVIATION,
        })

    return anomalies
