# FROM ai-agent-assignment: app/agent/behavioural_profiler.py — copied, needs changes: baseline must be per-device, not global

def profile_behaviour(features: dict) -> dict:
    """Compares this device's window against its department's (or, once
    enough real history exists, its own) learned baseline. The baseline
    itself is no longer read from ROLE_BASELINES/get_effective_baseline
    independently here -- feature_extractor.py's extract_features()
    already computed it once (via agent_logic/baseline_learning.py) and
    stashed the three values this function needs onto `features` (baseline_
    avg_files_per_day/baseline_normal_hours/baseline_avg_failed_logins),
    the same "compute once, thread through the features dict" pattern
    expected_files already used below for exactly the same reason: a
    second independent lookup here could theoretically disagree with the
    first (different DB read at a slightly different moment), and would
    just be redundant work every single cycle otherwise."""
    normal_start, normal_end = features["baseline_normal_hours"]
    login_hour = features.get("login_hour")
    files_accessed = features["files_accessed"]
    avg_files = features["baseline_avg_files_per_day"]

    # No login in the window at all counts as "within hours" — there's
    # nothing to flag.
    within_hours = login_hour is None or (normal_start <= login_hour < normal_end)

    # Originally a plain ratio against avg_files_per_day (a daily figure),
    # which broke the same way baseline_deviation did on short windows —
    # files_accessed is naturally tiny next to a daily average, so the
    # ratio stayed near zero regardless of actual behaviour and the
    # excessive_file_access flag almost never fired. Fixed the same way:
    # expected_files (feature_extractor.py) is already scaled to this
    # window's duration, and normalizing by sqrt(expected) instead of
    # dividing by the raw mean turns this into a proper z-score (files
    # accessed, standard deviations above what's expected for a window this
    # long) rather than a multiple of a daily figure. The >2.5 threshold
    # below reads the same either way — "notably above expected" — so it's
    # left as-is.
    expected_files = features.get("expected_files", avg_files)
    if expected_files > 0:
        file_volume_ratio = round((files_accessed - expected_files) / max(expected_files ** 0.5, 1), 2)
    else:
        file_volume_ratio = 0.0

    # consecutive_failed_logins (the streak, not the raw per-window count)
    # -- same reasoning as anomaly_detector.py/risk_scorer.py's switch:
    # a streak resets to zero the instant a login succeeds, so this flag
    # shouldn't keep firing off a stale per-window count after that.
    avg_failed = features["baseline_avg_failed_logins"]
    failed_logins = features.get("consecutive_failed_logins", features["failed_logins"])
    if avg_failed > 0:
        login_anomaly_ratio = round(failed_logins / avg_failed, 2)
    else:
        login_anomaly_ratio = float(failed_logins)

    # Reuses feature_extractor.py's out_of_scope_sensitive_count (department-
    # pattern-based) instead of duplicating the old flat "sensitive_access_
    # allowed" boolean check independently -- the two used to compute the
    # same underlying idea (unauthorised sensitive access) via two separate
    # code paths that could disagree; now there's one source of truth.
    unauthorised_sensitive = features.get("out_of_scope_sensitive_count", 0) > 0

    profile_flags = []
    if not within_hours:
        profile_flags.append("outside_normal_hours")
    if file_volume_ratio > 2.5:
        profile_flags.append("excessive_file_access")
    if login_anomaly_ratio > 5:
        profile_flags.append("excessive_failed_logins")
    if unauthorised_sensitive:
        profile_flags.append("unauthorised_sensitive_access")
    if features["baseline_deviation"] >= 3.5:
        profile_flags.append("high_baseline_deviation")

    return {
        "within_normal_hours": within_hours,
        "file_volume_ratio": file_volume_ratio,
        "login_anomaly_ratio": login_anomaly_ratio,
        "unauthorised_sensitive": unauthorised_sensitive,
        "profile_flags": profile_flags,
        "baseline_summary": (
            f"{features['department'] or 'unassigned'} department — normal hours "
            f"{normal_start:02d}:00-{normal_end:02d}:00, avg {avg_files} files/day"
        ),
    }
