# NEW — background task that periodically runs the detection pipeline for every approved device

"""
Nothing else in the running server calls
agent_logic.analyzer.analyze_device_window() — routes/logs.py only stores
Log rows and updates connection status. This is what actually triggers
detection: a background asyncio task, started in main.py's lifespan, that
wakes up every ANALYSIS_INTERVAL_SECONDS and analyzes each approved
device's trailing ANALYSIS_WINDOW_MINUTES of activity as a rolling window
(now - window, now], not a fixed non-overlapping slot — see core/config.py
for why those are two separate numbers.

Uses the CNN as the primary score_fn (per the original instructions: "1D
CNN as the primary detection model... Isolation Forest kept as a
secondary/baseline signal"). Isolation Forest is available behind the
identical score_fn interface (backend/ai/predict_isolation_forest) if this
ever needs to run both side by side for comparison — only one is wired
into risk_scorer.py's ml_contribution at a time.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from backend.agent_logic.analyzer import analyze_device_window
from backend.agent_logic.baseline_learning import maybe_update_baselines
from backend.agent_logic.risk_snapshots import maybe_record_snapshot, prune_old_snapshots
from backend.core.config import (
    ANALYSIS_INITIAL_DELAY_SECONDS,
    ANALYSIS_INTERVAL_SECONDS,
    ANALYSIS_WINDOW_MINUTES,
    OFFLINE_THRESHOLD_SECONDS,
    RISK_SNAPSHOT_PRUNE_INTERVAL_HOURS,
)
from backend.database.db import SessionLocal
from backend.models.devices import Device

TIME_WINDOW_LABEL = "hourly"

_score_fn = None

# NEW — risk-snapshot pruning gate (agent_logic/risk_snapshots.py's
# prune_old_snapshots), same in-memory single-process pattern as
# _last_cycle_completed_at below -- checked every cycle, only actually
# runs the DELETE roughly once every RISK_SNAPSHOT_PRUNE_INTERVAL_HOURS.
_last_snapshot_prune_at: datetime | None = None

# NEW — Overview page's system-health strip (routes/system.py's
# get_system_health). In-memory, single-process module state, same
# pattern already used for _score_fn above and routes/reports.py's
# weekly-report job store -- this process IS the scheduler, so there's
# nothing to persist across a restart: a fresh restart naturally starts
# this back at None ("not run yet") until the first real cycle completes,
# which is the correct state to show, not a stale leftover value from
# before the restart.
_last_cycle_completed_at: datetime | None = None


def get_last_cycle_at() -> datetime | None:
    return _last_cycle_completed_at


def _get_score_fn():
    """Loads (or trains, on first run) the CNN once and reuses it across
    every device/cycle — not re-loaded from disk on every device analyzed."""
    global _score_fn
    if _score_fn is None:
        from backend.ai.predict_cnn import make_score_fn
        _score_fn = make_score_fn()
    return _score_fn


def _mark_offline_if_stale(db, device: Device, now: datetime) -> None:
    """connection_status only ever gets flipped to "online" by a real
    check-in (routes/device.py's enroll_device, routes/logs.py's
    ingest_logs) -- there's no explicit "going offline" signal the agent
    can send (push-only by design, no listening port), so "offline" has to
    be INFERRED here, from staleness, rather than received. Only ever
    downgrades online -> offline; the reverse direction is exclusively the
    real check-in's job, never this cycle's -- an actual check-in is the
    only genuine evidence a device is back, and it already updates
    last_seen/connection_status itself the moment it happens, not waiting
    for the next scheduler tick."""
    if device.connection_status != "online":
        return
    if device.last_seen is None or (now - device.last_seen).total_seconds() > OFFLINE_THRESHOLD_SECONDS:
        device.connection_status = "offline"
        db.commit()


def run_analysis_cycle() -> int:
    """One pass over every approved device — analyzes the trailing
    ANALYSIS_WINDOW_MINUTES of activity (now - window, now]. This is a
    rolling window re-evaluated every cycle, not a fixed non-overlapping
    slot, so the same recent activity is deliberately seen again on the
    next cycle too; analyzer.py's dedup/refresh-in-place logic is what
    keeps that from creating duplicate alerts. Errors analyzing one device
    are logged and skipped rather than aborting the whole cycle, so one bad
    device's data can't stop every other device from being analyzed.
    Returns the number of devices successfully analyzed."""
    global _last_cycle_completed_at
    db = SessionLocal()
    analyzed = 0
    try:
        devices = db.query(Device).filter(Device.approval_status == "approved").all()
        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(minutes=ANALYSIS_WINDOW_MINUTES)
        score_fn = _get_score_fn()

        for device in devices:
            # Offline-staleness check -- isolated in its own try/except,
            # same as detection/baseline-update below, so one device's
            # connectivity bookkeeping can never block real-time detection
            # for this or any other device.
            try:
                _mark_offline_if_stale(db, device, window_end)
            except Exception as e:
                print(f"[scheduler] connection-status check failed for device {device.device_id}: {e}")
            try:
                analyze_device_window(
                    db, device.company_id, device.device_id, window_start, window_end,
                    score_fn, time_window=TIME_WINDOW_LABEL,
                )
                analyzed += 1
            except Exception as e:
                print(f"[scheduler] analysis failed for device {device.device_id}: {e}")
            # Learned-baseline daily rollup -- a cheap no-op unless
            # BASELINE_ROLLUP_INTERVAL_HOURS has actually elapsed for this
            # device (agent_logic/baseline_learning.py). Isolated in its
            # own try/except, same as detection above, so a baseline-
            # learning failure can never block real-time detection for
            # this or any other device.
            try:
                maybe_update_baselines(db, device, window_end)
            except Exception as e:
                print(f"[scheduler] baseline update failed for device {device.device_id}: {e}")
            # Risk-score sparkline snapshot -- purely observational (see
            # agent_logic/risk_snapshots.py's own module docstring for the
            # exact read-only boundary), cheap no-op unless RISK_SNAPSHOT_
            # INTERVAL_MINUTES has elapsed for this device. Isolated in its
            # own try/except like everything else in this loop.
            try:
                maybe_record_snapshot(db, device, window_end)
            except Exception as e:
                print(f"[scheduler] risk snapshot failed for device {device.device_id}: {e}")

        db.commit()  # covers every maybe_record_snapshot() add() above -- that function itself never commits

        global _last_snapshot_prune_at
        if _last_snapshot_prune_at is None or (window_end - _last_snapshot_prune_at) >= timedelta(hours=RISK_SNAPSHOT_PRUNE_INTERVAL_HOURS):
            try:
                deleted = prune_old_snapshots(db, window_end)
                _last_snapshot_prune_at = window_end
                if deleted:
                    print(f"[scheduler] pruned {deleted} old risk snapshot(s)")
            except Exception as e:
                print(f"[scheduler] risk snapshot pruning failed: {e}")
    finally:
        db.close()
    # Set at the end of every completed cycle, regardless of whether any
    # individual device's analysis/baseline-update raised (those are
    # already caught and logged per-device above, inside the try) -- this
    # timestamp answers "is the LOOP itself still alive," not "did every
    # device succeed this cycle." A loop that's genuinely stopped/crashed
    # (analysis_loop's own except below) is what correctly leaves this
    # stale, which is the real signal routes/system.py's health check
    # depends on.
    _last_cycle_completed_at = datetime.now(timezone.utc)
    return analyzed


async def analysis_loop():
    """Runs forever until cancelled (main.py cancels it on shutdown). The
    first cycle fires after a short delay, not a full interval, so local
    testing/demoing doesn't mean waiting for the first cycle to see the
    first alert."""
    await asyncio.sleep(ANALYSIS_INITIAL_DELAY_SECONDS)
    while True:
        try:
            count = run_analysis_cycle()
            print(f"[scheduler] analysis cycle complete — {count} device(s) analyzed")
        except Exception as e:
            print(f"[scheduler] analysis cycle failed: {e}")
        await asyncio.sleep(ANALYSIS_INTERVAL_SECONDS)
