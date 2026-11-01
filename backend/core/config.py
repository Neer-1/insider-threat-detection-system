# FROM ai-agent-assignment: app/core/config.py — copied direct (risk thresholds, role baselines already defined here), extended with company/device settings

from backend.core import env  # noqa: F401 -- loads .env before any os.getenv() below

import os
from math import exp
from pathlib import Path

from cryptography.fernet import Fernet

# ── Paths ──────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
AI_DIR = BASE_DIR / "backend" / "ai"

MODEL_PATH = AI_DIR / "isolation_forest.pkl"
DATASET_PATH = AI_DIR / "dataset.csv"

# ── Isolation Forest ──────────────────────────────────────────
IF_N_ESTIMATORS = 100
IF_CONTAMINATION = 0.2
IF_RANDOM_STATE = 42
TRAINING_SAMPLES = 500

# ── 1D CNN ──────────────────────────────────────────────────────
# New — the dissertation (section 4.5.2 / Figure 4.5) specifies the block
# sequence (conv -> relu -> max pool -> fully connected -> sigmoid) and the
# "shallow"/"lightweight" design intent, but doesn't pin down specific
# layer widths or training hyperparameters. These are this implementation's
# choices, kept here alongside the Isolation Forest's so both models'
# tunable parameters live in one place, per the dissertation's own
# requirement (3.4.8) that configuration stay external to system logic.
CNN_MODEL_PATH = AI_DIR / "cnn_model.pt"
# Number of consecutive feature windows the CNN convolves over (a temporal
# sequence, not a single window's 12 features treated as fake positions —
# see agent_logic/feature_extractor.py's extract_feature_sequence). 6 is a
# starting assumption, not a tuned value — chosen only as "enough steps for
# a kernel_size=3 conv to find a pattern across, short enough to stay
# shallow." If evaluation results don't justify it, this is the first thing
# to revisit/tune, not something to treat as load-bearing as-is.
CNN_SEQUENCE_LENGTH = 6
CNN_CONV_OUT_CHANNELS = 16
CNN_KERNEL_SIZE = 3
CNN_HIDDEN_UNITS = 8
CNN_DROPOUT = 0.3
CNN_EPOCHS = 30
CNN_BATCH_SIZE = 32
CNN_LEARNING_RATE = 0.001
# Seeds torch's global RNG at the start of every fit_model() call (weight
# init + DataLoader shuffle order) — without this, evaluate.py's CV folds
# and the deployment retrain vary metric-for-metric on every run, despite
# generate_training_sequences() already being fully seeded. Matches
# dissertation section 5.8's "fixed random seeds" reproducibility requirement.
CNN_RANDOM_SEED = 42

# ── Risk thresholds ────────────────────────────────────────────
# Copied direct — risk_scorer.py compares its 0-100 combined score
# against these unchanged. Also now what Device.current_risk_score (the
# persisted decaying score — see DECAY_TAU_SECONDS below) is bucketed
# against for risk_level, via risk_level_for_score() in this file.
RISK_CRITICAL = 75
RISK_HIGH = 50
RISK_MEDIUM = 25


def risk_level_for_score(score: float) -> str:
    """Single source of truth for score -> risk_level, shared between
    agent_logic/analyzer.py (persisting Device.current_risk_score) and
    routes/employees.py (reading it back for the grid/profile) so both
    can never compute a different band for the same number — the actual
    bug behind the last "grid says low, profile says high" report."""
    if score >= RISK_CRITICAL:
        return "critical"
    if score >= RISK_HIGH:
        return "high"
    if score >= RISK_MEDIUM:
        return "medium"
    return "low"


RISK_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ── Persisted device risk score (decay/rise model) ───────────────
# New — replaces "highest-severity unresolved alert" as the definition of
# a device's current risk (post-build bug report #2: that definition was a
# one-way ratchet, since nothing resolved alerts on its own). Device.
# current_risk_score is now the sum (capped at 100) of a set of PER-
# ANOMALY-TYPE decaying components (models/risk_components.py's
# DeviceRiskComponent, one row per (device, anomaly_type)) -- replacing a
# single global decay/rise pair applied to one aggregate number. A single
# global rate was too blunt: a failed-login streak should be forgiven
# within minutes of a successful login, while sustained privilege
# escalation shouldn't fade at the same speed just because a few clean
# minutes passed. Each component decays continuously toward 0 over real
# time and only rises toward a fresh window's severity for that type
# (never pulled down by a single calm reading -- only decay lowers it).
# All time constants are wall-clock based, not "per analysis cycle", so
# this behaves the same regardless of how often the scheduler runs
# (ANALYSIS_INTERVAL_SECONDS).
#
# ANOMALY_TYPE_TAU_SECONDS: {anomaly_type: (decay_tau, rise_tau)}, keyed by
# the same anomaly_type taxonomy anomaly_detector.py already emits for
# dedup. Types not listed here fall back to DEFAULT_DECAY_TAU_SECONDS /
# DEFAULT_RISE_TAU_SECONDS. None of these are measured against real usage
# data -- there isn't any yet (same caveat as ROLE_BASELINES below) --
# these are reasoned starting points, tunable here. Reasoning per type:
#
#   failed_logins (20min decay, 20s rise): decay is mostly a backstop --
#     the actual "forgive quickly on success" behaviour comes from
#     FAILED_LOGIN_STREAK below resetting to zero the moment a login
#     succeeds, which zeroes this type's severity on the very next cycle
#     regardless of decay. Kept short anyway so a streak that trails off
#     without an explicit success still fades fast.
#   privilege_escalation (24h decay, 15s rise): the most serious single
#     rule-based indicator in the taxonomy -- spikes to full severity
#     immediately, and stays visible long after it stops recurring so a
#     human has time to actually notice it.
#   department_mismatch (12h decay, 30s rise): out-of-scope sensitive
#     access is the core insider-threat scenario this whole system exists
#     for (see DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS below) -- deliberately
#     sticky.
#   unverified_install (12h decay, 30s rise): software installed from a
#     removable/internet-sourced origin without any other corroborating
#     signal -- same persistence tier as department_mismatch, same
#     reasoning (an unauthorised install is a standing risk, not a
#     momentary blip).
#   usb_insertion (6h decay, 30s rise): only fires on insertion FOLLOWED
#     by large transfer/install/execution now (see anomaly_detector.py) --
#     a real exfiltration vector, but a single episode isn't as inherently
#     severe as active privilege escalation.
#   large_download (6h decay, 30s rise): same tier as usb_insertion --
#     same category of vector (bulk content leaving/entering the machine),
#     just over a different channel.
#   large_print_job (8h decay, 30s rise): physical exfiltration risk,
#     similar persistence tier to the two above.
#   ml_signal (pseudo-type, not a rule check): the ML model's own window
#     score doesn't belong to any rule-based type, so it decays as its own
#     bucket rather than being folded into an arbitrary existing one or
#     dropped from the decay model entirely. Kept at the default rate --
#     it's a whole-window signal, same noisy/volume-like character as the
#     unlisted types below.
#
# high_file_access / access_velocity / sensitive_ratio / baseline_deviation
# / after_hours / time_deviation are deliberately left off this table
# (falling back to the default) -- these are volume/pattern-drift signals,
# noisier by nature, with no stronger basis for a different rate than the
# original global constant they're already using today.
ANOMALY_TYPE_TAU_SECONDS = {
    "failed_logins": (20 * 60, 20),
    "privilege_escalation": (24 * 3600, 15),
    "department_mismatch": (12 * 3600, 30),
    "unverified_install": (12 * 3600, 30),
    "usb_insertion": (6 * 3600, 30),
    "large_download": (6 * 3600, 30),
    "large_print_job": (8 * 3600, 30),
}
DEFAULT_DECAY_TAU_SECONDS = 4 * 3600
DEFAULT_RISE_TAU_SECONDS = 120


def tau_for_anomaly_type(anomaly_type: str) -> tuple[float, float]:
    """(decay_tau_seconds, rise_tau_seconds) for a given anomaly_type,
    falling back to the default pair for anything not explicitly tuned
    above (including "ml_signal")."""
    return ANOMALY_TYPE_TAU_SECONDS.get(anomaly_type, (DEFAULT_DECAY_TAU_SECONDS, DEFAULT_RISE_TAU_SECONDS))


# ── Decay-freeze near high/critical ───────────────────────────────────────
# Extends the same reasoning analyzer.py's stale-alert auto-resolve already
# applies one layer up ("high/critical alerts are never auto-resolved --
# those still need a human to actually look at them") down to the
# underlying decaying score itself: a device sitting at high/critical
# severity shouldn't quietly fade back to a clean state purely from the
# passage of time -- it should take an explicit admin action (dismissal,
# agent_logic/dismissal.py, which already correctly resets it) to come
# back down.
#
# REVISED AGAIN (was: a multiplicative slow-down -- decay_tau_multiplier(),
# a logistic curve of the device aggregate stretching each component's
# decay_tau, removed entirely below). That version was itself a fix for an
# even earlier per-component version (see git history) -- but real
# production data showed the multiplicative approach has its own separate,
# structural failure mode: base decay_tau varies enormously by anomaly type
# (failed_logins ~20min vs privilege_escalation ~24h, ANOMALY_TYPE_TAU_
# SECONDS above), so the SAME multiplier stretches a short-base-tau
# component's effective tau far less, in absolute terms, than a long-tau
# one -- and because a multiplier can only ever slow an exponential decay
# down, never stop it, the aggregate itself (the freeze's own basis) still
# genuinely drops over time. Once it drops even slightly below 100 the
# multiplier (a steep sigmoid) shrinks too, which speeds decay up further,
# which drops the aggregate more -- a self-reinforcing collapse, not a
# stable slowdown. Confirmed against a real device that peaked at exactly
# 100.0 and had collapsed to under 10 within about 19 hours (device_risk_
# snapshots: 100.0 -> 80.9 -> 65.1 -> 52.6 -> 43.0 -> ... -> 9.99, all
# strictly decreasing, no admin action taken) -- proof this wasn't a
# component-freeze-wiring regression (freeze_basis was, and still is,
# genuinely computed once per device per cycle and applied to every
# component -- verified directly against the running code first) but a
# structural property of "slower" never actually meaning "stopped."
#
# Fixed by replacing the multiplier with an explicit hard freeze instead:
# once a device's pre-cycle aggregate is at or above DECAY_FREEZE_
# THRESHOLD, decay is skipped ENTIRELY for every one of that device's
# components this cycle -- not slowed, not multiplied, literally zero
# change from the passage of time alone. Simpler than the sigmoid it
# replaces, deliberately: a single threshold and a boolean check, no width/
# amplitude tuning, and (unlike a multiplier) immune to the runaway-
# collapse dynamic above by construction, since there's no still-decaying
# number for the freeze basis to slip on. Only ever gates the DECAY branch
# (analyzer.py's _decay_and_rise) -- rise is completely untouched either
# way, so a genuine new anomaly (a fresh reading, or a different component
# growing) still climbs at full normal speed even on an already-frozen
# device, including all the way back up to 100. Coming back down from a
# frozen state still requires the existing dismiss/undo mechanism
# (agent_logic/dismissal.py), unchanged. 80 (not RISK_CRITICAL's 75) is a
# deliberately separate, higher threshold: freezing exactly at the
# high/critical boundary would make that boundary itself sticky in a way
# that could mask a device settling back into "high" from a worse
# "critical" peak; a small gap above it means the top of the range is what
# actually locks, not the entry point. Reasoned starting value, same "not
# measured against real usage data yet" caveat as every other constant in
# this section -- tunable here.
DECAY_FREEZE_THRESHOLD = 80.0


# ── Anomaly severity weights ──────────────────────────────────────
# The point-values each rule check contributes to a window's raw score.
# Used by BOTH risk_scorer.py (the window's own point-in-time Alert.
# risk_score/risk_level -- unchanged behaviour from before this file
# existed) AND anomaly_detector.py (tags each detected anomaly with its
# own "severity", which is what feeds that type's DeviceRiskComponent
# above) -- moved here from being hardcoded inline in risk_scorer.py so
# both files share one number instead of two copies that could drift
# apart. Values themselves are unchanged from the original risk_scorer.py
# weights, just named and centralised.
SEVERITY_FAILED_LOGINS_HIGH = 25
SEVERITY_FAILED_LOGINS_WARN = 10
SEVERITY_USB_ACTIVITY = 18
SEVERITY_PRIVILEGE_ESCALATION = 15
SEVERITY_LARGE_PRINT_JOB = 10
SEVERITY_AFTER_HOURS = 12
SEVERITY_DEPARTMENT_MISMATCH = 15
SEVERITY_FILES_ACCESSED_HIGH = 18
SEVERITY_FILES_ACCESSED_WARN = 8
SEVERITY_ACCESS_VELOCITY_CRITICAL = 15
SEVERITY_ACCESS_VELOCITY_HIGH = 8
SEVERITY_SENSITIVE_RATIO_HIGH = 15
SEVERITY_SENSITIVE_RATIO_WARN = 7
SEVERITY_BASELINE_DEVIATION_HIGH = 12
SEVERITY_BASELINE_DEVIATION_WARN = 6
# New — time_deviation was previously message-only in anomaly_detector.py
# and never actually contributed to risk_scorer.py's score (checked: the
# function never referenced it). Giving it a real weight is a small,
# deliberate scope addition alongside this change, not an oversight left
# unflagged -- consistent with treating "hours outside normal for this
# department" as a genuine signal like the others.
SEVERITY_TIME_DEVIATION = 8
# New — large downloads / unverified installs (see anomaly_detector.py
# and agent/collector.py for what these detect).
SEVERITY_LARGE_DOWNLOAD = 12
SEVERITY_UNVERIFIED_INSTALL = 15

# ── Anomaly rule thresholds ────────────────────────────────────
# Copied direct — anomaly_detector.py's rule checks unchanged.
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WARN = 2
FILES_ACCESSED_HIGH = 30
FILES_ACCESSED_WARN = 15
AFTER_HOURS_START = 22
AFTER_HOURS_END = 6
ACCESS_VELOCITY_HIGH = 5.0
ACCESS_VELOCITY_CRITICAL = 10.0
SENSITIVE_RATIO_WARN = 0.4
SENSITIVE_RATIO_HIGH = 0.7
BASELINE_DEVIATION_WARN = 2.0
BASELINE_DEVIATION_HIGH = 3.5

# New — the consecutive-failed-login STREAK (see feature_extractor.py's
# _consecutive_failed_logins) reuses these same two thresholds for its own
# severity bands, since the semantic meaning ("how many in a row") is the
# same as before, just correctly computed from actual login history now
# instead of a raw per-window count that could double-count the same
# failures across overlapping rolling windows. How far back to look when
# walking the device's authentication history for the current streak --
# comfortably above FAILED_LOGIN_THRESHOLD, not meant to be a hard cap on
# a real streak (a streak longer than this is still reported as "at least
# this many", which is already well past HIGH severity regardless).
FAILED_LOGIN_STREAK_LOOKBACK = 50

# ── USB: insertion-alone is not an anomaly ─────────────────────────
# Post-build refinement: plugging in a drive is routine behaviour and
# shouldn't score on its own. What actually matters is illicit USE
# following an insertion -- a large file transfer to/from the device, or
# an install/execution running from it -- within some window after the
# insertion. The insertion event itself is still logged (still shows up
# in GET /logs/significant as relevant context) but only contributes to
# the usb_insertion DeviceRiskComponent when followed by qualifying
# activity. See feature_extractor.py's _usb_followup_activity and agent/
# collector.py's device_name tagging (the correlation key between an
# insertion Log row and later file/process activity on that same device).
USB_ACTIVITY_WINDOW_MINUTES = 15
USB_LARGE_TRANSFER_BYTES = 10_000_000

# ── Downloads / installs: same exfiltration/introduction category as USB,
# previously not captured at all ─────────────────────────────────
# agent/collector.py already polls the Downloads folder (WATCHED_DIRS) --
# new files there are now tagged event_type="download" instead of the
# generic "file", and installer-pattern process launches (msiexec, *.msi,
# setup.exe, winget/choco invocations, pip/npm installs) are tagged
# event_type="install". Both get a best-effort "sourced from the internet
# or a removable device" signal (Windows Mark-of-the-Web / Zone.Identifier
# for downloaded files, or a removable-drive path for installs run
# straight off a USB device) -- see agent/collector.py's docstring for
# exactly what is and isn't reliably observable here; this is a heuristic,
# not a certainty, same caveat as everything else derived from a
# lightweight polling agent rather than real OS-level hooks.
#
# Upload detection was investigated and deliberately NOT implemented this
# round -- see the report accompanying this change. Attributing outbound
# network bytes to a specific file/upload action isn't reliably possible
# without packet inspection or browser integration, both out of scope for
# this agent's dependency budget (collector.py's own header comment: "not
# a full EDR"). A coarse "large outbound network volume" proxy was
# considered and rejected here for its high false-positive rate (video
# calls, cloud sync, and streaming would all trigger it) -- flagged as
# possible future work, not shipped as a silent, noisy heuristic.
LARGE_DOWNLOAD_FILE_SIZE_BYTES = 10_000_000
INSTALLER_PROCESS_NAME_KEYWORDS = ("setup", "install", "msiexec", ".msi")
INSTALLER_CMDLINE_KEYWORDS = ("pip install", "npm install", "winget install", "choco install")

# ── Significant-event / sensitive-content heuristics ─────────────
# Moved here from agent_logic/feature_extractor.py so routes/logs.py's
# significant-events view (GET /logs/significant) uses the exact same
# definition of "sensitive path" / "large print job" as feature extraction
# does, rather than a second copy that could quietly drift out of sync.
SENSITIVE_PATH_KEYWORDS = ("confidential", "payroll", "salary", "hr", "finance", "contract", "ssn", "passport")
LARGE_PRINT_FILE_SIZE_BYTES = 5_000_000

# ── Department-scoped sensitive access ─────────────────────────────
# NEW STATUS: seed data only now -- see the note on ROLE_BASELINES above.
# Replaces ROLE_BASELINES' old flat "sensitive_access_allowed" boolean
# (all-or-nothing per department) with a per-department allow-list of
# WHICH of SENSITIVE_PATH_KEYWORDS (above) are normal for that
# department -- an HR employee touching payroll files and an engineer
# touching the same file are no longer treated identically just because
# both paths contain a sensitive keyword. Every pattern below is
# deliberately drawn from SENSITIVE_PATH_KEYWORDS itself, not a new
# vocabulary -- this scopes WHICH sensitive keywords are in-bounds per
# department, it doesn't introduce new "is this sensitive at all"
# triggers (those stay global, for sensitive_ratio/sensitive_files across
# every department equally). Day-one granularity, deliberately: a keyword
# allow-list in the same style as SENSITIVE_PATH_KEYWORDS itself, not a
# real ACL/path-prefix system tied to actual filesystem permissions --
# that would be the real, "grown-up" version of this and is future work,
# same as every other synthetic/placeholder threshold in this file. A
# department with no entry (or an empty tuple) has no legitimate access
# to ANY sensitive content, matching the old boolean's "False" case.
#
# One deliberate change from the old boolean, worth flagging explicitly:
# "it" used to be unrestricted (sensitive_access_allowed=True). Scoped
# here instead -- an IT admin browsing payroll/HR files they have
# technical access to but no business reason to view is exactly the
# insider-threat pattern this system exists to catch, not something that
# should be waved through just because IT has broad system access.
#
# executive/compliance are a deliberate exception to the "narrow, per-
# department allow-list" design above: both get the FULL
# SENSITIVE_PATH_KEYWORDS set, not a scoped subset, because legitimate
# leadership oversight (executive) and legitimate audit access
# (compliance) genuinely span every other department's sensitive content
# by the nature of the role -- there's no narrower slice of
# SENSITIVE_PATH_KEYWORDS that would be "in scope" for a CEO or an auditor
# the way "payroll" is for Finance specifically. Real, named consequence,
# not silently absorbed: department_mismatch (anomaly_detector.py) can
# never fire for these two departments, since nothing is ever
# out-of-scope for them -- see docs/known_limitations.md's "Full sensitive
# access for executive/compliance" entry for the full tradeoff writeup.
DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS = {
    "finance": ("payroll", "salary", "finance", "contract"),
    "hr": ("hr", "salary", "payroll", "contract", "ssn", "passport"),
    "it": ("confidential",),
    "sales": ("contract",),
    "engineering": (),
    "operations": ("contract",),
    "executive": SENSITIVE_PATH_KEYWORDS,
    "compliance": SENSITIVE_PATH_KEYWORDS,
}

# ── Role baselines ──────────────────────────────────────────────
# NEW STATUS (departments feature): this dict, DEPARTMENT_ALLOWED_
# SENSITIVE_PATTERNS above, and POLICY_DEPARTMENT_KEYWORDS further below
# are no longer read at request/analysis time at all -- departments are
# now a per-company, admin-managed table (models/department.py), and
# every runtime consumer goes through agent_logic/departments.py's shared
# lookup helpers instead. These three dicts live on ONLY as the SEED DATA
# every company's starting 8-department set is copied from -- once, at
# POST /company/register for a new company, and once per already-existing
# company via database/init_db.py's _seed_default_departments backfill.
# Kept exactly as they were (not deleted) specifically so that seed data
# has a single, already-reasoned source rather than being invented fresh.
#
# behavioural_profiler.py looks a device's department up via
# DeviceMetadata, with the same "engineering" fallback name as before when
# nothing is set -- unchanged by this feature; a department by that name
# not existing for a given company (soft-removed, or simply never seeded)
# is handled by agent_logic/departments.py's own generic-floor fallback,
# not by this dict needing an "engineering" entry to exist.
ROLE_BASELINES = {
    "finance": {
        "avg_files_per_day": 12,
        "normal_hours": (8, 18),
        "avg_failed_logins": 0.5,
    },
    "engineering": {
        "avg_files_per_day": 25,
        "normal_hours": (7, 20),
        "avg_failed_logins": 1.0,
    },
    "hr": {
        "avg_files_per_day": 18,
        "normal_hours": (8, 17),
        "avg_failed_logins": 0.3,
    },
    "it": {
        "avg_files_per_day": 40,
        "normal_hours": (7, 22),
        "avg_failed_logins": 2.0,
    },
    "sales": {
        "avg_files_per_day": 15,
        "normal_hours": (8, 19),
        "avg_failed_logins": 0.5,
    },
    # Added for the admin-accounts/expanded-department pass -- same
    # reasoned-placeholder caveat as every other entry above, not measured
    # against real usage.
    "operations": {
        "avg_files_per_day": 15,
        "normal_hours": (8, 18),
        "avg_failed_logins": 0.5,
    },
    "executive": {
        # Lower routine file volume (less hands-on-keyboard file work,
        # more oversight/meetings) but a wider, less predictable working-
        # hours window than any other department -- irregular schedules
        # are the norm for this role, not an anomaly.
        "avg_files_per_day": 10,
        "normal_hours": (7, 21),
        "avg_failed_logins": 1.0,
    },
    "compliance": {
        # Reviewing many other people's records is the job, so file
        # volume sits at the high end (similar tier to IT); hours stay
        # structured/predictable like HR/finance, and failed-login
        # tolerance stays low -- a security-conscious role by nature.
        "avg_files_per_day": 20,
        "normal_hours": (8, 17),
        "avg_failed_logins": 0.3,
    },
}

# NEW — the static floor a brand-new, admin-created department is seeded
# with (routes/company.py's create_department) -- deliberately a single
# generic value, not a guessed department-specific number the admin never
# provided and litds has no basis to invent. Not arbitrary: identical to
# ROLE_BASELINES["operations"] above, the one entry among the original 8
# that already read as "the unremarkable generic default" rather than
# tuned to a specific role's known behavior pattern. Also the ultimate
# runtime fallback (agent_logic/departments.py's baseline_floor_for) for
# any department name that doesn't resolve to a real, active row --
# replacing the old ROLE_BASELINES.get(department, ROLE_BASELINES
# ["engineering"]) pattern, since "engineering" specifically is no longer
# guaranteed to exist once departments are admin-deletable.
DEFAULT_DEPARTMENT_BASELINE = {
    "avg_files_per_day": 15,
    "normal_hours": (8, 18),
    "avg_failed_logins": 0.5,
}

# ── Learned behavioral baselines (agent_logic/baseline_learning.py) ──────
# Replaces ROLE_BASELINES above as the actual comparison point feature_
# extractor.py/behavioural_profiler.py use, once enough real history
# exists. ROLE_BASELINES itself is untouched and stays the ultimate static
# floor both the department- and device-level learned baselines blend
# toward when there isn't (yet) enough real data -- see get_effective_
# baseline()'s docstring for the exact three-tier blend. All four values
# below are reasoned starting points, not measured against real usage
# data -- same caveat as ROLE_BASELINES itself, and everything else in
# this file that hasn't been validated against a real deployment yet.

# How often a device's/department's learned baseline gets a new daily
# sample folded in -- deliberately NOT the 10-second real-time detection
# cadence. ANALYSIS_WINDOW_MINUTES is a ROLLING window re-evaluated every
# ANALYSIS_INTERVAL_SECONDS, so the same ~15 minutes of real activity
# would otherwise get folded into a running statistic dozens of times
# before it ages out of the window, making "sample_count" meaningless as
# a proxy for days of real history. A rolling 24h check (not calendar-
# day-aligned -- avoids timezone complexity entirely, consistent with
# this whole system storing/comparing purely in UTC) keeps one sample
# genuinely meaning one day.
BASELINE_ROLLUP_INTERVAL_HOURS = 24

# EWMA half-life, in units of DAILY SAMPLES (not wall-clock time) -- since
# BASELINE_ROLLUP_INTERVAL_HOURS already enforces "one sample ~= one real
# day," a fixed per-sample alpha (not a separate dt-based decay) is the
# correct and simpler match, unlike DeviceRiskComponent's continuous wall-
# clock decay. Chosen (not cumulative/Welford's) specifically so a
# genuine multi-month shift in someone's role or work pattern is reflected
# rather than permanently diluted by their earliest history -- ~2 months
# is long enough that day-to-day noise doesn't overly perturb the
# baseline, short enough to adapt within a reasonable window.
BASELINE_EWMA_HALF_LIFE_DAYS = 60

# Trust ramps (personal_weight = min(1, sample_count / this)), NOT a hard
# cutover -- a hard switch would mean "what counts as anomalous" visibly
# jumps the moment a threshold is crossed. Department trust is a lower bar
# per unit of data than personal trust: department samples pool across
# every device in it, so even one device's worth of days there is exactly
# as strong a statistical basis as MIN_DAYS_FOR_PERSONAL_TRUST already
# requires for personal trust, and it only gets faster with more devices.
MIN_DAYS_FOR_PERSONAL_TRUST = 14
MIN_SAMPLES_FOR_DEPARTMENT_TRUST = 30

# How many learned standard deviations wide the derived "normal_hours"
# range is, once login-hour data has been learned -- 2 is a reasoned,
# unvalidated choice like the rest of this section. Known, deliberately
# unhandled simplification: login hour is treated as a plain linear
# quantity, not a circular one, so this would badly misrepresent a
# genuine night-shift worker (whose real "normal" straddles midnight) --
# flagged rather than silently mishandled, not fixed here.
BASELINE_HOURS_SPREAD_STD_MULTIPLIER = 2

# Fallback for get_expected_max_delta() (baseline_learning.py) when
# neither a device nor a department has any risk_delta history yet --
# there's no natural per-role static default to reason a "typical daily
# max risk-score jump" from the way ROLE_BASILINES could for file counts,
# so this is one single reasoned global floor rather than a per-department
# table, same "reasoned starting point, not measured" caveat as
# everything else in this section.
DEFAULT_EXPECTED_MAX_DELTA = 20.0

# ── AI Reasoning Core / notification trigger extensions ───────────
# Three trigger types (agent_logic/analyzer.py's reasoning-trigger block),
# all funneling into the same enqueue_reasoning_trigger() call site and
# therefore the same notification path (notifications/mailer.py) with no
# changes needed there -- only WHICH condition decides to enqueue differs.
#
# 1. Sharp/delta-based increase into MEDIUM specifically -- a deliberate,
#    narrow exception to the medium-band exclusion below (REASONING_
#    TRIGGER_MIN_LEVEL stays "high" for the ordinary edge-trigger; this is
#    a separate, additional condition, not a change to that floor).
#    SHARP_DELTA_MIN_ABSOLUTE is an always-enforced floor regardless of
#    how statistically "unusual" a tiny jump looks for a very quiet
#    device -- a jump has to be substantively large in absolute terms
#    too, not just relatively surprising. SHARP_DELTA_ZSCORE_MULTIPLIER
#    is how many learned standard deviations above this device/
#    department's own typical daily max jump (get_expected_max_delta())
#    counts as unusual, on top of that floor.
SHARP_DELTA_MIN_ABSOLUTE = 15.0
SHARP_DELTA_ZSCORE_MULTIPLIER = 2.5

# 3. Continued escalation while already sustained at high/critical (no
#    rank transition, so the ordinary edge-trigger doesn't fire) -- only
#    re-triggers on a genuine further climb since the LAST trigger of any
#    kind for this device (Device.last_reasoning_trigger_score, updated
#    whichever of the three conditions fires), not merely because time
#    has passed at the same level. The cooldown is a backstop against a
#    pathological fast-oscillation edge case, not the primary gate --
#    the score-increase requirement is.
ESCALATION_MIN_SCORE_INCREASE = 15.0
ESCALATION_MIN_COOLDOWN_SECONDS = 300

# ── WebSocket (live dashboard feed) ──────────────────────────────
WS_HOST = "0.0.0.0"
WS_PORT = 8000

# ── Detection scheduler ────────────────────────────────────────
# New — the packaging phase found that nothing in the running server ever
# called agent_logic.analyzer.analyze_device_window(): routes/logs.py only
# stores Log rows, it never triggers detection. backend/scheduler.py is the
# fix — a background task, started in main.py's lifespan, that wakes up
# on a fixed cadence and analyzes every approved device's most recent
# activity.
#
# Two separate knobs, deliberately not the same number (post-build bug
# report: "log collection every 15 mins is too long, I want real-time
# updates"):
#
# ANALYSIS_INTERVAL_SECONDS — how often the scheduler wakes up and runs a
# cycle. This is the "real-time" knob: dropped from the original 15-minute
# cadence to 10 seconds, so a new anomaly shows up on the dashboard within
# one cycle of the triggering activity actually reaching the server (which
# was already near-instant — routes/logs.py stores Log rows the moment
# /logs/ingest is called; the 15-minute lag users were actually seeing was
# entirely in when analysis NEXT ran, not in log storage).
#
# ANALYSIS_WINDOW_MINUTES — how much trailing history each analysis cycle
# looks at (a rolling [now - this, now) window), independent of how often
# that window gets re-evaluated. This is deliberately NOT also dropped to
# 10 seconds: it's the denominator behind every behavioural comparison in
# feature_extractor.py (files-accessed vs. avg_files_per_day, sensitive-
# access ratios, baseline_deviation's Poisson-variance math, the CNN's
# 6-window temporal sequence). A 10-second-wide window makes
# expected_files shrink to a fraction of a file, so baseline_deviation
# blows past its "high" threshold on almost any single file touch — i.e.
# collapsing this value to match the polling cadence would make ordinary
# activity look anomalous constantly, reintroducing (and worsening) the
# false-escalation problem just fixed in analyzer.py. Kept at a size
# that's still statistically meaningful; only the cadence at which that
# window gets *re-checked* became real-time.
#
# Alerts already deduplicate/refresh in place (agent_logic/analyzer.py)
# rather than stacking a new row every cycle, which is what makes running
# this every 10 seconds instead of every 15 minutes safe to do at all —
# without that fix, this cadence change alone would have flooded the
# alerts table.
ANALYSIS_INTERVAL_SECONDS = 10
ANALYSIS_WINDOW_MINUTES = 15
# Short delay before the FIRST cycle after startup, not a full interval —
# otherwise local testing/demoing would mean waiting the full interval to
# see the first alert appear.
ANALYSIS_INITIAL_DELAY_SECONDS = 5

# NEW — Device.connection_status has no explicit "going offline" signal to
# react to: the agent has no listening port (push-only by design,
# onboarding_flow.md), so the server can only ever INFER a device has gone
# offline from staleness, not be told. connection_status is flipped to
# "online" on every real check-in (routes/device.py's enroll_device,
# routes/logs.py's ingest_logs) — this is the only way it ever gets marked
# offline again, checked alongside the normal analysis cycle (scheduler.py)
# since that already iterates every approved device on a fixed cadence.
#
# Originally 60s, tightened to 40s once the agent started sending an
# explicit heartbeat (event_type="heartbeat", agent/collector.py's
# build_heartbeat_event) on any cycle with no real activity to report —
# before that, this had to stay loose enough to tolerate a real device
# legitimately going quiet for a while (ordinary idle periods produce no
# behavioral events at all, which used to be indistinguishable from a
# genuine disconnect without a regular signal to check against). With a
# guaranteed check-in every cycle regardless of behavior, 40s = the agent's
# own worst-case max send interval (agent/config.py clamps
# SEND_INTERVAL_SECONDS to [10, 30]) plus one full ANALYSIS_INTERVAL_
# SECONDS (10s) of this check's own detection granularity — covers a
# single check-in landing at the slowest configured interval, right before
# this check happens to run, with no room to spare for a SECOND
# consecutive missed check-in at that same worst-case interval. That's a
# deliberate, disclosed tradeoff, not an oversight: a device configured at
# the loose end of the interval range that also drops one single request
# (a transient network blip) could flicker offline for a few seconds
# before its next successful heartbeat brings it back — accepted as
# reasonable given this now has a genuine regular signal to key off,
# rather than tuned/measured against a real deployment's actual network
# reliability. Revisit if that flicker turns out to matter in practice.
OFFLINE_THRESHOLD_SECONDS = 40

# NEW — Overview page's system-health strip (dashboard/app.js's
# refreshOverviewExtras). How stale the scheduler's own last-completed-
# cycle timestamp (backend/scheduler.py's get_last_cycle_at) can get
# before the health strip reports it as stalled rather than running
# normally. Same reasoning shape as OFFLINE_THRESHOLD_SECONDS above: a
# real cycle completes every ANALYSIS_INTERVAL_SECONDS (10s) when the
# loop is alive at all, so this only needs margin for one slow cycle, not
# a guess -- 3x the interval.
SCHEDULER_STALL_THRESHOLD_SECONDS = ANALYSIS_INTERVAL_SECONDS * 3

# NEW — Live Employee Monitoring card's 24h risk sparkline (models/
# risk_snapshot.py's DeviceRiskSnapshot, agent_logic/risk_snapshots.py).
# 15 minutes -- coarser than the real-time 10s detection cadence on
# purpose (a snapshot every scheduler cycle would grow unboundedly fast
# for no benefit a sparkline actually needs): ~96 points over 24h reads as
# a genuinely smooth trend line without meaningfully increasing storage
# over a coarser interval at this table's scale (well under 100 rows per
# device at steady state).
RISK_SNAPSHOT_INTERVAL_MINUTES = 15
# 24h display window + a 1h buffer -- a snapshot just past the 24h mark
# shouldn't vanish mid-poll only to reappear if the retention cutoff were
# exactly 24h; the extra hour of slack is cheap (a handful of rows) and
# means the sparkline's own 24h query never has to worry about a row
# disappearing out from under it between two consecutive polls.
RISK_SNAPSHOT_RETENTION_HOURS = 25
# How often the pruning DELETE actually runs -- checked every scheduler
# cycle (cheap, an in-memory timestamp comparison) but only executed
# roughly this often, same gating pattern as scheduler.py's own per-device
# baseline rollup and this file's BASELINE_ROLLUP_INTERVAL_HOURS.
RISK_SNAPSHOT_PRUNE_INTERVAL_HOURS = 1

# NEW — Overview page's "Alerts Over Time"/"Top Trigger Categories"
# charts (routes/alerts.py's /alerts/stats/daily, /alerts/stats/by-type).
# Both charts deliberately share this one window so they describe the
# same period, not two independently-chosen ranges that could confuse a
# reader comparing them side by side.
ALERTS_TREND_WINDOW_DAYS = 7

# ── AI Reasoning Core (LLM-based, LM Studio + Gemma) ──────────────
# New — a separate layer on top of the deterministic pipeline above, not a
# replacement for any part of it. The CNN/Isolation Forest/rule-based
# anomaly detector/decay-aggregation system keep running unchanged, on
# every cycle, for every device; Device.current_risk_score stays the only
# thing driving the dashboard displays and the dissertation's quantitative
# evaluation (accuracy/precision/recall/ROC-AUC). This layer only ever
# reads what that pipeline already produced and reasons over it in plain
# language -- it never recomputes a risk score, and (backend/reasoning/
# actions.py) it never executes anything on its own; every action requires
# an explicit admin decision (routes/reasoning.py).
#
# Architecture is informed by Audit-LLM (Song et al., 2024)'s multi-agent
# framework for insider-threat auditing -- specifically its Evidence-based
# Multi-agent Debate (EMAD) pattern for cross-examining a judgment against
# evidence before presenting it, and the broader literature's convention
# of keeping LLM-based detection/explanation tools out of the response-
# execution path entirely (detection and explanation, not autonomous
# containment). What's implemented here is a bounded, two-pass version of
# that idea (backend/reasoning/core.py's run_two_pass_judgment), not full
# open-ended multi-round debate -- at ~10s per LLM pass on the hardware
# this was built and tested against (measured directly against the LM
# Studio instance below), an open-ended debate loop would make this
# unusably slow and directly contradict the project's lightweight-SME
# framing. Two passes (an initial judgment, then one evidence-grounded
# critic pass that can confirm or correct it) was chosen as the point that
# still gets real value from cross-examination without an unbounded cost.

# LM Studio's OpenAI-compatible local server. Confirmed reachable and
# serving this exact model via GET {base}/models before anything here was
# built. If a different Gemma size is swapped in later, update
# REASONING_MODEL -- nothing else needs to change.
LM_STUDIO_BASE_URL = "http://localhost:1234/v1"
REASONING_MODEL = "google/gemma-4-e2b"

# This model (as LM Studio serves it) emits a separate chain-of-thought
# "reasoning_content" block before its actual answer -- confirmed directly:
# a max_tokens=10 test call spent the entire budget on reasoning and
# returned empty content; max_tokens=900 completed naturally
# (finish_reason="stop") after ~550 reasoning tokens + ~120 content
# tokens, in ~10.5 seconds wall-clock. REASONING_MAX_TOKENS is set well
# above that observed ceiling so a real judgment doesn't get cut off mid-
# thought the way the first test call was -- this is a hardcoded
# assumption about this specific model's behaviour, not a guess; if the
# model changes, re-verify this budget is still enough rather than
# assuming it still is.
REASONING_MAX_TOKENS = 1200
REASONING_TEMPERATURE = 0.2
# Generous but bounded -- LM Studio unreachable/hung should fail this one
# judgment quickly (backend/reasoning/client.py catches this and returns
# None, which the caller treats as "skip, leave the deterministic alert
# as-is"), not hang the reasoning worker indefinitely.
REASONING_TIMEOUT_SECONDS = 45

# Trigger condition: an UPWARD transition into high or critical, not a
# level check re-evaluated every cycle -- a device that simply STAYS at
# "high" for the next twenty 10-second cycles does not re-trigger, only
# newly reaching high, or escalating high -> critical, does. medium is
# deliberately excluded: it's reached too easily by a single moderate
# signal (observed repeatedly during earlier testing rounds) to justify a
# ~20-second two-pass LLM round trip every time. See agent_logic/
# analyzer.py's _reasoning_trigger_fires -- compares this cycle's new
# level against the level implied by current_risk_score's value from
# BEFORE this cycle updated it.
REASONING_TRIGGER_MIN_LEVEL = "high"

# Serial queue backlog warning -- backend/reasoning/worker.py logs a line
# the moment the in-memory trigger queue's depth reaches this many pending
# items (and again if it drains and re-crosses later), rather than lagging
# silently. LM Studio serves one model instance; judgments are processed
# one at a time, so several devices crossing into high/critical around the
# same moment queues up rather than running in parallel. 3 is a small
# number deliberately -- at real SME scale (a handful of devices) this
# should be rare, so it's meant to be a real signal, not routine noise.
REASONING_QUEUE_BACKLOG_WARN_THRESHOLD = 3

# ── Company policy/bylaws document (Reasoning Core context) ───────
# Optional, owner-uploaded PDF (routes/company.py's /company/policy-
# document), converted once at upload time to Markdown and stored in
# CompanyPolicyDocument -- see reasoning/policy_document.py for the
# conversion/section-splitting/relevance-selection logic this all feeds.
# Confirmed against LM Studio directly (GET /api/v0/models) that the
# loaded model's context window is 131072 tokens -- large enough that a
# realistic bylaws document would actually fit whole. The constants below
# exist anyway for latency and relevance reasons, not because the
# document literally wouldn't fit: injecting an entire unrelated document
# into every single judgment (most of which have nothing to do with
# policy at all) would measurably slow down every judgment to serve the
# minority that need policy grounding, and dilutes the model's attention
# with irrelevant sections it might latch onto. Simple keyword-count
# section selection instead -- no embeddings, no vector search.
POLICY_MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20MB -- a plain size sanity cap at upload, independent of the context-window question
# Below this average extracted characters per page, treat the PDF as a
# scanned/image document with no real extractable text rather than
# silently storing near-nothing -- no OCR support here.
POLICY_MIN_TEXT_CHARS_PER_PAGE = 20
# Hard backstop on the combined injected excerpt regardless of how large
# the matched section(s) actually are -- ~3000 tokens at a rough 4
# chars/token, generous for one or two real bylaws sections.
POLICY_EXCERPT_MAX_CHARS = 12000

# Hand-authored keyword sets per anomaly_type (agent_logic/anomaly_
# detector.py's taxonomy) -- reasoned starting points, not measured
# against real bylaws documents, same caveat as ROLE_BASELINES/
# ANOMALY_TYPE_TAU_SECONDS above. Empty list = deliberately no keywords
# for a type too generic to usefully match a specific policy section on
# its own (baseline_deviation, ml_signal) -- better to match nothing than
# force in an arbitrary section.
POLICY_ANOMALY_KEYWORDS = {
    "usb_insertion": ["usb", "removable media", "external device", "flash drive", "portable storage"],
    "large_download": ["data transfer", "download", "external transfer", "file transfer"],
    "large_print_job": ["printing", "physical document", "hard copy", "print"],
    "unverified_install": ["software installation", "unauthorized software", "approved software", "install"],
    "privilege_escalation": ["privilege", "administrator access", "elevated access", "permission"],
    "department_mismatch": ["access control", "need to know", "authorized access", "confidential"],
    "failed_logins": ["login", "password", "authentication"],
    "sensitive_ratio": ["sensitive information", "confidential information", "sensitive data"],
    "high_file_access": ["file access", "document access"],
    "access_velocity": ["bulk access", "mass access"],
    "after_hours": ["after hours", "outside working hours", "off-hours"],
    "time_deviation": ["working hours", "schedule"],
    "baseline_deviation": [],
    "ml_signal": [],
}

# NEW STATUS: seed data only now -- see the note on ROLE_BASELINES above.
# Keyed by ROLE_BASELINES' own department keys. Deliberately NOT the bare
# department string itself for short ones like "it" -- a literal
# word-boundary match on "it" would hit the ordinary English word
# constantly (confirmed by inspection: "it is required that..." appears
# in virtually any policy prose) and turn into pure noise. More specific
# phrases per department instead.
POLICY_DEPARTMENT_KEYWORDS = {
    "finance": ["finance", "financial", "accounting", "payroll"],
    "engineering": ["engineering", "development", "source code", "technical"],
    "hr": ["human resources", "personnel"],
    "it": ["information technology", "systems administration", "network administration"],
    "sales": ["sales", "customer data", "client"],
    "operations": ["operations"],
    "executive": ["executive", "leadership", "management"],
    "compliance": ["compliance", "audit", "regulatory"],
}

# Fixed recommendation vocabulary -- what the Reasoning Core is allowed to
# recommend, and what routes/reasoning.py's accept/override flow is
# allowed to execute. Deliberately NOT free-form actions: a fixed,
# closed set the rest of the system (and the admin) can reason about,
# same principle as anomaly_detector.py's anomaly_type taxonomy.
REASONING_RECOMMENDATIONS = ("dismiss", "monitor", "alert_only", "alert_restrict", "escalate_hr")

# What accepting/overriding-to each recommendation actually does, via the
# existing Response model (models/responses.py) -- a NEW mapping, kept
# deliberately separate from response_engine.py's own risk-level-keyed
# action table rather than forced onto it: that table answers "what should
# happen for a critical/high/medium/low window", a different question
# than "what does this specific 5-value recommendation mean". dismiss maps
# to an empty list (no Response rows -- the judgment's own status still
# records that it was dismissed, see models/reasoning.py).
#
# escalate_hr is a deliberate scoping boundary, not an oversight: there is
# no HR-system integration in this project, so it resolves to a single
# notification-only action string with no automated system action behind
# it -- surfaced to the admin as a recommendation to act on manually, the
# same as every other Response row in this codebase already is (save_
# responses()'s own docstring: "there's no real actuator... wired up yet
# to ever mark one 'completed'"). Building real HR-system integration is
# out of scope here.
REASONING_ACTION_MAP = {
    "dismiss": [],
    "monitor": [
        "Enable 24-hour enhanced monitoring",
        "Flag session for manual review",
    ],
    "alert_only": [
        "Raise security alert to team lead",
        "Enable enhanced logging for this user",
    ],
    "alert_restrict": [
        "Lock active session",
        "Raise security alert to team lead",
        "Restrict account privileges pending review",
    ],
    "escalate_hr": [
        "Escalate to HR for review — notification only, no automated system action",
    ],
}

# Human-readable labels for the same five REASONING_RECOMMENDATIONS values
# -- backend-side single source (backend/reports/alert_report.py), kept
# alongside REASONING_ACTION_MAP since both key off the identical fixed
# vocabulary. dashboard/app.js keeps its own copy (REASONING_LABELS) since
# it's a separate runtime with no shared import path to this file -- if
# the wording here ever changes, update both.
REASONING_RECOMMENDATION_LABELS = {
    "dismiss": "Dismiss (false positive)",
    "monitor": "Monitor",
    "alert_only": "Alert only",
    "alert_restrict": "Alert + restrict",
    "escalate_hr": "Escalate to HR",
}

# ── Authentication secrets ──────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be configured with at least 32 characters")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # one admin working day

# Used by backend/core/secrets.py for encrypting SMTP passwords at rest.
SMTP_ENCRYPTION_KEY = os.getenv("SMTP_ENCRYPTION_KEY")
if not SMTP_ENCRYPTION_KEY:
    raise RuntimeError("SMTP_ENCRYPTION_KEY must be configured")
try:
    Fernet(SMTP_ENCRYPTION_KEY.encode("ascii"))
except (UnicodeEncodeError, ValueError) as error:
    raise RuntimeError("SMTP_ENCRYPTION_KEY must be a valid Fernet key") from error

# Fallback SMTP config, used ONLY when a company has no SmtpConfig row of
# its own in the database -- explicitly local/dev-only, never silently
# preferred over a company's real configured credentials (see
# notifications/smtp_resolver.py, which logs which of the two was
# actually used on every send). All four must be set for the fallback to
# be considered usable at all; a partial set is treated as "no fallback,"
# not an attempt to send with missing fields.
SMTP_FALLBACK_HOST = os.getenv("SMTP_FALLBACK_HOST")
SMTP_FALLBACK_PORT = os.getenv("SMTP_FALLBACK_PORT")
SMTP_FALLBACK_USERNAME = os.getenv("SMTP_FALLBACK_USERNAME")
SMTP_FALLBACK_PASSWORD = os.getenv("SMTP_FALLBACK_PASSWORD")
