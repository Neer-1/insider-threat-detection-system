# FROM ai-agent-assignment: app/ai/preprocessing.py — copied direct

import numpy as np
import pandas as pd

# Features the model trains and predicts on — unchanged from the original.
# Every one of these keys already exists in agent_logic/feature_extractor.py's
# output dict under the same name, which is what makes this port a straight
# copy rather than a rewrite.
ML_FEATURES = [
    "failed_logins",
    "files_accessed",
    "sensitive_files",
    "usb_inserted",
    "login_hour",
    "session_duration",
    "privilege_escalation",
    "large_print_job",
    "access_velocity",
    "sensitive_ratio",
    "time_deviation",
    "baseline_deviation",
]


def log_to_vector(features: dict) -> np.ndarray:
    """Converts a features dict to a numpy array in the correct column order
    for the Isolation Forest model. One adaptation from the original:
    login_hour can be None here (no login event fell in the window) where
    the original always had a real hour with a default of 9 — handled
    explicitly below since dict.get()'s default only kicks in when the key
    is missing, not when its value is None."""
    login_hour = features.get("login_hour")
    if login_hour is None:
        login_hour = 9

    return np.array([[
        features.get("failed_logins", 0),
        features.get("files_accessed", 0),
        features.get("sensitive_files", 0),
        int(features.get("usb_inserted", False)),
        login_hour,
        features.get("session_duration", 60),
        int(features.get("privilege_escalation", False)),
        int(features.get("large_print_job", False)),
        features.get("access_velocity", 0.0),
        features.get("sensitive_ratio", 0.0),
        features.get("time_deviation", 0.0),
        features.get("baseline_deviation", 0.0),
    ]])


def generate_training_data(n_samples: int = 500) -> pd.DataFrame:
    """Generates synthetic training data covering normal, suspicious, and
    malicious behaviour patterns — copied direct from the original
    assignment's Isolation Forest generator, with one addition: a binary
    "label" column (0 = normal, 1 = suspicious or malicious). Isolation
    Forest is unsupervised and never used this; the CNN's sigmoid output is
    a supervised binary classifier and needs a real ground-truth label to
    train against. Both models still train on exactly the same rows —
    train_isolation_forest.py selects only ML_FEATURES via df[ML_FEATURES]
    and silently ignores the extra column, so nothing about the baseline's
    training changed.

    This is placeholder data, not real collected logs (see
    docs/dataset_notes.md). It exists so both models have something to
    train on before any company has enrolled real devices; once genuine
    Log/Feature history accumulates, this synthetic generator should be
    replaced with a real training set built from actual feature windows,
    and both models retrained on that instead."""
    rng = np.random.default_rng(42)
    rows = []

    normal_count = int(n_samples * 0.70)  # 70% normal
    suspicious_count = int(n_samples * 0.20)  # 20% suspicious
    malicious_count = n_samples - normal_count - suspicious_count  # 10% malicious

    for _ in range(normal_count):
        session = rng.integers(30, 480)
        files = rng.integers(1, 20)
        rows.append({
            "failed_logins": rng.integers(0, 2),
            "files_accessed": files,
            "sensitive_files": rng.integers(0, max(1, int(files * 0.2))),
            "usb_inserted": 0,
            "login_hour": rng.integers(8, 18),
            "session_duration": session,
            "privilege_escalation": 0,
            "large_print_job": 0,
            "access_velocity": round(files / max(session, 1), 3),
            "sensitive_ratio": round(rng.uniform(0, 0.2), 3),
            "time_deviation": round(rng.uniform(0, 1), 3),
            "baseline_deviation": round(rng.uniform(0, 1.5), 3),
            "label": 0,
        })

    for _ in range(suspicious_count):
        session = rng.integers(10, 120)
        files = rng.integers(15, 50)
        rows.append({
            "failed_logins": rng.integers(2, 6),
            "files_accessed": files,
            "sensitive_files": rng.integers(3, max(4, int(files * 0.5))),
            "usb_inserted": int(rng.random() > 0.6),
            "login_hour": rng.choice([*range(0, 7), *range(20, 24)]),
            "session_duration": session,
            "privilege_escalation": int(rng.random() > 0.7),
            "large_print_job": int(rng.random() > 0.6),
            "access_velocity": round(files / max(session, 1), 3),
            "sensitive_ratio": round(rng.uniform(0.3, 0.7), 3),
            "time_deviation": round(rng.uniform(2, 5), 3),
            "baseline_deviation": round(rng.uniform(2, 4), 3),
            "label": 1,
        })

    for _ in range(malicious_count):
        session = rng.integers(5, 60)
        files = rng.integers(40, 120)
        rows.append({
            "failed_logins": rng.integers(6, 20),
            "files_accessed": files,
            "sensitive_files": rng.integers(10, max(11, int(files * 0.8))),
            "usb_inserted": 1,
            "login_hour": rng.choice([*range(0, 5), *range(22, 24)]),
            "session_duration": session,
            "privilege_escalation": 1,
            "large_print_job": int(rng.random() > 0.4),
            "access_velocity": round(files / max(session, 1), 3),
            "sensitive_ratio": round(rng.uniform(0.6, 1.0), 3),
            "time_deviation": round(rng.uniform(4, 8), 3),
            "baseline_deviation": round(rng.uniform(3.5, 7), 3),
            "label": 1,
        })

    return pd.DataFrame(rows, columns=ML_FEATURES + ["label"])


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _interpolated_row(rng: np.random.Generator, severity: float) -> dict:
    """One window's features, drawn from ranges linearly interpolated
    between the normal profile's parameter ranges (severity=0) and the
    malicious profile's (severity=1) — the same ranges generate_training_data
    uses discretely, blended continuously here instead. Each call still
    independently samples within its own interpolated bounds, so a run of
    calls at the same severity produces real per-window variation, not a
    deterministic repeated value. Used by generate_training_sequences to
    build genuine escalation trajectories rather than switching between
    three fixed profiles."""
    failed_lo, failed_hi = round(_lerp(0, 6, severity)), round(_lerp(2, 20, severity))
    failed_logins = int(rng.integers(failed_lo, max(failed_hi, failed_lo + 1)))

    files_lo, files_hi = round(_lerp(1, 40, severity)), round(_lerp(20, 120, severity))
    files_accessed = int(rng.integers(files_lo, max(files_hi, files_lo + 1)))

    sensitive_frac_lo, sensitive_frac_hi = _lerp(0.0, 0.6, severity), _lerp(0.2, 1.0, severity)
    sensitive_files = int(round(files_accessed * rng.uniform(sensitive_frac_lo, sensitive_frac_hi)))

    usb_inserted = int(rng.random() < severity)

    if rng.random() < severity:
        login_hour = int(rng.choice([*range(0, 5), *range(22, 24)]))
    else:
        login_hour = int(rng.integers(8, 18))

    session_lo, session_hi = round(_lerp(30, 5, severity)), round(_lerp(480, 60, severity))
    session_duration = int(rng.integers(session_lo, max(session_hi, session_lo + 1)))

    privilege_escalation = int(rng.random() < severity)
    large_print_job = int(rng.random() < severity * 0.6)  # ~60% at severity 1, matching the malicious profile's own rate

    access_velocity = round(files_accessed / max(session_duration, 1), 3)
    sensitive_ratio = round(rng.uniform(sensitive_frac_lo, sensitive_frac_hi), 3)

    time_dev_lo, time_dev_hi = _lerp(0, 4, severity), _lerp(1, 8, severity)
    time_deviation = round(rng.uniform(time_dev_lo, time_dev_hi), 3)

    baseline_dev_lo, baseline_dev_hi = _lerp(0, 3.5, severity), _lerp(1.5, 7, severity)
    baseline_deviation = round(rng.uniform(baseline_dev_lo, baseline_dev_hi), 3)

    return {
        "failed_logins": failed_logins,
        "files_accessed": files_accessed,
        "sensitive_files": sensitive_files,
        "usb_inserted": usb_inserted,
        "login_hour": login_hour,
        "session_duration": session_duration,
        "privilege_escalation": privilege_escalation,
        "large_print_job": large_print_job,
        "access_velocity": access_velocity,
        "sensitive_ratio": sensitive_ratio,
        "time_deviation": time_deviation,
        "baseline_deviation": baseline_deviation,
    }


def generate_training_sequences(
    n_samples: int = 500, sequence_length: int = 6, label_noise: float = 0.15
) -> tuple[np.ndarray, np.ndarray]:
    """Generates synthetic sequences of `sequence_length` consecutive
    windows for the CNN's temporal input (see train_cnn.py) — NOT
    independent single windows like generate_training_data(). Each sequence
    is a fully independent synthetic device-timeline generated fresh, with
    zero data shared between sequences: no sliding window over a longer
    underlying timeline, so there's no cross-sequence leakage risk and a
    plain sequence-level stratified split/CV is safe without grouping.

    Four trajectory types, chosen so there's actual data to confirm the
    model uses the whole sequence rather than mostly reading the last
    window (the entire justification for this architecture over a flat
    per-window vector):

      - stable normal    (70%, 350) — severity 0.0 for all 6 windows.
                           Still independently re-sampled each window (real
                           per-window noise), just no trend. Label 0.
      - stable anomalous  (10%,  50) — severity 1.0 for all 6 windows — an
                           already-compromised device, consistently risky,
                           not currently escalating. Label 1.
      - gradual escalation(15%,  75) — severity ramps 0.0 -> 1.0 linearly
                           across the 6 windows (0, .2, .4, .6, .8, 1.0).
                           The trend across windows is the signal; any
                           single early window looks unremarkable on its
                           own. Label 1.
      - sudden spike       (5%,  25) — severity 0.0 for windows 0-4, then
                           1.0 only at the final window. Distinguishes
                           "model reads the whole sequence" from "model
                           mostly reads the last window" — a model that
                           ignores history would score this identically to
                           stable anomalous, but a model that's actually
                           using the sequence should see the abrupt jump as
                           a distinct pattern from a device that was always
                           risky. Label 1.

    Label is always "is the final window's state anomalous" — consistent
    with generate_training_data()'s single-window label semantics.

    label_noise (default 0.15): after all sequences are generated, this
    fraction is chosen at random and has its label flipped (0->1 or 1->0),
    independent of severity. This simulates real-world labelling
    uncertainty (an analyst mislabels an incident, a borderline case gets
    called either way) rather than corrupting the underlying feature
    values themselves — the sequence still looks exactly like whatever
    trajectory generated it; only the label disagrees with it some of the
    time. Without this, severity-0 and severity-1 endpoints are perfectly
    separable by construction, which produced a suspicious 100%-everything
    result in evaluation — see docs/dataset_notes.md.

    Returns (X, y): X shape (n_samples, sequence_length, len(ML_FEATURES))
    — time-major; train_cnn.py transposes to (batch, features, time) for
    Conv1d. y shape (n_samples,), values 0.0/1.0.
    """
    rng = np.random.default_rng(42)

    stable_normal_count = int(n_samples * 0.70)
    stable_anomalous_count = int(n_samples * 0.10)
    gradual_count = int(n_samples * 0.15)
    spike_count = n_samples - stable_normal_count - stable_anomalous_count - gradual_count

    sequences = []
    labels = []

    for _ in range(stable_normal_count):
        sequences.append([_interpolated_row(rng, 0.0) for _ in range(sequence_length)])
        labels.append(0)

    for _ in range(stable_anomalous_count):
        sequences.append([_interpolated_row(rng, 1.0) for _ in range(sequence_length)])
        labels.append(1)

    for _ in range(gradual_count):
        sequences.append([_interpolated_row(rng, i / (sequence_length - 1)) for i in range(sequence_length)])
        labels.append(1)

    for _ in range(spike_count):
        seq = [_interpolated_row(rng, 0.0) for _ in range(sequence_length - 1)]
        seq.append(_interpolated_row(rng, 1.0))
        sequences.append(seq)
        labels.append(1)

    X = np.array([[[row[feat] for feat in ML_FEATURES] for row in seq] for seq in sequences], dtype=np.float32)
    y = np.array(labels, dtype=np.float32)

    # Shuffle — otherwise sequences are grouped by trajectory type, which
    # would make batches (and CV folds, before their own stratification)
    # non-representative.
    order = rng.permutation(len(y))
    X, y = X[order], y[order]

    if label_noise > 0:
        n_flip = int(round(len(y) * label_noise))
        flip_idx = rng.choice(len(y), size=n_flip, replace=False)
        y[flip_idx] = 1.0 - y[flip_idx]

    return X, y
