# FROM ai-agent-assignment: app/ai/predict.py — copied + renamed to pair with the file above

from typing import Callable

# Import order matters on this platform: if a caller ends up importing this
# module before predict_cnn.py in the same process (e.g. a future main.py
# wiring up both models' score_fn), loading sklearn's DLLs before torch's
# crashes with an OSError at torch import time — reproduced directly while
# closing out this phase. Forcing torch to load first here, even though
# nothing in this file uses it, makes this module safe regardless of
# whatever order a caller happens to import the two predict_* modules in.
import torch  # noqa: F401

import numpy as np

from backend.ai.preprocessing import log_to_vector
from backend.ai.train_isolation_forest import load_or_train


def predict(bundle: dict, feature_sequence: list[dict]) -> tuple[float, float]:
    """Runs the Isolation Forest on a single feature vector — the input is
    now the same list[dict] the CNN's predict() takes (see predict_cnn.py)
    rather than one dict, so both models share one score_fn interface
    (agent_logic/analyzer.py). Isolation Forest has no temporal awareness:
    it only ever looks at feature_sequence[-1], the current window, and
    ignores everything before it.

    bundle is a plain dict {"model", "score_min", "score_max"} — see
    train_isolation_forest.py for why that's a dict rather than a custom
    class.

    Returns:
        anomaly_score — float 0.0 to 1.0 (higher = more anomalous)
        confidence    — float 0.0 to 1.0 (model certainty)
    """
    features = feature_sequence[-1]
    X = log_to_vector(features)

    # score_samples returns negative values — more negative = more anomalous
    raw_score = bundle["model"].score_samples(X)[0]

    # Min-max scaled against THIS model's own training-time score range
    # (bundle["score_min"/"score_max"] — fit alongside the model, see
    # train_isolation_forest.fit_calibrated_model), then inverted so
    # higher = more anomalous, matching score_samples' opposite convention.
    # A raw score at or below score_min (as anomalous as anything seen
    # during training) maps to 1.0; at or above score_max (as normal as
    # anything seen) maps to 0.0. Replaces a fixed formula that was
    # calibrated for a different dataset's score range and, on this data,
    # pushed every sample above the classification threshold regardless of
    # how anomalous it actually was.
    score_min, score_max = bundle["score_min"], bundle["score_max"]
    span = max(score_max - score_min, 1e-9)
    anomaly_score = float(np.clip((score_max - raw_score) / span, 0.0, 1.0))

    # Distance from the 0.5 midpoint of the calibrated range — same formula
    # predict_cnn.py uses for its own decision boundary. The original
    # abs(raw_score)/0.3 had the identical calibrated-for-a-different-dataset
    # problem this whole fix addresses, so it's replaced here too rather
    # than left as the one remaining uncalibrated constant.
    confidence = float(np.clip(abs(anomaly_score - 0.5) * 2, 0.0, 1.0))

    return round(anomaly_score, 4), round(confidence, 4)


def make_score_fn(bundle: dict | None = None) -> Callable[[list[dict]], tuple[float, float]]:
    """Adapts predict(bundle, feature_sequence) — a two-argument call —
    into the single-argument `Callable[[list[dict]], tuple[float, float]]`
    signature agent_logic/analyzer.py's score_fn parameter expects. This is
    the only new piece here beyond the direct port: the original called
    predict() with an explicitly-passed model at each call site;
    analyzer.py was built to accept a pre-bound scoring function instead,
    so it never has to know a model object exists at all. Loads (or
    trains, on first run) the calibrated model once if none is passed in,
    then closes over it."""
    bound = bundle if bundle is not None else load_or_train()

    def score_fn(feature_sequence: list[dict]) -> tuple[float, float]:
        return predict(bound, feature_sequence)

    return score_fn
