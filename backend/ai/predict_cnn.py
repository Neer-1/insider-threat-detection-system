# NEW — 1D CNN inference, becomes the primary model; isolation forest output kept as a secondary/baseline signal

from typing import Callable

import numpy as np
import torch

from backend.ai.preprocessing import log_to_vector
from backend.ai.train_cnn import CNN_SEQUENCE_LENGTH, InsiderThreatCNN, load_or_train


def predict(model: InsiderThreatCNN, feature_sequence: list[dict]) -> tuple[float, float]:
    """Runs the CNN on a sequence of consecutive feature windows (see
    agent_logic/feature_extractor.extract_feature_sequence — chronological,
    current window last). Mirrors predict_isolation_forest.predict's
    (anomaly_score, confidence) contract exactly, so either model can back
    the same score_fn interface:

        anomaly_score — the model's own sigmoid output (0.0-1.0). Not an empirically
                        calibrated probability, unlike Isolation Forest's
                        score_samples output which needed re-scaling.
        confidence    — uncalibrated distance from the 0.5 decision boundary, scaled to
                        0.0-1.0 — mirrors how predict_isolation_forest
                        derives confidence from distance-to-boundary, just
                        using this model's own boundary (0.5, not 0).
    """
    if len(feature_sequence) != CNN_SEQUENCE_LENGTH:
        raise ValueError(
            f"expected a sequence of {CNN_SEQUENCE_LENGTH} feature windows, got {len(feature_sequence)}"
        )

    # log_to_vector returns shape (1, N_FEATURES) per window — same helper
    # the Isolation Forest uses. Stack into (sequence_length, N_FEATURES),
    # then transpose to (N_FEATURES, sequence_length): channels-then-time,
    # matching InsiderThreatCNN's expected input.
    vectors = np.stack([log_to_vector(f)[0] for f in feature_sequence])  # (sequence_length, N_FEATURES)
    X = vectors.T  # (N_FEATURES, sequence_length)
    X_tensor = torch.tensor(X, dtype=torch.float32).unsqueeze(0)  # (1, N_FEATURES, sequence_length)

    model.eval()
    with torch.no_grad():
        probability = model(X_tensor).item()

    anomaly_score = float(np.clip(probability, 0.0, 1.0))
    confidence = float(np.clip(abs(probability - 0.5) * 2, 0.0, 1.0))

    return round(anomaly_score, 4), round(confidence, 4)


def make_score_fn(model: InsiderThreatCNN | None = None) -> Callable[[list[dict]], tuple[float, float]]:
    """Same pattern as predict_isolation_forest.make_score_fn — closes over
    a loaded (or freshly trained) model and adapts predict()'s two-argument
    call into the single-argument `Callable[[list[dict]], tuple[float, float]]`
    signature agent_logic/analyzer.py expects. Which model backs a given
    score_fn is entirely the caller's choice; analyzer.py never knows or
    cares which one it's holding."""
    bound_model = model if model is not None else load_or_train()

    def score_fn(feature_sequence: list[dict]) -> tuple[float, float]:
        return predict(bound_model, feature_sequence)

    return score_fn
