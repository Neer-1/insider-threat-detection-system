# FROM ai-agent-assignment: app/ai/train_model.py — copied + renamed, so it sits alongside the CNN trainer; stays the baseline

import pickle

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.ai.preprocessing import ML_FEATURES, generate_training_data
from backend.core.config import DATASET_PATH, IF_CONTAMINATION, IF_N_ESTIMATORS, IF_RANDOM_STATE, MODEL_PATH, TRAINING_SAMPLES

# A calibrated model bundle is a plain dict: {"model": IsolationForest,
# "score_min": float, "score_max": float} — deliberately NOT a custom
# class. A custom class defined in this file gets pickled under whichever
# module name Python thinks this file is when train_and_save() runs (e.g.
# "__main__" if invoked via `python -m backend.ai.train_isolation_forest`
# or `python train_isolation_forest.py`), and unpickling it later through a
# normal import of backend.ai.train_isolation_forest then fails to resolve
# that class — a real bug hit while training this model. dict has no such
# problem: it's a builtin type, not tied to any module's execution context,
# so it always unpickles correctly regardless of how it was created.


def score_range(bundle: dict) -> tuple[float, float]:
    return bundle["score_min"], bundle["score_max"]


def fit_calibrated_model(X: np.ndarray) -> dict:
    """Fits the model AND its score calibration on the same X — whatever
    portion of data is passed in is what both the model and its
    calibration range reflect. Never call this with more data than the
    model itself is being trained on here (e.g. never a held-out test
    split) — the calibration would silently leak test-set information into
    what's supposed to be an honest evaluation, the same leakage concern
    already raised for the CNN's sequence grouping.

    score_samples()'s raw range is data-dependent — confirmed empirically:
    our synthetic data's raw range is roughly [-0.67, -0.38], nothing like
    the "-0.6 to 0.1" range the original assignment's fixed normalization
    constants assumed, so reusing that fixed formula silently miscalibrated
    every score into the same narrow high band (every sample above the 0.5
    classification threshold, precision/accuracy locked at the class prior
    — see the phase report). Fitting min/max here, once, alongside the
    model, is what predict_isolation_forest.py normalizes against instead."""
    model = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        contamination=IF_CONTAMINATION,
        random_state=IF_RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)
    raw = model.score_samples(X)
    return {"model": model, "score_min": float(raw.min()), "score_max": float(raw.max())}


def train_and_save() -> dict:
    """Generates synthetic training data, trains an Isolation Forest model
    and fits its score calibration, saves both the dataset and the
    calibrated model to disk. Hyperparameters already sitting in
    core/config.py from the earlier core/auth phase (IF_N_ESTIMATORS,
    IF_CONTAMINATION, IF_RANDOM_STATE, TRAINING_SAMPLES), not re-derived
    here.

    The dataset this trains on is synthetic placeholder data (see
    preprocessing.generate_training_data's docstring) — it stands in for
    real behavioural history until enough genuine Feature rows exist from
    actual enrolled devices, at which point this should be retrained on
    real data instead.

    Trains (and calibrates) on 100% of TRAINING_SAMPLES — this is the
    deployed model saved to MODEL_PATH, a separate run from
    backend/ai/evaluate.py's 80/20 split. Its real-world performance is
    represented by, but not identical in trained weights to, the evaluated
    model."""
    print("[AI] Generating training dataset...")
    df = generate_training_data(TRAINING_SAMPLES)

    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"[AI] Dataset saved -> {DATASET_PATH} ({len(df)} samples)")

    print("[AI] Training Isolation Forest...")
    X = df[ML_FEATURES].values
    bundle = fit_calibrated_model(X)
    print(f"[AI] Score calibration: min={bundle['score_min']:.4f} max={bundle['score_max']:.4f}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    print(f"[AI] Model saved -> {MODEL_PATH}")

    return bundle


def load_or_train() -> dict:
    """Loads the calibrated model from disk if it exists, otherwise trains
    a new one. Called once on server startup."""
    if MODEL_PATH.exists():
        print(f"[AI] Loading existing model from {MODEL_PATH}")
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    print("[AI] No model found — training new model")
    return train_and_save()


if __name__ == "__main__":
    train_and_save()
