# NEW — evaluation harness for both models, per dissertation sections 5.7/5.8

"""
Stratified 80/20 train/test split (fixed seed) -> 5-fold stratified
cross-validation within the training 80% only (a stable performance
estimate that never touches the test split) -> train the final model on
the full 80% -> evaluate once on the untouched 20% for the reported
numbers. Same procedure applied to both models. Isolation Forest and the
CNN are evaluated on their own respective datasets (flat single-window
rows vs 6-window sequences — see docs/dataset_notes.md and the phase
report on why they can't share literal rows) rather than on shared row
indices — "same procedure," not "same data."

Metrics: Accuracy, Precision, Recall, F1 (confusion-matrix, computed at a
0.5 threshold on each model's own anomaly-probability output) and ROC-AUC
(computed from the RAW, un-thresholded score for both models — Isolation
Forest's normalized anomaly_score, the CNN's raw sigmoid output — never
from thresholded 0/1 predictions, since ROC-AUC is only meaningful over a
continuous score).
"""

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, train_test_split

from backend.ai.preprocessing import ML_FEATURES, generate_training_data, generate_training_sequences
from backend.ai.train_cnn import InsiderThreatCNN, fit_model
from backend.ai.train_isolation_forest import fit_calibrated_model
from backend.core.config import CNN_SEQUENCE_LENGTH, TRAINING_SAMPLES

RANDOM_SEED = 42
TEST_SIZE = 0.2
N_FOLDS = 5
CLASSIFICATION_THRESHOLD = 0.5


def _compute_metrics(y_true, y_score) -> dict:
    """y_score must be the raw continuous anomaly probability/score for
    both the threshold-based metrics AND roc_auc_score — thresholding only
    happens here, internally, for accuracy/precision/recall/f1; roc_auc_score
    is always given the untouched y_score."""
    y_true = np.asarray(y_true)
    y_score = np.asarray(y_score)
    y_pred = (y_score >= CLASSIFICATION_THRESHOLD).astype(int)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_score),
    }


def _summarize_folds(fold_metrics: list[dict]) -> dict:
    return {
        metric: (
            float(np.mean([m[metric] for m in fold_metrics])),
            float(np.std([m[metric] for m in fold_metrics])),
        )
        for metric in fold_metrics[0]
    }


# ── Isolation Forest ──────────────────────────────────────────────────────

def _isolation_forest_scores(bundle: dict, X: np.ndarray) -> np.ndarray:
    """Same min-max calibration predict_isolation_forest.predict() applies
    to one row at a time, vectorised here over a whole array. Uses
    bundle["score_min"/"score_max"], which were fit on whatever data
    fit_calibrated_model() was called with — never X_test, see below."""
    raw = bundle["model"].score_samples(X)
    score_min, score_max = bundle["score_min"], bundle["score_max"]
    span = max(score_max - score_min, 1e-9)
    return np.clip((score_max - raw) / span, 0.0, 1.0)


def evaluate_isolation_forest() -> dict:
    df = generate_training_data(TRAINING_SAMPLES)
    X = df[ML_FEATURES].values
    y = df["label"].values

    # Stratified — preserves the ~70/30 class split in both the train and
    # test portions rather than letting a plain random split under- or
    # over-represent the minority (anomalous) class in either.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_SEED
    )

    # 5-fold CV strictly within X_train/y_train — X_test/y_test are never
    # touched until the single final evaluation below. fit_calibrated_model
    # fits BOTH the model and its score_min/score_max on the same fold
    # slice, so calibration never sees data the model itself didn't train
    # on either.
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    fold_metrics = []
    for fold_train_idx, fold_val_idx in skf.split(X_train, y_train):
        fold_bundle = fit_calibrated_model(X_train[fold_train_idx])
        scores = _isolation_forest_scores(fold_bundle, X_train[fold_val_idx])
        fold_metrics.append(_compute_metrics(y_train[fold_val_idx], scores))

    # Calibration fit on X_train only — never X_test, or the "held-out"
    # test evaluation would be scored against a calibration range that
    # already knows something about the test set.
    final_bundle = fit_calibrated_model(X_train)
    test_scores = _isolation_forest_scores(final_bundle, X_test)
    test_metrics = _compute_metrics(y_test, test_scores)

    return {
        "cv_mean_std": _summarize_folds(fold_metrics),
        "test": test_metrics,
        "model": final_bundle,
    }


# ── CNN ────────────────────────────────────────────────────────────────────

def _cnn_scores(model: InsiderThreatCNN, X: np.ndarray) -> np.ndarray:
    X_tensor = torch.tensor(X, dtype=torch.float32).permute(0, 2, 1)
    with torch.no_grad():
        return model(X_tensor).numpy()


def evaluate_cnn() -> dict:
    X, y = generate_training_sequences(TRAINING_SAMPLES, CNN_SEQUENCE_LENGTH)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_SEED
    )

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    fold_metrics = []
    for fold_train_idx, fold_val_idx in skf.split(X_train, y_train):
        fold_model = fit_model(X_train[fold_train_idx], y_train[fold_train_idx])
        scores = _cnn_scores(fold_model, X_train[fold_val_idx])
        fold_metrics.append(_compute_metrics(y_train[fold_val_idx], scores))

    final_model = fit_model(X_train, y_train)
    test_scores = _cnn_scores(final_model, X_test)
    test_metrics = _compute_metrics(y_test, test_scores)

    return {
        "cv_mean_std": _summarize_folds(fold_metrics),
        "test": test_metrics,
        "model": final_model,
    }


def _print_report(name: str, result: dict, caveat: str | None = None) -> None:
    print(f"\n=== {name} ===")
    print(f"{'metric':10s} {'CV mean':>10s} {'CV std':>10s} {'test':>10s}")
    for metric in result["test"]:
        cv_mean, cv_std = result["cv_mean_std"][metric]
        print(f"{metric:10s} {cv_mean:10.4f} {cv_std:10.4f} {result['test'][metric]:10.4f}")
    if caveat:
        print(f"NOTE: {caveat}")


# Required wherever CNN numbers get reported (here, or written up elsewhere)
# — see the phase report: a perfect or near-perfect score reflects trivial
# separability in clean synthetic data, not validated real-world
# performance. Do not quote CNN metrics without this caveat attached.
CNN_RESULT_CAVEAT = (
    "these numbers reflect trivial class separability in clean synthetic data by "
    "construction (severity-0 and severity-1 endpoints differ substantially by design) — "
    "not validated real-world performance. Real evaluation requires retraining on genuine "
    "Log/Feature data once devices are enrolled (see docs/dataset_notes.md)."
)


if __name__ == "__main__":
    if_result = evaluate_isolation_forest()
    _print_report("Isolation Forest", if_result)

    cnn_result = evaluate_cnn()
    _print_report("CNN", cnn_result, caveat=CNN_RESULT_CAVEAT)
