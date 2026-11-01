# NEW — 1D CNN training script, the actual outstanding AI work

"""
Architecture per dissertation section 4.5.2 (Lightweight CNN Architecture
Design) / Figure 4.5:

    Feature Matrix Input -> 1D Convolution Layer -> ReLU Activation
      -> Max Pooling Layer -> Fully Connected Layer
      -> Sigmoid Output Layer -> Anomaly Probability Score

The dissertation figure doesn't specify what the convolution actually
slides across. A single window's 12 features have no meaningful adjacency
to convolve over (there's no reason files_accessed should be "next to"
usb_inserted) — the version that's actually justified is convolving across
TIME: the last CNN_SEQUENCE_LENGTH consecutive feature windows for one
device, with each of the 12 ML_FEATURES as an input channel. This is what
lets the model learn escalation patterns (a device drifting from normal
toward malicious across several windows) that a single-window classifier —
including the Isolation Forest baseline — structurally cannot see.

Layer widths, kernel size, dropout rate, and training hyperparameters
aren't specified in the dissertation text either — see core/config.py's
CNN_* constants for those; with the current config this is ~1,000
trainable parameters.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.utils.data

from backend.ai.preprocessing import ML_FEATURES, generate_training_sequences
from backend.core.config import (
    CNN_BATCH_SIZE,
    CNN_CONV_OUT_CHANNELS,
    CNN_DROPOUT,
    CNN_EPOCHS,
    CNN_HIDDEN_UNITS,
    CNN_KERNEL_SIZE,
    CNN_LEARNING_RATE,
    CNN_MODEL_PATH,
    CNN_RANDOM_SEED,
    CNN_SEQUENCE_LENGTH,
    TRAINING_SAMPLES,
)

N_FEATURES = len(ML_FEATURES)


class InsiderThreatCNN(nn.Module):
    """1D CNN matching dissertation Figure 4.5, convolving over time rather
    than over a single window's features (see module docstring). Input is
    CNN_SEQUENCE_LENGTH consecutive feature windows for one device, each
    with N_FEATURES values — shape (batch, N_FEATURES, CNN_SEQUENCE_LENGTH):
    each of the 12 ML_FEATURES is a channel, the sequence dimension is time.

    feature_mean/feature_std are registered buffers rather than a separate
    scaler artifact: normalization parameters are learned from the training
    set and saved/loaded as part of the model's own state_dict, so there's
    no separate file to keep in sync with the weights."""

    def __init__(self):
        super().__init__()

        self.conv = nn.Conv1d(
            in_channels=N_FEATURES,
            out_channels=CNN_CONV_OUT_CHANNELS,
            kernel_size=CNN_KERNEL_SIZE,
            padding=CNN_KERNEL_SIZE // 2,  # "same" padding — preserves sequence length through the conv
        )
        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.dropout = nn.Dropout(CNN_DROPOUT)

        pooled_length = CNN_SEQUENCE_LENGTH // 2
        self.fc = nn.Linear(CNN_CONV_OUT_CHANNELS * pooled_length, CNN_HIDDEN_UNITS)
        self.output = nn.Linear(CNN_HIDDEN_UNITS, 1)
        self.sigmoid = nn.Sigmoid()

        self.register_buffer("feature_mean", torch.zeros(N_FEATURES))
        self.register_buffer("feature_std", torch.ones(N_FEATURES))

    def normalize(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, N_FEATURES, CNN_SEQUENCE_LENGTH) — broadcast mean/std
        # (each per-feature/channel) across the time dimension.
        mean = self.feature_mean.view(1, -1, 1)
        std = self.feature_std.view(1, -1, 1)
        return (x - mean) / std

    def _logits(self, x: torch.Tensor) -> torch.Tensor:
        """Raw pre-sigmoid output — used only during training, where
        BCEWithLogitsLoss needs logits rather than probabilities for
        numerical stability. forward() is the actual model contract
        (probabilities out); this is an internal training detail."""
        x = self.normalize(x)
        x = self.pool(self.relu(self.conv(x)))
        x = x.flatten(start_dim=1)
        x = self.relu(self.fc(x))
        x = self.dropout(x)  # only active in .train() mode — a no-op at inference
        x = self.output(x)
        return x.squeeze(-1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, N_FEATURES, CNN_SEQUENCE_LENGTH) raw (unnormalized)
        feature-window sequences. Returns (batch,) anomaly probabilities in
        [0, 1] — the dissertation's "Sigmoid Output Layer... Anomaly
        Probability Score" is part of the model itself, not a separate
        post-processing step."""
        return self.sigmoid(self._logits(x))


def fit_model(X: np.ndarray, y: np.ndarray) -> InsiderThreatCNN:
    """Core training loop — normalizes, weights the loss for class
    imbalance, trains for CNN_EPOCHS. Shared by train_and_save() (fits on
    100% of the data, for deployment) and backend/ai/evaluate.py (fits per
    CV fold and on the 80% training split, for evaluation) so both paths
    run the exact same procedure rather than two copies that could drift
    apart. X: (n, CNN_SEQUENCE_LENGTH, len(ML_FEATURES)) time-major, as
    preprocessing.generate_training_sequences returns it.

    Class imbalance (label=1 — suspicious/malicious-ending — is ~30% of
    sequences) is handled via a weighted loss (pos_weight in
    BCEWithLogitsLoss) rather than oversampling (SMOTE/ADASYN): simpler, no
    extra dependency, and sufficient for a shallow model — satisfies
    dissertation section 4.5.2's "imbalance handling strategies are
    incorporated during training" without adding weight to what's meant to
    stay a lightweight SME tool.

    Seeds torch's global RNG first — weight initialization (happens at
    InsiderThreatCNN() construction, below) and the DataLoader's
    shuffle=True order both draw from it, so without this every call
    produces a different result even given identical X/y. Every call to
    fit_model() reseeds to the same CNN_RANDOM_SEED, so every CV fold and
    the final/deployment model start from identical initial weights — the
    varying training data per fold is what CV is actually meant to vary,
    not the initialization."""
    torch.manual_seed(CNN_RANDOM_SEED)
    model = InsiderThreatCNN()

    flat = X.reshape(-1, X.shape[-1])
    model.feature_mean.copy_(torch.tensor(flat.mean(axis=0), dtype=torch.float32))
    # +1e-6 avoids a division by zero if a feature column is constant across the whole training set.
    model.feature_std.copy_(torch.tensor(flat.std(axis=0) + 1e-6, dtype=torch.float32))

    X_tensor = torch.tensor(X, dtype=torch.float32).permute(0, 2, 1)  # (n, seq, feat) -> (n, feat, seq)
    y_tensor = torch.tensor(y, dtype=torch.float32)

    n_pos = y_tensor.sum().item()
    n_neg = len(y_tensor) - n_pos
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)], dtype=torch.float32)

    optimizer = torch.optim.Adam(model.parameters(), lr=CNN_LEARNING_RATE)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    dataset = torch.utils.data.TensorDataset(X_tensor, y_tensor)
    loader = torch.utils.data.DataLoader(dataset, batch_size=CNN_BATCH_SIZE, shuffle=True)

    model.train()
    for epoch in range(CNN_EPOCHS):
        epoch_loss = 0.0
        for xb, yb in loader:
            optimizer.zero_grad()
            logits = model._logits(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * xb.size(0)
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"[AI]   epoch {epoch + 1}/{CNN_EPOCHS}  loss={epoch_loss / len(dataset):.4f}")

    model.eval()
    return model


def train_and_save() -> InsiderThreatCNN:
    """Trains on the FULL synthetic sequence dataset (100% of
    TRAINING_SAMPLES, not the 80% split backend/ai/evaluate.py's CV/test
    procedure uses) — this produces the actual model file loaded via
    CNN_MODEL_PATH / load_or_train() at runtime. Standard practice: the
    evaluation split exists to produce honest, held-out metrics; once
    those are recorded, using every available sample for the deployed
    model is strictly better than permanently withholding 20% of an
    already-small dataset from it.

    IMPORTANT: this is a separate, fresh training run from evaluate.py's —
    the deployed model's real-world performance is represented by, but not
    identical in trained weights to, the evaluated model. Never touch
    evaluate.py's 80/20 split or its reported numbers from here."""
    print("[AI] Generating training sequences...")
    X, y = generate_training_sequences(TRAINING_SAMPLES, CNN_SEQUENCE_LENGTH)
    print(f"[AI] {len(y)} sequences generated ({int(y.sum())} positive / {len(y) - int(y.sum())} negative)")

    print(f"[AI] Training CNN on 100% of the data — {len(y)} sequences, {CNN_EPOCHS} epochs, batch size {CNN_BATCH_SIZE}")
    model = fit_model(X, y)

    CNN_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), CNN_MODEL_PATH)
    print(f"[AI] Model saved -> {CNN_MODEL_PATH}")

    return model


def load_or_train() -> InsiderThreatCNN:
    """Loads the model from disk if it exists, otherwise trains a new one —
    same pattern as train_isolation_forest.load_or_train()."""
    if CNN_MODEL_PATH.exists():
        print(f"[AI] Loading existing CNN model from {CNN_MODEL_PATH}")
        model = InsiderThreatCNN()
        model.load_state_dict(torch.load(CNN_MODEL_PATH, map_location="cpu", weights_only=True))
        model.eval()
        return model
    raise RuntimeError("CNN weights absent. Training is an explicit offline experiment, never a startup side effect.")


if __name__ == "__main__":
    train_and_save()
