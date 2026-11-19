"""Isolation Forest anomaly model trained on benign traffic only (novelty detection)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from .features import FEATURE_NAMES, to_frame

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "models" / "isolation_forest.joblib"


@dataclass
class AnomalyModel:
    pipeline: Pipeline
    raw_threshold: float      # raw outlier score at the chosen benign false-positive budget
    raw_scale: float          # spread of benign raw scores, used to squash into [0, 1]
    metrics: dict = field(default_factory=dict)
    version: str = "iforest-v1"

    @classmethod
    def train(cls, benign_rows, fp_budget: float = 0.02, seed: int = 42) -> "AnomalyModel":
        X = to_frame(benign_rows)
        pipe = Pipeline([
            ("scale", RobustScaler()),
            ("iforest", IsolationForest(n_estimators=300, max_samples="auto", contamination="auto",
                                        random_state=seed, n_jobs=-1)),
        ])
        pipe.fit(X)
        raw = -pipe.score_samples(X)                       # higher = more anomalous
        thr = float(np.quantile(raw, 1 - fp_budget))       # e.g. 98th percentile of benign
        scale = float(np.std(raw)) or 1.0
        return cls(pipe, thr, scale)

    def raw_scores(self, rows) -> np.ndarray:
        return -self.pipeline.score_samples(to_frame(rows))

    def scores(self, rows) -> list[float]:
        """Anomaly probability-like score in [0, 1]; 0.5 == the calibrated threshold."""
        raw = self.raw_scores(rows)
        z = (raw - self.raw_threshold) / self.raw_scale
        return (1 / (1 + np.exp(-4 * z))).round(4).tolist()

    @property
    def threshold(self) -> float:
        return 0.5

    def save(self, path: Path = DEFAULT_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path = DEFAULT_PATH) -> "AnomalyModel":
        return joblib.load(path)


__all__ = ["AnomalyModel", "FEATURE_NAMES", "DEFAULT_PATH"]
