"""Train and evaluate the anomaly model.

    python -m threatlens_ml.train --csv ../data/sample/cicids2017_sample.csv

Methodology: fit on 70% of BENIGN flows only, then evaluate on the held-out
benign flows plus every attack flow, using the dataset's ground-truth labels.
Labels are never used for training, so this measures true novelty detection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

from .features import load_cic_csv
from .model import DEFAULT_PATH, AnomalyModel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(Path(__file__).resolve().parents[2] / "data/sample/cicids2017_sample.csv"))
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--out", default=str(DEFAULT_PATH))
    args = ap.parse_args()

    df = load_cic_csv(args.csv, args.max_rows)
    labels = df["Label"].astype(str).str.strip()
    is_attack = (labels.str.upper() != "BENIGN").to_numpy()
    rows = df.to_dict("records")

    benign_idx = np.where(~is_attack)[0]
    train_idx, holdout_idx = train_test_split(benign_idx, test_size=0.3, random_state=42)
    model = AnomalyModel.train([rows[i] for i in train_idx])

    eval_idx = np.concatenate([holdout_idx, np.where(is_attack)[0]])
    y_true = is_attack[eval_idx]
    scores = np.array(model.scores([rows[i] for i in eval_idx]))
    y_pred = scores >= model.threshold

    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    per_label = {}
    for lab in sorted(set(labels[eval_idx])):
        mask = (labels.to_numpy()[eval_idx] == lab)
        per_label[lab] = {"flows": int(mask.sum()), "flagged_pct": round(float(y_pred[mask].mean()) * 100, 1)}
    metrics = {
        "trained_on_benign_flows": int(len(train_idx)),
        "eval_flows": int(len(eval_idx)),
        "precision": round(float(p), 3),
        "recall": round(float(r), 3),
        "f1": round(float(f1), 3),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 3) if y_true.any() and (~y_true).any() else None,
        "benign_false_positive_rate": round(float(y_pred[~y_true].mean()), 4),
        "by_label": per_label,
    }
    model.metrics = metrics
    model.save(Path(args.out))
    print(json.dumps(metrics, indent=2))
    print(f"model saved to {args.out}")


if __name__ == "__main__":
    main()
