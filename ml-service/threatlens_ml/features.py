"""Feature engineering for CICFlowMeter network flows (CIC-IDS2017 schema)."""
from __future__ import annotations

from typing import Iterable, Mapping

import numpy as np
import pandas as pd

# Raw CICFlowMeter columns (names as in the dataset, whitespace-trimmed).
RAW_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587,
                636, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443}

FEATURE_NAMES = RAW_FEATURES + ["fwd_bwd_byte_ratio", "uncommon_port", "high_port"]


def _num(v) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return f if np.isfinite(f) else 0.0


def to_frame(rows: Iterable[Mapping]) -> pd.DataFrame:
    """Build the model's feature matrix from flow dicts (API payload or CSV rows)."""
    records = []
    for r in rows:
        rec = {c: _num(r.get(c)) for c in RAW_FEATURES}
        port = int(_num(r.get("Destination Port")))
        rec["fwd_bwd_byte_ratio"] = (rec["Total Length of Fwd Packets"] + 1) / (rec["Total Length of Bwd Packets"] + 1)
        rec["uncommon_port"] = 0.0 if port in COMMON_PORTS else 1.0
        rec["high_port"] = 1.0 if port >= 1024 else 0.0
        records.append(rec)
    df = pd.DataFrame.from_records(records, columns=FEATURE_NAMES)
    # Heavy-tailed counters/rates -> signed log so a few huge flows don't dominate the scaler.
    return np.sign(df) * np.log1p(np.abs(df))


def load_cic_csv(path: str, max_rows: int | None = None) -> pd.DataFrame:
    """Read a CIC-IDS2017 CSV, trimming the leading spaces in its header."""
    df = pd.read_csv(path, nrows=max_rows, low_memory=False, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    return df
