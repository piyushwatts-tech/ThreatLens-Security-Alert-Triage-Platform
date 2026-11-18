from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatlens_ml import summarizer
from threatlens_ml.features import FEATURE_NAMES, load_cic_csv, to_frame
from threatlens_ml.model import AnomalyModel

SAMPLE = Path(__file__).resolve().parents[2] / "data/sample/cicids2017_sample.csv"


@pytest.fixture(scope="module")
def data():
    df = load_cic_csv(str(SAMPLE))
    return df, df["Label"].str.strip()


def test_features_handle_infinity_and_missing():
    X = to_frame([{"Flow Bytes/s": "Infinity", "Destination Port": 4444}, {}])
    assert list(X.columns) == FEATURE_NAMES
    assert X.notna().all().all()
    assert X.loc[0, "uncommon_port"] > 0


def test_model_separates_attacks_from_benign(data):
    df, labels = data
    rows = df.to_dict("records")
    benign = [r for r, l in zip(rows, labels) if l == "BENIGN"]
    model = AnomalyModel.train(benign[:1500])
    holdout = model.scores(benign[1500:])
    exfil = model.scores([r for r, l in zip(rows, labels) if l == "Infiltration"])
    scan = model.scores([r for r, l in zip(rows, labels) if l == "PortScan"])
    fp_rate = sum(s >= 0.5 for s in holdout) / len(holdout)
    assert fp_rate < 0.05
    assert sum(s >= 0.5 for s in exfil) / len(exfil) > 0.8
    assert sum(scan) / len(scan) > sum(holdout) / len(holdout)


def test_template_summary_when_no_llm(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = summarizer.summarize({"title": "t", "description": "Port scan", "risk_score": 70,
                                         "severity": "HIGH", "playbook": ["Block it"],
                                         "entities": {"src_ip": "1.2.3.4"}})
    assert source == "template"
    assert "Port scan" in text and "1. Block it" in text


def test_api_score_roundtrip(data, tmp_path, monkeypatch):
    from threatlens_ml import app as app_mod, model as model_mod

    df, labels = data
    m = AnomalyModel.train(df[labels == "BENIGN"].head(800).to_dict("records"))
    path = tmp_path / "m.joblib"
    m.save(path)
    monkeypatch.setattr(app_mod, "DEFAULT_PATH", path)
    monkeypatch.setattr(app_mod, "_model", None)
    client = TestClient(app_mod.app)
    flows = df.head(5).to_dict("records")
    r = client.post("/score", json={"flows": flows})
    assert r.status_code == 200
    body = r.json()
    assert len(body["scores"]) == 5 and body["threshold"] == 0.5
