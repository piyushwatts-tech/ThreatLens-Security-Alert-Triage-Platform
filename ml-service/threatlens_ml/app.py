"""ThreatLens ML service: anomaly scoring for network flows + alert summaries."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import summarizer
from .model import DEFAULT_PATH, AnomalyModel

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("threatlens.ml")

app = FastAPI(title="ThreatLens ML", version="1.0.0")
_model: AnomalyModel | None = None


def model() -> AnomalyModel:
    global _model
    if _model is None:
        if not DEFAULT_PATH.exists():
            raise HTTPException(503, "Model not trained. Run: python -m threatlens_ml.train")
        _model = AnomalyModel.load(DEFAULT_PATH)
        log.info("Loaded model %s, metrics=%s", _model.version, _model.metrics)
    return _model


class ScoreRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(..., max_length=20_000)


class ScoreResponse(BaseModel):
    scores: list[float]
    threshold: float
    model: str


@app.get("/health")
def health():
    loaded = DEFAULT_PATH.exists()
    return {"status": "ok", "model_loaded": loaded, "llm_enabled": summarizer.llm_enabled(),
            "llm_model": summarizer.LLM_MODEL if summarizer.llm_enabled() else None}


@app.get("/model")
def model_info():
    m = model()
    return {"version": m.version, "threshold": m.threshold, "metrics": m.metrics}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    m = model()
    if not req.flows:
        return ScoreResponse(scores=[], threshold=m.threshold, model=m.version)
    return ScoreResponse(scores=m.scores(req.flows), threshold=m.threshold, model=m.version)


@app.post("/summarize")
def summarize(alert: dict[str, Any]):
    text, source = summarizer.summarize(alert)
    return {"summary": text, "source": source}
