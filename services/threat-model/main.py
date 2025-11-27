from __future__ import annotations

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Any, List, Optional

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


class LabelScore(BaseModel):
  id: str = Field(..., description="Identifier such as CWE-79 or CAPEC-163")
  score: Optional[float] = Field(
    None, description="Confidence score between 0 and 1 if available"
  )


class PredictionRequest(BaseModel):
  description: str = Field(..., description="Raw CVE description text")
  top_k: int = Field(5, ge=1, le=20, description="Max labels to return per taxonomy")
  threshold: float = Field(
    0.25, ge=0.0, le=1.0, description="Minimum probability required to keep a label"
  )


class PredictionResponse(BaseModel):
  cwe: List[LabelScore]
  capec: List[LabelScore]


class BatchPredictionItem(BaseModel):
  description: str = Field(..., description="Raw CVE description text")
  top_k: int = Field(5, ge=1, le=20)
  threshold: float = Field(0.25, ge=0.0, le=1.0)


class BatchPredictionRequest(BaseModel):
  items: List[BatchPredictionItem] = Field(..., min_length=1, max_length=50)


class BatchPredictionResponse(BaseModel):
  results: List[PredictionResponse]


MODELS_DIR = Path(
  os.environ.get("THREAT_MODELS_PATH", Path(__file__).resolve().parents[2] / "models copy")
)

if not MODELS_DIR.exists():
  raise RuntimeError(f"Models directory not found at {MODELS_DIR}")


def _load_pickle(name: str) -> Any:
  path = MODELS_DIR / name
  if not path.exists():
    raise RuntimeError(f"Missing model artifact: {path}")
  with path.open("rb") as file:
    return pickle.load(file)


logger = logging.getLogger("threat-model")
logging.basicConfig(
  level=os.environ.get("THREAT_MODEL_LOG_LEVEL", "INFO"),
  format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

vectorizer = _load_pickle("vectorizer.pkl")
cwe_model = _load_pickle("cwe_model.pkl")
cwe_binarizer = _load_pickle("cwe_binarizer.pkl")
capec_model = _load_pickle("capec_model.pkl")
capec_binarizer = _load_pickle("capec_binarizer.pkl")

logger.info("Loaded model artifacts from %s", MODELS_DIR)


def _ensure_probability_array(raw: Any) -> Optional[np.ndarray]:
  if raw is None:
    return None

  if isinstance(raw, list):
    columns = []
    for entry in raw:
      entry = np.asarray(entry)
      if entry.ndim == 2:
        if entry.shape[1] == 2:
          columns.append(entry[:, 1][:, None])
        else:
          columns.append(entry)
      else:
        columns.append(entry[:, None])
    return np.hstack(columns)

  return np.asarray(raw)


def _predict_labels(
  model: Any,
  binarizer: Any,
  features: Any,
  top_k: int,
  threshold: float,
) -> List[LabelScore]:
  predictions: List[LabelScore] = []
  proba = None

  if hasattr(model, "predict_proba"):
    proba = _ensure_probability_array(model.predict_proba(features))

  if proba is not None and proba.size:
    scores = proba[0]
    order = np.argsort(scores)[::-1]
    for idx in order[:top_k]:
      score = float(scores[idx])
      if score < threshold:
        continue
      predictions.append(LabelScore(id=str(binarizer.classes_[idx]), score=score))

  if not predictions:
    binary = model.predict(features)
    if hasattr(binary, "toarray"):
      binary = binary.toarray()
    decoded = binarizer.inverse_transform(binary)
    labels = decoded[0] if decoded else []
    for label in labels[:top_k]:
      predictions.append(LabelScore(id=str(label), score=None))

  return predictions


API_TOKEN = os.environ.get("THREAT_MODEL_TOKEN")


def _require_token(x_threat_model_key: Optional[str] = Header(None)) -> None:
  if not API_TOKEN:
    return
  if x_threat_model_key != API_TOKEN:
    raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(
  title="Threat Mapping Service",
  description="Maps CVE descriptions to CWE and CAPEC predictions using pre-trained models.",
  version="1.1.0",
)

app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


@app.get("/health")
def health_check() -> dict[str, str]:
  return {"status": "ok"}


def _run_prediction(payload: PredictionRequest) -> PredictionResponse:
  description = payload.description.strip()
  if not description:
    raise HTTPException(status_code=400, detail="Description must not be empty")

  try:
    features = vectorizer.transform([description])
    cwe_predictions = _predict_labels(
      cwe_model, cwe_binarizer, features, payload.top_k, payload.threshold
    )
    capec_predictions = _predict_labels(
      capec_model, capec_binarizer, features, payload.top_k, payload.threshold
    )
  except Exception as error:  # pylint: disable=broad-except
    logger.exception("Prediction failed")
    raise HTTPException(status_code=500, detail=f"Prediction failed: {error}") from error

  return PredictionResponse(cwe=cwe_predictions, capec=capec_predictions)


@app.post("/predict", response_model=PredictionResponse, dependencies=[Depends(_require_token)])
def predict(payload: PredictionRequest) -> PredictionResponse:
  start = time.perf_counter()
  response = _run_prediction(payload)
  logger.info("Prediction completed in %.2fms", (time.perf_counter() - start) * 1000)
  return response


@app.post(
  "/predict/batch",
  response_model=BatchPredictionResponse,
  dependencies=[Depends(_require_token)],
)
def predict_batch(payload: BatchPredictionRequest) -> BatchPredictionResponse:
  start = time.perf_counter()
  responses = [_run_prediction(PredictionRequest(**item.dict())) for item in payload.items]
  logger.info(
    "Batch prediction completed for %d items in %.2fms",
    len(payload.items),
    (time.perf_counter() - start) * 1000,
  )
  return BatchPredictionResponse(results=responses)


if __name__ == "__main__":
  import uvicorn

  uvicorn.run(app, host="0.0.0.0", port=8001)

