# Threat Mapping Service

FastAPI microservice that loads the provided machine-learning artifacts to map CVE
descriptions to CWE and CAPEC predictions.

## Prerequisites

- Python 3.11+
- The pickled artifacts inside `models copy/`

## Setup

```bash
cd services/threat-model
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running the service

```bash
export THREAT_MODELS_PATH="../../models copy"  # optional, defaults to repo root/models copy
uvicorn main:app --reload --port 8001
```

### Docker

```bash
docker build -t threat-model services/threat-model
docker run \
  -p 8001:8001 \
  -e THREAT_MODEL_TOKEN=dev-key \        # optional auth token
  -v /absolute/path/to/models:/models \  # mount your pickled artifacts
  threat-model
```

The container will read models from `/models` by default (override with `THREAT_MODELS_PATH`).

### Environment variables

| Variable               | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `THREAT_MODELS_PATH`   | Directory containing `vectorizer.pkl`, `cwe_model.pkl`, etc.             |
| `THREAT_MODEL_TOKEN`   | If set, all requests must send `X-Threat-Model-Key: <token>`            |
| `THREAT_MODEL_LOG_LEVEL` | Standard Python log level (`INFO`, `DEBUG`, …)                         |

## API surface

- `GET /health` – liveness probe
- `POST /predict` – single-description inference
- `POST /predict/batch` – array of `{ description, top_k, threshold }` payloads

Both prediction endpoints accept `X-Threat-Model-Key` when `THREAT_MODEL_TOKEN` is configured.

## Consuming from the frontend

Set `VITE_THREAT_MODEL_API=http://localhost:8001/predict` before running the console app.

```bash
cd apps/console
npm run dev
```

The CVE page will display CWE/CAPEC predictions using live model outputs, and the query service will persist them for later reuse.

## Retraining

To rebuild the pickled artifacts with consistent scikit-learn versions, see `training/README.md`
for dataset requirements and the `training/train.py` helper script.

