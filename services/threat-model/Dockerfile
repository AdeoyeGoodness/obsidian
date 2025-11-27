FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    THREAT_MODELS_PATH=/models

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001
VOLUME ["/models"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]

