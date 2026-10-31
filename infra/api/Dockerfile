FROM python:3.12.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.lock.txt ./requirements.lock.txt
RUN python -m pip install --no-cache-dir -r requirements.lock.txt

COPY src ./src
COPY run_dashboard_api.py ./run_dashboard_api.py
COPY initialize_mongodb.py ./initialize_mongodb.py
COPY reports/integration/mongodb_prediction.schema.json ./reports/integration/mongodb_prediction.schema.json
COPY reports/operational/model_registry_operational.json ./reports/operational/model_registry_operational.json
COPY experiments/scale_100k/models/isolation_forest.joblib ./experiments/scale_100k/models/isolation_forest.joblib

RUN addgroup --system app && adduser --system --ingroup app app && chown -R app:app /app
USER app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"

CMD ["python", "-m", "uvicorn", "run_dashboard_api:app", "--host", "0.0.0.0", "--port", "8000"]
