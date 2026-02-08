FROM python:3.11-slim

WORKDIR /app

COPY telemetry/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY scripts/github_utils.py ./scripts/github_utils.py
COPY scripts/retry_utils.py ./scripts/retry_utils.py
COPY scripts/pipeline_config.py ./scripts/pipeline_config.py

COPY telemetry/ ./

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/api/config', timeout=5).raise_for_status()"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
