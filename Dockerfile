# CRL Monitor — single container (API + UI + scheduler in one process group)
FROM python:3.12-slim

# OpenSSL libs are present in the base image; the app uses the `cryptography`
# Python library for CRL parsing/verification, so no openssl CLI is required.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    PORT=8080

WORKDIR /app

# curl is only for the container HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Persistent SQLite data lives here.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}${URL_PREFIX:-}/api/status" || exit 1

# Single gunicorn worker so the in-process scheduler runs exactly once.
# The work is I/O-bound (network CRL downloads), so threads give plenty of
# concurrency for a handful of monitors + the web UI.
CMD ["sh", "-c", "gunicorn --chdir app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:${PORT} app:app"]
