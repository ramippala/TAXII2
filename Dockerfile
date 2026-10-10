# TAXII 2.1 server — container image
# Runs the app the same way the README documents (`python server.py`): the
# process owns the background pollers (OTX / TAXII pullers, TTL sweeper) and
# the Flask server, so a single container is the right unit.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="TAXII 2.1 Server" \
      org.opencontainers.image.description="TAXII 2.1 threat-intelligence server (Vision One / XDR client feed)"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TAXII_CONFIG=/app/config.yaml

WORKDIR /app

# Dependencies first (layer cache). psycopg2-binary is the Postgres driver —
# installed in the image so the container works against a Postgres service.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary

# Application files (see .dockerignore — no venv, no .env, no tests).
COPY server.py intel-ui.html config.yaml ./

# Run unprivileged.
RUN useradd --create-home --uid 10001 app && chown -R app:app /app
USER app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4).status == 200 else 1)"

CMD ["python", "server.py"]
