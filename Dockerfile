FROM python:3.14-alpine3.24@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

COPY requirements.txt pyproject.toml ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.txt

COPY memory_router ./memory_router
COPY writer_registry.example.json ./writer_registry.example.json
COPY THIRD_PARTY_NOTICES.md ./THIRD_PARTY_NOTICES.md
COPY licenses ./licenses
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps . \
    && python -m pip uninstall --yes pip \
    && mkdir -p /app/data \
    && chown -R app:app /app/data

USER 10001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); opener.open(f\"http://127.0.0.1:{os.environ.get('MEMORY_ROUTER_PORT', '8890')}/health/ready\", timeout=2).close()"]
CMD ["python", "-m", "memory_router"]
