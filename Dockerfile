FROM python:3.14-alpine3.24@sha256:6f945b4c17e0a1ee862ada29a91406bc86d58180ce7de902d8de1f30730e3760

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
