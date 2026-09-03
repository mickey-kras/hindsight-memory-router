FROM python:3.14-alpine3.24@sha256:3f818d6811ff5f3f2b5e5d836df3d25c2dd2e588d3b4981338a8ba17e422f74f

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
