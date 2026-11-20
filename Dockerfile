FROM python:3.15-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS builder

WORKDIR /build

COPY build-requirements.txt ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    --require-hashes --only-binary=:all: -r build-requirements.txt

COPY pyproject.toml LICENSE THIRD_PARTY_NOTICES.md ./
COPY memory_router ./memory_router
COPY licenses ./licenses
RUN --network=none python -m pip wheel --no-cache-dir --disable-pip-version-check \
    --no-index --no-build-isolation --no-deps --wheel-dir /wheels .

FROM python:3.15-alpine3.24@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.txt

COPY --from=builder /wheels /wheels
COPY writer_registry.example.json ./writer_registry.example.json
COPY THIRD_PARTY_NOTICES.md ./THIRD_PARTY_NOTICES.md
COPY licenses ./licenses
RUN --network=none python -m pip install --no-cache-dir --disable-pip-version-check \
    --no-index --no-deps /wheels/*.whl \
    && rm -rf /wheels \
    && python -m pip uninstall --yes pip \
    && mkdir -p /app/data \
    && chown -R app:app /app/data

USER 10001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); opener.open(f\"http://127.0.0.1:{os.environ.get('MEMORY_ROUTER_PORT', '8890')}/health/ready\", timeout=2).close()"]
CMD ["python", "-m", "memory_router"]
