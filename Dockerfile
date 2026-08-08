FROM python:3.12-alpine3.24@sha256:f7fd610959cae736251523b54eb26cecb74f60ffa60bf39d9faccf128b526ab8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir --disable-pip-version-check -r requirements.lock

COPY memory_router ./memory_router
COPY writer_registry.example.json ./writer_registry.example.json

RUN mkdir -p /app/data /app/bootstrap/public /app/bootstrap/private \
    && chown -R app:app /app/data /app/bootstrap

USER app
CMD ["python", "-m", "memory_router"]
