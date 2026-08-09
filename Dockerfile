FROM python:3.13-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

COPY requirements.txt pyproject.toml ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY memory_router ./memory_router
COPY writer_registry.example.json ./writer_registry.example.json
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps . \
    && python -m pip uninstall --yes pip \
    && mkdir -p /app/data \
    && chown -R app:app /app/data

USER app
CMD ["python", "-m", "memory_router"]
