FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS build
WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.10.0
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
WORKDIR /app
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=build /app/.venv /app/.venv
COPY memory_router ./memory_router
COPY writer_registry.example.json ./writer_registry.example.json
RUN groupadd --gid 10001 memoryrouter \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin memoryrouter \
    && mkdir -p /app/data /app/bootstrap/public /app/bootstrap/private \
    && chown -R memoryrouter:memoryrouter /app/data /app/bootstrap
USER memoryrouter
CMD ["python", "-m", "memory_router.main"]
