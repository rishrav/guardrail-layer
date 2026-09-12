# Build context: repository root (the uv workspace lockfile lives there).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependency layer first so code edits don't reinstall everything.
COPY pyproject.toml uv.lock .python-version ./
COPY gateway/pyproject.toml gateway/pyproject.toml
# uv needs every workspace member's manifest to resolve the lockfile.
COPY sdk/pyproject.toml sdk/pyproject.toml
RUN uv sync --frozen --no-dev --package guardrail-gateway --no-install-workspace

COPY gateway gateway
RUN uv sync --frozen --no-dev --package guardrail-gateway

RUN useradd --create-home --uid 10001 guardrail
USER guardrail

ENV PATH="/app/.venv/bin:$PATH"
WORKDIR /app/gateway
EXPOSE 8000
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
