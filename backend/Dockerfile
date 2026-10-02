# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.12.17 AS uv

FROM python:3.13.15-slim-trixie AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

FROM python:3.13.15-slim-trixie
RUN useradd --system --uid 10001 --home-dir /srv dsn
WORKDIR /srv
COPY --from=build /srv/.venv /srv/.venv
COPY app ./app
ENV PATH="/srv/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN mkdir -p /srv/data && chown dsn:dsn /srv/data
USER dsn
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"]
CMD ["python", "-m", "app"]
