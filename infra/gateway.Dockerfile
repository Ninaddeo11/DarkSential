# syntax=docker/dockerfile:1
# Backend image for the lab gateway: the regular image plus nftables and nmap.
# Built from the backend/ context by infra/docker-compose.gateway.yml.
FROM ghcr.io/astral-sh/uv:0.12.17 AS uv

FROM python:3.13.15-slim-trixie AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra lab --extra ml

FROM python:3.13.15-slim-trixie
RUN apt-get update \
  && apt-get install -y --no-install-recommends nftables nmap iproute2 \
  && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home-dir /srv dsn
WORKDIR /srv
COPY --from=build /srv/.venv /srv/.venv
COPY app ./app
COPY config ./config
COPY migrations ./migrations
ENV PATH="/srv/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN mkdir -p /srv/data && chown dsn:dsn /srv/data
# nft needs CAP_NET_ADMIN *effective* for the process: grant the file capability
# to the nft binary only, so the app itself still runs unprivileged.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
  && setcap cap_net_admin+ep /usr/sbin/nft \
  && setcap cap_net_raw,cap_net_admin+ep /usr/bin/nmap \
  && rm -rf /var/lib/apt/lists/*
USER dsn
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"]
CMD ["python", "-m", "app"]
