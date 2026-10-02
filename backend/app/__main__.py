"""``python -m app``: serve the API using host/port from settings."""

from __future__ import annotations

import uvicorn

from app.core.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,  # logging is configured by create_app
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
