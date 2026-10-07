"""Alembic environment. Runs against the connection passed in by
``app.core.db.init_db`` (programmatic upgrades at startup) or, from the CLI,
against ``DSN_DATABASE_URL``."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

from app.core.db import Base
from app.models import device, feed_run, risk  # noqa: F401 - register tables

target_metadata = Base.metadata
config = context.config


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite ALTER support
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    _run(connection)
else:  # pragma: no cover - CLI path
    from app.core.config import get_settings
    from app.core.db import make_engine

    with make_engine(get_settings().database_url).connect() as conn:
        _run(conn)
