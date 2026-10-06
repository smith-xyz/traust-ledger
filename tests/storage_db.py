"""Storage setup for database-backed ledger tests."""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from sqlalchemy.engine import Engine, make_url
from traust_contracts.v1.storage import Store

PRODUCT = "ledger-tests"
REPO_URL = "https://example.test/repo"


def storage_for(config: object) -> None:
    url = getattr(config, "database_url", None)
    if url:
        prepare_storage(url)


def prepare_storage(
    target: Engine | str,
    *,
    product: str = PRODUCT,
    repo_url: str = REPO_URL,
    ref: str = "",
) -> str:
    if isinstance(target, Engine):
        return _with_engine(target, product, repo_url, ref)
    url = make_url(target)
    if url.get_backend_name() == "sqlite":
        conn: Any = sqlite3.connect(url.database or ":memory:")
    else:
        import psycopg

        conn = psycopg.connect(url.set(drivername="postgresql").render_as_string(False))
    try:
        return _register(conn, product, repo_url, ref)
    finally:
        conn.close()


def _with_engine(engine: Engine, product: str, repo_url: str, ref: str) -> str:
    raw = engine.raw_connection()
    try:
        return _register(raw.driver_connection, product, repo_url, ref)
    finally:
        raw.close()


def _register(conn: sqlite3.Connection | Any, product: str, repo_url: str, ref: str) -> str:
    store = Store(conn)
    store.init()
    return store.register_product_repo(
        store.register_product(product), store.register_repo(repo_url), ref
    )


def copy_registry(source: str, target: str) -> None:
    prepare_storage(target)
    src, dst = (sqlite3.connect(make_url(url).database or "") for url in (source, target))
    try:
        for table in ("product", "repo", "product_repo"):
            rows = src.execute(f"SELECT * FROM {table}").fetchall()
            if rows:
                marks = ",".join("?" * len(rows[0]))
                dst.executemany(f"INSERT OR IGNORE INTO {table} VALUES ({marks})", rows)
        dst.commit()
    finally:
        src.close()
        dst.close()


def owner_of(backend: object) -> str | None:
    from traust_ledger._internal.backends.db import DbBackend

    if not isinstance(backend, DbBackend):
        return None
    return prepare_storage(backend._engine, repo_url=f"https://example.test/{uuid.uuid4().hex}")
