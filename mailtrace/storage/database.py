"""Database management for MailTrace."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from mailtrace.storage.models import Base


def _sync_url(database_url: str) -> str:
    """Return the synchronous equivalent of an async database URL."""
    if database_url.startswith("sqlite+aiosqlite://"):
        return "sqlite://" + database_url[len("sqlite+aiosqlite://") :]
    if database_url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + database_url[len("postgresql+asyncpg://") :]
    return database_url


def _sqlite_path(database_url: str) -> Path | None:
    """Extract the filesystem path from a SQLite URL, if it has one."""
    prefix = "sqlite+aiosqlite:///"
    if not database_url.startswith(prefix):
        return None
    raw = database_url[len(prefix) :]
    if not raw or raw == ":memory:" or raw.startswith("file:"):
        return None
    return Path(raw)


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, database_url: str | None = None, data_dir: Path | None = None):
        self.data_dir = data_dir
        if database_url:
            self.database_url = database_url
        else:
            if data_dir is None:
                data_dir = Path.cwd()
                self.data_dir = data_dir
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "cases.db"
            self.database_url = f"sqlite+aiosqlite:///{db_path.resolve().as_posix()}"
        self.sync_database_url = _sync_url(self.database_url)

        # Ensure the parent directory of an on-disk SQLite database exists.
        sqlite_path = _sqlite_path(self.database_url)
        if sqlite_path is not None:
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)

        self.async_engine: AsyncEngine | None = None
        self.async_session_factory: async_sessionmaker[AsyncSession] | None = None
        self.sync_engine: Engine | None = None
        self.sync_session_factory: sessionmaker[Session] | None = None

    async def initialize(self) -> None:
        """Initialize database engines and create missing tables.

        Alembic migrations are retained for controlled schema upgrades, but a
        fresh installation must work without running a separate migration
        step.  ``create_all`` is safe to call repeatedly: it creates missing
        tables and leaves existing data untouched.
        """
        if self.async_engine is not None:
            return

        self.async_engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_pre_ping=True,
        )

        if self.database_url.startswith("sqlite"):
            # Enable foreign keys for SQLite.
            @event.listens_for(self.async_engine.sync_engine, "connect")
            def set_sqlite_pragma(
                dbapi_connection: Any, connection_record: Any
            ) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()

        self.async_session_factory = async_sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Synchronous engine is used for schema bootstrap and migrations.
        self.sync_engine = create_engine(self.sync_database_url, echo=False)
        self.sync_session_factory = sessionmaker(bind=self.sync_engine)
        Base.metadata.create_all(self.sync_engine)

    async def close(self) -> None:
        """Close database connections."""
        if self.async_engine:
            await self.async_engine.dispose()
        if self.sync_engine:
            self.sync_engine.dispose()
        self.async_engine = None
        self.async_session_factory = None
        self.sync_engine = None
        self.sync_session_factory = None

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session."""
        if not self.async_session_factory:
            await self.initialize()
        assert self.async_session_factory is not None
        async with self.async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def sync_session(self) -> Session:
        """Get a synchronous database session (for migrations)."""
        if not self.sync_session_factory:
            self.sync_engine = create_engine(self.sync_database_url, echo=False)
            self.sync_session_factory = sessionmaker(bind=self.sync_engine)
        return self.sync_session_factory()


# Global database manager
_db_manager: DatabaseManager | None = None


def get_database_manager(
    database_url: str | None = None, data_dir: Path | None = None
) -> DatabaseManager:
    """Get the global database manager instance.

    Supplying new connection arguments replaces a previously configured
    manager so tests and callers cannot accidentally reuse a stale database.
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(database_url, data_dir)
    elif database_url is not None or data_dir is not None:
        candidate = DatabaseManager(database_url, data_dir)
        if candidate.database_url != _db_manager.database_url:
            _db_manager = candidate
    return _db_manager


async def init_database(
    database_url: str | None = None, data_dir: Path | None = None
) -> DatabaseManager:
    """Initialize the database manager and return it."""
    global _db_manager
    if _db_manager is not None and (database_url is not None or data_dir is not None):
        candidate = DatabaseManager(database_url, data_dir)
        if candidate.database_url != _db_manager.database_url:
            await _db_manager.close()
            _db_manager = None

    manager = get_database_manager(database_url, data_dir)
    await manager.initialize()
    return manager


async def close_database() -> None:
    """Close the global database manager."""
    global _db_manager
    if _db_manager:
        await _db_manager.close()
        _db_manager = None


__all__ = [
    "DatabaseManager",
    "close_database",
    "get_database_manager",
    "init_database",
]
