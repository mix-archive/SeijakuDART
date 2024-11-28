from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cache
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import settings_dependency


class DatabaseSessionManager:
    def __init__(self, host: str, engine_kwargs: dict[str, Any] | None = None):
        self._engine = create_async_engine(host, **engine_kwargs or {})
        self._sessionmaker = async_sessionmaker(autocommit=False, bind=self._engine)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        if self._engine is None:
            return

        await self._engine.dispose()
        self._engine = None
        self._sessionmaker = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        if self._engine is None:
            raise ValueError("Engine has been disposed")

        async with self._engine.begin() as connection:
            try:
                yield connection
            except Exception:
                await connection.rollback()
                raise

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        if self._sessionmaker is None:
            raise ValueError("Session maker has been disposed")

        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@cache
def session_manager_dependency():
    settings = settings_dependency()
    return DatabaseSessionManager(str(settings.database_uri))


SessionManagerDependency = Annotated[
    DatabaseSessionManager, Depends(session_manager_dependency)
]


async def _database_session(manager: SessionManagerDependency):
    async with manager.session() as session:
        yield session


DatabaseSessionDependency = Annotated[AsyncSession, Depends(_database_session)]
