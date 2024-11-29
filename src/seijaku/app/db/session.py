import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import cache
from typing import Annotated, Any

from fastapi import Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.status import HTTP_409_CONFLICT

from ..config import settings_dependency

logger = logging.getLogger(__name__)


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
            await session.commit()
        except IntegrityError as e:
            await session.rollback()
            logger.warning("Error executing statement=%r: %r", e.statement, e.orig)
            logger.debug("Integrity error params=%r", e.params)
            raise HTTPException(HTTP_409_CONFLICT, detail=str(e.orig)) from e
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
