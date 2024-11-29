import asyncio
import logging
import uuid
from datetime import UTC
from functools import cache
from typing import Annotated, ClassVar, cast

import sqlalchemy as sa
from anyio import create_memory_object_stream
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from fastapi import Depends

from ..utils import AddressTuple, create_background_task
from .db import Clients, DatabaseSessionManager, SessionManagerDependency

MAX_BUFFER_SIZE = 1024

logger = logging.getLogger(__name__)


type ConnectionDuplex = tuple[
    ClientControlProtocol,
    MemoryObjectSendStream[bytes],
    MemoryObjectReceiveStream[bytes],
]
"""(client protocol, user -> client stream, client -> user stream)"""


class ConnectionsManager:
    cached_encryption_keys: ClassVar[dict[uuid.UUID, str]] = {}
    connections: ClassVar[dict[uuid.UUID, ConnectionDuplex]] = {}

    def __init__(self, session_manager: DatabaseSessionManager):
        self.session_manager = session_manager

    async def init_encryption_keys(self):
        async with self.session_manager.connect() as connection:
            clients = await connection.execute(sa.select(Clients))
            type(self).cached_encryption_keys.clear()
            type(self).cached_encryption_keys.update(
                {client.id_: client.encrypt_key for client in clients.all()}
            )
        logger.info("Initialized %d encryption keys", len(self.cached_encryption_keys))

    def list_encryption_keys(self):
        return self.cached_encryption_keys.copy()

    async def update_connection_last_status(
        self, client_id: str, peer_info: AddressTuple
    ):
        try:
            async with self.session_manager.connect() as connection:
                await connection.execute(
                    sa.update(Clients)
                    .where(Clients.id_ == client_id)
                    .values(last_seen=sa.func.now(UTC), last_from=str(peer_info))
                )
        except Exception:
            logger.exception("Failed to update last seen for %s", client_id)
        logger.debug("Updated last seen for %r to %s", client_id, peer_info)


@cache
def connections_manager_factory(manager: SessionManagerDependency):
    return ConnectionsManager(manager)


ConnectionsManagerDependency = Annotated[
    ConnectionsManager, Depends(connections_manager_factory)
]


class ClientControlProtocol(asyncio.Protocol):
    def __init__(self, manager: ConnectionsManager) -> None:
        self.manager = manager

    def connection_made(self, transport) -> None:
        self.transport = cast(asyncio.WriteTransport, transport)
        self.client_id = transport.get_extra_info("client")
        self.peername = transport.get_extra_info("peername")

        self.send_stream, recv = create_memory_object_stream[bytes](MAX_BUFFER_SIZE)
        send, self.recv_stream = create_memory_object_stream[bytes](MAX_BUFFER_SIZE)

        connections = type(self.manager).connections
        if existing_connection := connections.pop(self.client_id, None):
            logger.warning(
                "Closing duplicate connection of %s from %s",
                self.client_id,
                self.peername,
            )
            protocol, _, _ = existing_connection
            protocol.connection_lost(None)
        connections[self.client_id] = (self, send, recv)

        create_background_task(
            self.manager.update_connection_last_status(self.client_id, self.peername)
        )
        create_background_task(self._consume_recv_stream())

    async def _consume_recv_stream(self):
        async for data in self.recv_stream:
            self.transport.write(data)

    def data_received(self, data: bytes) -> None:
        self.send_stream.send_nowait(data)

    def eof_received(self):
        self.send_stream.send_nowait(b"")
        self.transport.write_eof()

    def connection_lost(self, exc: Exception | None) -> None:
        self.send_stream.close()
        self.recv_stream.close()
        self.transport.close()
