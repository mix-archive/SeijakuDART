import asyncio
import logging
from contextlib import asynccontextmanager
from importlib import metadata

from fastapi import FastAPI

from ..client.protocol import ControlServerProtocol
from .config import settings_dependency
from .connections import ClientControlProtocol, connections_manager_factory
from .db import session_manager_dependency

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = settings_dependency()
    session_manager = session_manager_dependency()
    connections_manager = connections_manager_factory(session_manager)
    await connections_manager.init_encryption_keys()
    server = await asyncio.get_running_loop().create_server(
        lambda: ControlServerProtocol(
            protocol_factory=lambda: ClientControlProtocol(connections_manager),
            list_encryption_keys=connections_manager.list_encryption_keys,
        ),
        settings.c2_host,
        settings.c2_port,
        reuse_address=True,
        reuse_port=True,
    )
    logger.info("C2 server listening on %s:%d", settings.c2_host, settings.c2_port)
    async with server, session_manager:
        await server.start_serving()
        yield
    return


package_name, *_ = __name__.split(".")
app = FastAPI(
    name=package_name,
    version=metadata.version(package_name),
    description=metadata.metadata(package_name).get("Summary", ""),
    lifespan=lifespan,
)
