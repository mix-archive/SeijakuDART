import asyncio
import logging
from contextlib import asynccontextmanager
from importlib import metadata

from fastapi import FastAPI

from seijaku.client.protocol import ControlServerProtocol

from .config import settings_dependency
from .db import session_manager_dependency

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = settings_dependency()
    session_manager = session_manager_dependency()
    server = await asyncio.get_running_loop().create_server(
        asyncio.Protocol,
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
