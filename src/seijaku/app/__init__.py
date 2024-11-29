import asyncio
import logging
from contextlib import asynccontextmanager
from importlib import metadata

from fastapi import FastAPI
from scalar_fastapi import get_scalar_api_reference

from ..client.protocol import ControlServerProtocol
from .api import router
from .config import settings_dependency
from .connections import ClientControlProtocol, connections_manager_factory
from .db import Base, session_manager_dependency

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = settings_dependency()
    session_manager = session_manager_dependency()
    async with session_manager.connect() as conn:
        # TODO: This should be done in a migration
        await conn.run_sync(Base.metadata.create_all)
    connections_manager = connections_manager_factory(session_manager)
    await connections_manager.init_encryption_keys()
    server = await asyncio.get_running_loop().create_server(
        lambda: ControlServerProtocol(
            protocol_factory=lambda: ClientControlProtocol(connections_manager),
            list_encryption_keys=connections_manager.list_encryption_keys,
        ),
        str(settings.c2_host) if settings.c2_host else None,
        int(settings.c2_port),
        reuse_address=True,
        reuse_port=True,
    )
    logger.info("C2 server listening on %r:%d", settings.c2_host, settings.c2_port)
    async with server, session_manager:
        await server.start_serving()
        yield
    return


package_name, *_ = __name__.split(".")
app = FastAPI(
    title=package_name.title(),
    version=metadata.version(package_name),
    description=metadata.metadata(package_name)["summary"],
    redoc_url=None,
    docs_url=None,
    lifespan=lifespan,
)
app.include_router(router)


@app.get("/scalar", include_in_schema=False)
async def scalar_api_doc():
    return get_scalar_api_reference(openapi_url=str(app.openapi_url), title=app.title)
