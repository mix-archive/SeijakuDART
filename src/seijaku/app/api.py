import sqlalchemy as sa
from fastapi import APIRouter, HTTPException
from starlette.status import HTTP_204_NO_CONTENT, HTTP_403_FORBIDDEN

from .auth import UserSessionDependency, login, rotate_session
from .config import SettingsDependency
from .db import DatabaseSessionDependency, UserRoles, Users
from .models import (
    ClientCreation,
    SessionCreation,
    SessionCreationResponse,
    UserCreation,
)

router = APIRouter(prefix="/api")


@router.post("/session")
async def create_session(
    model: SessionCreation, db: DatabaseSessionDependency, settings: SettingsDependency
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


@router.put("/client")
async def create_client(
    model: ClientCreation, user: UserSessionDependency, db: DatabaseSessionDependency
):
    pass
