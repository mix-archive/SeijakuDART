import logging
from datetime import UTC, datetime
from secrets import token_bytes
from typing import Annotated

import jwt
import sqlalchemy as sa
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_401_UNAUTHORIZED

from .config import SettingsDependency
from .db.models import UserRoles, Users
from .db.session import DatabaseSessionDependency

CredentialsDependency = Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]

JWT_SECRET_LENGTH = 32

logger = logging.getLogger(__name__)


class SessionData(BaseModel):
    uid: int
    username: str = Field(alias="sub")
    role: UserRoles = Field(alias="role")
    exp: datetime


class UnauthorizedError(HTTPException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


async def authentication_dependency(
    credentials: CredentialsDependency,
    session: DatabaseSessionDependency,
):
    try:
        user_id: int = jwt.decode(
            credentials.credentials,
            options={"verify_signature": False},
        )["uid"]
    except (jwt.PyJWTError, KeyError) as e:
        raise UnauthorizedError("Invalid token") from e
    result = await session.scalars(sa.select(Users).filter(Users.id_ == user_id))
    if (user := result.first()) is None or user.jwt_secret is None:
        raise UnauthorizedError("Invalid user")
    try:
        full_token = SessionData.model_validate(
            jwt.decode(
                credentials.credentials,
                user.jwt_secret,
                algorithms=["HS256"],
                subject=user.username,
            )
        )
    except (jwt.PyJWTError, ValidationError) as e:
        logger.debug("Token validation failed for user %r, error: %r", user.username, e)
        raise UnauthorizedError("Token validation failed") from e
    return full_token


UserSessionDependency = Annotated[SessionData, Depends(authentication_dependency)]


async def login(
    username: str, password: str, session: AsyncSession, settings: SettingsDependency
):
    result = await session.scalars(sa.select(Users).filter(Users.username == username))
    user = result.first()
    if user is None:
        raise UnauthorizedError("Invalid user")
    if user.password is None or user.jwt_secret is None:
        raise UnauthorizedError("User is not allowed to log in")
    if user.password != password:
        raise UnauthorizedError("Password is incorrect")
    data = SessionData(
        uid=user.id_,
        sub=user.username,
        role=user.role,
        exp=datetime.now(UTC) + settings.session_expire,
    )
    return data, jwt.encode(
        data.model_dump(by_alias=True),
        user.jwt_secret,
        algorithm="HS256",
    )


async def rotate_session(username: str, session: AsyncSession):
    new_secret = token_bytes(JWT_SECRET_LENGTH)
    await session.execute(
        sa.update(Users).where(Users.username == username).values(jwt_secret=new_secret)
    )
