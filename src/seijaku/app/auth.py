import time
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


class SessionData(BaseModel):
    user_id: int = Field(alias="sub")
    role: UserRoles = Field(alias="role")
    username: str
    exp: int


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
    settings: SettingsDependency,
):
    try:
        user_id: int = jwt.decode(
            credentials.credentials,
            options={"verify_signature": False},
        )["sub"]
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
            )
        )
    except (jwt.PyJWTError, ValidationError) as e:
        raise UnauthorizedError("Token validation failed") from e
    if full_token.exp + settings.session_expire < time.time():
        raise UnauthorizedError("Token expired")
    return full_token


UserSessionDependency = Annotated[SessionData, Depends(authentication_dependency)]


async def login(username: str, password: str, session: AsyncSession):
    result = await session.scalars(sa.select(Users).filter(Users.username == username))
    user = result.first()
    if user is None:
        raise UnauthorizedError("Invalid user")
    if user.password is None or user.jwt_secret is None:
        raise UnauthorizedError("User is not allowed to log in")
    if user.password != password:
        raise UnauthorizedError("Password is incorrect")
    data = SessionData(
        sub=user.id_,
        role=user.role,
        username=user.username,
        exp=int(time.time()),
    )
    return data, jwt.encode(
        data.model_dump(by_alias=True),
        user.jwt_secret,
        algorithm="HS256",
    )


async def logout(username: str, session: AsyncSession):
    new_secret = token_bytes(JWT_SECRET_LENGTH)
    await session.execute(
        sa.update(Users).where(Users.username == username).values(jwt_secret=new_secret)
    )
