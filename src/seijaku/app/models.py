import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .auth import SessionData
from .db.models import UserRoles


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserCreation(BaseSchema):
    username: str
    password: str


class UserCreationResponse(BaseSchema):
    id_: int
    username: str
    role: UserRoles
    created_at: datetime
    updated_at: datetime


class SessionCreation(BaseSchema):
    username: str
    password: str


class SessionCreationResponse(BaseSchema):
    session_data: SessionData
    token: str


class ClientCreation(BaseSchema):
    client_name: str = Field(pattern=r"^[a-zA-Z0-9_\-]+$", examples=["some-client_1"])


class ClientResponse(BaseSchema):
    id_: uuid.UUID
    client_name: str
    last_seen: datetime | None
    last_from: str | None
    created_at: datetime
    updated_at: datetime


class ListClientResponse(BaseSchema):
    online: bool
    owner_id: int
    owner_name: str
    info: ClientResponse


class ListUserResponse(UserCreationResponse):
    clients: list[ClientResponse]


class HostCommandRequest(BaseSchema):
    command: str
    stdin: bytes | None = None


class HostCommandResponse(BaseSchema):
    status: int
    stdout: bytes
    stderr: bytes
