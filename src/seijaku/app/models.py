import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from .auth import SessionData


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserCreation(BaseSchema):
    username: str
    password: str


class SessionCreation(BaseSchema):
    username: str
    password: str


class SessionCreationResponse(BaseSchema):
    session_data: SessionData
    token: str


class ClientCreation(BaseSchema):
    client_name: str


class ClientResponse(BaseSchema):
    id_: uuid.UUID
    client_name: str
    last_seen: datetime | None
    last_from: str | None
    owner_id: int
