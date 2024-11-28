from pydantic import BaseModel, ConfigDict

from .auth import SessionData


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SessionCreation(BaseSchema):
    username: str
    password: str


class SessionCreationResponse(BaseSchema):
    session_data: SessionData
    token: str


class ClientCreation(BaseSchema):
    client_name: str
