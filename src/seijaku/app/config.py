from functools import cache
from typing import Annotated

from fastapi import Depends
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SJK_")

    c2_port: int = 2333
    """Port of the C2 server"""
    c2_host: str | None = None
    """Host of the C2 server, if None, will bind to all interfaces"""
    database_uri: str = "sqlite+aiosqlite:///./db.sqlite3"
    """URI of the database to use"""
    encryption_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    """Key to use for encryption, must be 64 lowercase hex characters"""
    session_expire: int = 60 * 60 * 24
    """Session expiration time in seconds"""


@cache
def settings_dependency():
    return Settings()  # type:ignore


SettingsDependency = Annotated[Settings, Depends(settings_dependency)]
