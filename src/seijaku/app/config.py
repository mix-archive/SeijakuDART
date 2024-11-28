from datetime import timedelta
from enum import StrEnum
from functools import cache
from ipaddress import IPv4Address
from logging import getLevelNamesMapping
from typing import Annotated, cast

from fastapi import Depends
from pydantic import Field, IPvAnyAddress
from pydantic_settings import BaseSettings, CliImplicitFlag, SettingsConfigDict

from ..utils import PortNumber

LogLevels = StrEnum(
    "LogLevels",
    list(getLevelNamesMapping().keys()),
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="SJK_", cli_parse_args=True
    )

    host: IPvAnyAddress = Field(
        default=IPv4Address("0.0.0.0"),  # noqa: S104
        alias="host",
        description="Host the web server will listen on",
    )
    port: PortNumber = Field(
        default=8000, alias="port", description="Port the web server will listen on"
    )
    log_level: LogLevels = Field(
        default=cast(LogLevels, "info"),
        alias="log_level",
        description="Log level",
    )
    reload: CliImplicitFlag[bool] = Field(
        False, alias="reload", description="Enable auto-reload"
    )

    c2_port: PortNumber = Field(default=2333, description="Port of the C2 server")
    c2_host: IPvAnyAddress | None = Field(
        None, description="Host of the C2 server, if None, will bind to all interfaces"
    )
    database_uri: str = Field(
        "sqlite+aiosqlite:///./db.sqlite3", description="URI of the database to use"
    )
    encryption_key: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="Key to use for encryption, must be 64 lowercase hex characters",
    )
    session_expire: timedelta = Field(
        timedelta(days=1), description="Session expiration time"
    )


@cache
def settings_dependency():
    return Settings()  # type:ignore


SettingsDependency = Annotated[Settings, Depends(settings_dependency)]
